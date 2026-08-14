"""DOM-based injection analysis.

Server-side scanners miss this entire class because the vulnerability never
appears in a server response body — the payload travels through the URL fragment
or postMessage and is written to a sink by the page's own JavaScript. That is
where a large share of real XSS in modern single-page applications lives.

The analysis is static but dataflow-aware: it locates a taint **source**, locates
a **sink**, and only reports when the same expression or variable reaches both.
Co-occurrence alone is explicitly downgraded, because "this page contains
innerHTML somewhere" is noise, not a finding.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from app.config import settings
from app.targeting import is_same_target_scope
from app.tasks.vulnscan.danger.budget import (
    DangerBudget,
    danger_finding,
    evidence_block,
    fingerprint,
    truncated,
)
from app.tasks.vulnscan.danger.remediation import remediation_for

logger = logging.getLogger("recontitan.danger.dom")

MODULE = "dom_injection"
A03 = "A03:2021-Injection"

#: Attacker-controllable inputs available to client-side script.
TAINT_SOURCES: tuple[tuple[str, str, str], ...] = (
    ("location.hash", r"location\s*\.\s*hash", "URL fragment - never sent to the server, so server-side filtering cannot see it"),
    ("location.search", r"location\s*\.\s*search", "Query string read client-side"),
    ("location.href", r"location\s*\.\s*href", "Full URL read client-side"),
    ("location.pathname", r"location\s*\.\s*pathname", "URL path read client-side"),
    ("document.URL", r"document\s*\.\s*URL", "Full URL"),
    ("document.referrer", r"document\s*\.\s*referrer", "Referring URL, controllable by the linking site"),
    ("window.name", r"window\s*\.\s*name", "Survives cross-origin navigation"),
    ("postMessage", r"addEventListener\s*\(\s*['\"]message['\"]", "Cross-window message payload"),
    ("localStorage", r"localStorage\s*\.\s*getItem", "Client storage, attacker-writable via any XSS"),
    ("sessionStorage", r"sessionStorage\s*\.\s*getItem", "Client storage"),
    ("URLSearchParams", r"new\s+URLSearchParams", "Parsed query string"),
)

#: Sinks that turn a string into markup, code, or navigation.
TAINT_SINKS: tuple[tuple[str, str, str, str], ...] = (
    ("innerHTML", r"\.\s*innerHTML\s*=", "high", "Parses the string as HTML"),
    ("outerHTML", r"\.\s*outerHTML\s*=", "high", "Parses the string as HTML"),
    ("insertAdjacentHTML", r"\.\s*insertAdjacentHTML\s*\(", "high", "Parses the string as HTML"),
    ("document.write", r"document\s*\.\s*write(?:ln)?\s*\(", "high", "Parses the string as HTML during load"),
    ("eval", r"\beval\s*\(", "critical", "Executes the string as JavaScript"),
    ("Function", r"new\s+Function\s*\(", "critical", "Compiles the string as JavaScript"),
    ("setTimeout_string", r"setTimeout\s*\(\s*['\"]", "critical", "Executes a string argument as code"),
    ("setInterval_string", r"setInterval\s*\(\s*['\"]", "critical", "Executes a string argument as code"),
    ("jQuery_html", r"\$\([^)]*\)\s*\.\s*html\s*\(", "high", "jQuery .html() parses markup"),
    ("jQuery_append", r"\$\([^)]*\)\s*\.\s*(?:append|prepend|after|before)\s*\(", "high", "jQuery insertion parses markup"),
    ("jQuery_selector", r"\$\s*\(\s*(?:location|document\.URL|window\.name)", "high", "Tainted jQuery selector executes markup"),
    ("location_assign", r"location\s*(?:\.\s*(?:href|assign|replace)\s*(?:=|\())", "medium", "Navigates to the string"),
    ("srcdoc", r"\.\s*srcdoc\s*=", "high", "Renders the string as a document"),
    ("setAttribute_event", r"\.\s*setAttribute\s*\(\s*['\"]on\w+", "high", "Installs an event handler from a string"),
    ("dangerouslySetInnerHTML", r"dangerouslySetInnerHTML", "high", "React escape hatch that parses HTML"),
    ("v_html", r"v-html\s*=", "high", "Vue directive that parses HTML"),
)

#: Prototype-pollution gadgets reachable from client input.
POLLUTION_PATTERNS: tuple[tuple[str, str], ...] = (
    ("__proto__ assignment", r"__proto__\s*\]?\s*(?:=|\[)"),
    ("constructor.prototype write", r"constructor\s*\.\s*prototype\s*\["),
    ("recursive merge", r"function\s+(?:merge|extend|deepMerge|deepAssign)\s*\("),
    ("jQuery deep extend", r"\$\.extend\s*\(\s*true"),
    ("lodash merge", r"_\.(?:merge|mergeWith|defaultsDeep|set)\s*\("),
    ("Object.assign into literal", r"Object\.assign\s*\(\s*\{\}\s*,\s*(?:JSON\.parse|location|params)"),
)

#: DOM clobbering: named elements that shadow globals or object properties.
CLOBBER_RE = re.compile(
    r"<(?:a|form|img|iframe|input|object|embed)\b[^>]*\b(?:id|name)\s*=\s*[\"']?"
    r"(__proto__|constructor|config|options|settings|window|document|location|self|top|globalThis)\b",
    re.IGNORECASE,
)

#: postMessage handlers that never check the sender.
MESSAGE_HANDLER_RE = re.compile(
    r"addEventListener\s*\(\s*['\"]message['\"]\s*,\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>|\w+)",
    re.IGNORECASE,
)
ORIGIN_CHECK_RE = re.compile(r"\.\s*origin\s*(?:===?|!==?|\.\s*(?:indexOf|match|startsWith|includes))", re.IGNORECASE)

#: A statement that carries a source into a sink on one line or via one variable.
_ASSIGN_RE = re.compile(r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,400})")


@dataclass
class DomFlow:
    """One source -> sink dataflow with the evidence that links them."""

    source: str
    sink: str
    severity: str
    via: str
    direct: bool
    snippet: str
    script: str
    sink_effect: str = ""
    source_note: str = ""


def _script_sources(page_url: str, html_text: str, target: str) -> tuple[list[tuple[str, str]], int]:
    """Return ``[(label, code)]`` for inline and same-scope external scripts."""
    soup = BeautifulSoup(html_text, "html.parser")
    inline: list[tuple[str, str]] = []
    external: list[str] = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            url = urljoin(page_url, src)
            host = urlsplit(url).hostname or ""
            if is_same_target_scope(host, target) and url not in external:
                external.append(url)
        else:
            code = script.string or script.get_text(" ", strip=False)
            if code and code.strip():
                inline.append((f"inline@{page_url}", code[: settings.JS_ANALYSIS_MAX_BYTES]))
    # Inline handlers are a sink surface of their own.
    for tag in soup.find_all(True):
        for attribute, value in list(tag.attrs.items()):
            if attribute.lower().startswith("on") and isinstance(value, str) and value.strip():
                inline.append((f"handler:{attribute}@{page_url}", value))
    return inline, len(external)


def _trace_flows(label: str, code: str) -> list[DomFlow]:
    """Find source -> sink flows, preferring direct and one-hop variable links."""
    flows: list[DomFlow] = []
    seen: set[tuple[str, str]] = set()

    for source_name, source_pattern, source_note in TAINT_SOURCES:
        source_matches = list(re.finditer(source_pattern, code, re.IGNORECASE))
        if not source_matches:
            continue

        # Variables that receive the source directly.
        tainted: set[str] = set()
        for assignment in _ASSIGN_RE.finditer(code):
            variable, expression = assignment.group(1), assignment.group(2)
            if re.search(source_pattern, expression, re.IGNORECASE):
                tainted.add(variable)

        for sink_name, sink_pattern, severity, sink_effect in TAINT_SINKS:
            for sink_match in re.finditer(sink_pattern, code, re.IGNORECASE):
                key = (source_name, sink_name)
                start = sink_match.start()
                statement = code[start: start + 400]
                line_start = code.rfind("\n", 0, start) + 1
                line = code[line_start: code.find("\n", start) if code.find("\n", start) > 0 else len(code)]

                direct = bool(re.search(source_pattern, line, re.IGNORECASE)) or bool(
                    re.search(source_pattern, statement, re.IGNORECASE)
                )
                via = ""
                if not direct:
                    for variable in tainted:
                        if re.search(rf"\b{re.escape(variable)}\b", statement):
                            via = variable
                            break
                if not direct and not via:
                    continue
                if key in seen:
                    continue
                seen.add(key)
                flows.append(DomFlow(
                    source=source_name,
                    sink=sink_name,
                    severity=severity,
                    via=via,
                    direct=direct,
                    snippet=truncated(line.strip() or statement, 220),
                    script=label,
                    sink_effect=sink_effect,
                    source_note=source_note,
                ))
    return flows


def _severity_for(flow: DomFlow) -> str:
    """Direct flows are reported at full weight; one-hop flows one step lower."""
    if flow.direct:
        return flow.severity
    return {"critical": "high", "high": "medium", "medium": "low"}.get(flow.severity, "low")


def run_dom_analysis(target: str, budget: DangerBudget, seeds: list[str]) -> list[dict]:
    """Fetch in-scope pages and their scripts, then report DOM injection flows."""
    findings: list[dict] = []
    pages = (seeds or [f"https://{target}/"])[: settings.DANGER_MAX_HOSTS]
    all_flows: list[DomFlow] = []
    pollution_hits: list[tuple[str, str]] = []
    clobber_hits: list[str] = []
    message_handlers: list[tuple[str, bool]] = []
    scripts_examined = 0

    for page_url in pages:
        if not budget.can_spend(MODULE):
            break
        page = budget.probe(MODULE, "GET", page_url, counts_as_payload=False)
        if not page.ok or page.response is None:
            continue
        body = page.text
        if "html" not in page.response.headers.get("Content-Type", "").lower():
            continue

        for match in CLOBBER_RE.finditer(body):
            clobber_hits.append(f"{truncated(match.group(0), 160)} @ {truncated(page_url, 100)}")

        inline, external_count = _script_sources(page_url, body, target)
        sources: list[tuple[str, str]] = list(inline)

        soup = BeautifulSoup(body, "html.parser")
        for script in soup.find_all("script", src=True):
            if not budget.can_spend(MODULE):
                break
            url = urljoin(page_url, str(script["src"]))
            host = urlsplit(url).hostname or ""
            if not is_same_target_scope(host, target):
                continue
            asset = budget.probe(MODULE, "GET", url, counts_as_payload=False)
            if asset.ok:
                sources.append((truncated(url, 160), asset.text[: settings.JS_ANALYSIS_MAX_BYTES]))

        for label, code in sources:
            scripts_examined += 1
            all_flows.extend(_trace_flows(label, code))
            for name, pattern in POLLUTION_PATTERNS:
                if re.search(pattern, code, re.IGNORECASE):
                    pollution_hits.append((name, label))
            for handler in MESSAGE_HANDLER_RE.finditer(code):
                window = code[handler.start(): handler.start() + 700]
                message_handlers.append((label, bool(ORIGIN_CHECK_RE.search(window))))

    # ── Source -> sink flows ────────────────────────────────────────────────
    unique: dict[tuple[str, str, str], DomFlow] = {}
    for flow in all_flows:
        unique.setdefault((flow.source, flow.sink, flow.script), flow)
    flows = sorted(
        unique.values(),
        key=lambda item: ({"critical": 0, "high": 1, "medium": 2, "low": 3}[_severity_for(item)], not item.direct),
    )

    for flow in flows[:25]:
        severity = _severity_for(flow)
        link = "directly on the same statement" if flow.direct else f"through the variable '{flow.via}'"
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_dom_xss",
            severity=severity,
            title=f"DOM Injection - {flow.source} reaches {flow.sink}",
            description=(
                f"Client-side script reads {flow.source} and passes it to {flow.sink} {link}. "
                f"{flow.sink_effect}. {flow.source_note}. "
                + (
                    "The dataflow is on a single statement, so the taint path is unambiguous."
                    if flow.direct else
                    "The link is a one-hop variable assignment; confirm the value is not sanitized in between."
                )
                + " A fragment-based source is never transmitted to the server, so no server-side "
                "filter, WAF, or log will observe the payload."
            ),
            evidence=evidence_block([
                ("Script", flow.script),
                ("Taint source", f"{flow.source} - {flow.source_note}"),
                ("Sink", f"{flow.sink} - {flow.sink_effect}"),
                ("Link", "direct" if flow.direct else f"via variable '{flow.via}'"),
                ("Code", flow.snippet),
                ("Exploitation status", "CONFIRMED dataflow" if flow.direct else "candidate dataflow"),
                ("Proof type", "Static source-to-sink dataflow"),
            ]),
            remediation=remediation_for("dom_xss"),
            owasp=A03,
            attack_vector=f"DOM-based XSS ({flow.source} -> {flow.sink})",
            asset=flow.script,
        ))

    # ── Prototype pollution ─────────────────────────────────────────────────
    if pollution_hits:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_prototype_pollution",
            severity="high" if any("__proto__" in name for name, _ in pollution_hits) else "medium",
            title=f"Client-Side Prototype Pollution Gadgets - {len(pollution_hits)}",
            description=(
                "The application contains recursive merge or property-assignment patterns reachable from "
                "client-controlled data. Polluting Object.prototype lets an attacker inject properties that "
                "every object inherits, which commonly escalates to XSS through a template or option object, "
                "and to authorization bypass where code checks a flag that was never set."
            ),
            evidence=evidence_block([
                ("Gadgets found", len(pollution_hits)),
                *[(name, script) for name, script in pollution_hits[:20]],
                ("Proof type", "Static gadget identification"),
            ]),
            remediation=remediation_for("prototype_pollution"),
            owasp=A03,
            attack_vector="Client-side prototype pollution",
            asset=target,
        ))

    # ── DOM clobbering ──────────────────────────────────────────────────────
    if clobber_hits:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_dom_clobbering",
            severity="medium",
            title=f"DOM Clobbering Surface - {len(clobber_hits)} named element(s)",
            description=(
                "Markup contains elements whose id or name shadows a global or configuration property. If any "
                "of this markup is attacker-influenced, the named element replaces the real object and script "
                "that reads it receives an element instead, which is a well-established route to XSS and to "
                "bypassing client-side checks."
            ),
            evidence=evidence_block([
                ("Named elements", len(clobber_hits)),
                *[(f"Element {index}", value) for index, value in enumerate(clobber_hits[:15], 1)],
            ]),
            remediation=remediation_for("dom_clobbering"),
            owasp=A03,
            attack_vector="DOM clobbering",
            asset=target,
        ))

    # ── postMessage origin validation ───────────────────────────────────────
    unchecked = [label for label, checked in message_handlers if not checked]
    if unchecked:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_postmessage",
            severity="high",
            title=f"postMessage Handler Without Origin Check - {len(unchecked)}",
            description=(
                "A message event listener processes incoming data without comparing event.origin against an "
                "allow-list. Any page that can obtain a reference to this window — an opener, an embedding "
                "frame, or a popup it created — can drive that handler with arbitrary data."
            ),
            evidence=evidence_block([
                ("Handlers without an origin check", len(unchecked)),
                ("Handlers with an origin check", len(message_handlers) - len(unchecked)),
                *[(f"Script {index}", label) for index, label in enumerate(unchecked[:15], 1)],
                ("Proof type", "Static handler analysis"),
            ]),
            remediation=remediation_for("postmessage"),
            owasp=A03,
            attack_vector="Cross-window message injection",
            asset=target,
        ))

    findings.append(danger_finding(
        tool=MODULE,
        category="danger_dom_summary",
        severity="info",
        title=f"DOM Injection Analysis - {len(flows)} dataflow(s) across {scripts_examined} script(s)",
        description=(
            "Every same-scope script was parsed for taint sources and injection sinks, and only pairs linked by "
            "a shared statement or variable were reported. Bundled and minified code can hide flows that this "
            "static pass cannot follow, so a clean result here is not proof the client side is safe."
        ),
        evidence=evidence_block([
            ("Pages analysed", len(pages)),
            ("Scripts analysed", scripts_examined),
            ("Direct source-to-sink flows", sum(1 for flow in flows if flow.direct)),
            ("One-hop flows", sum(1 for flow in flows if not flow.direct)),
            ("Prototype pollution gadgets", len(pollution_hits)),
            ("DOM clobbering candidates", len(clobber_hits)),
            ("postMessage handlers", len(message_handlers)),
        ]),
        owasp=A03,
        asset=target,
    ))

    logger.info("[danger:dom] %s: %d flows, %d scripts", target, len(flows), scripts_examined)
    return findings
