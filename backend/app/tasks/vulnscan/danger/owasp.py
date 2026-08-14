"""OWASP Top 10 (2021) coverage checks and the danger coverage matrix.

Injection (A03) and SSRF (A10) live in :mod:`injection`; access control (A01)
in :mod:`idor` and :mod:`directory`. This module adds the remaining categories
and assembles the tested / not-tested matrix that the report renders.
"""

from __future__ import annotations

import logging
import re
import socket
import ssl
import warnings
from urllib.parse import urlencode, urlsplit

from app.models.schemas import AttackSurfaceItem, InputPointType, OwaspCoverageEntry
from app.services.danger_mode import OWASP_CATALOGUE
from app.tasks.vulnscan.danger.budget import (
    DangerBudget,
    danger_finding,
    evidence_block,
    fingerprint,
    truncated,
)

logger = logging.getLogger("recontitan.danger.owasp")

MODULE = "owasp_matrix"

A02 = "A02:2021-Cryptographic Failures"
A04 = "A04:2021-Insecure Design"
A05 = "A05:2021-Security Misconfiguration"
A06 = "A06:2021-Vulnerable and Outdated Components"
A07 = "A07:2021-Identification and Authentication Failures"
A08 = "A08:2021-Software and Data Integrity Failures"
A09 = "A09:2021-Security Logging and Monitoring Failures"

#: Product versions with well-known, widely exploited weaknesses. Fingerprint
#: matches are candidates only and always need authoritative confirmation.
KNOWN_VULNERABLE_VERSIONS: tuple[tuple[str, str, str], ...] = (
    ("openssl", r"^1\.0\.", "OpenSSL 1.0.x is end-of-life and unpatched"),
    ("openssl", r"^1\.1\.0", "OpenSSL 1.1.0 is end-of-life"),
    ("apache", r"^2\.4\.(?:[0-9]|[1-3][0-9]|4[0-8])$", "Apache httpd below 2.4.49 misses several fixed CVEs"),
    ("nginx", r"^1\.(?:[0-9]|1[0-7])\.", "nginx below 1.18 is out of mainline support"),
    ("php", r"^(?:5\.|7\.[0-3])", "PHP 5.x and 7.0-7.3 are end-of-life"),
    ("jquery", r"^(?:1\.|2\.|3\.[0-4])", "jQuery below 3.5.0 is affected by known XSS issues"),
    ("bootstrap", r"^3\.", "Bootstrap 3.x is end-of-life"),
    ("wordpress", r"^(?:[0-4]\.|5\.[0-7])", "WordPress below 5.8 is out of active support"),
)

CSRF_TOKEN_RE = re.compile(
    r"(?i)(csrf|xsrf|authenticity_token|__requestverificationtoken|_token)"
)
PASSWORD_POLICY_RE = re.compile(r"(?i)(minlength\s*=|pattern\s*=|autocomplete\s*=\s*[\"']?new-password)")
SRI_RE = re.compile(r"<script[^>]+src=[\"'](https?://[^\"']+)[\"'][^>]*>", re.IGNORECASE)
INTEGRITY_RE = re.compile(r"integrity\s*=\s*[\"']sha(?:256|384|512)-", re.IGNORECASE)
DESERIALIZATION_RE = re.compile(
    r"(?i)(rO0AB|aced0005|O:\d+:\"|__reduce__|pickle\.loads|yaml\.load\s*\(|ObjectInputStream)"
)


# ── A02: Cryptographic failures ───────────────────────────────────────────────

def check_cryptographic_failures(target: str, budget: DangerBudget, seeds: list[str]) -> list[dict]:
    """TLS protocol/cipher review plus plaintext-HTTP detection."""
    findings: list[dict] = []
    host = urlsplit(seeds[0]).hostname if seeds else target

    weak_protocols: list[str] = []
    negotiated = ""
    cipher = ""

    for protocol_name, version in (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        try:
            with warnings.catch_warnings():
                # Pinning an obsolete version is the point of this probe, so the
                # interpreter's deprecation notice is expected and not actionable.
                warnings.simplefilter("ignore", DeprecationWarning)
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                context.minimum_version = version
                context.maximum_version = version
            with socket.create_connection((host, 443), timeout=8) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    suite = (tls.cipher() or ("unknown",))[0]
                    weak_protocols.append(f"{protocol_name} accepted (cipher {suite})")
        except Exception:
            continue

    try:
        with socket.create_connection((host, 443), timeout=8) as raw:
            with ssl.create_default_context().wrap_socket(raw, server_hostname=host) as tls:
                negotiated = tls.version() or ""
                cipher = (tls.cipher() or ("",))[0]
    except Exception as exc:
        logger.debug("[danger:owasp] TLS probe failed for %s: %s", host, str(exc)[:120])

    if weak_protocols:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_weak_tls",
            severity="high",
            title=f"Obsolete TLS Protocol Accepted - {len(weak_protocols)}",
            description=(
                "The server completed a handshake using a TLS version that is deprecated and no longer considered "
                "secure. Clients that negotiate it are exposed to downgrade and cipher weaknesses."
            ),
            evidence=evidence_block([("Host", host), *[(f"Protocol {index}", value) for index, value in enumerate(weak_protocols, 1)]]),
            remediation="Disable TLS 1.0 and TLS 1.1 and require TLS 1.2 or newer with modern cipher suites.",
            owasp=A02,
            attack_vector="Obsolete transport encryption",
            asset=host,
        ))

    http_only = budget.probe(MODULE, "GET", f"http://{host}/", counts_as_payload=False)
    if http_only.ok and http_only.response is not None and http_only.status == 200:
        if not http_only.response.history:
            findings.append(danger_finding(
                tool=MODULE,
                category="danger_plaintext_http",
                severity="medium",
                title="Plaintext HTTP Served Without Redirect to HTTPS",
                description=(
                    "The host answered a plain HTTP request with content instead of redirecting to HTTPS. Any "
                    "credential, token, or session cookie sent over that channel travels in clear text."
                ),
                evidence=evidence_block([
                    ("Host", host),
                    ("HTTP status", http_only.status),
                    ("Redirect chain", "none"),
                    ("Response bytes", http_only.size),
                    ("Negotiated TLS on 443", negotiated or "not established"),
                ]),
                remediation="Redirect all HTTP traffic to HTTPS and send HSTS with a long max-age.",
                owasp=A02,
                attack_vector="Cleartext transport",
                asset=host,
            ))

    findings.append(danger_finding(
        tool=MODULE,
        category="danger_tls_review",
        severity="info",
        title="Transport Security Review",
        description="Danger Mode recorded the negotiated TLS parameters and obsolete-protocol support for the host.",
        evidence=evidence_block([
            ("Host", host),
            ("Negotiated protocol", negotiated or "handshake failed"),
            ("Negotiated cipher", cipher or "unknown"),
            ("Obsolete protocols accepted", len(weak_protocols)),
        ]),
        owasp=A02,
        asset=host,
    ))
    return findings


# ── A04: Insecure design ──────────────────────────────────────────────────────

def check_insecure_design(
    target: str,
    budget: DangerBudget,
    items: list[AttackSurfaceItem],
) -> tuple[list[dict], bool]:
    """Look for missing login rate limiting and weak password-reset design.

    Returns ``(findings, rate_limiting_observed)``. No credentials are ever
    submitted: the probes send an obviously invalid, non-existent value.
    """
    findings: list[dict] = []
    login_forms = [item for item in items if item.input_type == InputPointType.LOGIN_FORM]
    rate_limited = False

    if not login_forms:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_insecure_design",
            severity="info",
            title="Insecure Design - no login form discovered",
            description=(
                "No login form was found in the attack-surface inventory, so rate-limit and lockout behaviour "
                "could not be observed."
            ),
            evidence=evidence_block([("Target", target), ("Login forms", 0)]),
            owasp=A04,
            asset=target,
        ))
        return findings, rate_limited

    form = login_forms[0]
    statuses: list[int | None] = []
    # Six identical submissions of a value that cannot be a real account. This
    # is a rate-limit observation, not credential stuffing: one non-credential
    # value is reused, no list is iterated, and no account is targeted.
    body = urlencode({name: "recontitan-invalid-probe" for name in form.parameters}).encode("utf-8")
    for _ in range(6):
        if not budget.can_spend(MODULE):
            break
        probe = budget.probe(
            MODULE, form.method if form.method == "POST" else "GET", form.url,
            headers={"Content-Type": "application/x-www-form-urlencoded"} if form.method == "POST" else None,
            body=body if form.method == "POST" else None,
        )
        statuses.append(probe.status)
        if probe.status in {429, 423}:
            rate_limited = True
            break

    if statuses and not rate_limited:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_missing_rate_limit",
            severity="medium",
            title="No Observable Rate Limiting on Login Form",
            description=(
                f"{len(statuses)} consecutive submissions to the login form were answered without a throttling or "
                "lockout status. A login endpoint that does not slow repeated attempts enables credential stuffing "
                "and password spraying. ReconTitan submitted one fixed invalid value and never attempted a real "
                "credential."
            ),
            evidence=evidence_block([
                ("Endpoint", truncated(form.url, 300)),
                ("Method", form.method),
                ("Submissions sent", len(statuses)),
                ("Status codes returned", ", ".join(str(status) for status in statuses)),
                ("Throttling status observed", "none"),
                ("Credentials submitted", "none - fixed non-credential probe value"),
            ]),
            remediation=(
                "Apply per-account and per-source rate limiting with progressive delays, add lockout or step-up "
                "verification after repeated failures, and alert on bulk failures."
            ),
            owasp=A04,
            attack_vector="Missing authentication rate limiting",
            asset=form.url,
        ))

    reset_candidates = [
        item for item in items
        if re.search(r"(?i)(reset|forgot|recover)", item.url)
    ]
    if reset_candidates:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_insecure_design",
            severity="low",
            title=f"Password-Reset Flow Exposed - {len(reset_candidates)} endpoint(s)",
            description=(
                "Password-reset endpoints were discovered. Reset flows are a common design weakness when they "
                "confirm whether an account exists, issue predictable tokens, or let a token be reused. "
                "ReconTitan did not submit a reset request."
            ),
            evidence=evidence_block([
                (f"Endpoint {index}", f"{item.method} {truncated(item.url, 200)}")
                for index, item in enumerate(reset_candidates[:10], 1)
            ]),
            remediation=(
                "Return an identical response whether or not the account exists, issue single-use "
                "cryptographically random tokens with a short lifetime, and invalidate sessions after a reset."
            ),
            owasp=A04,
            attack_vector="Insecure password-reset design",
            asset=target,
        ))
    return findings, rate_limited


# ── A05: Security misconfiguration ────────────────────────────────────────────

DEBUG_PATHS = (
    "/debug", "/debug/vars", "/actuator", "/actuator/env", "/actuator/heapdump",
    "/server-status", "/server-info", "/.git/HEAD", "/.env", "/phpinfo.php",
    "/trace.axd", "/elmah.axd", "/__debug__/", "/_profiler",
)


def check_misconfiguration(target: str, budget: DangerBudget, seeds: list[str]) -> list[dict]:
    """Probe well-known debug, status, and metadata endpoints."""
    base = seeds[0].rstrip("/") if seeds else f"https://{target}"
    split = urlsplit(base)
    root = f"{split.scheme}://{split.netloc}"
    exposed: list[dict] = []
    for path in DEBUG_PATHS:
        if not budget.can_spend(MODULE):
            break
        probe = budget.probe(MODULE, "GET", f"{root}{path}")
        if not probe.ok or probe.status != 200 or probe.size == 0:
            continue
        exposed.append({
            "path": path,
            "status": probe.status,
            "bytes": probe.size,
            "content_type": truncated(probe.response.headers.get("Content-Type", ""), 60) if probe.response else "",
            "fingerprint": fingerprint(probe.response.content) if probe.response else "",
        })

    if not exposed:
        return [danger_finding(
            tool=MODULE,
            category="danger_misconfiguration",
            severity="info",
            title=f"Debug and Default Endpoints - {len(DEBUG_PATHS)} probed, none reachable",
            description=(
                "None of the well-known debug, status, or version-control metadata paths returned content."
            ),
            evidence=evidence_block([("Base URL", root), ("Paths probed", len(DEBUG_PATHS))]),
            owasp=A05,
            asset=root,
        )]

    return [danger_finding(
        tool=MODULE,
        category="danger_misconfiguration",
        severity="high",
        title=f"Debug or Default Endpoints Reachable - {len(exposed)}",
        description=(
            "Diagnostic, management, or version-control metadata endpoints answered an unauthenticated request. "
            "These typically disclose configuration, environment variables, dependency versions, or source history."
        ),
        evidence=evidence_block([
            (entry["path"], f"status={entry['status']} bytes={entry['bytes']} type={entry['content_type']} "
                            f"body={entry['fingerprint']}")
            for entry in exposed
        ]),
        remediation=(
            "Disable diagnostic endpoints in production or bind them to an internal interface behind "
            "authentication, and stop deploying version-control metadata to the web root."
        ),
        owasp=A05,
        attack_vector="Exposed debug or management endpoint",
        asset=root,
    )]


# ── A06: Vulnerable and outdated components ───────────────────────────────────

def check_outdated_components(target: str) -> list[dict]:
    """Match detected technology versions against a known-vulnerable fingerprint set."""
    try:
        from app.tasks.recon.tech_stack import run_tech_stack_detection

        tech_findings = run_tech_stack_detection(target) or []
    except Exception as exc:
        logger.debug("[danger:owasp] tech stack unavailable: %s", str(exc)[:120])
        tech_findings = []

    detected: list[tuple[str, str]] = []
    for finding in tech_findings:
        for line in str(finding.get("evidence", "")).splitlines():
            match = re.match(r"^\s*[•-]?\s*(.+?)\s+([0-9]+(?:\.[0-9A-Za-z_-]+)+)\s*[\[—-]", line)
            if match:
                detected.append((match.group(1).strip().lower(), match.group(2).strip()))

    matches: list[str] = []
    for name, version in detected:
        for product, pattern, note in KNOWN_VULNERABLE_VERSIONS:
            if product in name and re.match(pattern, version):
                matches.append(f"{name} {version} - {note}")

    if not matches:
        return [danger_finding(
            tool=MODULE,
            category="danger_outdated_components",
            severity="info",
            title=f"Component Version Review - {len(detected)} versioned component(s)",
            description=(
                "No detected component version matched the known-vulnerable fingerprint set. Version banners can "
                "be absent, incomplete, or deliberately misleading, so this is not evidence that components are "
                "current."
            ),
            evidence=evidence_block([
                ("Target", target),
                ("Versioned components detected", len(detected)),
                ("Components", "\n" + "\n".join(f"  {name} {version}" for name, version in detected[:30])
                 if detected else "  none"),
            ]),
            owasp=A06,
            asset=target,
        )]

    return [danger_finding(
        tool=MODULE,
        category="danger_outdated_components",
        severity="high",
        title=f"Known-Vulnerable Component Versions - {len(matches)}",
        description=(
            "Detected component versions match fingerprints for releases that are end-of-life or carry widely "
            "exploited weaknesses. Confirm the exact build from an authoritative source before acting."
        ),
        evidence=evidence_block([(f"Match {index}", value) for index, value in enumerate(matches, 1)]),
        remediation=(
            "Upgrade each component to a supported release, subscribe to its security advisories, and add "
            "dependency scanning to the build pipeline."
        ),
        owasp=A06,
        attack_vector="Outdated component with published weaknesses",
        asset=target,
    )]


# ── A07 and A08: authentication and integrity ─────────────────────────────────

def check_authentication_and_integrity(
    target: str,
    budget: DangerBudget,
    items: list[AttackSurfaceItem],
    seeds: list[str],
) -> list[dict]:
    """Login-form hygiene, session-cookie flags, and subresource integrity."""
    findings: list[dict] = []
    login_forms = [item for item in items if item.input_type == InputPointType.LOGIN_FORM]

    for form in login_forms[:3]:
        probe = budget.probe(MODULE, "GET", form.url, counts_as_payload=False)
        if not probe.ok:
            continue
        body = probe.text
        issues: list[str] = []
        if not CSRF_TOKEN_RE.search(body):
            issues.append("No CSRF token field or meta tag was present in the login page markup")
        if not PASSWORD_POLICY_RE.search(body):
            issues.append("No client-side password policy hint (minlength, pattern, autocomplete=new-password)")
        if form.url.startswith("http://"):
            issues.append("Login form is served over plaintext HTTP")
        if issues:
            findings.append(danger_finding(
                tool=MODULE,
                category="danger_auth_weakness",
                severity="medium",
                title=f"Login Form Hygiene Issues - {len(issues)}",
                description=(
                    "The login page is missing controls that are observable from the client. Absence in markup is "
                    "not proof the control is missing server-side; confirm the server's own CSRF and policy "
                    "enforcement manually."
                ),
                evidence=evidence_block([
                    ("Endpoint", truncated(form.url, 300)),
                    ("Method", form.method),
                    ("Fields", ", ".join(form.parameters[:12])),
                    *[(f"Issue {index}", value) for index, value in enumerate(issues, 1)],
                ]),
                remediation=(
                    "Issue and validate a per-session CSRF token on every state-changing form, enforce password "
                    "policy server-side, and serve authentication pages only over HTTPS."
                ),
                owasp=A07,
                attack_vector="Weak authentication implementation",
                asset=form.url,
            ))

    root = seeds[0] if seeds else f"https://{target}"
    home = budget.probe(MODULE, "GET", root, counts_as_payload=False)
    if home.ok and home.response is not None:
        body = home.text
        cookie_header = home.response.headers.get("Set-Cookie", "")
        if cookie_header:
            missing = [
                flag for flag, present in (
                    ("HttpOnly", "httponly" in cookie_header.lower()),
                    ("Secure", "secure" in cookie_header.lower()),
                    ("SameSite", "samesite" in cookie_header.lower()),
                )
                if not present
            ]
            if missing:
                findings.append(danger_finding(
                    tool=MODULE,
                    category="danger_session_cookie",
                    severity="medium",
                    title=f"Session Cookie Flags Missing - {', '.join(missing)}",
                    description=(
                        "A cookie was issued without one or more protective attributes. Cookie names and values "
                        "are not recorded; only the attribute state is."
                    ),
                    evidence=evidence_block([
                        ("Host", urlsplit(root).hostname),
                        ("Missing attributes", ", ".join(missing)),
                        ("Cookie value stored", "no - attributes only"),
                    ]),
                    remediation="Set HttpOnly, Secure, and SameSite on every session cookie.",
                    owasp=A07,
                    attack_vector="Weak session cookie configuration",
                    asset=root,
                ))

        external_scripts = SRI_RE.findall(body)
        third_party = [
            url for url in external_scripts
            if urlsplit(url).hostname and urlsplit(url).hostname not in (urlsplit(root).hostname or "")
        ]
        without_integrity = [] if INTEGRITY_RE.search(body) else third_party
        if without_integrity:
            findings.append(danger_finding(
                tool=MODULE,
                category="danger_integrity",
                severity="medium",
                title=f"Third-Party Scripts Without Subresource Integrity - {len(without_integrity)}",
                description=(
                    "Externally hosted scripts are loaded without an integrity attribute. If the third-party host "
                    "or its CDN is compromised, the modified script executes with full page privileges."
                ),
                evidence=evidence_block([
                    (f"Script {index}", truncated(url, 200))
                    for index, url in enumerate(without_integrity[:20], 1)
                ]),
                remediation=(
                    "Add integrity and crossorigin attributes to third-party script tags, pin versions, or self-host "
                    "the dependency."
                ),
                owasp=A08,
                attack_vector="Missing subresource integrity",
                asset=root,
            ))

        if DESERIALIZATION_RE.search(body):
            findings.append(danger_finding(
                tool=MODULE,
                category="danger_deserialization",
                severity="medium",
                title="Serialized Object Indicator in Response",
                description=(
                    "The response contains a marker associated with Java, PHP, Python, or YAML object "
                    "serialization. Applications that deserialize attacker-influenced data can be driven to "
                    "execute code. Only the indicator was recorded, not the value."
                ),
                evidence=evidence_block([
                    ("URL", truncated(root, 300)),
                    ("Indicator type", "serialized object marker"),
                    ("Response fingerprint", fingerprint(home.response.content)),
                    ("Value stored", "no"),
                ]),
                remediation=(
                    "Do not deserialize untrusted input. Use a data-only format, enforce type allow-lists, and "
                    "sign or encrypt any serialized state that must round-trip through the client."
                ),
                owasp=A08,
                attack_vector="Unsafe deserialization indicator",
                asset=root,
            ))
    return findings


# ── A09: logging and monitoring ───────────────────────────────────────────────

def check_logging_monitoring(target: str, rate_limiting_observed: bool, budget: DangerBudget) -> list[dict]:
    """Report the absence of observable throttling as a monitoring weakness."""
    if rate_limiting_observed:
        return [danger_finding(
            tool=MODULE,
            category="danger_monitoring",
            severity="info",
            title="Rate Limiting Observed During Testing",
            description=(
                "The target returned a throttling status during bounded probing, which indicates at least one "
                "abuse control is active. This does not confirm that security events are logged or alerted on."
            ),
            evidence=evidence_block([
                ("Target", target),
                ("Throttling observed", "yes"),
                ("Requests sent", budget.requests_sent),
            ]),
            owasp=A09,
            asset=target,
        )]

    return [danger_finding(
        tool=MODULE,
        category="danger_monitoring",
        severity="low",
        title="No Observable Rate Limiting or Abuse Response",
        description=(
            f"Danger Mode sent {budget.requests_sent} probes, including obvious attack patterns, without receiving "
            "a throttling, block, or challenge response. Detection and response cannot be assessed from outside, "
            "so confirm server-side whether these requests were logged and alerted on."
        ),
        evidence=evidence_block([
            ("Target", target),
            ("Requests sent", budget.requests_sent),
            ("Payloads sent", budget.payloads_sent),
            ("Throttling or block observed", "none"),
        ]),
        remediation=(
            "Log authentication and input-validation failures with enough context to investigate, alert on abuse "
            "patterns, and apply rate limiting or challenges at the edge."
        ),
        owasp=A09,
        attack_vector="Insufficient logging and monitoring",
        asset=target,
    )]


# ── Coverage matrix ───────────────────────────────────────────────────────────

def build_owasp_matrix(findings: list[dict], stages_completed: list[str]) -> list[OwaspCoverageEntry]:
    """Assemble the tested / not-tested matrix across all OWASP categories."""
    entries: list[OwaspCoverageEntry] = []
    for key, name, modules in OWASP_CATALOGUE:
        matched = [finding for finding in findings if finding.get("owasp_category") == key]
        ran = [module for module in modules if module in stages_completed]
        tested = bool(matched) or bool(ran)
        note = (
            f"{len(matched)} finding(s) from {', '.join(ran) or 'no completed module'}."
            if tested else
            f"{name} was not exercised: no contributing module completed."
        )
        entries.append(OwaspCoverageEntry(
            category=key,
            tested=tested,
            modules=list(modules),
            findings=len(matched),
            note=note,
        ))
    return entries


def owasp_matrix_finding(target: str, entries: list[OwaspCoverageEntry]) -> dict:
    """Render the coverage matrix as a reportable finding."""
    rows = [
        f"{entry.category:<58} {'TESTED' if entry.tested else 'NOT TESTED':<11} findings={entry.findings}"
        for entry in entries
    ]
    tested = sum(1 for entry in entries if entry.tested)
    return danger_finding(
        tool=MODULE,
        category="danger_owasp_matrix",
        severity="info",
        title=f"OWASP Top 10 Coverage Matrix - {tested}/10 categories exercised",
        description=(
            "Coverage recorded by Danger Mode for the OWASP Top 10 (2021). A category marked TESTED means at "
            "least one bounded module ran against it, not that the application is free of that weakness class. "
            "Categories requiring authenticated state, business-logic knowledge, or source access cannot be fully "
            "assessed from outside."
        ),
        evidence="\n".join(rows),
        remediation=(
            "Treat NOT TESTED categories as unassessed, not as clean, and cover them with authenticated dynamic "
            "testing, code review, or a manual engagement."
        ),
        asset=target,
    )
