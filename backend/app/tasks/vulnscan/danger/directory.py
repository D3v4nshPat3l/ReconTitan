"""Bounded directory fuzzing and encoded path-traversal probing.

Directory fuzzing issues plain GET requests for a bounded built-in wordlist and
classifies the status codes. Traversal probing sends encoded ``../`` variants
against file-serving parameters and looks only for well-known *signatures* of a
system file — the response body itself is never stored, only a fingerprint.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit, urlunsplit

from app.config import settings
from app.models.schemas import AttackSurfaceItem, InjectionSignal
from app.tasks.vulnscan.danger.budget import (
    DangerBudget,
    ProbeResult,
    danger_finding,
    evidence_block,
    fingerprint,
    truncated,
)

logger = logging.getLogger("recontitan.danger.directory")

FUZZ_MODULE = "directory_fuzzing"
TRAVERSAL_MODULE = "path_traversal"

A01 = "A01:2021-Broken Access Control"
A05 = "A05:2021-Security Misconfiguration"

#: Bounded built-in wordlist, trimmed to DANGER_DIR_BUST_WORDLIST at runtime.
DIRECTORY_WORDLIST: tuple[str, ...] = (
    "admin", "administrator", "admin.php", "admin/login", "wp-admin", "login", "signin",
    "dashboard", "panel", "console", "manage", "manager", "cpanel", "phpmyadmin", "adminer",
    "api", "api/v1", "api/v2", "api/docs", "swagger", "swagger-ui", "swagger.json",
    "openapi.json", "graphql", "graphiql", "rest", "rpc", "soap",
    "backup", "backups", "backup.zip", "backup.sql", "db.sql", "dump.sql", "database.sql",
    "old", "old.zip", "archive", "archive.zip", "site.zip", "www.zip", "release.tar.gz",
    ".env", ".env.local", ".env.production", ".git/HEAD", ".git/config", ".gitignore",
    ".svn/entries", ".hg", ".DS_Store", ".htaccess", ".htpasswd", "web.config",
    "config", "config.php", "config.json", "config.yml", "configuration.php", "settings.py",
    "credentials", "secrets", "secrets.json", "id_rsa", "private.key",
    "upload", "uploads", "files", "file", "download", "downloads", "media", "static",
    "assets", "images", "tmp", "temp", "cache", "logs", "log", "error.log", "access.log",
    "debug", "debug.php", "test", "tests", "testing", "dev", "staging", "demo", "sandbox",
    "server-status", "server-info", "status", "health", "healthz", "metrics", "actuator",
    "actuator/health", "actuator/env", "actuator/heapdump", "trace", "info", "version",
    "docs", "documentation", "readme", "README.md", "CHANGELOG.md", "LICENSE",
    "robots.txt", "sitemap.xml", "crossdomain.xml", "security.txt", ".well-known/security.txt",
    "user", "users", "account", "accounts", "profile", "register", "signup", "reset",
    "password-reset", "forgot-password", "logout", "session", "sessions", "token",
    "internal", "private", "secure", "restricted", "hidden", "portal", "intranet",
)

#: Path names that deserve a dedicated finding when they respond.
HIGH_INTEREST = re.compile(
    r"(^|/)(\.env|\.git|\.svn|\.htpasswd|backup|dump|db\.sql|database\.sql|id_rsa|private\.key|"
    r"secrets|credentials|server-status|server-info|actuator|heapdump|swagger|graphiql|adminer|phpmyadmin)",
    re.IGNORECASE,
)

#: Encoded traversal variants. All are read attempts against a canary file.
TRAVERSAL_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ("plain", "../../../../etc/hostname", "Plain dot-dot-slash traversal"),
    ("url_encoded", "..%2f..%2f..%2f..%2fetc%2fhostname", "URL-encoded slash traversal"),
    ("dot_encoded", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fhostname", "URL-encoded dot traversal"),
    ("double_dot_slash", "....//....//....//....//etc/hostname", "Doubled dot-slash filter-bypass traversal"),
    ("double_encoded", "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fhostname", "Double-encoded traversal"),
    ("semicolon", "..;/..;/..;/etc/hostname", "Path-parameter separator traversal"),
    ("windows", r"..\..\..\..\windows\win.ini", "Windows-style backslash traversal"),
)

DIRECTORY_LISTING_RE = re.compile(
    r"(<title>\s*index of\s*/|directory listing for|\[to parent directory\])",
    re.IGNORECASE,
)
VERBOSE_ERROR_RE = re.compile(
    r"(traceback \(most recent call last\)|stack trace:|at [\w.$]+\([\w.]+\.java:\d+\)|"
    r"fatal error:.*on line \d+|warning:.*on line \d+|<b>Notice</b>:|System\.\w+Exception)",
    re.IGNORECASE,
)


def _base_url(seed: str) -> str:
    split = urlsplit(seed)
    return urlunsplit((split.scheme or "https", split.netloc, "", "", ""))


def _interesting(status: int | None) -> bool:
    return status in {200, 201, 204, 301, 302, 401, 403}


def run_directory_fuzzing(target: str, budget: DangerBudget, seeds: list[str]) -> list[dict]:
    """Fuzz a bounded wordlist against the first discovered host."""
    findings: list[dict] = []
    base = _base_url(seeds[0]) if seeds else f"https://{target}"
    wordlist = DIRECTORY_WORDLIST[: settings.DANGER_DIR_BUST_WORDLIST]

    # A random path establishes how the server answers a path that cannot exist.
    control = budget.probe(FUZZ_MODULE, "GET", f"{base}/recontitan-404-control-{fingerprint(base)[7:15]}",
                           counts_as_payload=False)
    control_status = control.status
    control_size = control.size

    hits: list[dict] = []
    listings: list[dict] = []
    verbose_errors: list[dict] = []
    for word in wordlist:
        if not budget.can_spend(FUZZ_MODULE):
            break
        url = f"{base}/{word}"
        probe = budget.probe(FUZZ_MODULE, "GET", url)
        if not probe.ok or not _interesting(probe.status):
            continue
        # Soft-404 filter: same status and near-identical size as the control.
        if probe.status == control_status and abs(probe.size - control_size) <= 32:
            continue
        entry = {
            "path": f"/{word}",
            "status": probe.status,
            "bytes": probe.size,
            "location": truncated(probe.response.headers.get("Location", ""), 200) if probe.response else "",
            "content_type": truncated(probe.response.headers.get("Content-Type", ""), 80) if probe.response else "",
            "fingerprint": fingerprint(probe.response.content) if probe.response else "",
            "interesting": bool(HIGH_INTEREST.search(word)),
        }
        hits.append(entry)
        if probe.status == 200 and DIRECTORY_LISTING_RE.search(probe.text):
            listings.append(entry)
        if VERBOSE_ERROR_RE.search(probe.text):
            verbose_errors.append(entry)

    findings.append(danger_finding(
        tool=FUZZ_MODULE,
        category="danger_directory_fuzzing",
        severity="info",
        title=f"Directory Fuzzing - {len(hits)} responsive path(s) of {len(wordlist)} tested",
        description=(
            f"Danger Mode requested {len(wordlist)} bounded wordlist paths against {base} and recorded every path "
            "that answered with a status other than the server's not-found baseline. Only GET requests were sent."
        ),
        evidence=evidence_block([
            ("Base URL", base),
            ("Wordlist size", len(wordlist)),
            ("Not-found baseline", f"status={control_status} bytes={control_size}"),
            ("Responsive paths", len(hits)),
            ("Paths", "\n" + "\n".join(
                f"  {entry['status']} {entry['path']} ({entry['bytes']} bytes)"
                + (f" -> {entry['location']}" if entry["location"] else "")
                for entry in hits[:80]
            ) if hits else "  none"),
        ]),
        remediation=(
            "Remove or access-control paths that should not be publicly reachable, and return a consistent 404 for "
            "resources the requester is not authorized to know about."
        ),
        owasp=A01,
        asset=base,
    ))

    sensitive = [entry for entry in hits if entry["interesting"]]
    if sensitive:
        findings.append(danger_finding(
            tool=FUZZ_MODULE,
            category="danger_sensitive_path",
            severity="high",
            title=f"Sensitive Paths Reachable - {len(sensitive)}",
            description=(
                "Paths matching well-known sensitive names (version-control metadata, environment files, backups, "
                "credential files, debug and management endpoints) answered a request. Reachability does not prove "
                "the content is sensitive; verify each path manually."
            ),
            evidence=evidence_block([
                (entry["path"], f"status={entry['status']} bytes={entry['bytes']} type={entry['content_type']} "
                                f"body={entry['fingerprint']}")
                for entry in sensitive[:40]
            ]),
            remediation=(
                "Block version-control, backup, configuration, and management paths at the web server, remove them "
                "from the deployment artifact, and rotate any credential they may have exposed."
            ),
            owasp=A05,
            attack_vector="Forced browsing to sensitive paths",
            asset=base,
        ))

    if listings:
        findings.append(danger_finding(
            tool=FUZZ_MODULE,
            category="danger_directory_listing",
            severity="medium",
            title=f"Directory Listing Enabled - {len(listings)} path(s)",
            description=(
                "The server returned an auto-generated index page instead of a document, exposing the file names "
                "stored under that path."
            ),
            evidence=evidence_block([
                (entry["path"], f"status={entry['status']} bytes={entry['bytes']}") for entry in listings[:20]
            ]),
            remediation="Disable automatic directory indexing (`autoindex off` / `Options -Indexes`) for all paths.",
            owasp=A05,
            attack_vector="Directory listing",
            asset=base,
        ))

    if verbose_errors:
        findings.append(danger_finding(
            tool=FUZZ_MODULE,
            category="danger_verbose_error",
            severity="medium",
            title=f"Verbose Error Output - {len(verbose_errors)} path(s)",
            description=(
                "Responses contained stack traces or interpreter error text. Verbose errors disclose framework "
                "versions, file-system layout, and internal logic."
            ),
            evidence=evidence_block([
                (entry["path"], f"status={entry['status']} type={entry['content_type']} body={entry['fingerprint']}")
                for entry in verbose_errors[:20]
            ]),
            remediation=(
                "Disable debug mode in production, return a generic error page, and send diagnostic detail only to "
                "server-side logs."
            ),
            owasp=A05,
            attack_vector="Verbose error disclosure",
            asset=base,
        ))

    logger.info("[danger:dirfuzz] %s: %d/%d responsive", base, len(hits), len(wordlist))
    return findings


def _detect_signature(probe: ProbeResult) -> str:
    """Return the name of a matched system-file signature, or an empty string."""
    if not probe.ok or probe.response is None:
        return ""
    body = probe.text
    lowered = body.lower()
    if "root:x:0:0" in body:
        return "unix_passwd"
    if "[boot loader]" in lowered:
        return "windows_boot"
    if "[fonts]" in lowered or "[extensions]" in lowered:
        return "windows_ini"
    # /etc/hostname is a single short token; treat a very small text/plain body
    # that is one bare hostname as a candidate rather than a match.
    content_type = probe.response.headers.get("Content-Type", "").lower()
    stripped = body.strip()
    if "text/plain" in content_type and 0 < len(stripped) < 80 and "\n" not in stripped and " " not in stripped:
        return "short_plaintext_token"
    return ""


def run_path_traversal(
    target: str,
    budget: DangerBudget,
    items: list[AttackSurfaceItem],
) -> list[dict]:
    """Probe file-serving parameters with encoded traversal variants."""
    from app.tasks.vulnscan.danger.injection import send_payload, InjectionContext

    findings: list[dict] = []
    file_param_re = re.compile(
        r"(?i)^(file|filename|filepath|path|doc|document|page|template|view|include|load|read|"
        r"download|attachment|resource|asset|img|image|name)$"
    )
    candidates = [
        (item, parameter)
        for item in items[: settings.DANGER_MAX_ENDPOINTS]
        for parameter in item.parameters[:4]
        if file_param_re.fullmatch(parameter)
    ]

    if not candidates:
        return [danger_finding(
            tool=TRAVERSAL_MODULE,
            category="danger_path_traversal",
            severity="info",
            title="Path Traversal - no file-serving parameters discovered",
            description=(
                "No parameter matching a file, path, template, or download naming convention was found in the "
                "attack-surface inventory, so no traversal probe was sent."
            ),
            evidence=evidence_block([
                ("Target", target),
                ("Input points inspected", len(items)),
                ("File-serving parameters", 0),
            ]),
            owasp=A01,
            asset=target,
        )]

    context = InjectionContext(target=target, budget=budget, items=items)
    tested = 0
    for item, parameter in candidates:
        for payload_category, payload, payload_description in TRAVERSAL_PAYLOADS:
            if not budget.can_spend(TRAVERSAL_MODULE):
                break
            probe = send_payload(context, TRAVERSAL_MODULE, item, parameter, payload)
            tested += 1
            signature = _detect_signature(probe)
            if not signature:
                continue
            severity = "critical" if signature in {"unix_passwd", "windows_ini", "windows_boot"} else "medium"
            findings.append(danger_finding(
                tool=TRAVERSAL_MODULE,
                category="danger_path_traversal",
                severity=severity,
                title=f"Path Traversal Candidate - {parameter} ({payload_category})",
                description=(
                    f"An encoded traversal sequence supplied through '{parameter}' returned content matching the "
                    f"'{signature}' system-file signature. The response body was fingerprinted and discarded, not "
                    "stored. Confirm manually that the file is genuinely outside the intended directory."
                ),
                evidence=evidence_block([
                    ("Method", item.method),
                    ("Endpoint", truncated(item.url, 300)),
                    ("Parameter", parameter),
                    ("Encoding variant", payload_category),
                    ("Variant intent", payload_description),
                    ("Signature matched", signature),
                    ("Response status", probe.status),
                    ("Response bytes", probe.size),
                    ("Response fingerprint", fingerprint(probe.response.content) if probe.response else ""),
                    ("Response body stored", "no - fingerprint only"),
                ]),
                remediation=(
                    "Resolve the requested path and confirm it stays inside the intended directory, reject "
                    "traversal sequences after decoding, and serve files by identifier rather than by path."
                ),
                owasp=A01,
                attack_vector=f"Path traversal ({payload_category})",
                asset=item.url,
            ))
            context.record(item, parameter, "traversal", payload_category, InjectionSignal.DIFFERENTIAL, probe)
            break

    if not findings:
        findings.append(danger_finding(
            tool=TRAVERSAL_MODULE,
            category="danger_path_traversal",
            severity="info",
            title=f"Path Traversal - {tested} probe(s) sent, no signature matched",
            description=(
                f"{tested} encoded traversal probes were sent across {len(candidates)} file-serving parameter(s) "
                "without matching a system-file signature. This does not prove the parameters are safe; blind or "
                "restricted traversal would not produce a signature."
            ),
            evidence=evidence_block([
                ("Target", target),
                ("File-serving parameters", len(candidates)),
                ("Probes sent", tested),
                ("Encoding variants", ", ".join(name for name, _, _ in TRAVERSAL_PAYLOADS)),
            ]),
            owasp=A01,
            asset=target,
        ))
    return findings
