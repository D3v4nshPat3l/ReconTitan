"""Wayback Machine archive history, triaged into what each URL is worth.

The archive's value to an assessment is that it remembers endpoints the site
has stopped linking to. An old admin path, a retired API version, a debug
handler someone removed from the navigation but not from the router -- the
archive has them, and nothing else in a passive scan does.

Two things had to change for that value to be realised. The ceiling was 200
URLs, which for any real site is the first 200 alphabetically and not the
interesting ones. And the output was a flat list, which for ten thousand URLs
is unreadable, so the interesting entries were present but invisible.

So the sweep is wide and the output is triaged. Each URL is sorted into what
it tells you -- a script, an API endpoint, a parameterised URL worth testing,
a file extension that should never have been served -- and each bucket is
reported separately with its own severity. A flat list of ten thousand URLs is
data; four hundred URLs in four labelled buckets is a finding.

Every URL here is a *historical* observation. The archive recorded it once. It
is not evidence that the path still exists, and the module never requests one
to find out -- that would be active traffic from a passive check.
"""

import logging
import re
from collections import Counter
from urllib.parse import parse_qs, urlsplit

import requests

from app.config import settings

logger = logging.getLogger("recontitan.recon.wayback")

# web.archive.org is frequently slow or unreachable. Waiting is worth it when
# the scan has time -- the archive is the only source for historical URLs --
# but inside a serverless request a 15s connect timeout is a quarter of the
# whole budget spent finding out the host is down.
TIMEOUT = 5 if settings.SERVERLESS else 15

#: Extensions that should not be reachable on a web server at all. A archived
#: hit is evidence the file was once served, which is worth checking even
#: though it says nothing about today.
SENSITIVE_EXTENSIONS = {
    ".sql", ".bak", ".old", ".backup", ".swp", ".swo", ".tar", ".tar.gz",
    ".tgz", ".zip", ".rar", ".7z", ".gz", ".env", ".ini", ".conf", ".config",
    ".cfg", ".yml", ".yaml", ".log", ".pem", ".key", ".p12", ".pfx", ".jks",
    ".crt", ".csr", ".dump", ".dmp", ".db", ".sqlite", ".mdb", ".pdb",
    ".git", ".svn", ".DS_Store", ".htpasswd", ".htaccess",
}

#: Query-string parameter names worth testing, grouped by what they suggest.
#: The grouping is the point: "id" and "redirect" are both interesting and
#: they are not interesting for the same reason.
JUICY_PARAMS: dict[str, tuple[str, ...]] = {
    "redirect / SSRF": (
        "url", "uri", "redirect", "redirect_url", "redirect_uri", "return",
        "returnurl", "return_url", "next", "target", "dest", "destination",
        "continue", "goto", "out", "link", "forward", "callback", "feed",
        "host", "site", "domain", "proxy", "fetch", "load", "src", "open",
    ),
    "object reference": (
        "id", "uid", "user", "user_id", "userid", "account", "account_id",
        "order", "order_id", "invoice", "doc", "document", "file_id", "key",
        "number", "no", "num", "profile", "group", "role", "customer",
    ),
    "file access": (
        "file", "filename", "path", "filepath", "folder", "dir", "download",
        "read", "include", "page", "template", "view", "doc", "pdf", "attach",
        "name", "cat", "action", "module", "conf", "root",
    ),
    "injection surface": (
        "q", "query", "search", "s", "keyword", "term", "filter", "sort",
        "order_by", "orderby", "where", "select", "table", "column", "sql",
        "cmd", "command", "exec", "run", "code", "eval", "data", "input",
    ),
    "authentication": (
        "token", "auth", "access_token", "api_key", "apikey", "session",
        "sessionid", "sid", "jwt", "secret", "password", "passwd", "pwd",
        "hash", "signature", "sig", "nonce", "csrf",
    ),
}

#: Path fragments that name an interesting endpoint regardless of parameters.
INTERESTING_PATH_HINTS = (
    "admin", "backup", "config", "login", "password", "secret", "api",
    "upload", "install", "setup", "debug", "test", ".env", "phpinfo",
    ".git", "wp-", "xmlrpc", "graphql", "actuator", "swagger", "console",
    "internal", "private", "staging", "dev", "token", "oauth", "callback",
)

_SCRIPT_RE = re.compile(r"\.(?:js|mjs|jsx|ts|tsx)(?:$|\?)", re.I)
_API_RE = re.compile(
    r"(?:^|/)(?:api|v[0-9]{1,2}|rest|graphql|gql|rpc|jsonrpc|service|services|endpoint)(?:/|$)",
    re.I,
)


def _extension(path: str) -> str:
    name = path.rsplit("/", 1)[-1].lower()
    for ext in (".tar.gz",):  # compound extensions first
        if name.endswith(ext):
            return ext
    _, dot, tail = name.rpartition(".")
    return f".{tail}" if dot and tail else ""


#: The CDX endpoint gets its own, longer budget. It is doing real work -- an
#: index scan over every capture of every host under the domain -- and the
#: availability check's short timeout is sized for a different job entirely.
CDX_TIMEOUT = 10 if settings.SERVERLESS else 45


def _cdx_request(domain: str, limit: int, timeout: float) -> list[list[str]]:
    response = requests.get(
        "https://web.archive.org/cdx/search/cdx",
        params={
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype",
            "collapse": "urlkey",
            "limit": limit,
        },
        timeout=timeout,
    )
    response.raise_for_status()
    rows = response.json()
    return rows[1:] if rows and len(rows) > 1 else []


#: Total wall-clock the archive gets across every attempt. Without this the
#: retry ladder costs the most in exactly the case it helps least: when the
#: archive is down, each attempt burns its full timeout before the next one
#: starts, and a single module quietly becomes the longest stage in the scan.
CDX_TOTAL_BUDGET = 20 if settings.SERVERLESS else 75


def _fetch_cdx(domain: str) -> list[list[str]]:
    """Ask for the full set, and narrow the ask rather than give up.

    A wide request against a heavily archived domain routinely exceeds any
    timeout worth waiting for. Returning nothing in that case throws away the
    part of the archive that would have arrived comfortably, so each attempt
    asks for a fifth of the last.

    Each retry also gets a shorter timeout, because it is asking for less: a
    request for 500 URLs that has not answered in eleven seconds is not going
    to. Attempts stop once the total budget is spent, so the ladder cannot
    turn one slow dependency into the longest stage of the scan.
    """
    limits = [settings.WAYBACK_URL_LIMIT]
    while len(limits) < 3 and limits[-1] > 500:
        limits.append(max(500, limits[-1] // 5))

    import time

    deadline = time.monotonic() + CDX_TOTAL_BUDGET
    last_error: Exception | None = None

    for attempt, limit in enumerate(limits):
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            logger.info("[wayback] %s: archive budget spent after %d attempt(s)", domain, attempt)
            break
        timeout = min(remaining, CDX_TIMEOUT / (2 ** attempt))
        try:
            rows = _cdx_request(domain, limit, timeout)
            if attempt:
                logger.info(
                    "[wayback] %s: fell back to limit=%d after %d timeout(s)",
                    domain, limit, attempt,
                )
            return rows
        except (requests.exceptions.Timeout, requests.exceptions.HTTPError) as exc:
            last_error = exc
            logger.debug("[wayback] limit=%d (timeout %.0fs) failed: %s", limit, timeout, exc)
            continue

    if last_error:
        raise last_error
    return []


def _bucket(urls: list[str]) -> dict:
    """Sort archived URLs into what each one is worth looking at for."""
    scripts: set[str] = set()
    api: set[str] = set()
    sensitive: dict[str, set[str]] = {}
    parameterised: dict[str, set[str]] = {}
    interesting: set[str] = set()
    param_counter: Counter[str] = Counter()

    for url in urls:
        parts = urlsplit(url)
        path = parts.path or "/"
        # Matched against the path alone, never the whole URL. Matching the
        # full string meant the hostname counted: any host containing "api",
        # "dev" or "test" flagged every one of its URLs, and a bucket that
        # holds everything distinguishes nothing.
        lowered = path.lower()

        if _SCRIPT_RE.search(path):
            scripts.add(url)
        if _API_RE.search(path):
            api.add(url)

        extension = _extension(path)
        if extension in SENSITIVE_EXTENSIONS:
            sensitive.setdefault(extension, set()).add(url)

        if parts.query:
            names = set(parse_qs(parts.query, keep_blank_values=True))
            param_counter.update(names)
            for label, watched in JUICY_PARAMS.items():
                if names & set(watched):
                    parameterised.setdefault(label, set()).add(url)

        if any(hint in lowered for hint in INTERESTING_PATH_HINTS):
            interesting.add(url)

    return {
        "scripts": scripts,
        "api": api,
        "sensitive": sensitive,
        "parameterised": parameterised,
        "interesting": interesting,
        "param_counter": param_counter,
    }


def _listing(urls, limit: int) -> str:
    urls = sorted(urls)
    lines = [f"• {url}" for url in urls[:limit]]
    if len(urls) > limit:
        lines.append(f"... and {len(urls) - limit} more")
    return "\n".join(lines)


def run_wayback(target: str) -> list[dict]:
    """Query the Wayback Machine CDX API and triage what it returns."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings: list[dict] = []

    try:
        avail_resp = requests.get(
            "https://archive.org/wayback/available",
            params={"url": domain},
            timeout=TIMEOUT,
        )
        snapshot = avail_resp.json().get("archived_snapshots", {}).get("closest", {})
        snapshot_url = snapshot.get("url", "")
        snapshot_ts = snapshot.get("timestamp", "")
    except Exception as exc:  # noqa: BLE001
        logger.warning("[wayback] Availability check failed: %s", exc)
        snapshot_url = snapshot_ts = ""

    try:
        rows = _fetch_cdx(domain)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[wayback] CDX query failed: %s", exc)
        rows = []
        if not snapshot_url:
            return [{
                "tool": "wayback_machine",
                "category": "scanner_coverage",
                "severity": "info",
                "title": "Wayback Machine Unreachable — Archive Not Consulted",
                "description": (
                    "The Internet Archive did not answer, so historical URLs were not "
                    "retrieved. The archive is the only source for endpoints a site no "
                    "longer links to; without it, that part of the attack surface was "
                    "not examined. This is not evidence that no archived URLs exist."
                ),
                "evidence": f"Target: {domain}\nError: {type(exc).__name__}: {exc}"[:400],
            }]

    urls = [row[0] for row in rows if row]
    statuses = Counter(row[2] for row in rows if len(row) > 2 and row[2])
    buckets = _bucket(urls)

    truncated = len(urls) >= settings.WAYBACK_URL_LIMIT
    summary = [
        f"Archived URLs retrieved : {len(urls)}"
        + (f"  (ceiling {settings.WAYBACK_URL_LIMIT} reached)" if truncated else ""),
    ]
    if snapshot_url:
        summary += [
            f"Latest snapshot         : {snapshot_url}",
            f"Snapshot date           : {snapshot_ts[:8] if snapshot_ts else 'unknown'}",
        ]
    if statuses:
        summary.append(
            "Archived status codes   : "
            + ", ".join(f"{code}×{count}" for code, count in statuses.most_common(6))
        )
    summary += [
        "",
        "Triage:",
        f"  JavaScript files      : {len(buckets['scripts'])}",
        f"  API-shaped endpoints  : {len(buckets['api'])}",
        f"  Sensitive extensions  : {sum(len(v) for v in buckets['sensitive'].values())}",
        f"  Parameterised URLs    : {sum(len(v) for v in buckets['parameterised'].values())}",
        f"  Named-path matches    : {len(buckets['interesting'])}",
    ]
    if buckets["param_counter"]:
        summary += [
            "",
            "Most common query parameters:",
            *(
                f"  {name:<24} {count}"
                for name, count in buckets["param_counter"].most_common(15)
            ),
        ]

    if not urls and not snapshot_url:
        logger.info("[wayback] No archive data found for %s", domain)
        return findings

    findings.append({
        "tool": "wayback_machine",
        "category": "archive_history",
        "severity": "info",
        "title": f"Wayback Machine Archive — {len(urls)} URLs retrieved",
        "description": (
            f"The Internet Archive holds {len(urls)} distinct URLs for {domain}. "
            "Each is a historical observation: the archive recorded the URL at "
            "some point, which is not evidence that the path still exists. None "
            "of these were requested by this scan. They are triaged below by what "
            "each group is worth examining for."
            + (
                " The retrieval ceiling was reached, so this is a sample rather than "
                "the complete archive."
                if truncated else ""
            )
        ),
        "evidence": "\n".join(summary),
    })

    if buckets["scripts"]:
        findings.append({
            "tool": "wayback_machine",
            "category": "archive_javascript",
            "severity": "info",
            "title": f"Archived JavaScript Files — {len(buckets['scripts'])} found",
            "description": (
                "Script URLs recorded by the archive. Old bundles routinely contain "
                "endpoints, feature flags and occasionally keys that were removed "
                "from the current build but remain retrievable from the archive."
            ),
            "evidence": _listing(buckets["scripts"], 100),
        })

    if buckets["api"]:
        findings.append({
            "tool": "wayback_machine",
            "category": "archive_endpoints",
            "severity": "low",
            "title": f"Archived API Endpoints — {len(buckets['api'])} found",
            "description": (
                "URLs whose path shape indicates an API. Retired API versions are a "
                "recurring finding: the new version is hardened and the old one is "
                "still routed because nothing linked to it, so nobody noticed."
            ),
            "evidence": _listing(buckets["api"], 100),
            "remediation": (
                "Confirm retired API versions return 404 or 410 rather than still serving."
            ),
        })

    for extension, matched in sorted(
        buckets["sensitive"].items(), key=lambda item: -len(item[1])
    ):
        findings.append({
            "tool": "wayback_machine",
            "category": "sensitive_historical_urls",
            "severity": "high" if extension in {".sql", ".env", ".key", ".pem", ".dump"} else "medium",
            "title": f"Archived Files With Sensitive Extension '{extension}' — {len(matched)} found",
            "description": (
                f"The archive recorded {len(matched)} URL(s) ending in '{extension}'. "
                "Files of this type should not be served by a web server at all; the "
                "archive having one means it was reachable when the crawl ran. "
                "Whether it is reachable now was not tested."
            ),
            "evidence": _listing(matched, 50),
            "remediation": (
                "Confirm these are no longer served. If the file contained credentials "
                "or keys, rotate them — the archived copy remains retrievable by anyone."
            ),
            "requires_manual_validation": True,
        })

    for label, matched in sorted(
        buckets["parameterised"].items(), key=lambda item: -len(item[1])
    ):
        findings.append({
            "tool": "wayback_machine",
            "category": "archive_parameters",
            "severity": "low",
            "title": f"Archived URLs With {label.title()} Parameters — {len(matched)} found",
            "description": (
                f"These archived URLs carry query parameters associated with "
                f"{label}. The parameter name is the only evidence here — nothing "
                "was submitted and no behaviour was observed. They are listed "
                "because they identify where the application accepted input, which "
                "is where testing would start."
            ),
            "evidence": _listing(matched, 60),
        })

    if buckets["interesting"]:
        findings.append({
            "tool": "wayback_machine",
            "category": "sensitive_historical_urls",
            "severity": "medium",
            "title": f"Archived Paths With Sensitive Names — {len(buckets['interesting'])} found",
            "description": (
                "Archived URLs whose path names an administrative, debugging or "
                "authentication surface. These may have contained credentials, "
                "configuration or admin interfaces when the archive crawled them."
            ),
            "evidence": _listing(buckets["interesting"], 80),
            "remediation": (
                "Review these archived URLs. If they exposed sensitive data, submit "
                "an exclusion request to archive.org and rotate anything disclosed."
            ),
        })

    logger.info(
        "[wayback] %s: %d URLs — %d scripts, %d api, %d sensitive-ext, %d parameterised",
        domain, len(urls), len(buckets["scripts"]), len(buckets["api"]),
        sum(len(v) for v in buckets["sensitive"].values()),
        sum(len(v) for v in buckets["parameterised"].values()),
    )
    return findings
