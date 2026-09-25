"""Directory and file enumeration in pure Python, with soft-404 suppression.

The existing ``dir_fuzzing`` module shells out to ffuf or gobuster and looks
for a wordlist at a hardcoded Linux path. On a host with neither -- which is
every Windows host and most macOS ones -- it reports that it was skipped. That
is honest and still leaves the check undone on the platform the setup script
targets first.

This runs anywhere, ships its own wordlists, and solves the problem that makes
naive directory brute-forcing useless: **soft 404s**. A server that answers
``200 OK`` with a "page not found" body for every unknown path turns a 400-word
list into 400 findings, all of them false. Three mechanisms handle it, in the
order they matter:

1. **Phantom probing.** Before the real wordlist runs, several paths that
   cannot exist are requested. Whatever comes back *is* this server's idea of
   "not found" -- its status, its body length, its redirect target.
2. **Length clustering.** Real responses whose body length matches a phantom's
   (within a small tolerance, since many soft-404 pages echo the requested
   path) are discarded.
3. **Redirect clustering.** A server that redirects every unknown path to
   ``/login`` produces one redirect target repeated across the whole list.
   That target is learned from the phantoms and suppressed.

What survives is reported with the evidence for why it was believed: status,
length, and how it differed from the phantom baseline. A path is a *candidate*
-- it answered differently from a name that does not exist. Confirming what it
actually serves is a human step.
"""

from __future__ import annotations

import logging
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from app.config import settings
from app.targeting import validate_scan_target
from app.tasks.http_client import safe_get

logger = logging.getLogger("recontitan.recon.dir_enum")

WORDLIST_DIR = Path(__file__).resolve().parent.parent.parent / "wordlists"

#: Statuses worth reporting. 401 and 403 are included deliberately: "this
#: exists and you may not have it" is a finding, not a miss.
INTERESTING_STATUSES = (200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500)

#: Soft-404 pages routinely echo the requested path, so two responses for
#: different names differ by a few bytes while being the same page. Anything
#: inside this band of a phantom's length is treated as the same page.
LENGTH_TOLERANCE = 48

#: Phrases that mean "not found" in a body that claimed 200. Checked only
#: against short bodies, where a match is unambiguous.
NOT_FOUND_MARKERS = (
    "404", "not found", "page not found", "does not exist", "no such",
    "cannot be found", "nothing here", "page you requested",
)


def _phantom_paths(count: int = 4) -> list[str]:
    """Paths that cannot plausibly exist, used to learn this server's 404."""
    rng = random.SystemRandom()
    out = []
    for suffix in ("", ".php", ".html", "/"):
        token = "".join(rng.choices(string.ascii_lowercase + string.digits, k=18))
        out.append(f"recontitan-probe-{token}{suffix}")
    return out[:count]


def _load_wordlist() -> tuple[list[str], str]:
    """Return (entries, description of where they came from)."""
    configured = settings.DIR_ENUM_WORDLIST.strip()
    if configured:
        path = Path(configured)
        if path.is_file():
            entries = _read_wordlist(path)
            return entries, f"{path} ({len(entries)} entries)"
        logger.warning("[dir_enum] DIR_ENUM_WORDLIST=%s not found, using bundled list", configured)

    tier = settings.DIR_ENUM_WORDLIST_SIZE
    if tier not in {"small", "common", "big"}:
        tier = "common"
    bundled = WORDLIST_DIR / f"dirs-{tier}.txt"
    if not bundled.is_file():
        return [], "no wordlist available"
    entries = _read_wordlist(bundled)
    return entries, f"bundled '{tier}' list ({len(entries)} entries)"


def _read_wordlist(path: Path) -> list[str]:
    entries: list[str] = []
    seen: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        entry = line.strip().strip("/")
        if not entry or entry.startswith("#") or entry in seen:
            continue
        seen.add(entry)
        entries.append(entry)
    return entries


def _expand(entries: list[str]) -> list[str]:
    """Append configured extensions, keeping the bare name as well."""
    extensions = [ext.lstrip(".") for ext in settings.DIR_ENUM_EXTENSIONS if ext.strip()]
    if not extensions:
        return entries
    out: list[str] = []
    for entry in entries:
        out.append(entry)
        if "." in entry.rsplit("/", 1)[-1]:
            continue  # already has an extension
        out.extend(f"{entry}.{ext}" for ext in extensions)
    return out


class _Probe:
    """One request's outcome, reduced to what the filtering needs."""

    __slots__ = ("path", "status", "length", "location", "body_head", "error")

    def __init__(self, path, status=0, length=0, location="", body_head="", error=""):
        self.path = path
        self.status = status
        self.length = length
        self.location = location
        self.body_head = body_head
        self.error = error


def _request(base: str, path: str) -> _Probe:
    url = urljoin(base, path)
    try:
        response = safe_get(
            url,
            timeout=settings.DIR_ENUM_TIMEOUT,
            max_bytes=64 * 1024,
            follow_redirects=False,
        )
    except Exception as exc:  # noqa: BLE001 — one bad path must not end the sweep
        return _Probe(path, error=f"{type(exc).__name__}"[:60])
    body = response.content
    return _Probe(
        path,
        status=response.status_code,
        length=len(body),
        location=response.headers.get("Location", ""),
        body_head=body[:400].decode("utf-8", errors="replace").lower(),
    )


def _looks_like_soft_404(probe: _Probe) -> bool:
    """A 2xx whose short body says it is a 404."""
    if probe.status not in (200, 201):
        return False
    if probe.length > 4096:
        return False
    return any(marker in probe.body_head for marker in NOT_FOUND_MARKERS)


def run_dir_enum(target: str) -> list[dict]:
    """Enumerate paths against the target, suppressing this server's soft 404s."""
    if not settings.DIR_ENUM_ENABLED:
        return [{
            "tool": "dir_enum", "category": "scanner_coverage", "severity": "info",
            "title": "Directory Enumeration Disabled",
            "description": "DIR_ENUM_ENABLED=false, so no path enumeration was performed.",
            "evidence": "DIR_ENUM_ENABLED=false",
        }]

    ok, domain, error = validate_scan_target(target, resolve_dns=False)
    if not ok:
        return [{
            "tool": "dir_enum", "category": "directory_enumeration", "severity": "high",
            "title": "Unsafe or Invalid Enumeration Target",
            "description": "Path enumeration was blocked by target validation.",
            "evidence": error,
        }]

    base = target if target.startswith("http") else f"https://{domain}"
    if not base.endswith("/"):
        base += "/"

    entries, source = _load_wordlist()
    if not entries:
        return [{
            "tool": "dir_enum", "category": "directory_enumeration", "severity": "info",
            "title": "Directory Enumeration Skipped — No Wordlist",
            "description": "No wordlist could be loaded, so no paths were tested.",
            "evidence": f"Searched: {WORDLIST_DIR}",
            "remediation": "Set DIR_ENUM_WORDLIST to a wordlist path, or restore the bundled lists.",
        }]

    entries = _expand(entries)[: settings.DIR_ENUM_MAX_REQUESTS]

    # ── Phase 1: learn what "not found" looks like here ──
    phantoms = [_request(base, path) for path in _phantom_paths()]
    reachable = [p for p in phantoms if not p.error]
    if not reachable:
        return [{
            "tool": "dir_enum", "category": "directory_enumeration", "severity": "info",
            "title": "Directory Enumeration Could Not Establish A Baseline",
            "description": (
                f"None of the baseline probes against {domain} completed, so this "
                "server's 'not found' response is unknown. Enumerating without that "
                "baseline produces a list of paths that cannot be distinguished from "
                "noise, so nothing was tested. This is not evidence that no paths exist."
            ),
            "evidence": "\n".join(f"• {p.path}: {p.error}" for p in phantoms),
        }]

    baseline_statuses = {p.status for p in reachable}
    baseline_lengths = {p.length for p in reachable}
    baseline_locations = {
        urlsplit(p.location).path for p in reachable if p.location
    }
    # A server that answers 200 to names that cannot exist is a soft-404
    # server. Saying so changes how every result below should be read.
    soft_404_server = any(p.status in (200, 201) for p in reachable)

    def _is_baseline(probe: _Probe) -> bool:
        if probe.status not in baseline_statuses:
            return False
        if any(abs(probe.length - length) <= LENGTH_TOLERANCE for length in baseline_lengths):
            return True
        if probe.location and urlsplit(probe.location).path in baseline_locations:
            return True
        # Same status as the baseline but a materially different body: the
        # server distinguishes this path from a name that does not exist.
        return False

    # ── Phase 2: the wordlist ──
    results: list[_Probe] = []
    errors = 0
    workers = min(settings.DIR_ENUM_THREADS, max(1, len(entries)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_request, base, entry) for entry in entries]
        for future in as_completed(futures):
            probe = future.result()
            if probe.error:
                errors += 1
                continue
            results.append(probe)

    candidates = [
        probe for probe in results
        if probe.status in INTERESTING_STATUSES
        and not _is_baseline(probe)
        and not _looks_like_soft_404(probe)
    ]
    suppressed = len(results) - len(candidates)
    candidates.sort(key=lambda p: (p.status, p.path))

    baseline_summary = "\n".join(
        f"  {p.path:<44} {p.status}  {p.length} bytes"
        + (f"  -> {p.location}" if p.location else "")
        for p in reachable
    )

    findings: list[dict] = []

    if not candidates:
        findings.append({
            "tool": "dir_enum",
            "category": "directory_enumeration",
            "severity": "info",
            "title": "Directory Enumeration — No Distinguishable Paths Found",
            "description": (
                f"{len(results)} paths were tested against {domain} and none responded "
                "differently from a path that does not exist. That means this wordlist "
                "found nothing here — not that the server has no hidden paths."
            ),
            "evidence": (
                f"Wordlist   : {source}\n"
                f"Tested     : {len(results)} paths ({errors} request errors)\n"
                f"Suppressed : {suppressed} matched the not-found baseline\n\n"
                f"Baseline (paths that cannot exist):\n{baseline_summary}"
            ),
        })
        logger.info("[dir_enum] %s: 0 candidates from %d paths", domain, len(results))
        return findings

    by_status: dict[int, list[_Probe]] = {}
    for probe in candidates:
        by_status.setdefault(probe.status, []).append(probe)

    listing: list[str] = []
    for status in sorted(by_status):
        listing.append(f"── HTTP {status} ({len(by_status[status])}) ──")
        for probe in by_status[status][:80]:
            line = f"  /{probe.path:<40} {probe.length} bytes"
            if probe.location:
                line += f"  -> {probe.location}"
            listing.append(line)
        if len(by_status[status]) > 80:
            listing.append(f"  ... and {len(by_status[status]) - 80} more")
        listing.append("")

    findings.append({
        "tool": "dir_enum",
        "category": "directory_enumeration",
        "severity": "medium" if any(s in by_status for s in (200, 201)) else "low",
        "title": f"Directory Enumeration — {len(candidates)} Candidate Path(s)",
        "description": (
            f"{len(candidates)} of {len(results)} tested paths responded differently "
            f"from a path that cannot exist on {domain}. Each is a candidate: it "
            "answered distinctly, which is evidence the server knows the name. What "
            "it actually serves was not inspected. "
            + (
                "This server answers 2xx for names that do not exist, so its results "
                "are filtered by body length rather than status — treat them with "
                "more caution than usual."
                if soft_404_server else
                "This server returns a clean not-found response, so status alone is "
                "a reliable signal here."
            )
        ),
        "evidence": (
            f"Wordlist   : {source}\n"
            f"Tested     : {len(results)} paths ({errors} request errors)\n"
            f"Suppressed : {suppressed} matched the not-found baseline\n\n"
            f"Baseline (paths that cannot exist):\n{baseline_summary}\n\n"
            + "\n".join(listing)
        ),
        "remediation": (
            "Review each path. Administrative and configuration endpoints should "
            "not be reachable without authentication, and should not be "
            "distinguishable from non-existent paths by their response."
        ),
        "requires_manual_validation": True,
    })

    # Paths whose names indicate exposure rather than structure.
    high_value_markers = (
        ".env", ".git", "config", "backup", "dump", "sql", "phpinfo", "adminer",
        "phpmyadmin", ".htpasswd", "credentials", "secrets", "id_rsa", ".bak",
        "actuator", "server-status", "swagger", "api-docs",
    )
    exposed = [
        probe for probe in candidates
        if probe.status in (200, 201) and any(marker in probe.path.lower() for marker in high_value_markers)
    ]
    if exposed:
        findings.append({
            "tool": "dir_enum",
            "category": "information_disclosure",
            "severity": "high",
            "title": f"Configuration or Source Paths Answered — {len(exposed)} found",
            "description": (
                "These paths returned a success status and carry names associated "
                "with configuration, source control, database dumps or diagnostic "
                "endpoints. A reachable one of these usually discloses more than "
                "the path itself. The response body was not retrieved or stored — "
                "confirm the content by hand."
            ),
            "evidence": "\n".join(
                f"• [{probe.status}] /{probe.path}  ({probe.length} bytes)"
                for probe in exposed
            ),
            "remediation": (
                "Remove these from the document root or block them at the web "
                "server. Version-control directories, environment files and "
                "database dumps should never be served."
            ),
            "requires_manual_validation": True,
        })

    logger.info(
        "[dir_enum] %s: %d candidates, %d suppressed, %d errors from %d paths",
        domain, len(candidates), suppressed, errors, len(results),
    )
    return findings
