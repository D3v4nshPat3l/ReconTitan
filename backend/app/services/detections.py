"""Behavioural detections derived from the audit trail.

The middleware already blocks individual bad requests. What it cannot see is a
*pattern*: one injection attempt is noise, forty from one source in ten minutes
is somebody working through a payload list. This module reads the recorded
events and reports the patterns, so the console shows actors rather than a flat
list of incidents.

Every rule follows the same shape and the same rules of evidence:

* it counts real recorded events, never estimates;
* it carries the evidence it fired on, so an operator can disagree with it;
* it says what it cannot know. Recon probing and a security scanner running
  with permission look identical from the server side, and a detection that
  hides that ambiguity invites someone to block a colleague.

Thresholds are deliberately conservative. A console that cries wolf gets muted,
and a muted console is worth less than none at all.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from app.database import get_db
from app.services import audit

logger = logging.getLogger("recontitan.detections")

#: Paths that exist only in somebody else's software. A request for any of them
#: is not a mistake — it is a scanner walking a list of known admin panels and
#: secret files, and the only reason to ask is to find out whether it is here.
PROBE_PATHS = (
    "/wp-admin", "/wp-login", "/xmlrpc.php", "/phpmyadmin", "/pma",
    "/.env", "/.git", "/config.php", "/admin.php", "/administrator",
    "/manager/html", "/solr", "/jenkins", "/actuator", "/console",
    "/.aws", "/.ssh", "/backup", "/dump.sql", "/shell", "/cgi-bin",
)

#: Substrings that indicate the caller is looking for the admin surface itself.
ADMIN_PROBE_HINTS = ("/admin", "/soc", "/dashboard", "/session", "/login")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _since(hours: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def _events(db, since: datetime) -> list[dict]:
    return list(db["audit_events"].find({"at": {"$gte": since}}, {"_id": 0}))


def _count(rows: list[dict]) -> int:
    """Coalesced documents carry a count; single events do not."""
    return sum(int(r.get("count", 1) or 1) for r in rows)


def _by_source(rows: list[dict]) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(str(row.get("ip", "unknown")), []).append(row)
    return grouped


def _finding(
    rule: str, title: str, severity: str, source: str, count: int,
    rows: list[dict], explain: str, caveat: str = "",
) -> dict:
    times = sorted(r["at"] for r in rows if r.get("at"))
    agents = {str(r.get("user_agent", "")) for r in rows if r.get("user_agent")}
    paths = [str(r.get("path", "")) for r in rows if r.get("path")]
    return {
        "rule": rule,
        "title": title,
        "severity": severity,
        "source": source,
        "count": count,
        "first_seen": times[0] if times else None,
        "last_seen": times[-1] if times else None,
        "user_agents": sorted(a for a in agents if a)[:4],
        "sample_paths": sorted(set(paths))[:8],
        "explanation": explain,
        "caveat": caveat,
    }


# ── Rules ───────────────────────────────────────────────────────────────────

def _rule_injection(grouped: dict[str, list[dict]]) -> list[dict]:
    """Repeated blocked payloads: someone working through a payload list."""
    out = []
    for source, rows in grouped.items():
        hits = [r for r in rows if r.get("kind") == audit.INJECTION_BLOCKED]
        total = _count(hits)
        if total < 5:
            continue
        severity = "critical" if total >= 25 else "high"
        out.append(_finding(
            "payload_injection",
            f"Repeated injection payloads from {source}",
            severity, source, total, hits,
            "Each of these requests carried a payload the input screening "
            "recognised and refused. One is background noise; this many from a "
            "single source is somebody working through a list.",
            "All were blocked before reaching a scanner. This records intent, "
            "not a successful compromise.",
        ))
    return out


def _rule_admin_discovery(grouped: dict[str, list[dict]]) -> list[dict]:
    """Someone hunting for the admin console."""
    out = []
    for source, rows in grouped.items():
        hits = [
            r for r in rows
            if any(h in str(r.get("path", "")).lower() for h in ADMIN_PROBE_HINTS)
            and r.get("kind") in {audit.AUTH_FAILED, "admin.login_failed",
                                  "admin.locked_out", audit.BLOCKED_AGENT}
        ]
        total = _count(hits)
        if total < 3:
            continue
        locked = any(r.get("kind") == "admin.locked_out" for r in rows)
        out.append(_finding(
            "admin_discovery",
            f"Admin surface probing from {source}",
            "critical" if total >= 10 else "high", source, total, hits,
            "Failed authentication against the admin surface. The console is "
            "not linked from anywhere public, so a caller reaching it either "
            "knows it exists or is walking a list of common paths."
            + (" Brute-force lockout has already engaged." if locked else ""),
            "A mistyped token by a legitimate operator looks the same. Check "
            "whether the source is one of yours before acting.",
        ))
    return out


def _rule_path_scanning(grouped: dict[str, list[dict]]) -> list[dict]:
    """Walking known-vulnerable paths — the signature of an automated scanner."""
    out = []
    for source, rows in grouped.items():
        hits = [
            r for r in rows
            if any(p in str(r.get("path", "")).lower() for p in PROBE_PATHS)
        ]
        distinct = {str(r.get("path", "")) for r in hits}
        if len(distinct) < 3:
            continue
        out.append(_finding(
            "path_scanning",
            f"Vulnerability scanning from {source}",
            "high" if len(distinct) >= 8 else "medium",
            source, _count(hits), hits,
            f"Requests for {len(distinct)} distinct paths that belong to other "
            "software entirely — admin panels, dotfiles, and backups. Nothing "
            "here serves them, so the only reason to ask is to find out whether "
            "they exist.",
            "Commodity internet background noise looks like this too. Volume "
            "and whether it continues are what separate the two.",
        ))
    return out


def _rule_request_flood(grouped: dict[str, list[dict]]) -> list[dict]:
    """Sustained request volume: the rate limiter's view of a flood."""
    out = []
    for source, rows in grouped.items():
        limited = [r for r in rows if r.get("kind") == audit.RATE_LIMITED]
        total = _count(limited)
        if total < 10:
            continue
        severity = "critical" if total >= 100 else "high" if total >= 40 else "medium"
        out.append(_finding(
            "request_flood",
            f"Sustained request flood from {source}",
            severity, source, total, limited,
            "Requests continued after the rate limiter began refusing them. A "
            "normal client backs off when it receives 429; this one did not.",
            "A broken retry loop in a legitimate integration produces the same "
            "shape. Check the user agent before treating it as hostile.",
        ))
    return out


def _rule_scan_abuse(grouped: dict[str, list[dict]]) -> list[dict]:
    """One source aiming the scanner at many different targets."""
    out = []
    for source, rows in grouped.items():
        scans = [r for r in rows if r.get("kind") == audit.SCAN_ACCEPTED and r.get("target")]
        targets = {str(r.get("target")) for r in scans}
        if len(targets) < 8:
            continue
        out.append(_finding(
            "scan_abuse",
            f"{source} scanned {len(targets)} distinct targets",
            "high" if len(targets) >= 20 else "medium", source, len(scans), scans,
            "A single source aimed the scanner at many different hosts. Under "
            "an authorised engagement that is expected; from an unknown source "
            "it means this deployment is being used to scan third parties.",
            "Authorisation is not visible from here. Confirm the scope before "
            "treating breadth as abuse.",
        ))
        out[-1]["sample_paths"] = sorted(targets)[:8]
    return out


def _rule_blocked_agent(grouped: dict[str, list[dict]]) -> list[dict]:
    """Tools that announce themselves."""
    out = []
    for source, rows in grouped.items():
        hits = [r for r in rows if r.get("kind") == audit.BLOCKED_AGENT]
        total = _count(hits)
        if total < 1:
            continue
        out.append(_finding(
            "scanner_agent",
            f"Known scanning tool from {source}",
            "medium", source, total, hits,
            "The user agent identified itself as a security scanner and was "
            "refused. Trivially changed, so absence of this proves nothing — "
            "but its presence means the caller did not bother to hide.",
            "The header is self-reported and can be set to anything.",
        ))
    return out


RULES = (
    _rule_injection,
    _rule_admin_discovery,
    _rule_path_scanning,
    _rule_request_flood,
    _rule_scan_abuse,
    _rule_blocked_agent,
)


def detect(hours: int = 24) -> dict:
    """Run every rule over the window and return findings, worst first."""
    db = get_db()
    if db is None:
        return {"available": False, "reason": "MongoDB unavailable", "detections": []}

    rows = _events(db, _since(hours))
    grouped = _by_source(rows)

    findings: list[dict] = []
    for rule in RULES:
        try:
            findings.extend(rule(grouped))
        except Exception as exc:  # one broken rule must not blank the panel
            logger.warning("detection rule %s failed: %s", rule.__name__, str(exc)[:160])

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), -f["count"]))

    return {
        "available": True,
        "window_hours": hours,
        "events_examined": len(rows),
        "sources_examined": len(grouped),
        "detections": findings,
        "note": (
            "Derived from recorded events, not live inspection. Each detection "
            "carries the evidence it fired on and states what it cannot "
            "distinguish."
        ),
    }


def source_profile(ip: str, hours: int = 168) -> dict:
    """Everything recorded about one source, for the expanded row."""
    db = get_db()
    if db is None:
        return {"available": False, "reason": "MongoDB unavailable"}

    rows = list(
        db["audit_events"]
        .find({"ip": ip, "at": {"$gte": _since(hours)}}, {"_id": 0})
        .sort("at", -1)
    )
    if not rows:
        return {"available": True, "source": ip, "events": 0, "timeline": []}

    kinds: dict[str, int] = {}
    paths: dict[str, int] = {}
    agents: dict[str, int] = {}
    targets: dict[str, int] = {}
    clients: set[str] = set()
    callers: set[str] = set()
    hints: dict[str, str] = {}

    for row in rows:
        n = int(row.get("count", 1) or 1)
        kinds[str(row.get("kind", "?"))] = kinds.get(str(row.get("kind", "?")), 0) + n
        if row.get("path"):
            paths[str(row["path"])] = paths.get(str(row["path"]), 0) + n
        if row.get("user_agent"):
            agents[str(row["user_agent"])] = agents.get(str(row["user_agent"]), 0) + n
        if row.get("target"):
            targets[str(row["target"])] = targets.get(str(row["target"]), 0) + n
        if row.get("client_id"):
            clients.add(str(row["client_id"]))
        if row.get("api_caller"):
            callers.add(str(row["api_caller"]))
        for field in ("platform", "accept_language", "referer", "mobile", "client_hint"):
            if row.get(field) and field not in hints:
                hints[field] = str(row[field])

    times = sorted(r["at"] for r in rows if r.get("at"))
    hostile = sum(
        int(r.get("count", 1) or 1) for r in rows
        if r.get("kind") in {audit.INJECTION_BLOCKED, audit.AUTH_FAILED,
                             audit.RATE_LIMITED, audit.BLOCKED_AGENT,
                             "admin.login_failed", "admin.locked_out"}
    )

    top = lambda d, n=10: [  # noqa: E731 - a local shorthand, used four times
        {"value": k, "count": v}
        for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n]
    ]

    from app.services import blocklist

    return {
        "available": True,
        "source": ip,
        "events": _count(rows),
        "hostile_events": hostile,
        "first_seen": times[0] if times else None,
        "last_seen": times[-1] if times else None,
        "window_hours": hours,
        "kinds": top(kinds),
        "paths": top(paths),
        "user_agents": top(agents, 5),
        "targets_scanned": top(targets),
        "client_ids": sorted(clients)[:5],
        "api_callers": sorted(callers),
        "client_hints": hints,
        "blocked": blocklist.source_block(ip) is not None,
        "timeline": [
            {
                "at": r.get("at"), "kind": r.get("kind"), "path": r.get("path"),
                "method": r.get("method"), "detail": r.get("detail"),
                "count": r.get("count", 1), "target": r.get("target"),
            }
            for r in rows[:60]
        ],
        "caveat": (
            "Address, user agent, and client hints are all self-reported or "
            "shared. This describes traffic, not a person."
        ),
    }
