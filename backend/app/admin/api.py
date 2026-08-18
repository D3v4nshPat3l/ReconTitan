"""Admin and SOC data endpoints.

Everything here reads the audit trail and scan records written elsewhere; this
module never mutates either. It is the only place scan attribution is exposed,
because the public API deliberately no longer lists scans at all -- that route
let any key holder enumerate every target anyone had ever scanned.

The shape follows what a SOC console needs rather than what is easy to query:
a small set of headline counters, the sources responsible for the most blocked
activity, a breakdown by attack class, an hourly volume series, and a raw event
feed. Aggregation happens in MongoDB so a busy trail does not have to be pulled
into the API process to be counted.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query

from app.admin.deps import require_admin
from app.database import get_db
from app.services import audit

logger = logging.getLogger("recontitan.admin.api")

router = APIRouter(prefix="/admin/api", dependencies=[Depends(require_admin)])

#: Event kinds that represent hostile or rejected activity, as opposed to
#: ordinary operator actions. Used to separate "threat" counters from traffic.
THREAT_KINDS = (
    audit.AUTH_FAILED,
    audit.INJECTION_BLOCKED,
    audit.RATE_LIMITED,
    audit.BLOCKED_AGENT,
    "admin.login_failed",
    "admin.locked_out",
)

SEVERITY_BY_KIND = {
    "admin.login_failed": "critical",
    "admin.locked_out": "critical",
    audit.INJECTION_BLOCKED: "high",
    audit.AUTH_FAILED: "high",
    audit.BLOCKED_AGENT: "medium",
    audit.RATE_LIMITED: "medium",
    audit.SCAN_GATE_DENIED: "medium",
    audit.SCAN_REJECTED: "low",
    audit.SCAN_ACCEPTED: "info",
}


def _since(hours: int) -> datetime:
    return datetime.now(timezone.utc) - timedelta(hours=hours)


def _events(db):
    return db["audit_events"]


def _weighted_total(db, match: dict) -> int:
    """Sum ``count`` rather than documents.

    Security events are coalesced when written, so one document can represent
    thousands of requests. Counting documents would understate an attack by
    exactly the factor that makes it an attack.
    """
    pipeline = [{"$match": match}, {"$group": {"_id": None, "total": {"$sum": {"$ifNull": ["$count", 1]}}}}]
    result = list(_events(db).aggregate(pipeline))
    return int(result[0]["total"]) if result else 0


@router.get("/overview")
def overview(hours: int = Query(default=24, ge=1, le=720)):
    """Headline counters for the top of the console."""
    db = get_db()
    if db is None:
        return {"available": False, "reason": "MongoDB unavailable"}

    since = _since(hours)
    scans = db["scans"]
    threat_match = {"at": {"$gte": since}, "kind": {"$in": list(THREAT_KINDS)}}

    unique_sources = len(_events(db).distinct("ip", {"at": {"$gte": since}}))
    unique_attackers = len(_events(db).distinct("ip", threat_match))

    return {
        "available": True,
        "window_hours": hours,
        "generated_at": datetime.now(timezone.utc),
        "scans_total": scans.count_documents({}),
        "scans_window": scans.count_documents({"created_at": {"$gte": since}}),
        "scans_running": scans.count_documents({"status": "running"}),
        "scans_failed": scans.count_documents({"status": "failed", "created_at": {"$gte": since}}),
        "threat_events": _weighted_total(db, threat_match),
        "injections_blocked": _weighted_total(db, {"at": {"$gte": since}, "kind": audit.INJECTION_BLOCKED}),
        "auth_failures": _weighted_total(db, {"at": {"$gte": since}, "kind": audit.AUTH_FAILED}),
        "rate_limited": _weighted_total(db, {"at": {"$gte": since}, "kind": audit.RATE_LIMITED}),
        "admin_attempts": _weighted_total(
            db, {"at": {"$gte": since}, "kind": {"$in": ["admin.login_failed", "admin.locked_out"]}}
        ),
        "unique_sources": unique_sources,
        "unique_attackers": unique_attackers,
    }


@router.get("/threats")
def threats(hours: int = Query(default=24, ge=1, le=720), limit: int = Query(default=20, ge=1, le=200)):
    """Sources ranked by hostile volume — the SOC's "who is hitting us" view."""
    db = get_db()
    if db is None:
        return {"available": False, "sources": []}

    pipeline = [
        {"$match": {"at": {"$gte": _since(hours)}, "kind": {"$in": list(THREAT_KINDS)}}},
        {"$group": {
            "_id": "$ip",
            "events": {"$sum": {"$ifNull": ["$count", 1]}},
            "kinds": {"$addToSet": "$kind"},
            "last_seen": {"$max": "$at"},
            "first_seen": {"$min": "$at"},
            "agents": {"$addToSet": "$user_agent"},
        }},
        {"$sort": {"events": -1}},
        {"$limit": limit},
    ]
    sources = []
    for row in _events(db).aggregate(pipeline):
        kinds = [k for k in row.get("kinds", []) if k]
        worst = min(
            (SEVERITY_BY_KIND.get(k, "info") for k in kinds),
            key=lambda s: ["critical", "high", "medium", "low", "info"].index(s),
            default="info",
        )
        sources.append({
            "ip": row["_id"],
            "events": row["events"],
            "kinds": kinds,
            "severity": worst,
            "first_seen": row.get("first_seen"),
            "last_seen": row.get("last_seen"),
            "user_agent": next((a for a in row.get("agents", []) if a), ""),
        })
    return {"available": True, "window_hours": hours, "sources": sources}


@router.get("/classes")
def attack_classes(hours: int = Query(default=24, ge=1, le=720)):
    """Volume per attack class, for the breakdown panel."""
    db = get_db()
    if db is None:
        return {"available": False, "classes": []}

    pipeline = [
        {"$match": {"at": {"$gte": _since(hours)}}},
        {"$group": {
            "_id": "$kind",
            "events": {"$sum": {"$ifNull": ["$count", 1]}},
            "sources": {"$addToSet": "$ip"},
        }},
        {"$sort": {"events": -1}},
    ]
    classes = [
        {
            "kind": row["_id"],
            "events": row["events"],
            "sources": len([s for s in row.get("sources", []) if s]),
            "severity": SEVERITY_BY_KIND.get(row["_id"], "info"),
            "hostile": row["_id"] in THREAT_KINDS,
        }
        for row in _events(db).aggregate(pipeline)
    ]
    return {"available": True, "window_hours": hours, "classes": classes}


@router.get("/timeline")
def timeline(hours: int = Query(default=24, ge=1, le=168)):
    """Hourly event volume, split into hostile and normal traffic."""
    db = get_db()
    if db is None:
        return {"available": False, "buckets": []}

    pipeline = [
        {"$match": {"at": {"$gte": _since(hours)}}},
        {"$group": {
            "_id": {
                "hour": {"$dateToString": {"format": "%Y-%m-%dT%H:00", "date": "$at"}},
                "hostile": {"$in": ["$kind", list(THREAT_KINDS)]},
            },
            "events": {"$sum": {"$ifNull": ["$count", 1]}},
        }},
        {"$sort": {"_id.hour": 1}},
    ]
    merged: dict[str, dict] = {}
    for row in _events(db).aggregate(pipeline):
        hour = row["_id"]["hour"]
        bucket = merged.setdefault(hour, {"hour": hour, "hostile": 0, "normal": 0})
        bucket["hostile" if row["_id"]["hostile"] else "normal"] += row["events"]
    return {"available": True, "window_hours": hours, "buckets": list(merged.values())}


@router.get("/events")
def events(
    hours: int = Query(default=24, ge=1, le=720),
    kind: str = Query(default=""),
    ip: str = Query(default=""),
    limit: int = Query(default=100, ge=1, le=500),
):
    """Raw event feed, newest first, with optional filters."""
    db = get_db()
    if db is None:
        return {"available": False, "events": []}

    query: dict = {"at": {"$gte": _since(hours)}}
    if kind:
        query["kind"] = kind
    if ip:
        query["ip"] = ip

    rows = list(_events(db).find(query, {"_id": 0}).sort("at", -1).limit(limit))
    for row in rows:
        row["severity"] = SEVERITY_BY_KIND.get(row.get("kind", ""), "info")
        row["hostile"] = row.get("kind") in THREAT_KINDS
    return {"available": True, "window_hours": hours, "events": rows}


@router.get("/scans")
def scans(
    hours: int = Query(default=168, ge=1, le=8760),
    limit: int = Query(default=100, ge=1, le=500),
):
    """Scan history with attribution.

    This is the only place scan history is served. The public API no longer
    lists scans, so a target someone scanned is not readable by every other
    holder of the shared access key.
    """
    db = get_db()
    if db is None:
        return {"available": False, "scans": []}

    projection = {
        "_id": 0, "scan_id": 1, "target": 1, "scan_type": 1, "status": 1, "progress": 1,
        "total_findings": 1, "created_at": 1, "completed_at": 1, "error": 1,
        "client_ip": 1, "user_agent": 1, "api_key_id": 1, "findings.severity": 1,
    }
    rows = list(
        db["scans"].find({"created_at": {"$gte": _since(hours)}}, projection)
        .sort("created_at", -1).limit(limit)
    )
    for row in rows:
        findings = row.pop("findings", []) or []
        row["critical"] = sum(1 for f in findings if f.get("severity") == "critical")
        row["high"] = sum(1 for f in findings if f.get("severity") == "high")
    return {"available": True, "window_hours": hours, "scans": rows}


@router.get("/targets")
def targets(hours: int = Query(default=168, ge=1, le=8760), limit: int = Query(default=25, ge=1, le=200)):
    """Most-scanned targets and who scanned them — abuse detection."""
    db = get_db()
    if db is None:
        return {"available": False, "targets": []}

    pipeline = [
        {"$match": {"created_at": {"$gte": _since(hours)}}},
        {"$group": {
            "_id": "$target",
            "scans": {"$sum": 1},
            "sources": {"$addToSet": "$client_ip"},
            "profiles": {"$addToSet": "$scan_type"},
            "last_scan": {"$max": "$created_at"},
        }},
        {"$sort": {"scans": -1}},
        {"$limit": limit},
    ]
    return {
        "available": True,
        "window_hours": hours,
        "targets": [
            {
                "target": row["_id"],
                "scans": row["scans"],
                "sources": [s for s in row.get("sources", []) if s],
                "profiles": [p for p in row.get("profiles", []) if p],
                "last_scan": row.get("last_scan"),
            }
            for row in db["scans"].aggregate(pipeline)
        ],
    }
