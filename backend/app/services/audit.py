"""Append-only audit trail for scan attribution and security events.

Scan records carried no attribution at all, so "who scanned what" was
unanswerable. This module is the single writer for that history and the only
source the admin and SOC dashboards read.

Two write paths, because the two event classes have opposite risk profiles:

``record_scan_event``
    Low volume, high value, one document per event. A scan is an operator
    action worth recording individually and exactly.

``record_security_event``
    High volume and *attacker-controlled* -- blocked injections, auth failures,
    and rate-limit hits are emitted precisely when someone is hammering the
    service. Writing one document per event would let a flood convert into a
    database write flood, so identical events from one source are coalesced in
    memory and flushed periodically as a single counted document. The audit
    trail must not become the amplifier for the attack it is recording.

Every write is fail-soft. Losing an audit record is bad; failing a request
because the audit write failed is worse.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any

from app.config import settings
from app.database import get_db

logger = logging.getLogger("recontitan.audit")

#: Scan lifecycle and operator actions.
SCAN_ACCEPTED = "scan.accepted"
SCAN_REJECTED = "scan.rejected"
SCAN_GATE_DENIED = "scan.gate_denied"

#: Attacker-facing events. These are coalesced.
AUTH_FAILED = "auth.failed"
INJECTION_BLOCKED = "injection.blocked"
RATE_LIMITED = "ratelimit.exceeded"
BLOCKED_AGENT = "agent.blocked"

COALESCED_KINDS = frozenset({AUTH_FAILED, INJECTION_BLOCKED, RATE_LIMITED, BLOCKED_AGENT})

_COLLECTION = "audit_events"

_lock = threading.Lock()
#: (kind, ip, detail) -> mutable aggregate awaiting flush.
_pending: "OrderedDict[tuple[str, str, str], dict]" = OrderedDict()
_last_flush = time.monotonic()
_indexes_ready = False


def _clip(value: Any, limit: int) -> str:
    """Bound and flatten a value before it reaches storage.

    User agents, paths, and payload excerpts are attacker-controlled. Newlines
    are stripped so a crafted value cannot forge extra lines in any log view
    that renders these fields.
    """
    text = " ".join(str(value if value is not None else "").split())
    return text[:limit]


def client_ip(request: Any) -> str:
    """Resolve the real client address.

    uvicorn runs with ``--proxy-headers --forwarded-allow-ips``, so behind the
    Compose nginx ``request.client.host`` is already the rewritten client
    address rather than the proxy's. Reading the raw forwarding headers here
    would instead trust a value the client can set.
    """
    try:
        return request.client.host if request.client else "unknown"
    except Exception:
        return "unknown"


def key_fingerprint(supplied: str | None) -> str:
    """Identify which API key was used without ever storing the key itself."""
    if not supplied:
        return ""
    digest = hashlib.sha256(supplied.encode("utf-8", errors="ignore")).hexdigest()
    return f"k_{digest[:12]}"


def _base_event(kind: str, request: Any, **fields: Any) -> dict:
    event: dict[str, Any] = {
        "kind": kind,
        "at": datetime.now(timezone.utc),
        "ip": _clip(client_ip(request), 64),
    }
    if request is not None:
        try:
            event["method"] = _clip(request.method, 8)
            event["path"] = _clip(request.url.path, 256)
            event["user_agent"] = _clip(request.headers.get("user-agent", ""), 256)
        except Exception:
            pass
    for name, value in fields.items():
        if value is None or value == "":
            continue
        event[name] = value if isinstance(value, (int, float, bool)) else _clip(value, 512)
    return event


def _ensure_indexes(db: Any) -> None:
    global _indexes_ready
    if _indexes_ready:
        return
    try:
        collection = db[_COLLECTION]
        collection.create_index("at")
        collection.create_index("kind")
        collection.create_index("ip")
        collection.create_index([("kind", 1), ("at", -1)])
        # Retention is a deliberate ceiling: this collection holds IP addresses,
        # so it must expire rather than accumulate indefinitely.
        collection.create_index("at", expireAfterSeconds=settings.AUDIT_RETENTION_DAYS * 86400,
                                name="audit_ttl")
        _indexes_ready = True
    except Exception as exc:
        logger.debug("audit index setup skipped: %s", str(exc)[:120])


def _write(documents: list[dict]) -> None:
    if not documents:
        return
    db = get_db()
    if db is None:
        return
    try:
        _ensure_indexes(db)
        db[_COLLECTION].insert_many(documents, ordered=False)
    except Exception as exc:
        logger.warning("audit write failed: %s", str(exc)[:160])


def record_scan_event(kind: str, request: Any, **fields: Any) -> None:
    """Record one scan lifecycle event immediately."""
    if not settings.AUDIT_ENABLED:
        return
    try:
        _write([_base_event(kind, request, **fields)])
    except Exception as exc:  # never let auditing break a request
        logger.warning("audit scan event dropped: %s", str(exc)[:160])


def record_security_event(kind: str, request: Any, detail: str = "", **fields: Any) -> None:
    """Record an attacker-facing event, coalescing repeats from one source.

    Repeats within the flush window increment ``count`` on a single document
    instead of inserting one per request, so a flood cannot amplify into a
    write storm against MongoDB.
    """
    if not settings.AUDIT_ENABLED:
        return
    try:
        ip = client_ip(request)
        bucket = (kind, _clip(ip, 64), _clip(detail, 120))
        now = time.monotonic()
        flush: list[dict] = []
        with _lock:
            entry = _pending.get(bucket)
            if entry is None:
                entry = _base_event(kind, request, detail=detail, **fields)
                entry["count"] = 0
                entry["first_at"] = entry["at"]
                _pending[bucket] = entry
            entry["count"] += 1
            entry["last_at"] = datetime.now(timezone.utc)

            # Bound memory: a source rotating detail strings must not grow this
            # map without limit.
            if len(_pending) > settings.AUDIT_MAX_PENDING:
                flush = _drain_locked()
            elif now - _last_flush >= settings.AUDIT_FLUSH_SECONDS:
                flush = _drain_locked()
        _write(flush)
    except Exception as exc:
        logger.warning("audit security event dropped: %s", str(exc)[:160])


def _drain_locked() -> list[dict]:
    """Take everything pending. Caller must hold ``_lock``."""
    global _last_flush
    documents = list(_pending.values())
    _pending.clear()
    _last_flush = time.monotonic()
    return documents


def flush() -> None:
    """Force pending events to storage. Used at shutdown and by tests."""
    with _lock:
        documents = _drain_locked()
    _write(documents)
