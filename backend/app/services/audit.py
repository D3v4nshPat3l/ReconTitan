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

#: Ordinary, successful access. Not an attack -- this is what makes the console
#: show *everyone* using the service rather than only the people attacking it.
#: Necessarily the highest-volume kind, so it is coalesced like the rest.
ACCESS = "http.access"

COALESCED_KINDS = frozenset(
    {AUTH_FAILED, INJECTION_BLOCKED, RATE_LIMITED, BLOCKED_AGENT, ACCESS}
)

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

    Behind the Compose nginx, uvicorn runs with ``--proxy-headers
    --forwarded-allow-ips`` and has already rewritten ``request.client``, so the
    forwarding headers are ignored: reading them there would mean trusting a
    value the client sets, letting anyone forge their own source address in the
    audit trail.

    A serverless platform has no such rewrite. ``request.client`` is the
    platform's internal proxy, identical for every visitor, which would reduce
    the whole trail to one repeated address. ``TRUST_PROXY_HEADERS`` (default on
    only under ``SERVERLESS``) opts into the header instead. The leftmost entry
    is the originating client; the rest are proxies appended along the way.
    """
    direct = "unknown"
    try:
        if request.client:
            direct = request.client.host
    except Exception:
        pass

    if not settings.TRUST_PROXY_HEADERS:
        return direct

    try:
        forwarded = request.headers.get("x-forwarded-for", "")
    except Exception:
        return direct
    if forwarded:
        first = forwarded.split(",")[0].strip()
        # Bound it: the header is attacker-controlled even when trusted, and an
        # oversized value must not reach storage or a rendered table.
        if first and len(first) <= 64:
            return first
    return direct


#: Request headers recorded to help group requests from one origin. Every one
#: is client-controlled and trivially forged, which is why they are stored as
#: observations and never trusted as identity.
_CLIENT_HINT_HEADERS = (
    ("accept_language", "accept-language", 64),
    ("referer", "referer", 256),
    ("platform", "sec-ch-ua-platform", 32),
    ("client_hint", "sec-ch-ua", 128),
    ("mobile", "sec-ch-ua-mobile", 8),
)


def client_fingerprint(request: Any) -> str:
    """A stable label for "probably the same caller", not a device identity.

    Servers cannot identify a device. What is available is a handful of
    self-reported headers plus the source address, and every part of that is
    forgeable, shared behind NAT, and unstable across browser and network
    changes. Hashing them yields something useful for *grouping* requests --
    "these 200 probes look like one actor" -- and nothing stronger.

    The hash is truncated and one-way so the trail carries a correlation handle
    rather than a stored profile of the visitor. Treat a match as a hint and a
    mismatch as meaningless.
    """
    try:
        headers = request.headers
        parts = [
            client_ip(request),
            headers.get("user-agent", ""),
            headers.get("accept-language", ""),
            headers.get("accept-encoding", ""),
            headers.get("sec-ch-ua-platform", ""),
        ]
    except Exception:
        return ""
    joined = "|".join(part or "-" for part in parts)
    if joined.replace("|", "").replace("-", "") == "":
        return ""
    return f"c_{hashlib.sha256(joined.encode('utf-8', errors='ignore')).hexdigest()[:12]}"


def device_hints(request: Any) -> dict:
    """Client-declared context worth recording alongside a request."""
    hints: dict[str, str] = {}
    try:
        headers = request.headers
    except Exception:
        return hints
    for field, header, limit in _CLIENT_HINT_HEADERS:
        value = _clip(headers.get(header, ""), limit)
        if value:
            hints[field] = value
    return hints


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
        # Label of the API key that authenticated the request, set by the
        # security middleware. Without it the trail records that *someone* with
        # a valid credential acted, which is not attribution when the credential
        # is shared. Never the key itself -- only its name.
        try:
            caller = getattr(request.state, "api_caller", "")
            if caller:
                event["api_caller"] = _clip(caller, 64)
        except Exception:
            pass
        # Correlation handle plus the client-declared hints behind it. Recorded
        # so the console can group one actor's requests; see client_fingerprint
        # for why this is not device identification.
        try:
            correlation = client_fingerprint(request)
            if correlation:
                event["client_id"] = correlation
            event.update(device_hints(request))
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
