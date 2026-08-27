"""Operator-managed blocklists for scan targets and request sources.

Two separate lists, because they answer different questions:

``targets``
    Hosts ReconTitan must refuse to scan, whoever asks. A customer who has
    withdrawn permission, a domain outside the engagement scope, or anything a
    lawyer has said no to. Enforced before a single packet leaves.

``sources``
    Callers the deployment refuses to serve. Enforced in the middleware, before
    routing, so a blocked source cannot reach a scan endpoint at all.

Both are stored in MongoDB so they survive a restart and are shared by every
worker, and both are cached in memory with a short TTL — the target list is
consulted on every scan and the source list on every single request, and a
database round trip per request would make the blocklist itself the bottleneck.

Design decisions worth keeping:

* Entries never disappear silently. Removing one is an explicit operator
  action that is itself audited, so "why did this stop being blocked" always
  has an answer.
* Target matching covers subdomains. Blocking ``example.com`` blocks
  ``api.example.com``, because an operator blocking a company means the
  company, not one hostname.
* Source matching supports CIDR. A single address is rarely the whole actor.
* The cache fails *open* for targets on a database outage and *closed* for
  nothing: a Mongo failure must not silently start permitting scans of a
  forbidden host, so the last known list is kept and reused rather than
  discarded.
"""

from __future__ import annotations

import ipaddress
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from app.database import get_db
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.blocklist")

TARGETS = "blocked_targets"
SOURCES = "blocked_sources"

#: Long enough that the hot path is not a database call, short enough that an
#: operator blocking something sees it take effect while they are still looking
#: at the console.
_CACHE_TTL_SECONDS = 10

_lock = threading.Lock()
_cache: dict[str, dict[str, Any]] = {
    TARGETS: {"at": 0.0, "rows": []},
    SOURCES: {"at": 0.0, "rows": []},
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load(kind: str) -> list[dict]:
    """Return the current list, from cache when warm.

    On a database error the previous rows are returned rather than an empty
    list. An empty list means "nothing is blocked", and inferring that from an
    outage would quietly re-permit every blocked target.
    """
    with _lock:
        entry = _cache[kind]
        if time.monotonic() - entry["at"] < _CACHE_TTL_SECONDS:
            return entry["rows"]

    rows: list[dict] | None = None
    try:
        db = get_db()
        if db is not None:
            rows = list(db[kind].find({}, {"_id": 0}))
    except Exception as exc:
        logger.warning("blocklist load failed for %s: %s", kind, str(exc)[:160])

    with _lock:
        if rows is not None:
            _cache[kind] = {"at": time.monotonic(), "rows": rows}
        else:
            # Keep serving the last known list; only push the retry forward.
            _cache[kind]["at"] = time.monotonic() - (_CACHE_TTL_SECONDS / 2)
        return _cache[kind]["rows"]


def invalidate() -> None:
    """Drop the cache so the next read reflects a just-made change."""
    with _lock:
        for kind in _cache:
            _cache[kind]["at"] = 0.0


# ── Targets ─────────────────────────────────────────────────────────────────

def block_target(host: str, *, reason: str = "", added_by: str = "admin") -> dict:
    host = normalize_target(host)
    if not host:
        raise ValueError("A hostname is required")

    db = get_db()
    if db is None:
        raise RuntimeError("MongoDB is unavailable; the blocklist cannot be changed")

    doc = {
        "host": host,
        "reason": reason[:300],
        "added_by": added_by[:64],
        "added_at": _now(),
    }
    db[TARGETS].update_one({"host": host}, {"$set": doc}, upsert=True)
    db[TARGETS].create_index("host", unique=True)
    invalidate()
    logger.info("target blocked: %s (%s)", host, reason[:80] or "no reason given")
    return doc


def unblock_target(host: str) -> bool:
    host = normalize_target(host)
    db = get_db()
    if db is None:
        raise RuntimeError("MongoDB is unavailable; the blocklist cannot be changed")
    removed = db[TARGETS].delete_one({"host": host}).deleted_count > 0
    invalidate()
    if removed:
        logger.info("target unblocked: %s", host)
    return removed


def list_targets() -> list[dict]:
    return sorted(_load(TARGETS), key=lambda r: r.get("host", ""))


def target_block(host: str) -> dict | None:
    """Return the blocking entry for a host, or None.

    Matches the host itself and any parent domain, so blocking ``example.com``
    also refuses ``api.staging.example.com``. An operator blocking a company
    means the company, and expecting them to enumerate every subdomain is how
    a blocklist silently fails.
    """
    host = normalize_target(host)
    if not host:
        return None
    for row in _load(TARGETS):
        blocked = str(row.get("host", "")).lower()
        if not blocked:
            continue
        if host == blocked or host.endswith("." + blocked):
            return row
    return None


# ── Sources ─────────────────────────────────────────────────────────────────

def _parse_network(value: str):
    """Accept a bare address or CIDR; return a network or None."""
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except ValueError:
        return None


def block_source(value: str, *, reason: str = "", added_by: str = "admin") -> dict:
    value = (value or "").strip()
    if _parse_network(value) is None:
        raise ValueError("Expected an IP address or CIDR range, for example 203.0.113.4 or 203.0.113.0/24")

    db = get_db()
    if db is None:
        raise RuntimeError("MongoDB is unavailable; the blocklist cannot be changed")

    doc = {
        "source": value,
        "reason": reason[:300],
        "added_by": added_by[:64],
        "added_at": _now(),
    }
    db[SOURCES].update_one({"source": value}, {"$set": doc}, upsert=True)
    db[SOURCES].create_index("source", unique=True)
    invalidate()
    logger.warning("source blocked: %s (%s)", value, reason[:80] or "no reason given")
    return doc


def unblock_source(value: str) -> bool:
    value = (value or "").strip()
    db = get_db()
    if db is None:
        raise RuntimeError("MongoDB is unavailable; the blocklist cannot be changed")
    removed = db[SOURCES].delete_one({"source": value}).deleted_count > 0
    invalidate()
    if removed:
        logger.info("source unblocked: %s", value)
    return removed


def list_sources() -> list[dict]:
    return sorted(_load(SOURCES), key=lambda r: r.get("source", ""))


def source_block(ip: str) -> dict | None:
    """Return the blocking entry covering an address, or None."""
    ip = (ip or "").strip()
    if not ip:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        # Non-address sources such as "testclient" only ever match literally.
        for row in _load(SOURCES):
            if str(row.get("source", "")).strip() == ip:
                return row
        return None

    for row in _load(SOURCES):
        network = _parse_network(str(row.get("source", "")))
        if network is not None and address in network:
            return row
    return None
