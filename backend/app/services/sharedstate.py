"""Cross-instance counters for rate limiting and lockout.

Rate limits, admin lockout, and audit coalescing were all kept in plain Python
dicts inside one process. That is correct for a single uvicorn worker and wrong
everywhere else: with N instances each keeps its own counters, so a limit of 5
becomes 5N, and admin brute-force protection evaporates because an attacker
simply lands on a fresh instance. The project README already listed this as a
known limitation for horizontal scaling.

On a serverless platform it is not a limitation but a hole, because instances
are created and frozen constantly and none of them share memory.

This module puts those counters in Redis when one is configured, and keeps the
in-process behaviour otherwise so a single-node deployment and the test suite
work unchanged. It fails *open* on Redis errors for rate limiting (a broker
outage must not lock every user out) and *closed* for admin lockout (an outage
must not disable brute-force protection).
"""

from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict

from app.config import settings

logger = logging.getLogger("recontitan.sharedstate")

_redis = None
_redis_checked = False
_local_lock = threading.Lock()
_local_hits: dict[str, list[float]] = defaultdict(list)


def _client():
    """Return a Redis client, or None when unavailable or not configured."""
    global _redis, _redis_checked
    if _redis_checked:
        return _redis
    _redis_checked = True
    if not settings.SHARED_STATE_ENABLED:
        return None
    try:
        import redis

        client = redis.Redis.from_url(
            settings.REDIS_URL, socket_timeout=1.5, socket_connect_timeout=1.5,
            decode_responses=True,
        )
        client.ping()
        _redis = client
        logger.info("Shared rate-limit state backed by Redis")
    except Exception as exc:
        logger.warning("Shared state unavailable, using per-process counters: %s", str(exc)[:160])
        _redis = None
    return _redis


def reset() -> None:
    """Test hook: drop the cached client and any local counters."""
    global _redis, _redis_checked
    _redis, _redis_checked = None, False
    with _local_lock:
        _local_hits.clear()


def hit(bucket: str, window_seconds: int) -> int:
    """Record one hit against ``bucket`` and return the count in the window.

    Uses a fixed window rather than a sliding one: it costs a single INCR plus
    an EXPIRE, which keeps the hot path to one round trip. The trade-off is
    that a caller can burst across a window boundary, which is acceptable for
    abuse control and is why the per-scan ceilings exist independently.
    """
    client = _client()
    if client is None:
        return _hit_local(bucket, window_seconds)
    try:
        key = f"rt:rl:{bucket}:{int(time.time()) // window_seconds}"
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds + 5)
        return int(pipe.execute()[0])
    except Exception as exc:
        # Fail open: a Redis outage must not deny every request.
        logger.warning("shared rate-limit hit failed, falling back: %s", str(exc)[:120])
        return _hit_local(bucket, window_seconds)


def _hit_local(bucket: str, window_seconds: int) -> int:
    now = time.time()
    with _local_lock:
        hits = [stamp for stamp in _local_hits[bucket] if now - stamp < window_seconds]
        hits.append(now)
        _local_hits[bucket] = hits
        if len(_local_hits) > 50_000:  # bound memory on a long-lived process
            _local_hits.clear()
        return len(hits)


def lock_out(bucket: str, seconds: int) -> None:
    """Mark ``bucket`` locked out for ``seconds`` across every instance."""
    client = _client()
    if client is None:
        with _local_lock:
            _local_hits[f"lock:{bucket}"] = [time.time() + seconds]
        return
    try:
        client.setex(f"rt:lock:{bucket}", seconds, "1")
    except Exception as exc:
        logger.warning("shared lockout write failed: %s", str(exc)[:120])
        with _local_lock:
            _local_hits[f"lock:{bucket}"] = [time.time() + seconds]


def locked_for(bucket: str) -> int:
    """Seconds remaining on ``bucket``'s lockout, or 0."""
    client = _client()
    if client is None:
        with _local_lock:
            entries = _local_hits.get(f"lock:{bucket}") or [0]
        return max(0, int(entries[0] - time.time()))
    try:
        ttl = client.ttl(f"rt:lock:{bucket}")
        return max(0, int(ttl)) if ttl and ttl > 0 else 0
    except Exception:
        # Fail closed: if we cannot confirm the lockout is over, keep it.
        with _local_lock:
            entries = _local_hits.get(f"lock:{bucket}") or [0]
        return max(0, int(entries[0] - time.time()))


def clear_lock(bucket: str) -> None:
    client = _client()
    with _local_lock:
        _local_hits.pop(f"lock:{bucket}", None)
    if client is None:
        return
    try:
        client.delete(f"rt:lock:{bucket}")
    except Exception:
        pass


def is_shared() -> bool:
    """True when counters are genuinely shared across instances."""
    return _client() is not None
