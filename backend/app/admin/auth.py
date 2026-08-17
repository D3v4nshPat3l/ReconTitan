"""Admin authentication: fail-closed token check with lockout.

This is the *innermost* layer of the admin defence, not the only one. The
outer layers are structural:

1. the admin app is never proxied by nginx, so it has no public route;
2. its port is published to host loopback only, so reaching it requires an
   SSH tunnel or a shell on the host;
3. it runs on a Docker network the scanner containers are not attached to, so
   a target-validation bypass in the scanner cannot route to it.

This module covers what survives all three: someone who already has a shell on
the host, or a tunnel they should not have. Token comparison is constant time,
failures are locked out per source, and every attempt is written to the audit
trail from step 1 so an attack on admin is visible rather than silent.

Authentication is header-based rather than cookie-based on purpose: a request
that carries no ambient credential cannot be driven by a cross-site request, so
the whole CSRF class is structurally absent rather than mitigated.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from dataclasses import dataclass, field

from app.config import settings

logger = logging.getLogger("recontitan.admin.auth")

ADMIN_HEADER = "x-recontitan-admin"

#: Deliberately identical for every failure mode. A caller must not be able to
#: distinguish "no token", "wrong token", or "admin misconfigured".
GENERIC_DENIAL = "Unauthorized"


class AdminDisabled(RuntimeError):
    """Raised at startup when the admin surface is not safely configured."""


@dataclass
class _Attempts:
    count: int = 0
    locked_until: float = 0.0
    first_seen: float = field(default_factory=time.monotonic)


_lock = threading.Lock()
_failures: dict[str, _Attempts] = {}


def token_is_configured() -> bool:
    """True only when a token long enough to resist guessing is present."""
    return len(settings.ADMIN_TOKEN) >= settings.ADMIN_MIN_TOKEN_LENGTH


def assert_safely_configured() -> None:
    """Fail closed at startup rather than serving an unprotected admin app.

    A short or missing token must stop the process, not degrade to open
    access. This runs before the app binds a port.
    """
    if not settings.ADMIN_ENABLED:
        raise AdminDisabled(
            "Admin surface is disabled. Set ADMIN_ENABLED=true and ADMIN_TOKEN to enable it."
        )
    if not token_is_configured():
        raise AdminDisabled(
            f"ADMIN_TOKEN must be at least {settings.ADMIN_MIN_TOKEN_LENGTH} characters. "
            "Generate one with: python3 -c 'import secrets; print(secrets.token_urlsafe(48))'"
        )


def _prune(now: float) -> None:
    """Drop expired records so the table cannot grow without bound."""
    stale = [
        key for key, record in _failures.items()
        if record.locked_until < now and now - record.first_seen > settings.ADMIN_LOCKOUT_SECONDS
    ]
    for key in stale:
        _failures.pop(key, None)


def lockout_remaining(source: str) -> float:
    """Seconds left on an active lockout for ``source``; 0 when not locked."""
    with _lock:
        record = _failures.get(source)
        if record is None:
            return 0.0
        return max(0.0, record.locked_until - time.monotonic())


def register_failure(source: str) -> float:
    """Count a failed attempt and return the lockout now in force."""
    with _lock:
        now = time.monotonic()
        _prune(now)
        if len(_failures) > 10_000:  # hard ceiling against memory pressure
            _failures.clear()
        record = _failures.setdefault(source, _Attempts())
        record.count += 1
        if record.count >= settings.ADMIN_MAX_FAILURES:
            # Escalating: repeated rounds of failures lock out for longer.
            rounds = record.count // max(1, settings.ADMIN_MAX_FAILURES)
            record.locked_until = now + settings.ADMIN_LOCKOUT_SECONDS * min(rounds, 8)
        return max(0.0, record.locked_until - now)


def reset(source: str) -> None:
    """Clear the failure record after a successful authentication."""
    with _lock:
        _failures.pop(source, None)


def clear_all() -> None:
    """Test hook."""
    with _lock:
        _failures.clear()


def token_matches(supplied: str | None) -> bool:
    """Constant-time token comparison that fails closed when misconfigured."""
    if not token_is_configured():
        return False
    if not supplied:
        return False
    return secrets.compare_digest(supplied.strip(), settings.ADMIN_TOKEN)
