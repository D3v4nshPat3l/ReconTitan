"""Admin request authentication, shared by the app and its routers.

This lives apart from ``app.admin.main`` on purpose. The router module needs
``require_admin`` as a dependency, and the app module needs the router; putting
the dependency in either one makes the pair circular, and the failure only
appears when something imports the router first, which is exactly what a test
or a script tends to do.
"""

from __future__ import annotations

import ipaddress
import logging

from fastapi import HTTPException, Request

from app.admin import auth
from app.config import settings
from app.services import audit

logger = logging.getLogger("recontitan.admin")

ADMIN_LOGIN_FAILED = "admin.login_failed"
ADMIN_LOGIN_OK = "admin.login_ok"
ADMIN_LOCKED_OUT = "admin.locked_out"
ADMIN_IP_REFUSED = "admin.ip_refused"


def ip_allowed(source: str) -> bool:
    """Is this source permitted to reach the admin surface at all?

    An empty allowlist means unrestricted. Once set, anything that cannot be
    parsed as an address is refused: the intended access path is an SSH tunnel
    or a known egress range, and "I could not tell who this is" is not a reason
    to let someone through a control whose whole purpose is to say who may
    knock.
    """
    allowlist = settings.ADMIN_IP_ALLOWLIST
    if not allowlist:
        return True
    try:
        address = ipaddress.ip_address(source.strip())
    except ValueError:
        return False
    for entry in allowlist:
        try:
            if address in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            logger.warning("[admin] ignoring malformed ADMIN_IP_ALLOWLIST entry: %s", entry[:40])
    return False


def require_admin(request: Request) -> str:
    """Authenticate an admin request or refuse it.

    Every outcome is audited. An attack on the admin surface should be the
    most visible thing in the trail, not the quietest.
    """
    source = audit.client_ip(request)

    # Checked first, and deliberately before the lockout counter: a source that
    # is not allowed to be here should not be able to consume another source's
    # attempt budget, and should learn nothing about whether a token was close.
    if not ip_allowed(source):
        audit.record_security_event(ADMIN_IP_REFUSED, request, detail="not in ADMIN_IP_ALLOWLIST")
        logger.warning("[admin] refused %s: outside the allowlist", source)
        raise HTTPException(status_code=403, detail=auth.GENERIC_DENIAL)

    remaining = auth.lockout_remaining(source)
    if remaining > 0:
        audit.record_security_event(ADMIN_LOCKED_OUT, request, detail=f"{remaining:.0f}s left")
        raise HTTPException(
            status_code=429,
            detail=auth.GENERIC_DENIAL,
            headers={"Retry-After": str(int(remaining) + 1)},
        )

    supplied = request.headers.get(auth.ADMIN_HEADER, "")
    if not auth.token_matches(supplied):
        lockout = auth.register_failure(source)
        audit.record_security_event(
            ADMIN_LOGIN_FAILED, request,
            detail="locked out" if lockout > 0 else "bad token",
        )
        logger.warning("[admin] failed authentication from %s", source)
        # Identical response for missing, malformed, and wrong tokens.
        raise HTTPException(status_code=401, detail=auth.GENERIC_DENIAL)

    auth.reset(source)
    return source
