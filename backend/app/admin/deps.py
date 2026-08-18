"""Admin request authentication, shared by the app and its routers.

This lives apart from ``app.admin.main`` on purpose. The router module needs
``require_admin`` as a dependency, and the app module needs the router; putting
the dependency in either one makes the pair circular, and the failure only
appears when something imports the router first, which is exactly what a test
or a script tends to do.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request

from app.admin import auth
from app.services import audit

logger = logging.getLogger("recontitan.admin")

ADMIN_LOGIN_FAILED = "admin.login_failed"
ADMIN_LOGIN_OK = "admin.login_ok"
ADMIN_LOCKED_OUT = "admin.locked_out"


def require_admin(request: Request) -> str:
    """Authenticate an admin request or refuse it.

    Every outcome is audited. An attack on the admin surface should be the
    most visible thing in the trail, not the quietest.
    """
    source = audit.client_ip(request)

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
