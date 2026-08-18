"""Admin ASGI application — separate from the public API by construction.

This is a *different application object* from ``app.main:app``, served by its
own process on its own port. That separation is the point: the public app has
no admin routes to reach, so no bug in public routing, no path-traversal trick,
and no proxy misconfiguration can expose admin through the public origin.

It is served bound to loopback and published only to host loopback, so the
intended access path is an SSH tunnel:

    ssh -N -L 9000:127.0.0.1:9000 root@your-server

then browse http://127.0.0.1:9000/admin/ on your own machine.

Step 2 provides authentication and isolation only. The dashboard views land in
step 3 and mount behind :func:`require_admin`.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.admin import auth
from app.admin.deps import (
    ADMIN_LOCKED_OUT, ADMIN_LOGIN_FAILED, ADMIN_LOGIN_OK, require_admin,
)
from app.config import settings
from app.admin.api import router as admin_api_router
from app.services import audit

logger = logging.getLogger("recontitan.admin")

def create_admin_app() -> FastAPI:
    """Build the admin app, refusing to start if it would be unprotected."""
    auth.assert_safely_configured()

    admin_app = FastAPI(
        title="ReconTitan Admin",
        version=settings.APP_VERSION,
        # No interactive docs on an administrative surface: they describe every
        # route and parameter to anyone who reaches the port.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    @admin_app.middleware("http")
    async def _harden(request: Request, call_next):
        response = await call_next(request)
        # An admin page must never be embedded, sniffed, cached, or allowed to
        # load third-party content.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'; "
            "object-src 'none'"
        )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if "server" in response.headers:
            del response.headers["server"]
        return response

    @admin_app.get("/admin/health")
    def health():
        """Unauthenticated liveness only. Reveals nothing about the system."""
        return {"status": "ok"}

    @admin_app.get("/admin/api/session")
    def session(source: str = Depends(require_admin)):
        """Confirms a token is valid. Used by the step 3 dashboard to log in."""
        return {
            "authenticated": True,
            "source": source,
            "server_time": datetime.now(timezone.utc),
            "version": settings.APP_VERSION,
        }

    # Console assets are served from /admin/static so the CSP's
    # "default-src 'self'" already covers them without being widened.
    static_dir = settings.FRONTEND_DIR
    if static_dir.is_dir():
        admin_app.mount("/admin/static", StaticFiles(directory=str(static_dir)), name="admin-static")

        @admin_app.get("/admin", include_in_schema=False)
        @admin_app.get("/admin/", include_in_schema=False)
        def console():
            """The console shell only. It authenticates client-side and then
            calls the protected API, so the page itself carries no data."""
            return FileResponse(str(static_dir / "admin.html"), headers={"Cache-Control": "no-store"})

    admin_app.include_router(admin_api_router)

    @admin_app.exception_handler(HTTPException)
    async def _generic_errors(request: Request, exc: HTTPException):
        # Admin errors carry no detail that could help someone map the surface.
        status = exc.status_code
        body = {"error": auth.GENERIC_DENIAL if status in (401, 403, 429) else "Request failed"}
        return JSONResponse(status_code=status, content=body, headers=getattr(exc, "headers", None))

    logger.info("Admin surface ready on loopback port %s", settings.ADMIN_PORT)
    return admin_app


# Only built when explicitly enabled, so importing this module in the public
# process can never accidentally create an admin app.
admin_app = create_admin_app() if settings.ADMIN_ENABLED else None
