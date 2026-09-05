"""
ReconTitan — FastAPI Application Entry Point (Hardened)

Security-first architecture:
  1. SecurityMiddleware — rate limiting, anti-injection, security headers
  2. TrustedHostMiddleware — host header validation
  3. CORS — locked to required origins only
  4. No /docs or /redoc in production
  5. Global exception handler — never leak stack traces
"""

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
import traceback

from app.config import settings
from app.database import close_db
from app.middleware.security import SecurityMiddleware


# ── Logging ──
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-28s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("recontitan")


# ── Lifecycle ──
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown hooks."""
    settings.validate_production()
    logger.info("=" * 60)
    logger.info(f"  {settings.APP_NAME} {settings.APP_VERSION}")
    logger.info(f"  Debug: {settings.DEBUG}")
    logger.info(f"  Security middleware: ACTIVE")
    logger.info(f"  Rate limiting: ACTIVE")
    logger.info(f"  Anti-injection: ACTIVE")
    logger.info("=" * 60)
    yield
    close_db()
    logger.info("ReconTitan shutdown complete.")


# ── App Factory ──
# In production: disable docs endpoints
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="All-in-one OSINT & Web Vulnerability Scanner",
    lifespan=lifespan,
    docs_url="/api/docs" if settings.DEBUG else None,
    redoc_url="/api/redoc" if settings.DEBUG else None,
    openapi_url="/api/openapi.json" if settings.DEBUG else None,
)


# ── MIDDLEWARE STACK (last added = outermost in Starlette) ──

# 1. Trusted hosts — reject host-header abuse before routing.
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.TRUSTED_HOSTS,
)

# 2. CORS — explicit origins and only the methods/headers the browser uses.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=settings.CORS_ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-ReconTitan-Key"],
)

# 3. Security middleware is added last so it wraps TrustedHost and CORS responses.
app.add_middleware(SecurityMiddleware)


# ── Global Exception Handler — never leak stack traces ──
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch all unhandled exceptions. Log full trace, return sanitized response."""
    # The traceback goes to the server log unconditionally. It used to be gated
    # on DEBUG, which meant production -- the only place these are hard to
    # reproduce -- logged one line with no file, no line number and no stack.
    # The response below is what stays sanitized; the log is not user-facing.
    logger.error(
        "[UNHANDLED] %s %s — %s: %s\n%s",
        request.method,
        request.url.path,
        type(exc).__name__,
        str(exc),
        traceback.format_exc(),
    )
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error. This has been logged."},
    )


@app.exception_handler(404)
async def not_found_handler(request: Request, exc):
    """Custom 404 — don't reveal path structure."""
    if request.url.path.startswith("/api/"):
        return JSONResponse(
            status_code=404,
            content={"error": "Endpoint not found"},
        )
    # For frontend routes, let the SPA handle it
    return JSONResponse(status_code=404, content={"error": "Not found"})


@app.exception_handler(405)
async def method_not_allowed_handler(request: Request, exc):
    return JSONResponse(
        status_code=405,
        content={"error": "Method not allowed"},
    )


# ── Routers ──
from app.routers import ai, capabilities, news, reports, scans, test_scan, triage

app.include_router(capabilities.router)
app.include_router(ai.router)
app.include_router(scans.router)
app.include_router(reports.router)
app.include_router(news.router)
app.include_router(test_scan.router)
app.include_router(triage.router)

# On a server deployment the admin console is a separate ASGI app on its own
# loopback-only port, which is what makes it unreachable from the internet.
# A serverless platform gives one entry point and no private networking, so
# there is nowhere else for it to live: mount it here instead. This is a real
# reduction in isolation -- the console becomes publicly routed and defended by
# its token alone -- and it is deliberately confined to the serverless case so
# the stronger separation is never quietly given up on a VPS.
if settings.SERVERLESS and settings.ADMIN_ENABLED:
    from app.admin.main import create_admin_app

    app.mount("/admin", create_admin_app(), name="admin-console")
    logger.warning(
        "Admin console mounted on the public origin (serverless mode). "
        "It is protected by ADMIN_TOKEN only; there is no network isolation here."
    )


# ── Health Check ──
@app.get("/api/health", tags=["system"])
async def health_check():
    """Health check — minimal info, no version leakage in production."""
    resp = {"status": "healthy"}
    if settings.DEBUG:
        resp["app"] = settings.APP_NAME
        resp["version"] = settings.APP_VERSION
    return resp


# ── Frontend Static Files ──
class RevalidatingStaticFiles(StaticFiles):
    """StaticFiles that makes the browser check before reusing a cached asset.

    Without this, a browser may hold a heuristically-cached copy of report.js
    indefinitely and never ask whether it changed. That produced a genuinely
    confusing failure: the page kept rendering a fixed-and-redeployed card
    from a stale script, so the bug looked unfixed on a server serving correct
    code.

    "no-cache" does not mean "do not cache" — it means "revalidate first".
    The browser still keeps the file and still gets a 304 from the ETag
    StaticFiles already sends, so the cost is one conditional request per
    asset, not a re-download.

    The ?v= stamps in the HTML remain valid and harmless; this just means
    forgetting to bump one is no longer a silent failure.
    """

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers.setdefault("Cache-Control", "no-cache")
        return response


# MUST be the last mount — catches all unmatched routes.
app.mount(
    "/",
    RevalidatingStaticFiles(directory=str(settings.FRONTEND_DIR), html=True),
    name="frontend",
)


# ── Entry Point ──
# Run with: python -m app.main  OR  double-click start.bat
# The --no-server-header flag is baked in here so you never need to remember it.
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=8000,
        server_header=False,   # ← hides "uvicorn" from Server header
        date_header=False,     # ← hides Date header (info leak)
        reload=settings.DEBUG,
    )
