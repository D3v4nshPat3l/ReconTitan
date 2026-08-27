"""Deployment preflight: check a configuration before it reaches production.

Run it against the environment you are about to deploy with:

    python -m app.preflight

Every gap this reports is one that would otherwise surface as silence rather
than an error — MongoDB missing means the console renders "unavailable" and
audit writes are dropped fail-soft; Redis missing means rate limits multiply by
instance count with nothing logged; a missing NVD key turns 403s into what look
like clean CVE results. None of those raise, which is exactly why they need a
deliberate check.

Exit code is 1 if anything BLOCKING failed, so CI can gate on it.
"""

from __future__ import annotations

import os
import sys

from app.config import settings

BLOCK = "BLOCK"
WARN = "WARN"
OK = "OK"


def _row(level: str, name: str, detail: str) -> tuple[str, str, str]:
    return (level, name, detail)


def _check_secrets() -> list[tuple[str, str, str]]:
    out = []
    if settings.DEBUG:
        out.append(_row(WARN, "RECONTITAN_DEBUG", "true — /api/docs is public and errors carry detail"))
    else:
        out.append(_row(OK, "RECONTITAN_DEBUG", "false"))

    try:
        settings.validate_production()
        out.append(_row(OK, "production config", "secrets, CORS, and domain accepted"))
    except RuntimeError as exc:
        for part in str(exc).replace("Unsafe production configuration: ", "").split("; "):
            out.append(_row(BLOCK, "production config", part))
    return out


def _check_storage() -> list[tuple[str, str, str]]:
    out = []
    uri = settings.MONGO_URI
    local = "localhost" in uri or "127.0.0.1" in uri

    if settings.SERVERLESS and local:
        out.append(_row(
            BLOCK, "MongoDB",
            "points at localhost, which does not exist in a serverless function. "
            "Set MONGO_URI to your Atlas connection string.",
        ))
    else:
        out.append(_row(OK, "MongoDB", f"scheme {uri.split('://', 1)[0]}://, {'local' if local else 'remote'}"))

    try:
        from app.database import get_db

        out.append(_row(OK if get_db() is not None else WARN, "MongoDB reachable",
                        "connected" if get_db() is not None else "not reachable from here"))
    except Exception as exc:
        out.append(_row(WARN, "MongoDB reachable", f"{type(exc).__name__}: {str(exc)[:60]}"))

    if settings.SHARED_STATE_ENABLED:
        out.append(_row(OK, "Shared state", "Redis configured; limits are shared across instances"))
    elif settings.SERVERLESS:
        out.append(_row(
            WARN, "Shared state",
            "no Redis. Rate limits and admin lockout become per-instance, so a "
            "limit of 5 effectively becomes 5 x instance count. Set REDIS_URL.",
        ))
    else:
        out.append(_row(OK, "Shared state", "single node; in-process counters are correct here"))
    return out


def _check_attribution() -> list[tuple[str, str, str]]:
    out = []
    if settings.SERVERLESS and not settings.TRUST_PROXY_HEADERS:
        out.append(_row(
            WARN, "Client IPs",
            "TRUST_PROXY_HEADERS is off under SERVERLESS; every visitor will be "
            "recorded as the platform proxy.",
        ))
    elif settings.TRUST_PROXY_HEADERS and not settings.SERVERLESS:
        out.append(_row(
            WARN, "Client IPs",
            "TRUST_PROXY_HEADERS is on outside SERVERLESS. Only correct if "
            "something in front always overwrites X-Forwarded-For, otherwise a "
            "client can forge its own source address.",
        ))
    else:
        out.append(_row(OK, "Client IPs", f"TRUST_PROXY_HEADERS={settings.TRUST_PROXY_HEADERS}"))

    out.append(_row(OK if settings.AUDIT_ENABLED else WARN, "Audit trail",
                    "enabled" if settings.AUDIT_ENABLED else "disabled; nothing is attributable"))
    return out


def _check_admin() -> list[tuple[str, str, str]]:
    out = []
    if not settings.ADMIN_ENABLED:
        out.append(_row(OK, "Admin console", "disabled"))
        return out

    if len(settings.ADMIN_TOKEN) < settings.ADMIN_MIN_TOKEN_LENGTH:
        out.append(_row(BLOCK, "ADMIN_TOKEN", f"shorter than {settings.ADMIN_MIN_TOKEN_LENGTH} characters"))
    else:
        out.append(_row(OK, "ADMIN_TOKEN", f"{len(settings.ADMIN_TOKEN)} characters"))

    if settings.ADMIN_TOKEN_PREVIOUS:
        out.append(_row(WARN, "Token rotation", "ADMIN_TOKEN_PREVIOUS is still accepted; clear it once nothing uses it"))

    if settings.SERVERLESS:
        if settings.ADMIN_IP_ALLOWLIST:
            out.append(_row(OK, "Admin exposure",
                            f"public origin, restricted to {len(settings.ADMIN_IP_ALLOWLIST)} network(s)"))
        else:
            out.append(_row(
                WARN, "Admin exposure",
                "mounted on the public origin with no ADMIN_IP_ALLOWLIST. The "
                "token is the only control; anyone who finds /admin may try it.",
            ))
    else:
        out.append(_row(OK, "Admin exposure", "separate process, bind to loopback and reach it over SSH"))
    return out


def _check_scanning() -> list[tuple[str, str, str]]:
    out = []
    out.append(_row(
        WARN if settings.ALLOW_DANGER_MODE else OK, "Danger Mode",
        "ENABLED — active penetration-test traffic is one typed phrase away"
        if settings.ALLOW_DANGER_MODE else "disabled",
    ))
    out.append(_row(
        WARN if settings.ALLOW_HACKERTARGET else OK, "Third-party lookups",
        "api.hackertarget.com will receive target addresses"
        if settings.ALLOW_HACKERTARGET else "hackertarget disabled",
    ))
    out.append(_row(
        OK if settings.NVD_API_KEY else WARN, "NVD_API_KEY",
        "set" if settings.NVD_API_KEY else
        "absent. Rate-limited 403s are indistinguishable from 'no CVEs found'.",
    ))

    if settings.AI_PROVIDER == "openai" and settings.OPENAI_API_KEY:
        out.append(_row(WARN, "AI provider", "openai — finding text leaves your infrastructure"))
    else:
        out.append(_row(OK, "AI provider", f"{settings.AI_PROVIDER}; findings stay local"))
    return out


def run() -> int:
    groups = [
        ("Secrets and exposure", _check_secrets()),
        ("Storage", _check_storage()),
        ("Attribution", _check_attribution()),
        ("Admin console", _check_admin()),
        ("Scanning behaviour", _check_scanning()),
    ]

    blocking = warnings = 0
    print(f"\nReconTitan preflight — {'SERVERLESS' if settings.SERVERLESS else 'server'} deployment\n")
    for title, rows in groups:
        print(f"  {title}")
        for level, name, detail in rows:
            blocking += level == BLOCK
            warnings += level == WARN
            mark = {OK: "  ok ", WARN: " warn", BLOCK: "BLOCK"}[level]
            print(f"    [{mark}] {name:22} {detail}")
        print()

    if blocking:
        print(f"  {blocking} blocking issue(s), {warnings} warning(s). Not ready to deploy.\n")
    elif warnings:
        print(f"  No blocking issues. {warnings} warning(s) — read them, then deploy.\n")
    else:
        print("  All checks passed.\n")
    return 1 if blocking else 0


if __name__ == "__main__":
    sys.exit(run())
