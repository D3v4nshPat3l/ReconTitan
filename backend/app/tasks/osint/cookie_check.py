"""Cookie security flag analysis for the OSINT phase."""
from __future__ import annotations

import logging
import re

from app.tasks.http_client import safe_get
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.osint.cookie_check")
TIMEOUT = 12


def run_cookie_check(target: str) -> list[dict]:
    domain = normalize_target(target)
    findings: list[dict] = []
    response = None
    for scheme in ("https", "http"):
        try:
            response = safe_get(f"{scheme}://{domain}/", timeout=TIMEOUT, max_bytes=256 * 1024)
            break
        except Exception as exc:
            logger.debug("[cookies] %s failed for %s: %s", scheme, domain, exc)
    if response is None:
        return findings

    raw = response.headers.get("Set-Cookie", "")
    if not raw:
        return [{
            "tool": "cookie_check", "category": "cookie_security", "severity": "info",
            "title": "No Cookies Observed", "description": f"No Set-Cookie header was observed from {domain}.",
            "evidence": f"Response URL: {response.url}",
        }]

    # Header dictionaries may combine multiple Set-Cookie fields. Split only at
    # commas that look like the beginning of another name=value pair, preserving
    # commas inside Expires dates.
    cookie_headers = re.split(r",\s*(?=[!#$%&'*+.^_`|~0-9A-Za-z-]+=)", raw)
    issues: list[str] = []
    for cookie in cookie_headers:
        name = cookie.split("=", 1)[0].strip()[:100] or "unnamed"
        lower = cookie.lower()
        missing = []
        if response.url.startswith("https://") and "; secure" not in lower:
            missing.append("Secure")
        if "; httponly" not in lower:
            missing.append("HttpOnly")
        if "; samesite=" not in lower:
            missing.append("SameSite")
        if missing:
            issues.append(f"{name}: missing {', '.join(missing)}")

    if not issues:
        return [{
            "tool": "cookie_check", "category": "cookie_security", "severity": "info",
            "title": "Observed Cookies Include Recommended Flags",
            "description": "Every observed cookie included the expected security attributes.",
            "evidence": f"Analyzed {len(cookie_headers)} Set-Cookie value(s).",
        }]
    return [{
        "tool": "cookie_check", "category": "cookie_security", "severity": "medium",
        "title": f"Cookie Security Attributes Missing — {len(issues)} affected",
        "description": "Session cookies without Secure, HttpOnly, or SameSite protections increase session theft and CSRF risk.",
        "evidence": "\n".join(issues),
        "remediation": "Set sensitive cookies with Secure; HttpOnly; SameSite=Lax or Strict, as appropriate.",
    }]
