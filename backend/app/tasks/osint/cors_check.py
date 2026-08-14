"""CORS misconfiguration detection for the OSINT phase."""
from __future__ import annotations

import logging

from app.tasks.http_client import safe_options
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.osint.cors_check")
TIMEOUT = 10
TEST_ORIGINS = ("https://evil.example", "null", "https://subdomain.{domain}")


def run_cors_check(target: str) -> list[dict]:
    domain = normalize_target(target)
    base_url = f"https://{domain}/"
    findings: list[dict] = []
    vulnerabilities: list[dict] = []

    for origin_template in TEST_ORIGINS:
        origin = origin_template.replace("{domain}", domain)
        try:
            response = safe_options(
                base_url,
                timeout=TIMEOUT,
                max_bytes=64 * 1024,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "authorization,content-type",
                },
            )
            acao = response.headers.get("Access-Control-Allow-Origin", "").strip()
            acac = response.headers.get("Access-Control-Allow-Credentials", "").strip().lower()
            if acao not in {origin, "*"}:
                continue
            credentials = acac == "true"
            vulnerabilities.append({"origin": origin, "acao": acao, "credentials": credentials})
            severity = "high" if acao == origin and credentials else "medium"
            findings.append({
                "tool": "cors_check",
                "category": "cors_misconfiguration",
                "severity": severity,
                "title": f"CORS Policy Accepts Untrusted Origin — {origin}",
                "description": (
                    "The preflight response allows an untrusted Origin. "
                    + ("Credentials are also enabled, allowing authenticated cross-origin reads." if credentials else "Cross-origin reads may be possible for exposed resources.")
                ),
                "evidence": (
                    f"Request Origin: {origin}\n"
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac or 'not set'}\n"
                    f"HTTP status: {response.status_code}"
                ),
                "remediation": "Use an exact allowlist of trusted origins and never reflect arbitrary Origin values.",
            })
        except Exception as exc:
            logger.debug("[cors] %s failed for %s: %s", origin, domain, exc)

    if not vulnerabilities:
        findings.append({
            "tool": "cors_check",
            "category": "cors_misconfiguration",
            "severity": "info",
            "title": "CORS Policy: No Obvious Reflection Detected",
            "description": "The tested untrusted origins were not allowed by the preflight response.",
            "evidence": f"Tested {len(TEST_ORIGINS)} untrusted origins.",
        })
    return findings
