"""Security-header analysis using the pinned outbound HTTP client."""
from __future__ import annotations

import logging

from app.tasks.http_client import safe_get
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.osint.security_headers")
TIMEOUT = 12

HEADERS_TO_CHECK = {
    "Strict-Transport-Security": ("medium", "Add HSTS after confirming all subdomains support HTTPS."),
    "Content-Security-Policy": ("medium", "Deploy a restrictive Content-Security-Policy."),
    "X-Frame-Options": ("medium", "Set X-Frame-Options: DENY or use CSP frame-ancestors."),
    "X-Content-Type-Options": ("low", "Set X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("low", "Set Referrer-Policy: strict-origin-when-cross-origin."),
    "Permissions-Policy": ("low", "Disable browser capabilities the application does not use."),
}


def _fetch(domain: str):
    try:
        return safe_get(f"https://{domain}/", timeout=TIMEOUT, max_bytes=256 * 1024)
    except Exception as https_error:
        try:
            return safe_get(f"http://{domain}/", timeout=TIMEOUT, max_bytes=256 * 1024)
        except Exception:
            raise https_error


def run_security_headers(target: str) -> list[dict]:
    domain = normalize_target(target)
    findings: list[dict] = []
    try:
        response = _fetch(domain)
    except Exception as exc:
        logger.warning("[sec_headers] failed for %s: %s", domain, exc)
        return findings

    headers = {key.lower(): value for key, value in response.headers.items()}
    for header_name, (severity, remediation) in HEADERS_TO_CHECK.items():
        if header_name.lower() in headers:
            continue
        findings.append({
            "tool": "security_headers",
            "category": "security_headers",
            "severity": severity,
            "title": f"Missing Security Header: {header_name}",
            "description": f"The HTTP response from {response.url} did not include {header_name}.",
            "evidence": f"Response URL: {response.url}\nStatus: {response.status_code}",
            "remediation": remediation,
        })

    xss_header = headers.get("x-xss-protection")
    if xss_header and xss_header.strip() != "0":
        findings.append({
            "tool": "security_headers",
            "category": "security_headers",
            "severity": "low",
            "title": "Legacy X-XSS-Protection Filter Enabled",
            "description": "The deprecated browser XSS filter can create unexpected behavior; modern applications should rely on CSP.",
            "evidence": f"X-XSS-Protection: {xss_header}",
            "remediation": "Set X-XSS-Protection: 0 and deploy a strong Content-Security-Policy.",
        })

    leaks = []
    for header in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "via"):
        if headers.get(header):
            leaks.append(f"{header}: {headers[header][:200]}")
    if leaks:
        findings.append({
            "tool": "security_headers",
            "category": "information_disclosure",
            "severity": "low",
            "title": "Technology Details Disclosed in HTTP Headers",
            "description": "Response headers reveal implementation details useful for targeted vulnerability research.",
            "evidence": "\n".join(leaks),
            "remediation": "Suppress detailed Server, X-Powered-By, and framework version headers.",
        })
    return findings
