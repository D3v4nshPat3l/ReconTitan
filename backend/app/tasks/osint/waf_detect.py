"""Conservative WAF/CDN detection from a pinned HTTP response."""

from __future__ import annotations

import logging

from app.tasks.http_client import safe_get
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.osint.waf_detect")
TIMEOUT = 12

WAF_HEADERS = {
    "x-sucuri-id": "Sucuri WAF",
    "x-sucuri-cache": "Sucuri CDN",
    "x-firewall-protection": "Generic Firewall",
    "cf-ray": "Cloudflare",
    "x-cache": "CDN/Cache Layer",
    "x-akamai-transformed": "Akamai WAF",
    "x-amz-cf-id": "AWS CloudFront",
    "x-avi-request-id": "Avi Networks WAF",
}


def run_wafw00f(target: str) -> list[dict]:
    """Detect common WAF/CDN signatures without handing DNS to a subprocess."""
    domain = normalize_target(target)
    response = None
    error = None
    for scheme in ("https", "http"):
        try:
            response = safe_get(f"{scheme}://{domain}/", timeout=TIMEOUT, max_bytes=256 * 1024)
            break
        except Exception as exc:
            error = exc
    if response is None:
        logger.warning("[waf] request failed for %s: %s", domain, error)
        return []

    headers = {key.lower(): value for key, value in response.headers.items()}
    detected = sorted({name for header, name in WAF_HEADERS.items() if header in headers})
    if detected:
        evidence = "\n".join(
            f"• {header}: {headers[header][:240]}"
            for header in WAF_HEADERS
            if header in headers
        )
        return [{
            "tool": "waf_detect",
            "category": "waf_detection",
            "severity": "info",
            "title": f"WAF/CDN Detected: {', '.join(detected)}",
            "description": "A WAF or CDN signature was detected in the target response headers.",
            "evidence": evidence,
        }]

    return [{
        "tool": "waf_detect",
        "category": "waf_detection",
        "severity": "low",
        "title": "No Known WAF Header Signature Detected",
        "description": (
            "No known WAF/CDN response-header signature was found. This is not proof that no WAF exists, "
            "because many products hide or customize their headers."
        ),
        "evidence": f"Checked {len(WAF_HEADERS)} header signatures on {response.url}.",
        "remediation": "Evaluate a managed WAF or a hardened reverse proxy where the application's risk profile warrants it.",
    }]
