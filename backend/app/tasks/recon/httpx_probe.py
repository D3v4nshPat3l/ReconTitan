"""
HTTP probing — tech fingerprinting, title, redirect chain, server info.
Pure requests-based (no binary needed). Covers what httpx does via API.
"""
import re
import logging

from app.tasks.http_client import safe_get
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.recon.httpx_probe")
TIMEOUT = 12

# Technology signatures detected from headers + HTML body
TECH_SIGNATURES = {
    "WordPress":    [r"wp-content/", r"wp-includes/", r"/wp-json/"],
    "Joomla":       [r"/components/com_", r"Joomla"],
    "Drupal":       [r'Drupal\.settings', r"/sites/default/files/"],
    "Laravel":      [r"laravel_session", r"X-Powered-By: PHP"],
    "Django":       [r"csrfmiddlewaretoken", r"django"],
    "React":        [r"__REACT_DEVTOOLS_GLOBAL_HOOK__", r"react-dom"],
    "Next.js":      [r"/_next/static/", r"__NEXT_DATA__"],
    "Angular":      [r"ng-version=", r"/angular"],
    "Vue.js":       [r"__vue_app__", r"Vue.js"],
    "jQuery":       [r'jquery[.\-](\d+\.\d+\.\d+)', r"jQuery v"],
    "Bootstrap":    [r"bootstrap\.min\.(css|js)"],
    "Cloudflare":   [r"Server: cloudflare", r"cf-ray"],
    "Nginx":        [r"Server: nginx"],
    "Apache":       [r"Server: Apache"],
    "PHP":          [r"X-Powered-By: PHP", r"\.php\b"],
    "ASP.NET":      [r"X-Powered-By: ASP\.NET", r"__VIEWSTATE"],
    "IIS":          [r"Server: Microsoft-IIS"],
    "Shopify":      [r"Shopify\.theme", r"cdn\.shopify\.com"],
    "Wix":          [r"wix\.com/", r"X-Wix-Request-Id"],
    "GraphQL":      [r"/__graphql", r"graphql"],
}


def run_httpx_probe(target: str) -> list[dict]:
    """HTTP probe: title, lightweight tech signals, redirects, and banners."""
    domain = normalize_target(target)
    findings: list[dict] = []
    response = None
    https_error = None
    try:
        response = safe_get(f"https://{domain}/", timeout=TIMEOUT, max_bytes=512 * 1024)
    except Exception as exc:
        https_error = exc
        try:
            response = safe_get(f"http://{domain}/", timeout=TIMEOUT, max_bytes=512 * 1024)
            findings.append({
                "tool": "httpx_probe", "category": "ssl_issue", "severity": "high",
                "title": "HTTPS Unavailable — HTTP Fallback Used",
                "description": f"A validated TLS connection to {domain} could not be established.",
                "evidence": f"HTTP fallback URL: {response.url}",
                "remediation": "Install a valid TLS certificate and redirect HTTP to HTTPS.",
            })
        except Exception as exc:
            logger.warning("[httpx] HTTPS and HTTP failed for %s: %s / %s", domain, https_error, exc)
            return findings

    headers = response.headers
    body = response.text[:50_000]
    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    page_title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200] if title_match else "No title found"
    combined = "\n".join([str(headers), body[:10_000]])
    detected_tech = [
        tech for tech, patterns in TECH_SIGNATURES.items()
        if any(re.search(pattern, combined, re.IGNORECASE) for pattern in patterns)
    ]
    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")
    evidence = (
        f"Final URL   : {response.url}\nStatus Code : {response.status_code}\nPage Title  : {page_title}\n"
        f"Server      : {server or 'not disclosed'}\nX-Powered-By: {powered or 'not disclosed'}"
    )
    if detected_tech:
        evidence += "\nTechnologies: " + ", ".join(detected_tech)
    if response.history:
        evidence += "\nRedirects:\n" + "\n".join(response.history)
    findings.append({
        "tool": "httpx_probe", "category": "http_probe", "severity": "info",
        "title": f"HTTP Probe — {domain} ({response.status_code}) | {page_title[:60]}",
        "description": f"Bounded HTTP fingerprinting completed for {domain}.",
        "evidence": evidence,
    })
    return findings
