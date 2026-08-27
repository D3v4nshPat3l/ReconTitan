"""Wayback Machine archive history lookup for ReconTitan."""
import requests
import logging
from urllib.parse import quote

logger = logging.getLogger("recontitan.recon.wayback")

# web.archive.org is frequently unreachable, and a 15s connect timeout
# spent a quarter of the serverless request budget waiting to find out.
TIMEOUT = 5

def run_wayback(target: str) -> list[dict]:
    """
    Queries the Wayback Machine CDX API to discover historical URLs.
    Free, no API key required.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []

    # 1. Check if the domain has been archived
    try:
        avail_resp = requests.get(
            "https://archive.org/wayback/available",
            params={"url": domain},
            timeout=TIMEOUT,
        )
        avail_data = avail_resp.json()
        snapshot = avail_data.get("archived_snapshots", {}).get("closest", {})
        snapshot_url = snapshot.get("url", "")
        snapshot_ts  = snapshot.get("timestamp", "")
    except Exception as e:
        logger.warning("[wayback] Availability check failed: %s", e)
        snapshot_url = ""
        snapshot_ts  = ""

    # 2. Get historical URLs via CDX API (max 200)
    historical_urls = []
    try:
        cdx_resp = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={
                "url":      f"*.{domain}/*",
                "output":   "json",
                "fl":       "original,timestamp,statuscode",
                "collapse": "urlkey",
                "limit":    200,
            },
            timeout=TIMEOUT,
        )
        rows = cdx_resp.json()
        # First row is header
        if rows and len(rows) > 1:
            historical_urls = rows[1:]
    except Exception as e:
        logger.warning("[wayback] CDX query failed: %s", e)

    if not snapshot_url and not historical_urls:
        logger.info("[wayback] No archive data found for %s", domain)
        return findings

    # Build evidence
    evidence_lines = []
    if snapshot_url:
        evidence_lines.append(f"Latest snapshot : {snapshot_url}")
        evidence_lines.append(f"Snapshot date   : {snapshot_ts[:8] if snapshot_ts else 'unknown'}")
        evidence_lines.append(f"Total archived URLs: {len(historical_urls)}")
        evidence_lines.append("")

    # Find interesting historical paths
    interesting_keywords = [
        "admin", "backup", "config", "login", "password", "secret",
        "api", "upload", "install", "setup", "debug", "test", ".env",
        "phpinfo", ".git", "wp-", "xmlrpc",
    ]
    interesting_urls = []
    if historical_urls:
        evidence_lines.append("Sample historical URLs (newest first):")
        for row in historical_urls[:50]:
            url, ts, status = row[0], row[1], row[2] if len(row) > 2 else ""
            evidence_lines.append(f"  [{status}] {url}")
            if any(kw in url.lower() for kw in interesting_keywords):
                interesting_urls.append(url)

    findings.append({
        "tool":        "wayback_machine",
        "category":    "archive_history",
        "severity":    "info",
        "title":       f"Wayback Machine Archive — {len(historical_urls)} URLs found",
        "description": (
            f"The Internet Archive has {len(historical_urls)} historical snapshots "
            f"of {domain}. Old/removed pages may still be accessible via archive.org "
            "and can reveal sensitive historical content."
        ),
        "evidence":    "\n".join(evidence_lines),
    })

    if interesting_urls:
        findings.append({
            "tool":        "wayback_machine",
            "category":    "sensitive_historical_urls",
            "severity":    "medium",
            "title":       f"Sensitive Historical Paths in Archive — {len(interesting_urls)} found",
            "description": (
                f"{len(interesting_urls)} URLs with sensitive-sounding paths were found "
                "in the Wayback Machine archive. These may have contained credentials, "
                "configuration files, or admin interfaces."
            ),
            "evidence":    "\n".join(f"• {u}" for u in interesting_urls[:30]),
            "remediation": (
                "Review these archived URLs. If they contained sensitive data, "
                "submit an exclusion request to archive.org."
            ),
        })

    logger.info("[wayback] %d URLs, %d interesting for %s",
                len(historical_urls), len(interesting_urls), domain)
    return findings
