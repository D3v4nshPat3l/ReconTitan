"""IP geolocation and ASN lookup via ipinfo.io (free, no key required for basic use)."""
import requests
import socket
import logging

from app.config import settings

logger = logging.getLogger("recontitan.recon.ipinfo")

TIMEOUT = 10

def run_ipinfo(target: str) -> list[dict]:
    """
    Resolves the target to an IP and queries ipinfo.io for geolocation,
    ASN, ISP, and VPN/proxy/hosting detection.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []

    # Resolve domain to IP
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        logger.warning("[ipinfo] Cannot resolve %s: %s", domain, e)
        return findings

    # Query ipinfo.io
    try:
        resp = requests.get(
            f"https://ipinfo.io/{ip}/json",
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        logger.warning("[ipinfo] API error for %s: %s", ip, e)
        return findings

    org      = data.get("org", "Unknown")
    city     = data.get("city", "Unknown")
    region   = data.get("region", "Unknown")
    country  = data.get("country", "Unknown")
    hostname = data.get("hostname", "")
    timezone = data.get("timezone", "")

    evidence = (
        f"IP Address  : {ip}\n"
        f"Hostname    : {hostname or 'N/A'}\n"
        f"Organization: {org}\n"
        f"Location    : {city}, {region}, {country}\n"
        f"Timezone    : {timezone}\n"
    )

    # Detect cloud/hosting providers (shared hosting risk)
    hosting_providers = [
        "amazon", "aws", "google", "azure", "cloudflare", "digitalocean",
        "linode", "vultr", "ovh", "hetzner", "fastly", "akamai",
    ]
    is_cloud = any(p in org.lower() for p in hosting_providers)
    if is_cloud:
        evidence += f"\n✓ Hosted on cloud/CDN infrastructure ({org})"

    findings.append({
        "tool":        "ipinfo.io",
        "category":    "ip_geolocation",
        "severity":    "info",
        "title":       f"IP Geolocation — {ip} ({country})",
        "description": f"IP address and geolocation information for {domain} resolved to {ip}.",
        "evidence":    evidence,
    })

    # Reverse-IP lookup (shared-hosting check) via api.hackertarget.com. This
    # sends the resolved address to a third party, so it is opt-in: the scan
    # authorization an operator holds rarely covers onward disclosure.
    if not settings.ALLOW_HACKERTARGET:
        logger.info("[reverse_ip] skipped (ALLOW_HACKERTARGET=false)")
        return findings

    try:
        rev_resp = requests.get(
            "https://api.hackertarget.com/reverseiplookup/",
            params={"q": ip},
            timeout=TIMEOUT,
        )
        shared_domains = [d.strip() for d in rev_resp.text.strip().split("\n")
                          if d.strip() and "error" not in d.lower() and d.strip() != domain]

        if shared_domains:
            severity = "low" if len(shared_domains) > 5 else "info"
            findings.append({
                "tool":        "hackertarget",
                "category":    "reverse_ip",
                "severity":    severity,
                "title":       f"Reverse IP — {len(shared_domains)} domains share {ip}",
                "description": (
                    f"{len(shared_domains)} other domains are hosted on the same IP ({ip}). "
                    "On shared hosting, a vulnerability in any co-hosted site may affect this target."
                ),
                "evidence":    "\n".join(f"• {d}" for d in shared_domains[:40]),
                "remediation": "Consider dedicated hosting or isolate sensitive applications.",
            })
    except Exception as e:
        logger.debug("[reverse_ip] hackertarget failed: %s", e)

    return findings
