"""
Threat Intel APIs: VirusTotal, Shodan, Censys, GreyNoise.
All have free tiers. API keys read from environment variables.
"""
import requests
import logging
import os

logger = logging.getLogger("recontitan.osint.threat_intel")
TIMEOUT = 15

VT_KEY       = os.getenv("VIRUSTOTAL_API_KEY", "")
SHODAN_KEY   = os.getenv("SHODAN_API_KEY", "")
CENSYS_ID    = os.getenv("CENSYS_API_ID", "")
CENSYS_SEC   = os.getenv("CENSYS_API_SECRET", "")
GN_KEY       = os.getenv("GREYNOISE_API_KEY", "")


def run_virustotal(target: str) -> list[dict]:
    """Query VirusTotal for domain/IP reputation."""
    if not VT_KEY:
        logger.info("[virustotal] No API key — skipping")
        return []
    domain   = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_KEY}, timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return findings
        data       = resp.json().get("data", {})
        attrs      = data.get("attributes", {})
        stats      = attrs.get("last_analysis_stats", {})
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        total      = sum(stats.values())
        reputation = attrs.get("reputation", 0)
        categories = attrs.get("categories", {})

        severity = "info"
        if malicious >= 5:
            severity = "critical"
        elif malicious >= 2:
            severity = "high"
        elif malicious >= 1 or suspicious >= 3:
            severity = "medium"

        evidence = (
            f"Domain     : {domain}\n"
            f"Reputation : {reputation}\n"
            f"Malicious  : {malicious}/{total} vendors\n"
            f"Suspicious : {suspicious}/{total} vendors\n"
            f"Harmless   : {harmless}/{total} vendors\n"
        )
        if categories:
            evidence += f"Categories : {', '.join(set(categories.values()))}\n"

        findings.append({
            "tool": "virustotal", "category": "threat_intelligence",
            "severity": severity,
            "title": f"VirusTotal — {malicious} Malicious Detections for {domain}",
            "description": (
                f"VirusTotal scanned {domain} across {total} security vendors. "
                f"{malicious} flagged it as malicious, {suspicious} as suspicious."
            ),
            "evidence": evidence,
            "remediation": (
                "If flagged, investigate recent changes to the domain. "
                "Request a review from VirusTotal if the result is a false positive."
            ) if malicious > 0 else None,
        })

        # Also check URL scan
        url_resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{requests.utils.quote(f'https://{domain}', safe='')}",
            headers={"x-apikey": VT_KEY}, timeout=TIMEOUT,
        )
        if url_resp.status_code == 200:
            url_stats = url_resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            url_mal = url_stats.get("malicious", 0)
            if url_mal > 0:
                findings.append({
                    "tool": "virustotal", "category": "threat_intelligence",
                    "severity": "high" if url_mal >= 3 else "medium",
                    "title": f"VirusTotal URL Scan — {url_mal} Malicious Detections",
                    "description": f"The URL https://{domain} was flagged by {url_mal} vendors.",
                    "evidence": f"URL malicious detections: {url_mal}/{sum(url_stats.values())}",
                })

    except Exception as e:
        logger.warning("[virustotal] Error for %s: %s", domain, e)
    return findings


def run_shodan(target: str) -> list[dict]:
    """Query Shodan for internet-exposed services."""
    if not SHODAN_KEY:
        logger.info("[shodan] No API key — skipping")
        return []
    import socket
    domain   = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_KEY}, timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return findings
        data  = resp.json()
        ports = data.get("ports", [])
        vulns = data.get("vulns", {})
        org   = data.get("org", "Unknown")
        os_   = data.get("os", "Unknown")
        tags  = data.get("tags", [])

        evidence = (
            f"IP       : {ip}\n"
            f"Org      : {org}\n"
            f"OS       : {os_}\n"
            f"Ports    : {', '.join(str(p) for p in ports)}\n"
            f"Tags     : {', '.join(tags) or 'none'}\n"
            f"CVEs     : {', '.join(vulns.keys()) or 'none'}\n"
        )

        findings.append({
            "tool": "shodan", "category": "internet_exposure",
            "severity": "critical" if vulns else ("high" if len(ports) > 10 else "medium"),
            "title": f"Shodan — {len(ports)} Exposed Services, {len(vulns)} CVEs",
            "description": (
                f"Shodan found {domain} ({ip}) with {len(ports)} exposed services. "
                f"{len(vulns)} known CVEs associated with exposed services."
            ),
            "evidence": evidence,
        })

        for cve_id, cve_data in list(vulns.items())[:10]:
            cvss = cve_data.get("cvss", 0.0) if isinstance(cve_data, dict) else 0.0
            severity = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium"
            findings.append({
                "tool": "shodan", "category": "cve_finding",
                "severity": severity,
                "title": f"CVE Detected via Shodan: {cve_id} (CVSS {cvss})",
                "description": f"Shodan identified {cve_id} on {ip}.",
                "evidence": f"CVE: {cve_id}\nCVSS: {cvss}\nIP: {ip}",
                "cve_id": cve_id, "cvss_score": cvss,
            })

    except Exception as e:
        logger.warning("[shodan] Error: %s", e)
    if any(finding.get("cve_id") for finding in findings):
        from app.tasks.vulnscan.exploit_priority import enrich_cve_findings
        return enrich_cve_findings(findings)
    return findings


def run_greynoise(target: str) -> list[dict]:
    """Query GreyNoise for IP threat context."""
    import socket
    domain   = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []
    try:
        ip = socket.gethostbyname(domain)
        headers = {"Accept": "application/json"}
        if GN_KEY:
            headers["key"] = GN_KEY

        resp = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers=headers, timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return findings
        data = resp.json()
        noise      = data.get("noise", False)
        riot       = data.get("riot", False)
        classif    = data.get("classification", "unknown")
        message    = data.get("message", "")
        name       = data.get("name", "")
        link       = data.get("link", "")

        severity = "info"
        if classif == "malicious":
            severity = "high"
        elif noise and classif != "benign":
            severity = "medium"

        evidence = (
            f"IP             : {ip}\n"
            f"Classification : {classif}\n"
            f"Noise          : {noise} (known internet scanner)\n"
            f"RIOT           : {riot} (known benign service)\n"
            f"Name           : {name or 'unknown'}\n"
            f"Details        : {link or message}\n"
        )

        findings.append({
            "tool": "greynoise", "category": "threat_intelligence",
            "severity": severity,
            "title": f"GreyNoise — IP {ip} Classification: {classif.upper()}",
            "description": (
                f"GreyNoise classifies {ip} as '{classif}'. "
                f"{'This IP is actively scanning the internet.' if noise else ''} "
                f"{'This is a known benign service.' if riot else ''}"
            ),
            "evidence": evidence,
        })
    except Exception as e:
        logger.debug("[greynoise] Error: %s", e)
    return findings


def run_censys(target: str) -> list[dict]:
    """Query Censys for certificate and host exposure data."""
    if not CENSYS_ID or not CENSYS_SEC:
        logger.info("[censys] No credentials — skipping")
        return []
    import socket
    domain   = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []
    try:
        ip = socket.gethostbyname(domain)
        resp = requests.get(
            f"https://search.censys.io/api/v2/hosts/{ip}",
            auth=(CENSYS_ID, CENSYS_SEC), timeout=TIMEOUT,
        )
        if resp.status_code != 200:
            return findings
        result   = resp.json().get("result", {})
        services = result.get("services", [])
        labels   = result.get("labels", [])

        svc_lines = []
        for svc in services:
            port     = svc.get("port", "?")
            protocol = svc.get("transport_protocol", "")
            service  = svc.get("service_name", "unknown")
            svc_lines.append(f"  {port}/{protocol} — {service}")

        evidence = f"IP: {ip}\nLabels: {', '.join(labels) or 'none'}\n\nServices:\n"
        evidence += "\n".join(svc_lines) if svc_lines else "  None found"

        findings.append({
            "tool": "censys", "category": "internet_exposure",
            "severity": "medium" if len(services) > 5 else "info",
            "title": f"Censys — {len(services)} Services Indexed for {ip}",
            "description": (
                f"Censys has indexed {len(services)} services on {ip} ({domain}). "
                "This shows what is visible to internet-wide scanners."
            ),
            "evidence": evidence,
        })
    except Exception as e:
        logger.warning("[censys] Error: %s", e)
    return findings
