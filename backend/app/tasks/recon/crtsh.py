"""Certificate Transparency subdomain enumeration via crt.sh API."""
import requests
import logging
import json

logger = logging.getLogger("recontitan.recon.crtsh")

CRT_SH_URL = "https://crt.sh/"
TIMEOUT = 20

def run_crtsh(target: str) -> list[dict]:
    """
    Queries crt.sh Certificate Transparency logs to enumerate subdomains.
    Returns Finding-compatible dicts.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []

    try:
        resp = requests.get(
            CRT_SH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=TIMEOUT,
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        certs = resp.json()

        # Extract unique subdomains
        subdomains = set()
        for cert in certs:
            name_value = cert.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name and domain in name and name != domain:
                    subdomains.add(name)

        subdomains = sorted(subdomains)

        # Flag sensitive-looking subdomains
        sensitive_keywords = [
            "admin", "dev", "staging", "test", "internal", "vpn",
            "api", "portal", "manage", "dashboard", "backup", "old",
            "beta", "qa", "uat", "corp", "intranet", "jenkins",
            "gitlab", "jira", "confluence", "mail", "smtp",
        ]

        sensitive = [s for s in subdomains
                     if any(kw in s.split(".")[0] for kw in sensitive_keywords)]
        normal = [s for s in subdomains if s not in sensitive]

        # Main finding — all subdomains
        evidence = f"Total subdomains discovered: {len(subdomains)}\n\n"
        if sensitive:
            evidence += "⚠️ Potentially sensitive subdomains:\n"
            evidence += "\n".join(f"  • {s}" for s in sensitive)
            evidence += "\n\nOther subdomains:\n"
        evidence += "\n".join(f"  • {s}" for s in normal[:100])
        if len(normal) > 100:
            evidence += f"\n  ... and {len(normal) - 100} more"

        findings.append({
            "tool":        "crt.sh",
            "category":    "subdomain_enumeration",
            "severity":    "info",
            "title":       f"Subdomains Discovered via crt.sh — {len(subdomains)} found",
            "description": (
                f"Certificate Transparency logs revealed {len(subdomains)} subdomains "
                f"for {domain}. These were obtained from SSL/TLS certificates issued "
                "by public Certificate Authorities and logged publicly."
            ),
            "evidence":    evidence,
        })

        # Separate high-severity finding for sensitive subdomains
        if sensitive:
            findings.append({
                "tool":        "crt.sh",
                "category":    "sensitive_subdomains",
                "severity":    "medium",
                "title":       f"Sensitive Subdomains Exposed — {len(sensitive)} found",
                "description": (
                    f"{len(sensitive)} subdomains with sensitive names (admin, dev, vpn, etc.) "
                    f"were found via certificate transparency logs for {domain}. "
                    "These may expose internal infrastructure or staging environments."
                ),
                "evidence":    "\n".join(f"• {s}" for s in sensitive),
                "remediation": (
                    "Restrict access to these subdomains by IP allowlist or VPN. "
                    "Ensure staging/dev environments do not contain production data."
                ),
            })

        logger.info("[crt.sh] %d subdomains found for %s (%d sensitive)",
                    len(subdomains), domain, len(sensitive))

    except requests.exceptions.Timeout:
        logger.warning("[crt.sh] Timeout for %s", domain)
    except Exception as e:
        logger.warning("[crt.sh] Error for %s: %s", domain, e)

    return findings
