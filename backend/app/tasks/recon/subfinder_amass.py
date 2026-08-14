"""
Subfinder + Amass subprocess wrappers for subdomain enumeration.
Both are Go binaries. Falls back gracefully if not installed.
"""
import subprocess
import shutil
import logging

logger = logging.getLogger("recontitan.recon.subfinder_amass")


def _run_binary(cmd: list, timeout: int = 120) -> str:
    """Run a binary and return stdout. Returns '' if binary not found."""
    binary = cmd[0]
    if not shutil.which(binary):
        logger.info("[subfinder_amass] %s not installed — skipping", binary)
        return ""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        logger.warning("[subfinder_amass] %s timed out", binary)
        return ""
    except Exception as e:
        logger.warning("[subfinder_amass] %s error: %s", binary, e)
        return ""


def run_subfinder(target: str) -> list[dict]:
    """Run subfinder for passive subdomain enumeration."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []

    raw = _run_binary(["subfinder", "-d", domain, "-silent"], timeout=120)
    if not raw:
        return findings

    subdomains = sorted(set(s.strip() for s in raw.splitlines() if s.strip()))
    sensitive_kw = ["admin","dev","staging","vpn","portal","api","internal","test","qa","uat","mail","smtp","git","jenkins","jira"]
    sensitive = [s for s in subdomains if any(kw in s.split(".")[0] for kw in sensitive_kw)]

    findings.append({
        "tool": "subfinder", "category": "subdomain_enumeration",
        "severity": "info",
        "title": f"Subfinder — {len(subdomains)} Subdomains Found",
        "description": f"Passive subdomain enumeration via 50+ sources found {len(subdomains)} subdomains for {domain}.",
        "evidence": "\n".join(f"• {s}" for s in subdomains[:100]),
    })

    if sensitive:
        findings.append({
            "tool": "subfinder", "category": "sensitive_subdomains",
            "severity": "medium",
            "title": f"Subfinder — {len(sensitive)} Sensitive Subdomains",
            "description": "Sensitive-named subdomains discovered (admin, dev, vpn, etc.).",
            "evidence": "\n".join(f"• {s}" for s in sensitive),
            "remediation": "Restrict access to sensitive subdomains via firewall/VPN.",
        })

    return findings


def run_amass(target: str) -> list[dict]:
    """Run amass passive enumeration."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []

    raw = _run_binary(["amass", "enum", "-passive", "-d", domain], timeout=180)
    if not raw:
        return findings

    subdomains = sorted(set(s.strip() for s in raw.splitlines() if domain in s))

    findings.append({
        "tool": "amass", "category": "subdomain_enumeration",
        "severity": "info",
        "title": f"Amass — {len(subdomains)} Subdomains Found",
        "description": f"Amass passive enumeration found {len(subdomains)} subdomains for {domain}.",
        "evidence": "\n".join(f"• {s}" for s in subdomains[:100]),
    })

    return findings
