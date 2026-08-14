"""Bounded port scanning against a prevalidated, pinned public IP address."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess

import requests

from app.config import settings
from app.targeting import resolve_target_addresses, validate_scan_target

logger = logging.getLogger("recontitan.recon.port_scan")
TIMEOUT = 30

DANGEROUS_PORTS = {
    21: ("FTP — unencrypted file transfer", "medium"),
    23: ("Telnet — unencrypted remote access", "high"),
    25: ("SMTP — review relay and exposure", "medium"),
    445: ("SMB — high-value remote attack surface", "high"),
    1433: ("MSSQL database exposed", "high"),
    1521: ("Oracle database exposed", "high"),
    3306: ("MySQL database exposed", "high"),
    3389: ("RDP exposed", "high"),
    4444: ("Common reverse-shell listener port", "critical"),
    5432: ("PostgreSQL database exposed", "high"),
    5900: ("VNC remote access exposed", "high"),
    6379: ("Redis exposed", "critical"),
    8080: ("Alternate HTTP service", "low"),
    8443: ("Alternate HTTPS service", "low"),
    9200: ("Elasticsearch exposed", "critical"),
    27017: ("MongoDB exposed", "critical"),
}


def _hackertarget_portscan(target: str) -> str:
    try:
        response = requests.get("https://api.hackertarget.com/nmap/", params={"q": target}, timeout=TIMEOUT)
        response.raise_for_status()
        return response.text if "open" in response.text else ""
    except requests.RequestException as exc:
        logger.warning("[portscan] HackerTarget failed: %s", exc)
        return ""


def _nmap_subprocess(address: str) -> str:
    if not shutil.which("nmap"):
        return ""
    try:
        result = subprocess.run(
            ["nmap", "-sV", "--open", "-T3", "--top-ports", "1000", "--", address],
            capture_output=True, text=True, timeout=settings.SCAN_TIMEOUT_NMAP, check=False,
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("[portscan] nmap failed: %s", exc)
        return ""


def _rustscan_subprocess(address: str) -> str:
    if not shutil.which("rustscan"):
        return ""
    try:
        result = subprocess.run(
            ["rustscan", "-a", address, "--", "-sV"],
            capture_output=True, text=True, timeout=min(settings.SCAN_TIMEOUT_NMAP, 180), check=False,
        )
        return result.stdout
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("[portscan] rustscan failed: %s", exc)
        return ""


def _parse_open_ports(raw_output: str) -> list[dict]:
    ports: list[dict] = []
    for line in raw_output.splitlines():
        match = re.search(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if match:
            ports.append({"port": int(match.group(1)), "service": match.group(2), "raw": line.strip()})
    return ports


def run_port_scan(target: str) -> list[dict]:
    ok, domain, error = validate_scan_target(target, resolve_dns=True)
    if not ok:
        return [{
            "tool": "port_scan", "category": "port_scan", "severity": "high",
            "title": "Unsafe or Invalid Port-Scan Target",
            "description": "Port scanning was blocked by target validation.",
            "evidence": error,
        }]
    addresses = resolve_target_addresses(domain)
    address = addresses[0]

    raw = _rustscan_subprocess(address)
    method = "rustscan" if raw else ""
    if not raw:
        raw = _nmap_subprocess(address)
        method = "nmap" if raw else ""
    if not raw:
        raw = _hackertarget_portscan(address)
        method = "hackertarget" if raw else ""
    if not raw:
        logger.warning("[portscan] no output for %s (%s)", domain, address)
        return [{
            "tool": "port_scan", "category": "port_scan", "severity": "info",
            "title": "Port Scan Produced No Results",
            "description": "No local scanner result or third-party fallback result was available.",
            "evidence": f"Target: {domain}\nPinned address: {address}",
        }]

    open_ports = _parse_open_ports(raw)
    if not open_ports:
        return [{
            "tool": method, "category": "port_scan", "severity": "info",
            "title": "No Common Open TCP Ports Found",
            "description": f"No open TCP ports were parsed for {domain} using {method}.",
            "evidence": f"Target: {domain}\nPinned address: {address}\n\n{raw[:1000]}",
        }]

    findings = [{
        "tool": method, "category": "port_scan", "severity": "info",
        "title": f"Port Scan — {len(open_ports)} Open Port(s) Found",
        "description": f"The scanner checked the validated address for {domain}.",
        "evidence": (
            f"Target: {domain}\nPinned address: {address}\nTool: {method}\n\n" +
            "\n".join(f"• {item['raw']}" for item in open_ports)
        ),
    }]
    for item in open_ports:
        port = item["port"]
        if port not in DANGEROUS_PORTS:
            continue
        description, severity = DANGEROUS_PORTS[port]
        findings.append({
            "tool": method, "category": "dangerous_port", "severity": severity,
            "title": f"Internet-Exposed Port: {port}/{item['service']}",
            "description": f"Port {port} is open on {domain}: {description}.",
            "evidence": f"Pinned address: {address}\n{item['raw']}",
            "remediation": "Restrict the service with firewall rules, a VPN, or a tightly scoped allowlist.",
        })
    return findings
