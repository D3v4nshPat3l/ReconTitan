"""Bounded port scanning against a prevalidated, pinned public IP address."""

from __future__ import annotations

import logging
import os
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
    """Third-party port scan, used only when no local scanner is installed.

    This hands the target address to api.hackertarget.com, so it stays off
    unless the operator opts in. Scanning is often done under an authorization
    that does not extend to disclosing the host to an unrelated service.
    """
    if not settings.ALLOW_HACKERTARGET:
        logger.info("[portscan] HackerTarget fallback disabled (ALLOW_HACKERTARGET=false)")
        return ""
    try:
        response = requests.get("https://api.hackertarget.com/nmap/", params={"q": target}, timeout=TIMEOUT)
        response.raise_for_status()
        return response.text if "open" in response.text else ""
    except requests.RequestException as exc:
        logger.warning("[portscan] HackerTarget failed: %s", exc)
        return ""


def _find_binary(name: str) -> str | None:
    """Locate a scanner binary, PATH first and then the usual install roots.

    nmap's Windows installer does not reliably add itself to PATH, so
    shutil.which misses a perfectly good installation and the report says
    "Binary not installed" about a binary sitting in Program Files. Checking
    the standard locations turns that into a non-issue rather than something
    every user has to diagnose.
    """
    found = shutil.which(name)
    if found:
        return found

    exe = f"{name}.exe" if os.name == "nt" else name
    candidates = [
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "Nmap", exe),
        os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"), "Nmap", exe),
        f"/usr/bin/{name}",
        f"/usr/local/bin/{name}",
        f"/opt/homebrew/bin/{name}",
        f"/snap/bin/{name}",
    ]
    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            logger.info("[portscan] %s found outside PATH at %s", name, path)
            return path
    return None


def _has_raw_socket_privilege() -> bool:
    """Can this process send raw packets?

    -sS and -O need it. Without it nmap silently falls back to a connect scan
    and skips OS detection, so the difference is detected here and reported
    rather than left to look like a scan that simply found nothing.
    """
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _nmap_subprocess(address: str) -> str:
    """Run nmap, deeply if the operator has opted in.

    The deep form scans all 65535 TCP ports with the most thorough version
    probing nmap offers, plus the safe, version, discovery, default and vuln
    NSE categories.

    Two families of flag are deliberately absent, and this is the place to say
    why rather than leave a future reader to wonder:

    * Decoys (-D), fragmentation (-f), --data-length, --ttl and --source-port
      exist to defeat attribution and evade intrusion detection. They find
      nothing extra. Decoys in particular forge the source address, so the
      target's logs implicate machines that had no part in the scan.
    * The `exploit` NSE category attempts exploitation rather than detection.
      Every finding this tool emits is candidate-graded and non-destructive;
      running exploit scripts would make that claim untrue.

    An operator who needs either can run nmap directly. It should not be
    something a web service does on their behalf.
    """
    nmap_bin = _find_binary("nmap")
    if not nmap_bin:
        return ""

    if settings.NMAP_DEEP_SCAN:
        privileged = _has_raw_socket_privilege()
        argv = [nmap_bin]
        if privileged:
            # SYN scan and OS fingerprinting, both of which need raw sockets.
            argv += ["-sS", "-O"]
        else:
            argv += ["-sT"]
        argv += [
            "-sV",
            "--version-intensity", str(settings.NMAP_VERSION_INTENSITY),
            "-Pn", "-n",
            "-p-",
            "-T4",
            "--script", "safe,version,discovery,default,vuln",
            "--script-args", "vulns.showall",
            "--open",
            "--", address,
        ]
        timeout = settings.SCAN_TIMEOUT_NMAP_DEEP
        logger.info(
            "[portscan] deep scan of %s — all 65535 ports, NSE safe/version/"
            "discovery/default/vuln, %s",
            address,
            "SYN + OS detection (privileged)" if privileged
            else "TCP connect, no OS detection (unprivileged)",
        )
    else:
        argv = [nmap_bin, "-sV", "--open", "-T3", "--top-ports", "1000", "--", address]
        timeout = settings.SCAN_TIMEOUT_NMAP

    try:
        result = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False,
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        # A deep scan that ran out of time still found whatever it found before
        # the clock stopped; discarding that would be worse than reporting it.
        logger.warning("[portscan] nmap timed out after %ss", timeout)
        return ""
    except (OSError, subprocess.SubprocessError) as exc:
        logger.warning("[portscan] nmap failed: %s", exc)
        return ""


def _parse_nse_findings(raw_output: str) -> list[dict]:
    """Pull NSE script results out of nmap output.

    Without this the deep scan would run every vuln script and then throw the
    answers away, keeping only the port list — which is the one thing the
    shallow scan already gives you.
    """
    findings: list[dict] = []
    current_port = None
    block: list[str] = []

    def flush():
        if not block:
            return
        text = chr(10).join(block)
        vulnerable = "VULNERABLE:" in text
        script = block[0].lstrip("|_ ").split(":")[0].strip()
        findings.append({
            "tool": "nmap-nse",
            "category": "port_scan",
            "severity": "medium" if vulnerable else "info",
            "title": (
                f"NSE: {script} flagged {current_port or 'the host'} as VULNERABLE"
                if vulnerable else f"NSE: {script} on {current_port or 'host'}"
            ),
            "description": (
                "An nmap NSE script reported a candidate weakness. NSE results are "
                "signatures, not proof — confirm by hand before acting."
                if vulnerable else "Output from an nmap NSE script."
            ),
            "evidence": text[:2000],
            "requires_manual_validation": True,
        })

    for line in raw_output.splitlines():
        port_match = re.match(r"^(\d+/tcp)\s+open", line)
        if port_match:
            flush(); block = []
            current_port = port_match.group(1)
            continue
        if line.startswith("|"):
            block.append(line)
        elif block:
            flush(); block = []
    flush()
    return findings


def _rustscan_subprocess(address: str) -> str:
    rustscan_bin = _find_binary("rustscan")
    if not rustscan_bin:
        return ""
    try:
        result = subprocess.run(
            [rustscan_bin, "-a", address, "--", "-sV"],
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
        # Say which of the three sources were even attempted. "No results"
        # otherwise reads as "no open ports", which is the opposite conclusion
        # when the real cause is that nothing ran.
        local_available = bool(_find_binary("rustscan") or _find_binary("nmap"))
        if local_available:
            reason = "A local scanner ran but returned no parseable output."
        elif settings.ALLOW_HACKERTARGET:
            reason = (
                "Neither rustscan nor nmap is installed, and the third-party "
                "fallback returned no usable result."
            )
        else:
            reason = (
                "Neither rustscan nor nmap is installed, and the third-party "
                "fallback is disabled (ALLOW_HACKERTARGET=false). No port scan "
                "was performed — this is not evidence that no ports are open."
            )
        return [{
            "tool": "port_scan", "category": "port_scan", "severity": "info",
            "title": "Port Scan Did Not Run",
            "description": reason,
            "evidence": f"Target: {domain}\nPinned address: {address}",
            "remediation": (
                "Install nmap (or rustscan) on the scanner host to run this check locally, "
                "or set ALLOW_HACKERTARGET=true to permit the third-party fallback — which "
                "discloses the target address to api.hackertarget.com."
            ),
        }]

    open_ports = _parse_open_ports(raw)
    if not open_ports:
        return [{
            "tool": method, "category": "port_scan", "severity": "info",
            "title": "No Common Open TCP Ports Found",
            "description": f"No open TCP ports were parsed for {domain} using {method}.",
            "evidence": f"Target: {domain}\nPinned address: {address}\n\n{raw[:1000]}",
        }]

    findings = []
    if method == "nmap" and settings.NMAP_DEEP_SCAN:
        findings.extend(_parse_nse_findings(raw))
        if not _has_raw_socket_privilege():
            # Say it plainly. Otherwise the report shows a deep scan with no OS
            # line and the reader concludes the host hid it, when in fact the
            # probe was never sent.
            findings.append({
                "tool": "nmap", "category": "port_scan", "severity": "info",
                "title": "Deep Scan Ran Without Raw-Socket Privilege",
                "description": (
                    "SYN scanning (-sS) and OS detection (-O) need raw sockets, which "
                    "this process does not have. A TCP connect scan was used instead: "
                    "ports and service versions are accurate, but no OS fingerprint "
                    "was attempted and the scan is more visible in the target's logs."
                ),
                "evidence": (
                    f"Target: {domain}" + chr(10)
                    + f"Pinned address: {address}" + chr(10)
                    + "Scan type used: -sT"
                ),
                "remediation": (
                    "On Linux, grant the capability to the nmap binary rather than "
                    "running the service as root:" + chr(10) + chr(10) +
                    "    sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "
                    "$(which nmap)" + chr(10) + chr(10) +
                    "That gives nmap the one privilege it needs and leaves the scanner "
                    "unprivileged. Running a network-facing service as root so it can "
                    "shell out to nmap trades a much larger problem for a smaller one. "
                    "On Windows, run the scanner from an Administrator terminal."
                ),
            })

    findings += [{
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
