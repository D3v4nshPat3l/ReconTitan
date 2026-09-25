"""Bounded port scanning against a prevalidated, pinned public IP address."""

from __future__ import annotations

import logging
import contextvars
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


#: The TCP ports that actually carry internet-facing services, plus the ones
#: whose exposure is itself the finding. Deliberately a curated few hundred
#: rather than a swept range: with a connect timeout per port, a 65535-port
#: sweep does not finish inside any scan budget, and a scan that does not
#: finish reports nothing.
BUILTIN_SCAN_PORTS: tuple[int, ...] = tuple(sorted({
    # Web and proxies
    80, 81, 88, 443, 444, 591, 593, 832, 981, 1010, 1311, 2082, 2083, 2086,
    2087, 2095, 2096, 2480, 3000, 3001, 3002, 3128, 3333, 4000, 4001, 4002,
    4100, 4243, 4567, 4711, 4712, 4993, 5000, 5001, 5104, 5108, 5280, 5281,
    5601, 5800, 6543, 7000, 7001, 7002, 7396, 7474, 8000, 8001, 8002, 8003,
    8004, 8005, 8006, 8008, 8009, 8010, 8014, 8042, 8060, 8069, 8080, 8081,
    8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8118, 8123,
    8172, 8181, 8222, 8243, 8280, 8281, 8333, 8337, 8443, 8500, 8501, 8530,
    8531, 8834, 8880, 8888, 8983, 9000, 9001, 9002, 9043, 9060, 9080, 9090,
    9091, 9200, 9443, 9800, 9981, 9999, 10000, 10250, 11371, 12443, 16080,
    18091, 18092, 20720, 28017,
    # Remote access and management
    22, 23, 513, 514, 3389, 5900, 5901, 5902, 5985, 5986, 4899, 5938, 6000,
    6001, 6002, 7070, 32768,
    # Mail
    25, 26, 110, 143, 465, 475, 587, 993, 995, 2525, 24,
    # File transfer and sharing
    20, 21, 69, 115, 139, 445, 548, 873, 989, 990, 2049, 2121, 3702,
    # Directory, auth and time
    49, 88, 113, 123, 389, 464, 636, 749, 3268, 3269, 1812, 1813,
    # Databases and caches
    1433, 1434, 1521, 1830, 2483, 2484, 3050, 3306, 3351, 4505, 4506, 5432,
    5433, 5984, 6379, 7199, 7473, 8086, 8087, 9042, 9160, 11211, 27017,
    27018, 27019, 50000,
    # Message queues, orchestration and infrastructure
    2375, 2376, 2377, 4369, 5222, 5223, 5269, 5671, 5672, 6066, 6443, 7077,
    8300, 8301, 8302, 8400, 8600, 9092, 9093, 9300, 9418, 15672, 25672,
    # Industrial, printing and misc services
    102, 502, 515, 631, 623, 1099, 1723, 1900, 2000, 2001, 3299, 4444, 4445,
    5060, 5061, 5353, 5666, 5667, 6660, 6661, 6662, 6663, 6664, 6665, 6666,
    6667, 6668, 6669, 7777, 8021, 9100, 9101, 9102, 10001, 11111, 20000,
    44818, 47808,
}))

#: Names for ports whose registered service name is missing or unhelpful on
#: Windows, where ``getservbyport`` covers far less than it does on Linux.
PORT_SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "ms-sql-s", 1521: "oracle",
    2049: "nfs", 2375: "docker", 2376: "docker-tls", 3000: "http-alt",
    3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5985: "wsman", 5986: "wsmans", 6379: "redis",
    6443: "kubernetes", 8000: "http-alt", 8080: "http-proxy", 8443: "https-alt",
    9042: "cassandra", 9092: "kafka", 9200: "elasticsearch", 9300: "elasticsearch-cluster",
    11211: "memcached", 15672: "rabbitmq-mgmt", 27017: "mongodb", 27018: "mongodb",
}


def _service_name(port: int) -> str:
    if port in PORT_SERVICE_NAMES:
        return PORT_SERVICE_NAMES[port]
    try:
        import socket as _socket

        return _socket.getservbyport(port, "tcp")
    except Exception:  # noqa: BLE001 — an unknown port is not an error
        return "unknown"


def _builtin_portscan(address: str) -> str:
    """TCP connect scan in pure Python, for hosts with no scanner installed.

    This exists because the alternative was worse. Without a local binary the
    only remaining option was a third-party API that has to be told the
    target's address, and a scan authorization frequently does not extend to
    disclosing the host to an unrelated company. A connect scan finds less
    than nmap -- no version detection, no OS fingerprint, no UDP -- but it
    runs on the scanning machine, and what it does report is directly observed.

    Output is formatted like nmap's so the existing parser handles it.
    """
    import socket
    from concurrent.futures import ThreadPoolExecutor

    timeout = settings.PORT_SCAN_CONNECT_TIMEOUT

    def _probe(port: int) -> int | None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex((address, port)) == 0:
                    return port
        except OSError:
            return None
        return None

    ports = BUILTIN_SCAN_PORTS
    workers = min(settings.PORT_SCAN_THREADS, len(ports))
    open_ports: list[int] = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for result in pool.map(_probe, ports):
                if result is not None:
                    open_ports.append(result)
    except Exception as exc:  # noqa: BLE001
        logger.warning("[portscan] builtin scan failed: %s", exc)
        return ""

    logger.info(
        "[portscan] builtin connect scan of %s: %d/%d ports open",
        address, len(open_ports), len(ports),
    )
    if not open_ports:
        # An empty result is a real result here, unlike a missing binary. Say
        # so in the parser's own format so it is not mistaken for "no output".
        return f"# builtin connect scan: 0 of {len(ports)} probed ports open\n"
    return "\n".join(
        f"{port}/tcp open {_service_name(port)}" for port in sorted(open_ports)
    ) + "\n"


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


# Set by the scan runner for the duration of a Danger Mode scan. Depth belongs
# to the authorisation gate, not to a global setting: NMAP_DEEP_SCAN=true would
# otherwise make a plain "Full" scan fire all 65535 ports with vuln scripts,
# which is far more traffic than that profile's description promises.
DANGER_ACTIVE = contextvars.ContextVar("recontitan_danger_scan", default=False)


def deep_scan_requested() -> bool:
    return bool(settings.NMAP_DEEP_SCAN or DANGER_ACTIVE.get())


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


def _script_args(domain: str) -> str:
    """Build --script-args, naming the domain where a script needs it.

    dns-zone-transfer takes the zone to ask for as an argument and skips
    itself entirely without one, so passing the scanned domain is the
    difference between the script running and silently doing nothing.
    """
    args = ["unsafe=1", "vulns.showall", "http.useragent=Mozilla/5.0"]
    if domain:
        # Commas separate arguments, so a domain containing one would split
        # into two malformed args. Real hostnames cannot, but the value
        # reaches here from user input and is not worth trusting on that.
        safe = domain.replace(",", "")
        args.append(f"dns-zone-transfer.domain={safe}")
    return ",".join(args)


def _nmap_subprocess(address: str, domain: str = "") -> str:
    """Run nmap, deeply if the operator has opted in.

    The deep form scans the NMAP_DEEP_PORTS range (1-20000 by default) with
    the most thorough version probing nmap offers, plus the NSE scripts
    selected by NMAP_DEEP_SCRIPTS. The range stops short of all 65535 on
    purpose: with -sV and scripts running against every open port, an
    all-ports sweep does not finish inside SCAN_TIMEOUT_NMAP_DEEP, and a
    scan that times out contributes nothing to the report at all.

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

    if deep_scan_requested():
        privileged = _has_raw_socket_privilege()
        argv = [nmap_bin]
        if privileged:
            # SYN scan and OS fingerprinting, both of which need raw sockets.
            # --osscan-guess makes nmap report its best guess rather than
            # staying silent when the fingerprint is not an exact match.
            argv += ["-sS", "-O", "--osscan-guess", "-A", "-sU"]
        else:
            argv += ["-sT"]
        argv += [
            "-sV",
            "--version-intensity", str(settings.NMAP_VERSION_INTENSITY),
            "-Pn", "-n",
            "-p", settings.NMAP_DEEP_PORTS,
            "-T5",
            "--max-retries", "2",
            "--min-rate", "10000",
            "--script", settings.NMAP_DEEP_SCRIPTS,
            "--script-args", _script_args(domain),
            "--open",
            "--", address,
        ]
        if settings.NMAP_OUTPUT_DIR:
            # -oA writes .nmap/.gnmap/.xml. Named per address so concurrent
            # scans cannot overwrite each other's artifacts.
            stem = os.path.join(
                settings.NMAP_OUTPUT_DIR,
                "recontitan_" + re.sub(r"[^A-Za-z0-9._-]", "_", address),
            )
            argv[-2:-2] = ["-oA", stem]
        timeout = settings.SCAN_TIMEOUT_NMAP_DEEP
        logger.info(
            "[portscan] deep scan of %s - ports %s, NSE %s, %s",
            address,
            settings.NMAP_DEEP_PORTS,
            settings.NMAP_DEEP_SCRIPTS,
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
        raw = _nmap_subprocess(address, domain)
        method = "nmap" if raw else ""
    if not raw and settings.ALLOW_BUILTIN_PORT_SCAN:
        # Preferred over the third-party fallback, and deliberately ordered
        # before it: this runs on the scanning machine and tells nobody else
        # what is being scanned.
        raw = _builtin_portscan(address)
        method = "builtin" if raw else ""
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
        elif not settings.ALLOW_BUILTIN_PORT_SCAN:
            reason = (
                "Neither rustscan nor nmap is installed, and the built-in connect "
                "scanner is disabled (ALLOW_BUILTIN_PORT_SCAN=false). No port scan "
                "was performed — this is not evidence that no ports are open."
            )
        else:
            reason = (
                "Neither rustscan nor nmap is installed, and the built-in connect "
                "scanner returned no usable result — every probe failed, which "
                "usually means outbound connections are filtered on this host. "
                "This is not evidence that no ports are open."
            )
        return [{
            "tool": "port_scan", "category": "port_scan", "severity": "info",
            "title": "Port Scan Did Not Run",
            "description": reason,
            "evidence": f"Target: {domain}\nPinned address: {address}",
            "remediation": (
                "Install nmap (or rustscan) on the scanner host for version detection "
                "and wider port coverage. The built-in scanner needs nothing installed "
                "but reports open ports only, without service versions."
            ),
        }]

    open_ports = _parse_open_ports(raw)
    if not open_ports:
        return [{
            "tool": method, "category": "port_scan", "severity": "info",
            "title": "No Common Open TCP Ports Found",
            "description": (
                f"No open TCP ports were parsed for {domain} using {method}."
                + (
                    f" The built-in scanner probes {len(BUILTIN_SCAN_PORTS)} commonly "
                    "used TCP ports, not all 65535, so a service on an unusual port "
                    "would not appear here."
                    if method == "builtin" else ""
                )
            ),
            "evidence": f"Target: {domain}\nPinned address: {address}\n\n{raw[:1000]}",
        }]

    findings = []
    if method == "nmap" and deep_scan_requested():
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
