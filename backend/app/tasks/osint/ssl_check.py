"""SSL/TLS certificate analysis with prevalidated and pinned target addresses."""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone

from app.targeting import resolve_target_addresses, validate_scan_target

logger = logging.getLogger("recontitan.osint.ssl_check")


def _connect_tls(domain: str):
    """Connect to a validated address while retaining hostname/SNI verification."""
    ok, domain, error = validate_scan_target(domain, resolve_dns=True)
    if not ok:
        raise ValueError(error)
    addresses = resolve_target_addresses(domain)
    last_error: Exception | None = None
    context = ssl.create_default_context()
    for address in addresses:
        raw = None
        try:
            raw = socket.create_connection((address, 443), timeout=10)
            tls_socket = context.wrap_socket(raw, server_hostname=domain)
            return tls_socket
        except Exception as exc:
            last_error = exc
            if raw is not None:
                raw.close()
    if last_error:
        raise last_error
    raise OSError("Target did not resolve to a usable address")


def run_ssl_check(target: str) -> list[dict]:
    """Analyze certificate validity, protocol, cipher, and SAN disclosure."""
    ok, domain, validation_error = validate_scan_target(target, resolve_dns=True)
    if not ok:
        return [{
            "tool": "ssl_check", "category": "ssl_certificate", "severity": "high",
            "title": "Unsafe or Invalid TLS Target",
            "description": "TLS analysis was blocked by outbound target validation.",
            "evidence": validation_error,
            "remediation": "Use a valid public hostname or explicitly enable private targets only in an isolated lab.",
        }]

    findings: list[dict] = []
    cert_info = None
    try:
        with _connect_tls(domain) as tls_socket:
            cert_info = tls_socket.getpeercert()
            protocol = tls_socket.version()
            cipher = tls_socket.cipher()
    except ssl.SSLCertVerificationError as exc:
        return [{
            "tool": "ssl_check", "category": "ssl_certificate", "severity": "high",
            "title": "SSL Certificate Verification Failed",
            "description": "The certificate is untrusted, expired, or does not match the hostname.",
            "evidence": str(exc)[:1000],
            "remediation": "Install a valid certificate from a trusted CA and configure automated renewal.",
        }]
    except (ConnectionRefusedError, socket.timeout, OSError, ValueError) as exc:
        logger.warning("[ssl] Cannot connect to %s:443 — %s", domain, exc)
        return [{
            "tool": "ssl_check", "category": "ssl_certificate", "severity": "medium",
            "title": "HTTPS Not Available",
            "description": f"Could not establish a verified TLS connection to {domain}:443.",
            "evidence": f"{type(exc).__name__}: {str(exc)[:800]}",
            "remediation": "Ensure port 443 serves a valid certificate and modern TLS configuration.",
        }]

    if not cert_info:
        return findings

    not_after_str = cert_info.get("notAfter", "")
    not_before_str = cert_info.get("notBefore", "")
    try:
        not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days
        if days_left < 0:
            severity, expiry_msg = "critical", f"Certificate expired {abs(days_left)} days ago"
        elif days_left < 14:
            severity, expiry_msg = "high", f"Certificate expires in {days_left} days"
        elif days_left < 30:
            severity, expiry_msg = "medium", f"Certificate expires in {days_left} days"
        else:
            severity, expiry_msg = "info", f"Certificate valid for {days_left} more days"
    except (TypeError, ValueError):
        severity, expiry_msg, days_left = "info", f"Expiry: {not_after_str or 'unknown'}", 9999

    subject = dict(item[0] for item in cert_info.get("subject", []))
    issuer = dict(item[0] for item in cert_info.get("issuer", []))
    sans = [value for _kind, value in cert_info.get("subjectAltName", [])]
    evidence = (
        f"Subject CN: {subject.get('commonName', 'N/A')}\n"
        f"Issuer: {issuer.get('organizationName', 'N/A')}\n"
        f"Valid From: {not_before_str}\nValid Until: {not_after_str}\n"
        f"Status: {expiry_msg}\nProtocol: {protocol}\n"
        f"Cipher Suite: {cipher[0] if cipher else 'Unknown'}"
    )
    if sans:
        evidence += f"\n\nSANs ({len(sans)} entries):\n" + "\n".join(f"• {value}" for value in sans[:30])

    findings.append({
        "tool": "ssl_check", "category": "ssl_certificate", "severity": severity,
        "title": f"SSL Certificate Analysis — {expiry_msg}",
        "description": f"Verified TLS certificate and negotiated protocol details for {domain}.",
        "evidence": evidence,
        "remediation": "Use an automatically renewed certificate and a modern TLS configuration.",
    })

    if protocol in {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}:
        findings.append({
            "tool": "ssl_check", "category": "weak_tls", "severity": "high",
            "title": f"Deprecated TLS Protocol Negotiated: {protocol}",
            "description": "The server negotiated an obsolete protocol with known security weaknesses.",
            "evidence": f"Negotiated protocol: {protocol}",
            "remediation": "Disable TLS 1.0/1.1 and require TLS 1.2 or newer.",
        })
    if len(sans) > 1:
        findings.append({
            "tool": "ssl_check", "category": "subdomain_enumeration", "severity": "info",
            "title": f"Certificate SANs Reveal {len(sans)} Names",
            "description": "The public certificate exposes additional DNS names for authorized review.",
            "evidence": "\n".join(f"• {value}" for value in sans[:100]),
        })
    logger.info("[ssl] %d findings for %s (days_left=%d, protocol=%s)", len(findings), domain, days_left, protocol)
    return findings
