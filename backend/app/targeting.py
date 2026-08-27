"""Target normalization and outbound network safety helpers."""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

from app.config import settings

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "instance-data",
}
BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".home", ".lan")


def normalize_target(target: str) -> str:
    """Return a lowercase hostname/IP without scheme, port, path or trailing dot."""
    value = (target or "").strip()
    if not value:
        return ""
    raw_ip = value.strip("[]")
    try:
        return ipaddress.ip_address(raw_ip).compressed.lower()
    except ValueError:
        pass
    if "://" not in value:
        value = "//" + value
    parsed = urlsplit(value, scheme="https")
    host = parsed.hostname or ""
    return host.rstrip(".").lower()


def _ip_is_allowed(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    if settings.ALLOW_PRIVATE_TARGETS:
        return not (ip.is_unspecified or ip.is_multicast)
    return ip.is_global


def validate_hostname_format(host: str) -> tuple[bool, str]:
    if not host:
        return False, "Target is required"
    if len(host) > 253:
        return False, "Target is too long"
    if host in BLOCKED_HOSTNAMES or host.endswith(BLOCKED_SUFFIXES):
        return False, "Local and internal hostnames are not allowed"
    try:
        ipaddress.ip_address(host)
        if _ip_is_allowed(host):
            return True, ""
        return False, "Private, reserved, multicast, or non-routable IP addresses are not allowed"
    except ValueError:
        pass
    if not DOMAIN_RE.fullmatch(host):
        return False, "Invalid domain or IP format"
    return True, ""


def resolve_target_addresses(host: str) -> list[str]:
    """Resolve a target and return unique IPv4/IPv6 addresses."""
    addresses: set[str] = set()
    for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM):
        addresses.add(item[4][0])
    return sorted(addresses)


def validate_scan_target(target: str, *, resolve_dns: bool = False) -> tuple[bool, str, str]:
    """Validate and normalize a scan target.

    Returns ``(ok, normalized_target, error_message)``.
    """
    host = normalize_target(target)
    ok, error = validate_hostname_format(host)
    if not ok:
        return False, host, error

    # Operator blocklist. Checked here rather than in each router because every
    # scan path already funnels through this function, so a new endpoint cannot
    # accidentally skip it. Imported lazily: targeting is used by tools that
    # have no database, and importing the service at module scope would drag
    # pymongo into them.
    try:
        from app.services import blocklist

        entry = blocklist.target_block(host)
        if entry is not None:
            reason = str(entry.get("reason", "")).strip()
            return False, host, (
                "This target is on the operator blocklist and cannot be scanned"
                + (f": {reason}" if reason else ".")
            )
    except Exception:  # a blocklist outage must not break target validation
        pass

    if resolve_dns and not settings.ALLOW_PRIVATE_TARGETS:
        try:
            addresses = resolve_target_addresses(host)
        except socket.gaierror:
            return False, host, "Target does not resolve"
        except OSError:
            return False, host, "Target resolution failed"
        if not addresses:
            return False, host, "Target does not resolve"
        try:
            if any(not _ip_is_allowed(address) for address in addresses):
                return False, host, "Target resolves to a private, reserved, or non-routable address"
        except ValueError:
            return False, host, "Target resolution returned an invalid address"

    return True, host, ""


def is_same_target_scope(host: str, target: str) -> bool:
    """Allow the exact target and its subdomains; reject suffix-confusion domains."""
    host = host.rstrip(".").lower()
    target = target.rstrip(".").lower()
    return host == target or host.endswith("." + target)
