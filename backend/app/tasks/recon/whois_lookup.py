"""WHOIS lookup for the ReconTitan reconnaissance pipeline."""

from __future__ import annotations

import logging
from datetime import date, datetime, timezone
from typing import Any

logger = logging.getLogger("recontitan.recon.whois")


def _normalise_date(value: datetime | date) -> datetime | date | None:
    """Drop invalid sentinel dates and normalize real datetimes to UTC."""
    if value.year <= 1:
        return None
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _format_whois_value(value: Any) -> str:
    """Format python-whois values without leaking raw Python repr objects."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        normalized = _normalise_date(value)
        if normalized is None:
            return ""
        assert isinstance(normalized, datetime)
        return normalized.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if isinstance(value, date):
        normalized = _normalise_date(value)
        return normalized.isoformat() if normalized else ""
    if isinstance(value, (list, tuple, set)):
        items: list[str] = []
        for item in value:
            formatted = _format_whois_value(item)
            if formatted and formatted not in items:
                items.append(formatted)
        return ", ".join(items)
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            formatted = _format_whois_value(item)
            if formatted:
                parts.append(f"{key}={formatted}")
        return ", ".join(parts)
    return str(value).strip()


def _expiry_datetime(value: Any) -> datetime | None:
    """Choose the most useful valid expiration datetime from WHOIS output."""
    candidates = value if isinstance(value, (list, tuple, set)) else [value]
    datetimes: list[datetime] = []
    for candidate in candidates:
        if isinstance(candidate, datetime):
            normalized = _normalise_date(candidate)
            if isinstance(normalized, datetime):
                datetimes.append(normalized.astimezone(timezone.utc))
        elif isinstance(candidate, date):
            normalized = _normalise_date(candidate)
            if normalized:
                datetimes.append(datetime(normalized.year, normalized.month, normalized.day, tzinfo=timezone.utc))
    if not datetimes:
        return None
    future = [item for item in datetimes if item >= datetime.now(timezone.utc)]
    return min(future) if future else max(datetimes)


def run_whois(target: str) -> list[dict]:
    """Perform a WHOIS lookup and return Finding-compatible dictionaries."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings: list[dict] = []
    try:
        import whois

        # quiet=True is the library's own switch for this, and it is the only
        # reliable one. python-whois logs a failed socket with logger.error at
        # the point of failure, so suppressing it afterwards through logging
        # configuration is a race against whatever the library does to the root
        # handlers. Telling it not to log in the first place is not a race.
        record = whois.whois(domain, quiet=True)
        fields = {
            "Registrar": record.registrar,
            "Creation Date": record.creation_date,
            "Expiration Date": record.expiration_date,
            "Updated Date": record.updated_date,
            "Name Servers": record.name_servers,
            "Registrant Country": record.country,
            "Organization": record.org,
            "DNSSEC": record.dnssec,
        }
        evidence_lines = []
        for label, raw_value in fields.items():
            formatted = _format_whois_value(raw_value)
            if formatted:
                evidence_lines.append(f"{label}: {formatted}")

        # python-whois swallows a failed socket connection, logs it to its own
        # logger, and hands back a record whose every field is None. That is
        # indistinguishable here from a registry that answered with nothing,
        # and reporting it as a successful lookup with empty evidence is the
        # failure this project exists to avoid: a check that did not run must
        # say so rather than produce a finding shaped like a result.
        if not evidence_lines:
            return [{
                "tool": "whois",
                "category": "scanner_coverage",
                "severity": "info",
                "title": f"WHOIS Lookup Returned No Data - {domain}",
                "description": (
                    "The WHOIS query completed without returning a single field. "
                    "That usually means the registry refused the query, rate-limited "
                    "it, or could not be reached - not that the domain is "
                    "unregistered. Registration details for this target were not "
                    "examined."
                ),
                "evidence": (
                    f"Queried: {domain}\n"
                    "Fields returned: none\n"
                    "Registrar, dates, name servers and registrant country are all absent."
                ),
                "remediation": (
                    "Confirm outbound WHOIS (TCP 43) and RDAP are permitted from this "
                    "host, then retry. Some TLD registries answer only over RDAP or "
                    "rate-limit by source address."
                ),
            }]

        evidence = "\n".join(evidence_lines)
        severity = "info"
        remediation = None
        expiry = _expiry_datetime(record.expiration_date)
        if expiry:
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                severity = "high"
                evidence += f"\nDomain Status: Expired {abs(days_left)} day(s) ago"
                remediation = "Confirm registrar status immediately and renew the domain if it is still an owned production asset."
            elif days_left < 30:
                severity = "medium"
                evidence += f"\nDomain Status: Expires in {days_left} day(s)"
                remediation = "Renew the domain before expiry and verify that registrar auto-renewal and billing contacts are current."

        findings.append({
            "tool": "whois",
            "category": "whois",
            "severity": severity,
            "title": f"WHOIS Record - {domain}",
            "description": f"WHOIS registration data for {domain}.",
            "evidence": evidence,
            "remediation": remediation,
        })
    except Exception as exc:
        logger.warning("[whois] Error for %s: %s", domain, exc)
        findings.append({
            "tool": "whois",
            "category": "whois",
            "severity": "info",
            "title": f"WHOIS Lookup Failed - {domain}",
            "description": "WHOIS query returned no data or timed out.",
            "evidence": str(exc),
            "remediation": "Retry against the authoritative registry or registrar service and confirm that outbound WHOIS/RDAP traffic is permitted.",
        })

    return findings
