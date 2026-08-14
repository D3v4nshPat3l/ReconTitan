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

        record = whois.whois(domain)
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

        evidence = "\n".join(evidence_lines) or "No WHOIS data returned."
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
