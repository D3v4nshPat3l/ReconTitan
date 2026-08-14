"""Data exposure proof.

The question a company needs answered is not "could data leak" but "how much, of
what kind, and reachable by whom". This module answers that by quantifying what
an endpoint returns — record counts, field names, the classes of personal data
present, and whether authentication is required — while deliberately not
capturing the values.

That constraint is a feature, not a limitation. A report that proves 12,400
unauthenticated records carrying email, phone, and payment-card fields is fully
actionable, and it does not create a second copy of the very data it is warning
about. Values are counted and fingerprinted; they are never stored or emitted.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.config import settings
from app.models.schemas import AttackSurfaceItem, InputPointType
from app.tasks.vulnscan.danger.budget import (
    DangerBudget,
    ProbeResult,
    danger_finding,
    evidence_block,
    fingerprint,
    truncated,
)
from app.tasks.vulnscan.danger.remediation import remediation_for

logger = logging.getLogger("recontitan.danger.data_exposure")

MODULE = "data_exposure"
A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"

#: Personal-data classes. Patterns detect presence; values are never retained.
PII_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("email_address", r"[\w.+-]+@[\w-]+\.[\w.]{2,}", "Email addresses"),
    ("phone_number", r"(?<!\d)(?:\+\d{1,3}[\s-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)", "Phone numbers"),
    ("payment_card", r"(?<!\d)(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})(?!\d)", "Payment card numbers"),
    ("us_ssn", r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)", "US social security numbers"),
    ("iban", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", "Bank account numbers (IBAN)"),
    ("ip_address", r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", "IP addresses"),
    ("date_of_birth", r"(?i)\"(?:dob|date_of_birth|birth_?date)\"\s*:", "Dates of birth"),
    ("postal_address", r"(?i)\"(?:address|street|address_?line_?1|postcode|zip_?code)\"\s*:", "Postal addresses"),
    ("national_id", r"(?i)\"(?:national_?id|passport|aadhaar|nino|pan_?number)\"\s*:", "Government identifiers"),
)

#: Credential and secret material. Presence alone is a critical finding.
SECRET_PATTERNS: tuple[tuple[str, str, str], ...] = (
    ("password_hash", r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2[id]{1,2}\$", "Password hashes"),
    ("password_field", r"(?i)\"(?:password|passwd|pwd|secret)\"\s*:\s*\"[^\"]{3,}\"", "Plaintext password fields"),
    ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "JSON Web Tokens"),
    ("aws_key", r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b", "AWS access keys"),
    ("google_key", r"\bAIza[0-9A-Za-z_-]{35}\b", "Google API keys"),
    ("private_key", r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----", "Private keys"),
    ("stripe_key", r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}", "Stripe secret keys"),
    ("slack_token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}", "Slack tokens"),
    ("github_token", r"\bgh[pousr]_[A-Za-z0-9]{36,}", "GitHub tokens"),
    ("session_token", r"(?i)\"(?:session_?(?:id|token)|access_?token|refresh_?token|api_?key)\"\s*:\s*\"[^\"]{8,}\"", "Session or API tokens"),
)

#: Parameters that control how many records come back.
PAGINATION_PARAMS = re.compile(r"(?i)^(limit|per_?page|page_?size|count|size|max|take|rows|results)$")

#: Fields whose names alone indicate a sensitive record shape.
SENSITIVE_FIELD_RE = re.compile(
    r"(?i)\"(password|passwd|hash|salt|token|secret|api_?key|private|ssn|national_?id|"
    r"card_?number|cvv|iban|dob|date_of_birth|salary|medical|diagnosis)\w*\"\s*:"
)


@dataclass
class ExposureReport:
    """What an endpoint returned, quantified rather than captured."""

    url: str
    status: int | None
    bytes: int
    record_count: int = 0
    field_names: list[str] = field(default_factory=list)
    pii_classes: dict[str, int] = field(default_factory=dict)
    secret_classes: dict[str, int] = field(default_factory=dict)
    authenticated: bool = False
    body_fingerprint: str = ""


def _count_records(payload) -> int:
    """Count records in a JSON payload without inspecting their values."""
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for key in ("data", "items", "results", "records", "rows", "content", "list", "docs", "edges"):
            value = payload.get(key)
            if isinstance(value, list):
                return len(value)
        for key in ("total", "count", "totalCount", "total_count", "totalElements"):
            value = payload.get(key)
            if isinstance(value, int):
                return value
        return 1
    return 0


def _field_names(payload) -> list[str]:
    """Collect key names only. Values are never read."""
    names: set[str] = set()

    def walk(node, depth: int = 0) -> None:
        if depth > 4 or len(names) > 120:
            return
        if isinstance(node, dict):
            for key, value in node.items():
                names.add(str(key)[:60])
                walk(value, depth + 1)
        elif isinstance(node, list):
            for child in node[:3]:
                walk(child, depth + 1)

    walk(payload)
    return sorted(names)


def classify_body(body: str) -> tuple[dict[str, int], dict[str, int]]:
    """Return ``(pii_counts, secret_counts)`` — occurrence counts, never values."""
    pii: dict[str, int] = {}
    secrets: dict[str, int] = {}
    sample = body[:400_000]
    for name, pattern, _label in PII_PATTERNS:
        matches = re.findall(pattern, sample)
        if matches:
            pii[name] = len(matches)
    for name, pattern, _label in SECRET_PATTERNS:
        matches = re.findall(pattern, sample)
        if matches:
            secrets[name] = len(matches)
    return pii, secrets


def _analyse(url: str, probe: ProbeResult) -> ExposureReport | None:
    if not probe.ok or probe.response is None or probe.status != 200:
        return None
    body = probe.text
    report = ExposureReport(
        url=url, status=probe.status, bytes=probe.size,
        body_fingerprint=fingerprint(probe.response.content),
    )
    content_type = probe.response.headers.get("Content-Type", "").lower()
    if "json" in content_type:
        try:
            payload = json.loads(body)
            report.record_count = _count_records(payload)
            report.field_names = _field_names(payload)
        except (json.JSONDecodeError, ValueError):
            pass
    report.pii_classes, report.secret_classes = classify_body(body)
    return report


def _with_param(url: str, parameter: str, value: str) -> str:
    split = urlsplit(url)
    pairs = [(name, value if name == parameter else existing)
             for name, existing in parse_qsl(split.query, keep_blank_values=True)]
    if not any(name == parameter for name, _ in pairs):
        pairs.append((parameter, value))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs), split.fragment))


def _label(name: str, table: tuple[tuple[str, str, str], ...]) -> str:
    for key, _pattern, label in table:
        if key == name:
            return label
    return name


def run_data_exposure(target: str, budget: DangerBudget, items: list[AttackSurfaceItem], seeds: list[str]) -> list[dict]:
    """Quantify what data is reachable without authentication."""
    findings: list[dict] = []
    reports: list[ExposureReport] = []

    candidates: list[str] = []
    for item in items[: settings.DANGER_MAX_ENDPOINTS]:
        if item.input_type in {InputPointType.API_ENDPOINT, InputPointType.OBJECT_REFERENCE, InputPointType.QUERY_PARAM}:
            if item.url not in candidates:
                candidates.append(item.url)
    for seed in seeds[:2]:
        base = urlsplit(seed)
        root = f"{base.scheme}://{base.netloc}"
        for path in ("/api/users", "/api/v1/users", "/api/orders", "/api/customers",
                     "/api/accounts", "/api/export", "/api/report", "/graphql"):
            candidate = root + path
            if candidate not in candidates:
                candidates.append(candidate)

    for url in candidates[: settings.DANGER_MAX_ENDPOINTS]:
        if not budget.can_spend(MODULE):
            break
        probe = budget.probe(MODULE, "GET", url)
        report = _analyse(url, probe)
        if report and (report.record_count or report.pii_classes or report.secret_classes):
            reports.append(report)

    # ── Secrets in responses ────────────────────────────────────────────────
    with_secrets = [report for report in reports if report.secret_classes]
    if with_secrets:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_data_exposure",
            severity="critical",
            title=f"Credential Material In Responses - {len(with_secrets)} endpoint(s)",
            description=(
                "Responses contain values matching credential, token, or private-key formats. Anything served "
                "this way must be treated as compromised and rotated, regardless of who could reach the endpoint. "
                "ReconTitan counted and classified the matches; it did not store, transmit, or log any value."
            ),
            evidence=evidence_block([
                ("Endpoints affected", len(with_secrets)),
                *[
                    (truncated(report.url, 150),
                     "; ".join(f"{_label(name, SECRET_PATTERNS)} x{count}" for name, count in report.secret_classes.items())
                     + f" | HTTP {report.status}, {report.bytes} bytes, body {report.body_fingerprint}")
                    for report in with_secrets[:15]
                ],
                ("Values captured", "none - occurrences counted and classified only"),
                ("Exploitation status", "CONFIRMED exposure"),
                ("Proof type", "Pattern class match with occurrence count"),
            ]),
            remediation=remediation_for("sensitive_data_exposure"),
            owasp=A02,
            attack_vector="Credential disclosure in an application response",
            asset=with_secrets[0].url,
        ))

    # ── Bulk personal data without authentication ───────────────────────────
    with_pii = [report for report in reports if report.pii_classes]
    if with_pii:
        total_records = sum(report.record_count for report in with_pii)
        classes = sorted({name for report in with_pii for name in report.pii_classes})
        severity = "critical" if total_records >= 100 or "payment_card" in classes or "us_ssn" in classes else "high"
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_data_exposure",
            severity=severity,
            title=f"Personal Data Reachable Without Authentication - {total_records} record(s)",
            description=(
                f"Unauthenticated requests returned data containing {len(classes)} class(es) of personal "
                "information across "
                f"{len(with_pii)} endpoint(s). This is the exposure an attacker would exfiltrate in bulk; the "
                "record counts below quantify the scale. ReconTitan counted occurrences and field names only - no "
                "personal data was captured, stored, or transmitted."
            ),
            evidence=evidence_block([
                ("Endpoints exposing personal data", len(with_pii)),
                ("Total records reachable", total_records),
                ("Data classes present", ", ".join(_label(name, PII_PATTERNS) for name in classes)),
                *[
                    (truncated(report.url, 150),
                     f"{report.record_count} record(s); "
                     + "; ".join(f"{_label(name, PII_PATTERNS)} x{count}" for name, count in report.pii_classes.items())
                     + f" | fields: {', '.join(report.field_names[:12]) or 'n/a'}")
                    for report in with_pii[:15]
                ],
                ("Authentication required", "no"),
                ("Values captured", "none - counts, field names, and fingerprints only"),
                ("Exploitation status", "CONFIRMED unauthenticated access"),
                ("Proof type", "Record count and data-class classification"),
            ]),
            remediation=remediation_for("sensitive_data_exposure"),
            owasp=A01,
            attack_vector="Unauthenticated bulk data exposure",
            asset=with_pii[0].url,
        ))

    # ── Pagination ceiling: quantify the full extent ────────────────────────
    for report in list(with_pii)[:3]:
        pagination = [
            name for name, _ in parse_qsl(urlsplit(report.url).query)
            if PAGINATION_PARAMS.fullmatch(name)
        ]
        if not pagination or not budget.can_spend(MODULE):
            continue
        parameter = pagination[0]
        probe = budget.probe(MODULE, "GET", _with_param(report.url, parameter, "10000"))
        expanded = _analyse(report.url, probe)
        if expanded and expanded.record_count > max(report.record_count, 0):
            findings.append(danger_finding(
                tool=MODULE,
                category="danger_data_exposure",
                severity="high",
                title=f"Unbounded Pagination - {parameter} has no server-side ceiling",
                description=(
                    f"Raising '{parameter}' to 10000 returned {expanded.record_count} records against a baseline "
                    f"of {report.record_count}. Without a server-side maximum, the entire dataset can be "
                    "retrieved in a single request, which is what turns a minor exposure into a full database "
                    "extraction. Only counts were recorded."
                ),
                evidence=evidence_block([
                    ("Endpoint", truncated(report.url, 300)),
                    ("Pagination parameter", parameter),
                    ("Baseline records", report.record_count),
                    ("Records with limit=10000", expanded.record_count),
                    ("Response size", f"{report.bytes} bytes -> {expanded.bytes} bytes"),
                    ("Values captured", "none - record counts only"),
                    ("Exploitation status", "CONFIRMED unbounded retrieval"),
                    ("Proof type", "Record-count differential"),
                ]),
                remediation=remediation_for("sensitive_data_exposure"),
                owasp=A01,
                attack_vector="Unbounded pagination enabling bulk extraction",
                asset=report.url,
            ))

    # ── Sensitive field names in otherwise ordinary responses ───────────────
    sensitive_fields: list[tuple[str, list[str]]] = []
    for report in reports:
        flagged = [name for name in report.field_names if SENSITIVE_FIELD_RE.search(f'"{name}":')]
        if flagged:
            sensitive_fields.append((report.url, flagged))
    if sensitive_fields:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_data_exposure",
            severity="medium",
            title=f"Over-Broad Serialization - {len(sensitive_fields)} endpoint(s) return sensitive fields",
            description=(
                "Responses include field names that a client-facing API should not serialize at all, such as "
                "password hashes, salts, internal tokens, or identity numbers. Even when the current interface "
                "ignores them, they are returned to anyone who can call the endpoint. Field names only were "
                "recorded; no values were read."
            ),
            evidence=evidence_block([
                *[(truncated(url, 150), ", ".join(fields[:15])) for url, fields in sensitive_fields[:15]],
                ("Values captured", "none - field names only"),
            ]),
            remediation=remediation_for("sensitive_data_exposure"),
            owasp=A01,
            attack_vector="Over-broad object serialization",
            asset=sensitive_fields[0][0],
        ))

    findings.append(danger_finding(
        tool=MODULE,
        category="danger_data_exposure_summary",
        severity="info",
        title=f"Data Exposure Analysis - {len(reports)} responsive endpoint(s)",
        description=(
            "Reachable endpoints were quantified rather than harvested: record counts, field names, and the "
            "classes of personal or credential data present. This deliberately proves the scale of an exposure "
            "without creating a second copy of the data, which is what a remediation team needs and what a "
            "report should never contain."
        ),
        evidence=evidence_block([
            ("Target", target),
            ("Endpoints probed", len(candidates[: settings.DANGER_MAX_ENDPOINTS])),
            ("Endpoints returning data", len(reports)),
            ("Endpoints with personal data", len(with_pii)),
            ("Endpoints with credential material", len(with_secrets)),
            ("Total records reachable", sum(report.record_count for report in reports)),
            ("Data values stored by ReconTitan", "none"),
        ]),
        owasp=A01,
        asset=target,
    ))

    logger.info("[danger:data_exposure] %s: %d endpoints, %d with PII", target, len(reports), len(with_pii))
    return findings
