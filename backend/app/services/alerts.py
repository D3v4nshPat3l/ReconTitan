"""Opt-in, bounded scan-completion alerts.

Email is configured exclusively by the operator's environment. The public scan
API never receives a recipient, avoiding an accidental mail relay.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import Any

from app.config import settings

logger = logging.getLogger("recontitan.alerts")
_SEVERITIES = ("critical", "high")


def alert_counts(report: dict[str, Any]) -> dict[str, int]:
    """Return triggering severity and exploit-priority counts."""
    findings = report.get("findings") or []
    urgent = sum(
        1 for finding in findings
        if isinstance(finding, dict) and finding.get("exploit_priority") == "urgent"
    )
    counts = report.get("severity_counts")
    # Queued scan records persist individual findings and derive their summary
    # only when a report is read. Local scans already carry severity_counts.
    if not isinstance(counts, dict):
        counts = {}
    if not counts:
        counts = {
            severity: sum(
                1 for finding in findings
                if str(finding.get("severity", "")).lower() == severity
            )
            for severity in _SEVERITIES
        }
    allowed = _SEVERITIES if settings.ALERT_MIN_SEVERITY == "high" else ("critical",)
    # Exploit-priority URGENT always triggers: it means a version-confirmed CVE
    # is in CISA KEV, even when its older CVSS score sits below the configured
    # severity threshold.
    normalised: dict[str, int] = {"urgent": urgent}
    for severity in allowed:
        try:
            normalised[severity] = max(0, int(counts.get(severity, 0)))
        except (TypeError, ValueError):
            normalised[severity] = 0
    return normalised


def _message(report: dict[str, Any], counts: dict[str, int]) -> EmailMessage:
    target = str(report.get("target") or "unknown target").replace("\r", " ").replace("\n", " ")[:253]
    scan_id = str(report.get("scan_id") or "local scan")[:100]
    severity_total = sum(value for name, value in counts.items() if name != "urgent")
    urgent_below_threshold = sum(
        1 for finding in (report.get("findings") or [])
        if isinstance(finding, dict)
        and finding.get("exploit_priority") == "urgent"
        and str(finding.get("severity", "")).lower() not in counts
    )
    total = severity_total + urgent_below_threshold
    finding_lines = []
    for finding in (report.get("findings") or []):
        severity = str(finding.get("severity", "")).lower()
        urgent = finding.get("exploit_priority") == "urgent"
        if urgent or (severity in counts and counts[severity]):
            title = str(finding.get("title") or "Untitled finding").replace("\r", " ").replace("\n", " ")[:300]
            finding_lines.append(f"- {'URGENT / ' if urgent else ''}{severity.upper()}: {title}")
            if len(finding_lines) == 10:
                break

    message = EmailMessage()
    message["From"] = settings.SMTP_FROM
    message["To"] = ", ".join(settings.ALERT_EMAIL_RECIPIENTS)
    message["Subject"] = f"[ReconTitan] {total} actionable finding(s) on {target}"
    summary = ", ".join(f"{count} {severity}" for severity, count in counts.items() if count)
    message.set_content(
        "ReconTitan completed a scan that met the configured alert threshold.\n\n"
        f"Target: {target}\nScan ID: {scan_id}\nTriggered findings: {summary}\n\n"
        "Top findings (titles only; evidence is intentionally omitted from email):\n"
        + ("\n".join(finding_lines) if finding_lines else "- No finding titles were recorded.")
        + "\n\nOpen ReconTitan to review evidence and remediation guidance."
    )
    return message


def send_scan_alert(report: dict[str, Any]) -> dict[str, Any]:
    """Send one non-fatal email after a completed scan, when configured."""
    counts = alert_counts(report)
    if not any(counts.values()):
        return {"status": "not_triggered", "counts": counts}
    if not settings.EMAIL_ALERTS_ENABLED:
        return {"status": "disabled", "counts": counts}
    if not (settings.SMTP_HOST and settings.SMTP_FROM and settings.ALERT_EMAIL_RECIPIENTS):
        logger.error("Email alerts enabled but SMTP_HOST, SMTP_FROM, or ALERT_EMAIL_RECIPIENTS is missing")
        return {"status": "misconfigured", "counts": counts}
    if bool(settings.SMTP_USERNAME) != bool(settings.SMTP_PASSWORD):
        logger.error("Email alerts enabled with incomplete SMTP credentials")
        return {"status": "misconfigured", "counts": counts}

    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=settings.SMTP_TIMEOUT_SECONDS) as client:
            client.ehlo()
            if settings.SMTP_USE_TLS:
                client.starttls(context=ssl.create_default_context())
                client.ehlo()
            if settings.SMTP_USERNAME:
                client.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
            client.send_message(_message(report, counts))
    except (OSError, smtplib.SMTPException):
        # Delivery failures must never turn a completed security scan into a
        # failed one. Details stay in operator logs, not in the browser report.
        logger.exception("Could not deliver scan alert")
        return {"status": "failed", "counts": counts}
    logger.info("Sent scan alert for %s (%s)", str(report.get("scan_id", "local"))[:100], counts)
    return {"status": "sent", "counts": counts}
