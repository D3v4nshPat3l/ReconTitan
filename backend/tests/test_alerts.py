"""Alert delivery is mocked; the suite never contacts an SMTP server."""

from email.message import EmailMessage

import pytest

from app.services import alerts


@pytest.fixture(autouse=True)
def alert_settings(monkeypatch):
    monkeypatch.setattr(alerts.settings, "EMAIL_ALERTS_ENABLED", False)
    monkeypatch.setattr(alerts.settings, "ALERT_MIN_SEVERITY", "high")
    monkeypatch.setattr(alerts.settings, "ALERT_EMAIL_RECIPIENTS", ["security@example.com"])
    monkeypatch.setattr(alerts.settings, "SMTP_HOST", "smtp.example.com")
    monkeypatch.setattr(alerts.settings, "SMTP_PORT", 587)
    monkeypatch.setattr(alerts.settings, "SMTP_USERNAME", "scanner")
    monkeypatch.setattr(alerts.settings, "SMTP_PASSWORD", "not-a-real-password")
    monkeypatch.setattr(alerts.settings, "SMTP_FROM", "ReconTitan <alerts@example.com>")
    monkeypatch.setattr(alerts.settings, "SMTP_USE_TLS", True)
    monkeypatch.setattr(alerts.settings, "SMTP_TIMEOUT_SECONDS", 9)


def report(**counts):
    return {
        "scan_id": "scan_example", "target": "example.com", "severity_counts": counts,
        "findings": [
            {"severity": "critical", "title": "Header\ninjection attempt"},
            {"severity": "high", "title": "Exposed admin panel"},
            {"severity": "low", "title": "This must not be mailed"},
        ],
    }


def test_only_high_and_critical_counts_trigger_by_default():
    assert alerts.alert_counts(report(critical="2", high=1, low=999)) == {"critical": 2, "high": 1}
    assert alerts.send_scan_alert(report(low=99))["status"] == "not_triggered"


def test_queued_records_without_precomputed_counts_still_trigger():
    queued_record = report()
    queued_record.pop("severity_counts")
    assert alerts.alert_counts(queued_record) == {"critical": 1, "high": 1}


def test_critical_threshold_ignores_high(monkeypatch):
    monkeypatch.setattr(alerts.settings, "ALERT_MIN_SEVERITY", "critical")
    assert alerts.send_scan_alert(report(high=1))["status"] == "not_triggered"
    assert alerts.alert_counts(report(critical=1, high=9)) == {"critical": 1}


def test_disabled_alerts_do_not_open_smtp(monkeypatch):
    monkeypatch.setattr(alerts.smtplib, "SMTP", lambda *a, **k: pytest.fail("SMTP must not be opened"))
    assert alerts.send_scan_alert(report(critical=1))["status"] == "disabled"


def test_configured_alert_uses_tls_auth_and_never_includes_evidence(monkeypatch):
    sent = {}

    class SMTP:
        def __init__(self, host, port, timeout):
            sent.update(host=host, port=port, timeout=timeout)
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def ehlo(self): sent["ehlo"] = sent.get("ehlo", 0) + 1
        def starttls(self, context): sent["tls"] = context
        def login(self, username, password): sent["login"] = (username, password)
        def send_message(self, message): sent["message"] = message

    monkeypatch.setattr(alerts.settings, "EMAIL_ALERTS_ENABLED", True)
    monkeypatch.setattr(alerts.smtplib, "SMTP", SMTP)
    payload = report(critical=1, high=1)
    payload["findings"][0]["evidence"] = "super-secret-token"
    result = alerts.send_scan_alert(payload)
    assert result == {"status": "sent", "counts": {"critical": 1, "high": 1}}
    assert sent["host"] == "smtp.example.com" and sent["port"] == 587 and sent["timeout"] == 9
    assert sent["ehlo"] == 2 and sent["login"] == ("scanner", "not-a-real-password")
    assert isinstance(sent["message"], EmailMessage)
    body = sent["message"].get_content()
    assert "CRITICAL: Header injection attempt" in body
    assert "super-secret-token" not in body
    assert "This must not be mailed" not in body


def test_misconfiguration_and_delivery_failure_are_non_fatal(monkeypatch):
    monkeypatch.setattr(alerts.settings, "EMAIL_ALERTS_ENABLED", True)
    monkeypatch.setattr(alerts.settings, "SMTP_FROM", "")
    assert alerts.send_scan_alert(report(critical=1))["status"] == "misconfigured"
    monkeypatch.setattr(alerts.settings, "SMTP_FROM", "alerts@example.com")
    monkeypatch.setattr(alerts.smtplib, "SMTP", lambda *a, **k: (_ for _ in ()).throw(OSError("offline")))
    assert alerts.send_scan_alert(report(critical=1))["status"] == "failed"


def test_message_headers_and_titles_cannot_be_split_by_finding_data():
    message = alerts._message(report(critical=1), {"critical": 1, "high": 0})
    assert "\n" not in str(message["Subject"])
    assert "Header\ninjection" not in message.get_content()
