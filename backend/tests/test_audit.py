"""Audit trail: attribution, retention, and flood resistance.

The admin and SOC dashboards read only from this trail, so a gap here is a
blind spot there. The coalescing tests matter most: security events are
emitted exactly when someone is attacking the service, so the trail must not
turn a request flood into a database write flood.
"""

from __future__ import annotations

import pytest

from app.services import audit


class _FakeClient:
    def __init__(self, host):
        self.host = host


class _FakeRequest:
    def __init__(self, ip="203.0.113.9", ua="curl/8.0", path="/api/scan", method="POST", key=None):
        self.client = _FakeClient(ip)
        self.method = method
        self.headers = {"user-agent": ua}
        if key:
            self.headers["x-recontitan-key"] = key
        self.url = type("U", (), {"path": path})()


@pytest.fixture(autouse=True)
def _captured(monkeypatch):
    """Capture writes instead of touching MongoDB."""
    written: list[dict] = []
    monkeypatch.setattr(audit, "_write", lambda docs: written.extend(docs))
    monkeypatch.setattr(audit.settings, "AUDIT_ENABLED", True)
    with audit._lock:
        audit._pending.clear()
    yield written
    with audit._lock:
        audit._pending.clear()


# ── Attribution ──────────────────────────────────────────────────────────────

def test_scan_event_records_who_and_what(_captured):
    audit.record_scan_event(
        audit.SCAN_ACCEPTED, _FakeRequest(ip="198.51.100.4"),
        scan_id="scan_abc123abc123", target="example.com", scan_type="danger",
    )
    event = _captured[0]
    assert event["kind"] == audit.SCAN_ACCEPTED
    assert event["ip"] == "198.51.100.4"
    assert event["target"] == "example.com"
    assert event["scan_type"] == "danger"
    assert event["user_agent"] == "curl/8.0"
    assert event["at"] is not None


def test_gate_denial_is_recorded(_captured):
    """A rejected danger scan is a signal worth keeping, not just a 403."""
    audit.record_scan_event(
        audit.SCAN_GATE_DENIED, _FakeRequest(), target="example.com", reason="disabled"
    )
    assert _captured[0]["kind"] == audit.SCAN_GATE_DENIED
    assert _captured[0]["reason"] == "disabled"


def test_api_key_is_fingerprinted_never_stored():
    """The trail identifies which key was used without holding the secret."""
    fingerprint = audit.key_fingerprint("super-secret-access-key")
    assert fingerprint.startswith("k_")
    assert "super-secret-access-key" not in fingerprint
    assert audit.key_fingerprint("super-secret-access-key") == fingerprint
    assert audit.key_fingerprint("different-key") != fingerprint
    assert audit.key_fingerprint("") == ""
    assert audit.key_fingerprint(None) == ""


def test_client_ip_uses_the_proxy_rewritten_value():
    """uvicorn --proxy-headers already rewrote this; raw headers are spoofable."""
    request = _FakeRequest(ip="203.0.113.9")
    request.headers["x-forwarded-for"] = "1.2.3.4"
    assert audit.client_ip(request) == "203.0.113.9"


def test_client_ip_survives_a_missing_client():
    request = _FakeRequest()
    request.client = None
    assert audit.client_ip(request) == "unknown"


# ── Untrusted input is bounded and flattened ─────────────────────────────────

def test_attacker_controlled_fields_are_length_bounded(_captured):
    audit.record_scan_event(audit.SCAN_REJECTED, _FakeRequest(ua="A" * 5000), target="B" * 5000)
    event = _captured[0]
    assert len(event["user_agent"]) <= 256
    assert len(event["target"]) <= 512


def test_newlines_cannot_forge_extra_log_lines(_captured):
    """A crafted user agent must not be able to fake entries in a log view."""
    audit.record_scan_event(
        audit.SCAN_REJECTED,
        _FakeRequest(ua="real\nkind=admin.login\nip=127.0.0.1"),
        target="example.com",
    )
    assert "\n" not in _captured[0]["user_agent"]
    assert "\r" not in _captured[0]["user_agent"]


# ── Flood resistance ─────────────────────────────────────────────────────────

def test_repeated_attacks_coalesce_into_one_counted_document(_captured, monkeypatch):
    """1000 blocked injections must not become 1000 database writes."""
    monkeypatch.setattr(audit.settings, "AUDIT_FLUSH_SECONDS", 3600)  # no time flush
    request = _FakeRequest(ip="203.0.113.66")
    for _ in range(1000):
        audit.record_security_event(audit.INJECTION_BLOCKED, request, detail="sqli")

    assert _captured == [], "nothing should have been written yet"
    audit.flush()
    assert len(_captured) == 1, "1000 identical events must collapse to one document"
    assert _captured[0]["count"] == 1000
    assert _captured[0]["ip"] == "203.0.113.66"


def test_distinct_sources_stay_separate(_captured, monkeypatch):
    monkeypatch.setattr(audit.settings, "AUDIT_FLUSH_SECONDS", 3600)
    for octet in range(5):
        audit.record_security_event(
            audit.AUTH_FAILED, _FakeRequest(ip=f"203.0.113.{octet}"), detail="invalid key"
        )
    audit.flush()
    assert len({event["ip"] for event in _captured}) == 5


def test_pending_buffer_is_bounded(_captured, monkeypatch):
    """A source rotating payloads must not grow the buffer without limit."""
    monkeypatch.setattr(audit.settings, "AUDIT_FLUSH_SECONDS", 3600)
    monkeypatch.setattr(audit.settings, "AUDIT_MAX_PENDING", 50)
    request = _FakeRequest()
    for i in range(500):
        audit.record_security_event(audit.INJECTION_BLOCKED, request, detail=f"payload-{i}")
    with audit._lock:
        assert len(audit._pending) <= 50


def test_flush_happens_on_a_timer(_captured, monkeypatch):
    monkeypatch.setattr(audit.settings, "AUDIT_FLUSH_SECONDS", 0)
    audit.record_security_event(audit.RATE_LIMITED, _FakeRequest(), detail="/api/scan")
    assert _captured, "a zero-second window should flush immediately"


# ── Fail-soft ────────────────────────────────────────────────────────────────

def test_a_failing_write_never_raises(monkeypatch):
    """Losing an audit record is bad; failing the user's request is worse."""
    def boom(_docs):
        raise RuntimeError("mongo down")

    monkeypatch.setattr(audit, "_write", boom)
    monkeypatch.setattr(audit.settings, "AUDIT_ENABLED", True)
    audit.record_scan_event(audit.SCAN_ACCEPTED, _FakeRequest(), target="example.com")
    monkeypatch.setattr(audit.settings, "AUDIT_FLUSH_SECONDS", 0)
    audit.record_security_event(audit.AUTH_FAILED, _FakeRequest())


def test_a_broken_request_object_never_raises(_captured):
    audit.record_scan_event(audit.SCAN_ACCEPTED, object(), target="example.com")
    assert _captured[0]["kind"] == audit.SCAN_ACCEPTED


def test_auditing_can_be_disabled(_captured, monkeypatch):
    monkeypatch.setattr(audit.settings, "AUDIT_ENABLED", False)
    audit.record_scan_event(audit.SCAN_ACCEPTED, _FakeRequest(), target="example.com")
    audit.record_security_event(audit.AUTH_FAILED, _FakeRequest())
    audit.flush()
    assert _captured == []


# ── Retention ────────────────────────────────────────────────────────────────

def test_retention_is_bounded_by_default():
    """This collection holds IP addresses, so it must expire, not accumulate."""
    from app.config import settings

    assert 1 <= settings.AUDIT_RETENTION_DAYS <= 365


def test_ttl_index_is_configured():
    import inspect

    source = inspect.getsource(audit._ensure_indexes)
    assert "expireAfterSeconds" in source
    assert "AUDIT_RETENTION_DAYS" in source


# ── Middleware wiring ────────────────────────────────────────────────────────

@pytest.mark.parametrize("hook", [
    "auth.failed",
    "injection.blocked",
    "ratelimit.exceeded",
    "agent.blocked",
])
def test_middleware_reports_each_attack_class(hook):
    """A SOC view is only as good as the events the middleware actually emits."""
    from pathlib import Path

    source = Path(audit.__file__).resolve().parents[1] / "middleware" / "security.py"
    assert hook in source.read_text(encoding="utf-8"), f"middleware never emits {hook}"


def test_scan_records_carry_attribution():
    from pathlib import Path

    source = (Path(audit.__file__).resolve().parents[1] / "routers" / "scans.py").read_text(encoding="utf-8")
    for field in ("client_ip", "user_agent", "api_key_id"):
        assert f'"{field}"' in source, f"scan record is missing {field}"
