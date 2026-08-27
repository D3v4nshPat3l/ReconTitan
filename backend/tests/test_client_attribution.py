"""Resolving who made a request, without letting them choose the answer.

`X-Forwarded-For` is set by the client unless something in front of the app
overwrites it. Behind the Compose nginx, uvicorn already rewrites
`request.client`, so reading the header there would let anyone forge their own
source address in the audit trail.

On a serverless platform nothing rewrites it, and `request.client` is the
platform's own proxy — identical for every visitor. Attribution there is either
the header or nothing, so trusting it is opt-in and defaults on only under
SERVERLESS.
"""

from __future__ import annotations

import pytest

from app.config import Settings
from app.services import audit


class _Request:
    def __init__(self, host="10.0.0.5", headers=None):
        self.client = type("C", (), {"host": host})() if host else None
        self.headers = headers or {}


# ── Default posture ─────────────────────────────────────────────────────────

def test_forwarded_header_is_ignored_by_default(monkeypatch):
    """A normal deployment must not let a client name its own address."""
    monkeypatch.setattr(audit.settings, "TRUST_PROXY_HEADERS", False)
    request = _Request("10.0.0.5", {"x-forwarded-for": "1.2.3.4"})
    assert audit.client_ip(request) == "10.0.0.5"


def test_forwarded_header_is_used_when_trusted(monkeypatch):
    monkeypatch.setattr(audit.settings, "TRUST_PROXY_HEADERS", True)
    request = _Request("10.0.0.5", {"x-forwarded-for": "203.0.113.9"})
    assert audit.client_ip(request) == "203.0.113.9"


def test_the_leftmost_entry_is_the_client(monkeypatch):
    """Proxies append themselves, so the originating client is first."""
    monkeypatch.setattr(audit.settings, "TRUST_PROXY_HEADERS", True)
    request = _Request("10.0.0.5", {"x-forwarded-for": "203.0.113.9, 70.41.3.18, 10.0.0.1"})
    assert audit.client_ip(request) == "203.0.113.9"


def test_trusted_but_absent_header_falls_back_to_the_socket(monkeypatch):
    monkeypatch.setattr(audit.settings, "TRUST_PROXY_HEADERS", True)
    assert audit.client_ip(_Request("10.0.0.5", {})) == "10.0.0.5"


def test_an_oversized_forwarded_value_is_refused(monkeypatch):
    """Still attacker-controlled even when trusted; it must not reach storage."""
    monkeypatch.setattr(audit.settings, "TRUST_PROXY_HEADERS", True)
    request = _Request("10.0.0.5", {"x-forwarded-for": "x" * 500})
    assert audit.client_ip(request) == "10.0.0.5"


def test_a_request_without_a_client_is_unknown(monkeypatch):
    monkeypatch.setattr(audit.settings, "TRUST_PROXY_HEADERS", False)
    assert audit.client_ip(_Request(None)) == "unknown"


# ── Where the default comes from ────────────────────────────────────────────

def test_a_server_deployment_does_not_trust_the_header(monkeypatch):
    monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("SERVERLESS", raising=False)
    assert Settings().TRUST_PROXY_HEADERS is False


def test_serverless_trusts_it_because_nothing_else_can(monkeypatch):
    """Otherwise every visitor is recorded as the platform's proxy address."""
    monkeypatch.delenv("TRUST_PROXY_HEADERS", raising=False)
    monkeypatch.setenv("VERCEL", "1")
    assert Settings().TRUST_PROXY_HEADERS is True


def test_an_explicit_setting_overrides_the_platform_default(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("TRUST_PROXY_HEADERS", "false")
    assert Settings().TRUST_PROXY_HEADERS is False


# ── The fingerprint follows the resolved address ────────────────────────────

def test_fingerprint_separates_clients_behind_one_proxy(monkeypatch):
    """The whole point on serverless: two visitors must not collapse into one."""
    monkeypatch.setattr(audit.settings, "TRUST_PROXY_HEADERS", True)
    a = _Request("10.0.0.5", {"x-forwarded-for": "203.0.113.9", "user-agent": "Mozilla/5.0"})
    b = _Request("10.0.0.5", {"x-forwarded-for": "198.51.100.4", "user-agent": "Mozilla/5.0"})
    assert audit.client_fingerprint(a) != audit.client_fingerprint(b)


def test_the_same_client_keeps_one_fingerprint(monkeypatch):
    monkeypatch.setattr(audit.settings, "TRUST_PROXY_HEADERS", True)
    headers = {"x-forwarded-for": "203.0.113.9", "user-agent": "Mozilla/5.0"}
    assert audit.client_fingerprint(_Request("10.0.0.5", headers)) == \
           audit.client_fingerprint(_Request("10.0.0.9", dict(headers)))


def test_recorded_event_carries_the_resolved_address(monkeypatch):
    monkeypatch.setattr(audit.settings, "TRUST_PROXY_HEADERS", True)

    class _Full(_Request):
        method = "GET"
        state = type("S", (), {})()

        class url:
            path = "/api/test-scan"

    event = audit._base_event(
        audit.SCAN_ACCEPTED,
        _Full("10.0.0.5", {"x-forwarded-for": "203.0.113.9", "user-agent": "curl/8"}),
        target="example.com",
    )
    assert event["ip"] == "203.0.113.9"
    assert event["target"] == "example.com"
