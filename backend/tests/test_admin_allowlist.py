"""Network allowlist for the admin surface.

The token is strong, but it is one secret and it is the *only* thing between
the internet and the console on any deployment that cannot hide the port. An
allowlist turns that into two independent controls: be on the network, then
hold the secret.

Order matters as much as the check. The allowlist runs before the lockout
counter and before the token comparison, so a refused source cannot burn
another source's attempt budget and learns nothing about whether a token was
close.
"""

from __future__ import annotations

import pytest

from app.admin import deps
from app.config import Settings


class _Request:
    def __init__(self, host="127.0.0.1", headers=None):
        self.client = type("C", (), {"host": host})()
        self.headers = headers or {}
        self.method = "GET"
        self.state = type("S", (), {})()

        class _URL:
            path = "/api/overview"
        self.url = _URL()


# ── Matching ────────────────────────────────────────────────────────────────

def test_an_empty_allowlist_permits_everyone(monkeypatch):
    """The pre-existing behaviour: an upgrade must not lock an operator out."""
    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", [])
    assert deps.ip_allowed("203.0.113.9") is True
    assert deps.ip_allowed("127.0.0.1") is True


def test_a_listed_address_is_permitted(monkeypatch):
    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["203.0.113.9"])
    assert deps.ip_allowed("203.0.113.9") is True


def test_an_unlisted_address_is_refused(monkeypatch):
    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["203.0.113.9"])
    assert deps.ip_allowed("203.0.113.10") is False


def test_a_cidr_range_covers_its_members(monkeypatch):
    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["10.8.0.0/24"])
    assert deps.ip_allowed("10.8.0.1") is True
    assert deps.ip_allowed("10.8.0.254") is True
    assert deps.ip_allowed("10.8.1.1") is False


def test_several_entries_are_all_honoured(monkeypatch):
    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["127.0.0.1/32", "10.8.0.0/24"])
    assert deps.ip_allowed("127.0.0.1") is True
    assert deps.ip_allowed("10.8.0.5") is True
    assert deps.ip_allowed("8.8.8.8") is False


def test_ipv6_is_supported(monkeypatch):
    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["2001:db8::/32", "::1"])
    assert deps.ip_allowed("2001:db8::5") is True
    assert deps.ip_allowed("::1") is True
    assert deps.ip_allowed("2001:db9::5") is False


def test_an_unparseable_source_is_refused(monkeypatch):
    """"I cannot tell who this is" is not a reason to admit someone."""
    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["127.0.0.1"])
    assert deps.ip_allowed("testclient") is False
    assert deps.ip_allowed("unknown") is False
    assert deps.ip_allowed("") is False


def test_a_malformed_entry_is_skipped_not_fatal(monkeypatch):
    """One typo must not silently disable the whole control."""
    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["not-an-ip", "10.8.0.0/24"])
    assert deps.ip_allowed("10.8.0.5") is True
    assert deps.ip_allowed("8.8.8.8") is False


# ── Enforcement order ───────────────────────────────────────────────────────

def test_a_refused_source_never_reaches_the_token(monkeypatch):
    from fastapi import HTTPException

    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["10.8.0.0/24"])

    def _must_not_run(_supplied):
        raise AssertionError("the token must not be compared for a refused source")

    monkeypatch.setattr(deps.auth, "token_matches", _must_not_run)

    with pytest.raises(HTTPException) as excinfo:
        deps.require_admin(_Request("203.0.113.9", {"x-recontitan-admin": "whatever"}))
    assert excinfo.value.status_code == 403


def test_a_refused_source_does_not_consume_the_lockout_budget(monkeypatch):
    """Otherwise an outsider could lock a legitimate operator out."""
    from fastapi import HTTPException

    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["10.8.0.0/24"])

    def _must_not_run(_source):
        raise AssertionError("a refused source must not register a failure")

    monkeypatch.setattr(deps.auth, "register_failure", _must_not_run)

    with pytest.raises(HTTPException):
        deps.require_admin(_Request("203.0.113.9"))


def test_an_allowed_source_still_needs_the_token(monkeypatch):
    """The allowlist adds a control; it never replaces one."""
    from fastapi import HTTPException

    monkeypatch.setattr(deps.settings, "ADMIN_IP_ALLOWLIST", ["10.8.0.0/24"])
    monkeypatch.setattr(deps.auth, "token_matches", lambda _s: False)
    monkeypatch.setattr(deps.auth, "register_failure", lambda _s: 0)
    monkeypatch.setattr(deps.auth, "lockout_remaining", lambda _s: 0)

    with pytest.raises(HTTPException) as excinfo:
        deps.require_admin(_Request("10.8.0.5", {"x-recontitan-admin": "wrong"}))
    assert excinfo.value.status_code == 401


# ── Configuration ───────────────────────────────────────────────────────────

def test_the_setting_parses_a_comma_separated_list(monkeypatch):
    monkeypatch.setenv("ADMIN_IP_ALLOWLIST", "127.0.0.1/32, 10.8.0.0/24 ,203.0.113.9")
    assert Settings().ADMIN_IP_ALLOWLIST == ["127.0.0.1/32", "10.8.0.0/24", "203.0.113.9"]


def test_the_setting_defaults_to_unrestricted(monkeypatch):
    monkeypatch.delenv("ADMIN_IP_ALLOWLIST", raising=False)
    assert Settings().ADMIN_IP_ALLOWLIST == []
