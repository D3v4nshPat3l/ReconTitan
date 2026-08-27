"""Rotating the admin token without a flag day.

Changing a single static token breaks every session and script at the instant
the process restarts. That cost is why tokens in practice never get rotated at
all, which is the real security problem — a token that is never changed is one
leak away from permanent access.

An overlap window makes rotation routine: publish the new token, keep accepting
the old one, watch the log for anything still using it, then clear it.
"""

from __future__ import annotations

import pytest

from app.admin import auth
from app.config import Settings

CURRENT = "c" * 48
PREVIOUS = "p" * 48


@pytest.fixture(autouse=True)
def _tokens(monkeypatch):
    monkeypatch.setattr(auth.settings, "ADMIN_TOKEN", CURRENT)
    monkeypatch.setattr(auth.settings, "ADMIN_TOKEN_PREVIOUS", "")
    monkeypatch.setattr(auth.settings, "ADMIN_MIN_TOKEN_LENGTH", 32)


# ── Acceptance ──────────────────────────────────────────────────────────────

def test_the_current_token_is_accepted():
    assert auth.token_matches(CURRENT) is True


def test_a_wrong_token_is_refused():
    assert auth.token_matches("x" * 48) is False


def test_an_empty_token_is_refused():
    assert auth.token_matches("") is False
    assert auth.token_matches("   ") is False


def test_the_previous_token_is_accepted_during_rotation(monkeypatch):
    monkeypatch.setattr(auth.settings, "ADMIN_TOKEN_PREVIOUS", PREVIOUS)
    assert auth.token_matches(PREVIOUS) is True
    assert auth.token_matches(CURRENT) is True


def test_the_previous_token_stops_working_once_cleared():
    """Finishing the rotation is what actually revokes the old token."""
    assert auth.token_matches(PREVIOUS) is False


def test_use_of_the_old_token_is_logged(monkeypatch, caplog):
    """The overlap is only useful if it tells you who has not moved yet."""
    monkeypatch.setattr(auth.settings, "ADMIN_TOKEN_PREVIOUS", PREVIOUS)
    with caplog.at_level("WARNING"):
        assert auth.token_matches(PREVIOUS) is True
    assert any("ADMIN_TOKEN_PREVIOUS" in r.message for r in caplog.records)


def test_using_the_current_token_logs_nothing(monkeypatch, caplog):
    monkeypatch.setattr(auth.settings, "ADMIN_TOKEN_PREVIOUS", PREVIOUS)
    with caplog.at_level("WARNING"):
        auth.token_matches(CURRENT)
    assert not any("ADMIN_TOKEN_PREVIOUS" in r.message for r in caplog.records)


def test_a_wrong_token_is_still_refused_mid_rotation(monkeypatch):
    monkeypatch.setattr(auth.settings, "ADMIN_TOKEN_PREVIOUS", PREVIOUS)
    assert auth.token_matches("x" * 48) is False


# ── Misconfiguration is refused at startup ──────────────────────────────────

def _production(monkeypatch, **env):
    monkeypatch.setenv("ADMIN_ENABLED", "true")
    monkeypatch.setenv("ADMIN_TOKEN", CURRENT)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings()


def test_an_identical_previous_token_is_not_a_rotation(monkeypatch):
    settings = _production(monkeypatch, ADMIN_TOKEN_PREVIOUS=CURRENT)
    monkeypatch.setattr(auth, "settings", settings)
    with pytest.raises(RuntimeError, match="identical"):
        auth.assert_safely_configured()


def test_a_short_previous_token_is_refused(monkeypatch):
    """Rotation must not be a route to keep a weak token alive."""
    settings = _production(monkeypatch, ADMIN_TOKEN_PREVIOUS="short")
    monkeypatch.setattr(auth, "settings", settings)
    with pytest.raises(RuntimeError, match="shorter than the minimum"):
        auth.assert_safely_configured()


def test_a_valid_rotation_starts_cleanly(monkeypatch):
    settings = _production(monkeypatch, ADMIN_TOKEN_PREVIOUS=PREVIOUS)
    monkeypatch.setattr(auth, "settings", settings)
    auth.assert_safely_configured()


def test_no_rotation_configured_is_the_normal_case(monkeypatch):
    monkeypatch.delenv("ADMIN_TOKEN_PREVIOUS", raising=False)
    settings = _production(monkeypatch)
    assert settings.ADMIN_TOKEN_PREVIOUS == ""
    monkeypatch.setattr(auth, "settings", settings)
    auth.assert_safely_configured()
