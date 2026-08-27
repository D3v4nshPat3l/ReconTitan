"""Named API keys: independent revocation and audit attribution.

One shared secret means a deployment cannot tell its callers apart, and cannot
revoke a leaked credential without cutting off everyone at once. Named keys fix
both without introducing accounts or roles -- these are still all-or-nothing
credentials, and the label is an audit handle, not a privilege.

Backwards compatibility is the load-bearing property here: an existing
deployment sets only API_ACCESS_KEY and must keep working untouched.
"""

from __future__ import annotations

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.config import Settings, settings
from app.main import app
from app.middleware import security
from app.middleware.security import rate_limiter

KEY_A = "a" * 40
KEY_B = "b" * 40


@pytest.fixture(autouse=True)
def _clean_limiter():
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()
    yield
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()


# ── Parsing ─────────────────────────────────────────────────────────────────

def test_named_keys_are_parsed_into_labelled_secrets(monkeypatch):
    monkeypatch.setenv("API_ACCESS_KEYS", f"ci:{KEY_A},scanner-ui:{KEY_B}")
    monkeypatch.delenv("API_ACCESS_KEY", raising=False)

    keys = Settings().API_ACCESS_KEYS
    assert keys == {KEY_A: "ci", KEY_B: "scanner-ui"}


def test_a_bare_comma_separated_list_still_works(monkeypatch):
    """No colon means no label, not a broken entry."""
    monkeypatch.setenv("API_ACCESS_KEYS", f"{KEY_A},{KEY_B}")
    monkeypatch.delenv("API_ACCESS_KEY", raising=False)

    keys = Settings().API_ACCESS_KEYS
    assert set(keys) == {KEY_A, KEY_B}
    assert all(label for label in keys.values()), "every key needs some audit label"


def test_whitespace_and_empty_entries_are_ignored(monkeypatch):
    monkeypatch.setenv("API_ACCESS_KEYS", f"  ci : {KEY_A} , , ")
    monkeypatch.delenv("API_ACCESS_KEY", raising=False)
    assert Settings().API_ACCESS_KEYS == {KEY_A: "ci"}


def test_the_legacy_single_key_is_still_accepted(monkeypatch):
    """The whole point: an existing deployment changes nothing."""
    monkeypatch.delenv("API_ACCESS_KEYS", raising=False)
    monkeypatch.setenv("API_ACCESS_KEY", KEY_A)

    assert Settings().API_ACCESS_KEYS == {KEY_A: "default"}


def test_legacy_and_named_keys_coexist(monkeypatch):
    monkeypatch.setenv("API_ACCESS_KEY", KEY_A)
    monkeypatch.setenv("API_ACCESS_KEYS", f"ci:{KEY_B}")

    keys = Settings().API_ACCESS_KEYS
    assert keys[KEY_A] == "default"
    assert keys[KEY_B] == "ci"


def test_no_keys_configured_means_the_gate_is_off(monkeypatch):
    monkeypatch.delenv("API_ACCESS_KEY", raising=False)
    monkeypatch.delenv("API_ACCESS_KEYS", raising=False)
    assert Settings().API_ACCESS_KEYS == {}


def test_assigning_the_legacy_key_at_runtime_takes_effect(monkeypatch):
    """API_ACCESS_KEYS is derived, not snapshotted, so a live process can be
    reconfigured -- and monkeypatching it in tests still means something."""
    monkeypatch.delenv("API_ACCESS_KEY", raising=False)
    monkeypatch.delenv("API_ACCESS_KEYS", raising=False)
    instance = Settings()
    assert instance.API_ACCESS_KEYS == {}

    instance.API_ACCESS_KEY = KEY_A
    assert instance.API_ACCESS_KEYS == {KEY_A: "default"}


# ── Matching ────────────────────────────────────────────────────────────────

def test_any_configured_key_authenticates(monkeypatch):
    monkeypatch.setattr(settings, "_NAMED_API_KEYS", {KEY_A: "ci", KEY_B: "scanner-ui"})
    monkeypatch.setattr(settings, "API_ACCESS_KEY", "")

    assert security._match_api_key(KEY_A) == "ci"
    assert security._match_api_key(KEY_B) == "scanner-ui"


def test_an_unknown_key_matches_nothing(monkeypatch):
    monkeypatch.setattr(settings, "_NAMED_API_KEYS", {KEY_A: "ci"})
    monkeypatch.setattr(settings, "API_ACCESS_KEY", "")

    assert security._match_api_key("c" * 40) is None
    assert security._match_api_key("") is None


def test_a_key_prefix_does_not_authenticate(monkeypatch):
    """Guards against a substring or startswith comparison creeping in."""
    monkeypatch.setattr(settings, "_NAMED_API_KEYS", {KEY_A: "ci"})
    monkeypatch.setattr(settings, "API_ACCESS_KEY", "")

    assert security._match_api_key(KEY_A[:20]) is None
    assert security._match_api_key(KEY_A + "extra") is None


def test_revoking_one_key_leaves_the_others_working(monkeypatch):
    """The reason named keys exist: revocation must not be all-or-nothing."""
    monkeypatch.setattr(settings, "API_ACCESS_KEY", "")
    monkeypatch.setattr(settings, "_NAMED_API_KEYS", {KEY_A: "ci", KEY_B: "scanner-ui"})
    assert security._match_api_key(KEY_A) == "ci"

    monkeypatch.setattr(settings, "_NAMED_API_KEYS", {KEY_B: "scanner-ui"})
    assert security._match_api_key(KEY_A) is None
    assert security._match_api_key(KEY_B) == "scanner-ui"


# ── End to end through the middleware ───────────────────────────────────────

def test_each_named_key_is_accepted_over_http(monkeypatch):
    monkeypatch.setattr(settings, "API_ACCESS_KEY", "")
    monkeypatch.setattr(settings, "_NAMED_API_KEYS", {KEY_A: "ci", KEY_B: "scanner-ui"})

    with TestClient(app) as client:
        assert client.get("/api/ai/status", headers={"X-ReconTitan-Key": KEY_A}).status_code == 200
        rate_limiter.requests.clear()
        assert client.get("/api/ai/status", headers={"X-ReconTitan-Key": KEY_B}).status_code == 200
        rate_limiter.requests.clear()
        assert client.get("/api/ai/status", headers={"X-ReconTitan-Key": "z" * 40}).status_code == 401


def test_bearer_authentication_also_accepts_named_keys(monkeypatch):
    monkeypatch.setattr(settings, "API_ACCESS_KEY", "")
    monkeypatch.setattr(settings, "_NAMED_API_KEYS", {KEY_A: "ci"})

    with TestClient(app) as client:
        response = client.get("/api/ai/status", headers={"Authorization": f"Bearer {KEY_A}"})
    assert response.status_code == 200


def test_the_caller_label_is_attached_for_the_audit_trail(monkeypatch):
    """End to end: the label the middleware resolved must reach request.state.

    Without it the audit trail records that *someone* holding a valid
    credential acted, which is not attribution when the credential is shared.
    A temporary route reads the attribute back out of a request the real app
    handled, so a refactor that drops the assignment fails here rather than
    silently stripping attribution from every audit record.
    """
    monkeypatch.setattr(settings, "API_ACCESS_KEY", "")
    monkeypatch.setattr(settings, "_NAMED_API_KEYS", {KEY_A: "ci", KEY_B: "scanner-ui"})

    path = "/api/_test_caller_label"

    # `Request` must be resolvable from module globals: this file uses
    # `from __future__ import annotations`, so FastAPI sees the annotation as
    # the string "Request" and looks it up there. An import local to this
    # function would leave it unresolvable, and the parameter would be treated
    # as a query field -- a 422 instead of the route running.
    async def _echo_caller(request: Request):
        return {"caller": getattr(request.state, "api_caller", None)}

    app.add_api_route(path, _echo_caller, methods=["GET"])
    # main.py mounts StaticFiles at "/" last, and Starlette matches in order,
    # so an appended route is unreachable. Move it in front of that catch-all.
    app.router.routes.insert(0, app.router.routes.pop())
    try:
        with TestClient(app) as client:
            first = client.get(path, headers={"X-ReconTitan-Key": KEY_A})
            rate_limiter.requests.clear()
            second = client.get(path, headers={"X-ReconTitan-Key": KEY_B})
            rate_limiter.requests.clear()
            rejected = client.get(path, headers={"X-ReconTitan-Key": "z" * 40})
    finally:
        app.router.routes[:] = [
            route for route in app.router.routes if getattr(route, "path", None) != path
        ]

    assert first.status_code == 200
    assert first.json()["caller"] == "ci"
    assert second.json()["caller"] == "scanner-ui", "each key must be attributed to its own label"
    assert rejected.status_code == 401


def test_audit_event_records_the_caller_label():
    """_base_event copies request.state.api_caller, and never the secret."""
    from app.services import audit

    class _State:
        api_caller = "ci"

    class _Request:
        method = "GET"
        state = _State()
        headers = {"user-agent": "pytest"}

        class url:
            path = "/api/scan"

    event = audit._base_event("scan.started", _Request())
    assert event["api_caller"] == "ci"
    assert KEY_A not in str(event)


def test_audit_event_omits_the_caller_when_unauthenticated():
    from app.services import audit

    class _Request:
        method = "GET"
        state = type("S", (), {})()
        headers = {"user-agent": "pytest"}

        class url:
            path = "/api/health"

    assert "api_caller" not in audit._base_event("http.request", _Request())


# ── Production validation ───────────────────────────────────────────────────

def _production(monkeypatch) -> Settings:
    monkeypatch.setenv("RECONTITAN_DEBUG", "false")
    monkeypatch.setenv("DOMAIN", "scanner.example.com")
    monkeypatch.setenv("SECRET_KEY", "s" * 40)
    monkeypatch.setenv("CORS_ORIGINS", "https://scanner.example.com")
    return Settings()


def test_named_keys_alone_satisfy_production(monkeypatch):
    """A deployment using only API_ACCESS_KEYS is configured, and must not be
    told to also set the legacy variable."""
    monkeypatch.delenv("API_ACCESS_KEY", raising=False)
    monkeypatch.setenv("API_ACCESS_KEYS", f"ci:{KEY_A}")
    _production(monkeypatch).validate_production()


def test_production_rejects_a_short_named_key(monkeypatch):
    monkeypatch.delenv("API_ACCESS_KEY", raising=False)
    monkeypatch.setenv("API_ACCESS_KEYS", "ci:short")

    with pytest.raises(RuntimeError, match="at least 32 characters"):
        _production(monkeypatch).validate_production()


def test_the_offending_key_is_named_in_the_error(monkeypatch):
    """An operator with several keys needs to know which one is weak."""
    monkeypatch.delenv("API_ACCESS_KEY", raising=False)
    monkeypatch.setenv("API_ACCESS_KEYS", f"good:{KEY_A},weak-one:tooshort")

    with pytest.raises(RuntimeError, match="weak-one"):
        _production(monkeypatch).validate_production()


def test_production_still_rejects_no_keys_at_all(monkeypatch):
    monkeypatch.delenv("API_ACCESS_KEY", raising=False)
    monkeypatch.delenv("API_ACCESS_KEYS", raising=False)

    with pytest.raises(RuntimeError, match="API_ACCESS_KEY"):
        _production(monkeypatch).validate_production()
