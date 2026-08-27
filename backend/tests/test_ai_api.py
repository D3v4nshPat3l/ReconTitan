"""Endpoint tests for the AI narration routes.

The module-level logic is covered in test_ai_ollama.py. What matters here is
the HTTP contract: schema validation, the shape the report page consumes, and
the guarantee that these routes stay useful with no model reachable -- a dead
Ollama must degrade the answer, never fail the request.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.middleware.security import rate_limiter
from app.tasks import ai_analysis


@pytest.fixture
def client() -> TestClient:
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()
    return TestClient(app)


@pytest.fixture(autouse=True)
def _offline(monkeypatch):
    """No test may contact a model. Offline is also the interesting case."""
    ai_analysis._probe_cache.update({"checked_at": 0.0, "available": False, "model": "", "error": ""})
    monkeypatch.setattr(ai_analysis.settings, "OPENAI_API_KEY", "")
    monkeypatch.setattr(
        ai_analysis, "_ollama_models", lambda: (_ for _ in ()).throw(ConnectionError("refused"))
    )
    yield
    ai_analysis._probe_cache.update({"checked_at": 0.0, "available": False, "model": "", "error": ""})


# ── GET /api/ai/status ──────────────────────────────────────────────────────

def test_status_reports_fallback_and_the_reason(client):
    body = client.get("/api/ai/status").json()

    assert body["active_backend"] == "fallback"
    assert body["ollama"]["available"] is False
    assert body["ollama"]["error"], "the UI needs a reason to show the operator"


def test_status_never_leaks_the_openai_key(client, monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "OPENAI_API_KEY", "sk-secret-value-not-for-browsers")

    raw = client.get("/api/ai/status").text
    assert "sk-secret-value-not-for-browsers" not in raw
    assert client.get("/api/ai/status").json()["openai"]["configured"] is True


def test_status_reports_disabled_when_provider_is_none(client, monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "AI_PROVIDER", "none")
    body = client.get("/api/ai/status").json()
    assert body["enabled"] is False
    assert body["active_backend"] == "fallback"


# ── POST /api/ai/explain ────────────────────────────────────────────────────

def test_explain_returns_a_usable_answer_with_no_model(client):
    """The button must never show an empty panel because Ollama is down."""
    response = client.post("/api/ai/explain", json={"topic": "CORS misconfiguration"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["ai_generated"] is False
    assert body["ai_backend"] == "fallback"
    assert len(body["explanation"]) > 40


def test_explain_rejects_an_empty_topic(client):
    assert client.post("/api/ai/explain", json={"topic": ""}).status_code == 422


def test_explain_rejects_an_oversized_topic(client):
    assert client.post("/api/ai/explain", json={"topic": "x" * 5000}).status_code == 422


def test_explain_requires_a_json_content_type(client):
    """The middleware enforces JSON on this route like the other POST endpoints."""
    response = client.post(
        "/api/ai/explain",
        content=b"topic=cors",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 415


def test_explain_context_is_bounded(client):
    assert client.post(
        "/api/ai/explain", json={"topic": "cors", "context": "x" * 10_000}
    ).status_code == 422


# ── POST /api/ai/explain-finding ────────────────────────────────────────────

def _finding_payload(**overrides) -> dict:
    payload = {
        "scan_id": "scan-1",
        "finding_id": "finding-1",
        "finding_text": "Missing Security Header: Content-Security-Policy",
        "target": "example.com",
        "severity": "medium",
        "description": "The response did not include a CSP header.",
    }
    payload.update(overrides)
    return payload


def test_explain_finding_echoes_identifiers_and_answers(client):
    body = client.post("/api/ai/explain-finding", json=_finding_payload()).json()

    assert body["scan_id"] == "scan-1"
    assert body["finding_id"] == "finding-1"
    assert body["explanation"]
    assert body["ai_backend"] == "fallback"


def test_explain_finding_rejects_an_unknown_severity(client):
    assert client.post(
        "/api/ai/explain-finding", json=_finding_payload(severity="catastrophic")
    ).status_code == 422


# ── POST /api/verify ────────────────────────────────────────────────────────

def test_verify_degrades_without_claiming_ai_ran(client):
    """The old behaviour reported success unconditionally; the response must
    now say plainly that no model answered."""
    body = client.post("/api/verify", json=_finding_payload()).json()

    assert body["status"] == "ok"
    assert body["ai_available"] is False
    assert body["ai_backend"] == "fallback"
    assert body["assessment"] == "NEEDS_MANUAL_REVIEW"
    assert body["confidence"] == "low"


def test_verify_always_returns_the_shape_the_report_renders(client):
    """report.js reads these keys directly; a missing one renders as blank."""
    body = client.post("/api/verify", json=_finding_payload()).json()

    for key in ("explanation", "impact", "remediation", "references", "assessment", "confidence"):
        assert key in body, f"report.js expects {key}"
    assert isinstance(body["remediation"], list) and body["remediation"]
    assert isinstance(body["references"], list) and body["references"]


def test_verify_rejects_an_oversized_description(client):
    assert client.post(
        "/api/verify", json=_finding_payload(description="x" * 25_000)
    ).status_code == 422


def test_verify_requires_a_scan_id(client):
    assert client.post("/api/verify", json=_finding_payload(scan_id="")).status_code == 422


# ── Shared hardening ────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("get", "/api/ai/status", None),
        ("post", "/api/ai/explain", {"topic": "cors"}),
        ("post", "/api/verify", None),
    ],
)
def test_ai_routes_carry_the_standard_security_headers(client, method, path, payload):
    caller = getattr(client, method)
    response = caller(path, json=payload or _finding_payload()) if method == "post" else caller(path)

    headers = {key.lower() for key in response.headers}
    assert {"x-content-type-options", "x-frame-options", "content-security-policy"}.issubset(headers)


def test_ai_routes_are_not_public_when_a_key_is_configured(monkeypatch):
    """These endpoints accept operator-supplied text and reach a model, so they
    must sit behind the same access key as the rest of /api."""
    from app.config import settings as app_settings

    monkeypatch.setattr(app_settings, "API_ACCESS_KEY", "k" * 40)
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()

    with TestClient(app) as test_client:
        assert test_client.get("/api/ai/status").status_code == 401
        assert test_client.post("/api/ai/explain", json={"topic": "cors"}).status_code == 401
        authorised = test_client.get("/api/ai/status", headers={"X-ReconTitan-Key": "k" * 40})
        assert authorised.status_code == 200
