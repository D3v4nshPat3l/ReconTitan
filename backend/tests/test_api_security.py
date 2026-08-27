from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.middleware.security import rate_limiter


def client() -> TestClient:
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()
    return TestClient(app)


def test_health_has_hardened_headers_and_no_framework_server():
    with client() as test_client:
        response = test_client.get("/api/health")
    assert response.status_code == 200
    required = {
        "strict-transport-security", "x-content-type-options", "x-frame-options",
        "content-security-policy", "referrer-policy", "permissions-policy",
        "x-dns-prefetch-control", "x-download-options", "x-permitted-cross-domain-policies",
    }
    assert required.issubset({key.lower() for key in response.headers})
    assert "'unsafe-inline'" not in response.headers["content-security-policy"].split("style-src", 1)[0]
    assert response.headers["server"] == "ReconTitan"


def test_injection_private_targets_scanner_ua_and_dangerous_headers_are_blocked():
    with client() as test_client:
        injection = test_client.get("/api/test-scan", params={"target": "' UNION SELECT 1--"})
        private = test_client.get("/api/test-scan", params={"target": "127.0.0.1"})
        scanner = test_client.get("/api/health", headers={"User-Agent": "sqlmap/1.8"})
        dangerous = test_client.get("/api/health", headers={"X-Original-URL": "/admin"})
    assert injection.status_code == 400
    assert private.status_code == 400
    assert scanner.status_code == 403
    assert dangerous.status_code == 400


def test_hidden_paths_and_unsupported_methods_are_blocked():
    with client() as test_client:
        assert test_client.get("/.env").status_code == 404
        assert test_client.delete("/api/health").status_code == 405


def test_large_api_body_is_rejected():
    body = b"x" * (2 * 1024 * 1024 + 1)
    with client() as test_client:
        response = test_client.post("/api/report/pdf", content=body, headers={"Content-Type": "application/json"})
    assert response.status_code == 413


def test_pdf_endpoint_allows_security_evidence_and_sanitizes_filename():
    payload = {
        "target": "example.com/../../evil",
        "total_findings": 1,
        "severity_counts": {"high": 1},
        "findings": [{
            "tool": "xss", "category": "xss", "severity": "high",
            "title": "Stored XSS", "description": "Observed test payload",
            "evidence": "<script>alert(document.cookie)</script>",
        }],
    }
    with client() as test_client:
        response = test_client.post("/api/report/pdf", json=payload)
    assert response.status_code == 200
    assert response.content.startswith(b"%PDF-")
    assert response.headers["content-type"].startswith("application/pdf")
    assert int(response.headers["x-report-generation-ms"]) >= 1
    assert int(response.headers["content-length"]) == len(response.content)
    disposition = response.headers["content-disposition"]
    assert ".." not in disposition and "/" not in disposition


def test_production_api_key_gate(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "API_ACCESS_KEY", "k" * 40)
    with client() as test_client:
        health = test_client.get("/api/health")
        no_key = test_client.post("/api/report/pdf", json={"target": "example.com"})
        wrong_key = test_client.post(
            "/api/report/pdf", json={"target": "example.com"}, headers={"X-ReconTitan-Key": "wrong"}
        )
        valid = test_client.post(
            "/api/report/pdf", json={"target": "example.com"}, headers={"X-ReconTitan-Key": "k" * 40}
        )
    assert health.status_code == 200
    assert no_key.status_code == 401
    assert wrong_key.status_code == 401
    assert valid.status_code == 200


def test_invalid_api_key_attempts_are_rate_limited(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "API_ACCESS_KEY", "k" * 40)
    monkeypatch.setattr(rate_limiter, "API_LIMIT", 2)
    with client() as test_client:
        first = test_client.post("/api/report/pdf", json={"target": "example.com"})
        second = test_client.post("/api/report/pdf", json={"target": "example.com"})
        third = test_client.post("/api/report/pdf", json={"target": "example.com"})
    assert first.status_code == 401
    assert second.status_code == 401
    assert third.status_code == 429


def test_capabilities_are_public_and_versioned():
    with client() as test_client:
        response = test_client.get("/api/capabilities")
    assert response.status_code == 200
    payload = response.json()
    assert payload["version"] == "0.5.0"
    assert {item["key"] for item in payload["capabilities"]} >= {
        "pdf_report", "subdomain_takeover", "js_analysis", "favicon_hash", "tech_stack",
    }


def test_json_endpoints_reject_wrong_content_type():
    with client() as test_client:
        response = test_client.post(
            "/api/report/pdf",
            content='{"target":"example.com"}',
            headers={"Content-Type": "text/plain"},
        )
    assert response.status_code == 415
    assert response.headers["x-request-id"]


def test_security_middleware_wraps_trusted_host_rejections():
    with client() as test_client:
        response = test_client.get("/api/health", headers={"Host": "attacker.invalid"})
    assert response.status_code == 400
    assert response.headers["server"] == "ReconTitan"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-request-id"]


def test_pdf_export_has_dedicated_rate_limit(monkeypatch):
    monkeypatch.setattr(rate_limiter, "EXPORT_LIMIT", 1)
    with client() as test_client:
        first = test_client.post("/api/report/pdf", json={"target": "example.com"})
        second = test_client.post("/api/report/pdf", json={"target": "example.com"})
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"] == str(rate_limiter.EXPORT_WINDOW)
