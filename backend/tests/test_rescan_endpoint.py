"""Guards on /api/rescan, which backs the refresh control on each report card.

The refresh button re-runs one scanner. That makes it a smaller version of the
scan endpoint, and it inherits the same obligations: it must validate its
target, and it must not become a way around the Danger Mode gate.
"""

from __future__ import annotations

from unittest import mock

from fastapi.testclient import TestClient

from app.main import app
from app.middleware.security import rate_limiter


def client() -> TestClient:
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()
    return TestClient(app)


def test_rescan_runs_the_named_scanner_and_returns_only_its_findings():
    fake = mock.Mock(return_value=[{"title": "Cert expires soon", "severity": "medium"}])
    with mock.patch(
        "app.routers.test_scan._tool_groups",
        return_value={"osint": [("ssl_check", fake)]},
    ):
        with client() as test_client:
            response = test_client.get("/api/rescan?target=example.com&tool=ssl_check")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["tool"] == "ssl_check"
    fake.assert_called_once()

    # Findings are normalised the same way the full scan normalises them, so
    # the frontend can render a refreshed card with the same code path.
    finding = body["findings"][0]
    assert finding["tool"] == "ssl_check"
    assert finding["category"] == "general"
    assert finding["id"].startswith("finding_")


def test_rescan_refuses_a_scanner_that_is_not_in_the_safe_registry():
    """The danger stages must not be reachable here.

    They are gated on a typed acknowledgement that a refresh button cannot
    collect, so the only correct answer is to refuse rather than to run them
    unacknowledged.
    """
    with client() as test_client:
        for tool in ("sqli_probe", "xss_probe", "command_injection", "../../etc/passwd"):
            response = test_client.get(f"/api/rescan?target=example.com&tool={tool}")
            assert response.status_code in (400, 422), tool


def test_rescan_validates_its_target_like_a_full_scan():
    with client() as test_client:
        response = test_client.get("/api/rescan?target=127.0.0.1&tool=ssl_check")
    # Loopback is refused by the targeting rules; the point is that rescan
    # goes through them at all rather than trusting the query string.
    assert response.status_code == 400


def test_rescan_reports_a_scanner_failure_instead_of_returning_500():
    """A card needs something to display even when its check breaks.

    "This check failed, here is why" is actionable; a browser-level 500 is
    not, and it would leave the card showing a spinner that never resolves.
    """
    def explode(_target):
        raise RuntimeError("upstream refused the connection")

    with mock.patch(
        "app.routers.test_scan._tool_groups",
        return_value={"osint": [("ssl_check", explode)]},
    ):
        with client() as test_client:
            response = test_client.get("/api/rescan?target=example.com&tool=ssl_check")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "error"
    assert body["error"] == "RuntimeError"
    assert body["findings"] == []


def test_rescan_accepts_an_alphanumeric_alias_for_a_dotted_scanner_name():
    """crt.sh cannot travel in the query string under its own name.

    The injection filter blocks a value ending in .sh, correctly -- it cannot
    know this one names a certificate log rather than a shell script. The
    alias exists so the filter stays as strict as it is.
    """
    fake = mock.Mock(return_value=[])
    with mock.patch(
        "app.routers.test_scan._tool_groups",
        return_value={"recon": [("crt.sh", fake)]},
    ):
        with client() as test_client:
            response = test_client.get("/api/rescan?target=example.com&tool=crtsh")

    assert response.status_code == 200
    assert response.json()["tool"] == "crt.sh"
    fake.assert_called_once()
