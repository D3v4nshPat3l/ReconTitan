"""Guards on triage state.

Any suppression feature is one bad decision away from being a way to hide
findings. Most of what is asserted here is that it cannot be used that way:
a reason is mandatory, nothing is deleted, and the report always states what
is being suppressed.

The other half is fingerprint behaviour. A decision has to survive a re-scan,
and finding ids are a fresh uuid every run, so triage keys on content. The
asymmetry matters: a fingerprint that changes too easily is annoying, while
one that collides silently hides a real finding under an unrelated decision.
These tests pin both directions.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.middleware.security import rate_limiter
from app.services import triage


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    """Every test gets its own store; none of them touch the real one."""
    store = tmp_path / "triage.json"
    monkeypatch.setattr(triage.settings, "TRIAGE_STORE_PATH", str(store), raising=False)
    return store


def client() -> TestClient:
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()
    return TestClient(app)


def finding(**overrides) -> dict:
    base = {
        "id": "f_1", "tool": "nvd_cve", "category": "cve_finding", "severity": "critical",
        "title": "Apache httpd 2.4.49 is affected by CVE-2021-41773",
        "cve_id": "CVE-2021-41773",
    }
    base.update(overrides)
    return base


# ── Fingerprint stability ─────────────────────────────────────────────────────

@pytest.mark.parametrize("first,second", [
    # The expiry countdown moves every day and identifies nothing.
    (
        {"tool": "ssl_check", "category": "ssl_certificate",
         "title": "SSL Certificate Analysis — Certificate valid for 53 more days"},
        {"tool": "ssl_check", "category": "ssl_certificate",
         "title": "SSL Certificate Analysis — Certificate valid for 7 more days"},
    ),
    # So does a count of what was found.
    (
        {"tool": "nmap", "category": "port_scan", "title": "Port Scan — 2 Open Port(s) Found"},
        {"tool": "nmap", "category": "port_scan", "title": "Port Scan — 9 Open Port(s) Found"},
    ),
    # A CVE keeps its identity when the upstream wording changes.
    (
        finding(),
        finding(title="CVE-2021-41773 affects Apache HTTP Server (reworded upstream)"),
    ),
    # The same parameter with a different value is the same flaw.
    (
        {"tool": "sqli_probe", "category": "danger_sql_injection", "title": "SQL injection on id",
         "affected_asset": "https://shop.example.com/item?id=7"},
        {"tool": "sqli_probe", "category": "danger_sql_injection", "title": "SQL injection on id",
         "affected_asset": "https://shop.example.com/item?id=9"},
    ),
])
def test_a_decision_survives_the_things_that_change_between_scans(first, second):
    assert triage.fingerprint(first) == triage.fingerprint(second)


@pytest.mark.parametrize("first,second,why", [
    (
        {"tool": "nmap", "category": "dangerous_port", "title": "Internet-Exposed Port: 3306/mysql"},
        {"tool": "nmap", "category": "dangerous_port", "title": "Internet-Exposed Port: 22/ssh"},
        "a blanket digit rule would merge two different exposed ports",
    ),
    (
        finding(),
        finding(cve_id="CVE-2021-42013", title="Apache httpd 2.4.50 is affected by CVE-2021-42013"),
        "two CVEs on the same product are separate decisions",
    ),
    (
        {"tool": "sqli_probe", "category": "danger_sql_injection", "title": "SQL injection on id",
         "affected_asset": "https://shop.example.com/item?id=7"},
        {"tool": "sqli_probe", "category": "danger_sql_injection", "title": "SQL injection on q",
         "affected_asset": "https://shop.example.com/search?q=1"},
        "different endpoints are different findings",
    ),
    (
        {"tool": "sqli_probe", "category": "danger_sql_injection", "title": "SQL injection on id",
         "affected_asset": "https://shop.example.com/item?id=7"},
        {"tool": "xss_probe", "category": "danger_reflected_xss", "title": "Reflected XSS on id",
         "affected_asset": "https://shop.example.com/item?id=7"},
        "two different flaws on one endpoint must not share a decision",
    ),
])
def test_distinct_findings_never_collide(first, second, why):
    assert triage.fingerprint(first) != triage.fingerprint(second), why


# ── The rules that stop this becoming a way to hide things ────────────────────

@pytest.mark.parametrize("state", triage.SUPPRESSING)
def test_suppressing_without_a_written_reason_is_refused(state):
    with pytest.raises(ValueError, match="reason is required"):
        triage.record("shop.example.com", triage.fingerprint(finding()), state, reason="")


@pytest.mark.parametrize("state", [triage.OPEN, triage.CONFIRMED])
def test_states_that_hide_nothing_need_no_reason(state):
    stored = triage.record("shop.example.com", triage.fingerprint(finding()), state)
    assert stored["state"] == state


def test_a_suppressed_finding_stays_in_the_report():
    """Suppression changes the counts. It must never remove evidence."""
    key = triage.fingerprint(finding())
    triage.record("shop.example.com", key, triage.FALSE_POSITIVE, "Backported patch in 2.4.49-1ubuntu1.4")

    report = {"target": "shop.example.com", "findings": [finding(), finding(
        id="f_2", tool="nmap", category="dangerous_port", severity="high",
        title="Internet-Exposed Port: 3306/mysql", cve_id=None)]}
    triage.apply_to_report(report)

    assert len(report["findings"]) == 2, "a suppressed finding was removed from the report"
    suppressed = report["findings"][0]
    assert suppressed["triage"]["state"] == triage.FALSE_POSITIVE
    assert suppressed["triage"]["reason"].startswith("Backported patch")
    # But it no longer inflates the counts.
    assert report["severity_counts"]["critical"] == 0
    assert report["severity_counts"]["high"] == 1
    assert report["total_findings"] == 1


def test_the_report_always_states_what_is_being_suppressed():
    """A quiet report has to say why it is quiet."""
    triage.record("shop.example.com", triage.fingerprint(finding()),
                  triage.ACCEPTED_RISK, "Behind a WAF; compensating control accepted by the owner")
    report = {"target": "shop.example.com", "findings": [finding()]}
    triage.apply_to_report(report)

    summary = report["triage_summary"]
    assert summary["suppressed_total"] == 1
    assert summary["counts"][triage.ACCEPTED_RISK] == 1
    entry = summary["suppressed"][0]
    assert entry["state"] == triage.ACCEPTED_RISK
    assert "compensating control" in entry["reason"]
    assert entry["decided_at"], "a decision with no timestamp is not attributable"


def test_confirmed_raises_confidence_without_hiding_anything():
    triage.record("shop.example.com", triage.fingerprint(finding()), triage.CONFIRMED)
    report = {"target": "shop.example.com", "findings": [finding()]}
    triage.apply_to_report(report)

    assert report["severity_counts"]["critical"] == 1, "confirming must not suppress"
    assert report["triage_summary"]["suppressed_total"] == 0
    assert report["findings"][0]["triage"]["state"] == triage.CONFIRMED


def test_returning_a_finding_to_open_forgets_the_decision(isolated_store):
    key = triage.fingerprint(finding())
    triage.record("shop.example.com", key, triage.FALSE_POSITIVE, "mistaken")
    assert key in triage.decisions_for("shop.example.com")

    triage.record("shop.example.com", key, triage.OPEN)
    assert key not in triage.decisions_for("shop.example.com")
    # The whole target drops out rather than leaving an empty husk behind.
    assert json.loads(isolated_store.read_text(encoding="utf-8")) == {}


# ── Scoping and storage ───────────────────────────────────────────────────────

def test_decisions_do_not_leak_between_targets():
    key = triage.fingerprint(finding())
    triage.record("shop.example.com", key, triage.FALSE_POSITIVE, "not our build")

    other = {"target": "other.example.com", "findings": [finding()]}
    triage.apply_to_report(other)
    assert other["findings"][0]["triage"]["state"] == triage.OPEN
    assert other["severity_counts"]["critical"] == 1


def test_every_finding_gets_a_fingerprint_even_when_never_reviewed():
    """The UI needs a key to submit a decision against."""
    report = {"target": "shop.example.com", "findings": [finding()]}
    triage.apply_to_report(report)
    assert len(report["findings"][0]["triage_fingerprint"]) == 32
    assert report["findings"][0]["triage"]["state"] == triage.OPEN


def test_a_corrupt_store_does_not_take_the_scanner_down(isolated_store):
    isolated_store.write_text("{not json at all", encoding="utf-8")
    report = {"target": "shop.example.com", "findings": [finding()]}
    triage.apply_to_report(report)
    assert report["severity_counts"]["critical"] == 1


def test_unknown_states_and_malformed_fingerprints_are_refused():
    with pytest.raises(ValueError, match="Unknown triage state"):
        triage.record("shop.example.com", triage.fingerprint(finding()), "deleted", "x")
    with pytest.raises(ValueError, match="Malformed"):
        triage.record("shop.example.com", "../../etc/passwd", triage.CONFIRMED)
    with pytest.raises(ValueError, match="target is required"):
        triage.record("", triage.fingerprint(finding()), triage.CONFIRMED)


def test_apply_survives_junk_findings():
    report = {"target": "shop.example.com", "findings": [None, "text", 42, finding()]}
    triage.apply_to_report(report)
    assert report["total_findings"] == 1


# ── API ───────────────────────────────────────────────────────────────────────

def test_the_endpoint_refuses_an_unjustified_suppression():
    with client() as test_client:
        response = test_client.post("/api/triage", json={
            "target": "example.com",
            "fingerprint": triage.fingerprint(finding()),
            "state": "false_positive",
            "reason": "   ",
        })
    assert response.status_code == 400
    assert "reason is required" in response.json()["detail"]


def test_the_endpoint_records_and_reads_back_a_decision():
    key = triage.fingerprint(finding())
    with client() as test_client:
        write = test_client.post("/api/triage", json={
            "target": "example.com", "fingerprint": key,
            "state": "accepted_risk", "reason": "Owner accepted; internal-only host",
        })
        assert write.status_code == 200, write.text
        assert write.json()["state"] == "accepted_risk"

        read = test_client.get("/api/triage?target=example.com")
    assert read.status_code == 200
    body = read.json()
    assert body["count"] == 1
    assert body["decisions"][key]["reason"] == "Owner accepted; internal-only host"


def test_the_endpoint_validates_its_target_and_fingerprint():
    with client() as test_client:
        bad_target = test_client.post("/api/triage", json={
            "target": "127.0.0.1", "fingerprint": triage.fingerprint(finding()),
            "state": "confirmed",
        })
        bad_fingerprint = test_client.post("/api/triage", json={
            "target": "example.com", "fingerprint": "not-a-fingerprint",
            "state": "confirmed",
        })
    assert bad_target.status_code == 400
    assert bad_fingerprint.status_code == 422
