"""SOC console: aggregation correctness, authentication, and data separation.

Two properties matter most here and neither is obvious from reading the code:

* counters must sum the ``count`` field, not documents. Security events are
  coalesced when written, so one document can stand for thousands of requests
  and counting documents understates an attack by exactly the factor that
  makes it an attack;
* scan history must not be reachable from the public API. It used to be, and
  any holder of the shared access key could enumerate every target anyone had
  ever scanned.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def seeded(monkeypatch):
    """A small, realistic slice of traffic: one noisy attacker, one scanner."""
    mongomock = pytest.importorskip("mongomock")

    import app.database as database
    from app.admin import api as admin_api

    db = mongomock.MongoClient()["recontitan"]
    now = datetime.now(timezone.utc)
    db["audit_events"].insert_many([
        {"kind": "injection.blocked", "ip": "45.9.148.2", "at": now - timedelta(minutes=5),
         "count": 1240, "detail": "sqli", "user_agent": "sqlmap/1.7"},
        {"kind": "auth.failed", "ip": "45.9.148.2", "at": now - timedelta(minutes=9), "count": 88},
        {"kind": "ratelimit.exceeded", "ip": "103.21.44.9", "at": now - timedelta(hours=2), "count": 310},
        {"kind": "admin.login_failed", "ip": "8.8.4.4", "at": now - timedelta(minutes=31), "count": 6},
        {"kind": "scan.accepted", "ip": "49.36.20.11", "at": now - timedelta(hours=3), "target": "example.com"},
        # Outside a 24h window; must not leak into windowed counters.
        {"kind": "injection.blocked", "ip": "1.1.1.1", "at": now - timedelta(days=9), "count": 99999},
    ])
    db["scans"].insert_many([
        {"scan_id": "scan_a1", "target": "example.com", "scan_type": "danger", "status": "completed",
         "total_findings": 56, "created_at": now - timedelta(hours=3), "client_ip": "49.36.20.11",
         "api_key_id": "k_9f2a11bc", "user_agent": "Mozilla/5.0",
         "findings": [{"severity": "critical"}, {"severity": "high"}, {"severity": "high"}]},
        {"scan_id": "scan_b2", "target": "test.internal", "scan_type": "full", "status": "failed",
         "total_findings": 0, "created_at": now - timedelta(hours=6), "client_ip": "45.9.148.2",
         "api_key_id": "k_deadbeef", "error": "ceiling", "findings": []},
    ])
    monkeypatch.setattr(database, "_db", db)
    return admin_api


# ── Counters reflect coalesced volume ────────────────────────────────────────

def test_counters_sum_request_volume_not_documents(seeded):
    """One coalesced document can represent thousands of blocked requests."""
    data = seeded.overview(24)
    assert data["injections_blocked"] == 1240, "counted documents instead of requests"
    assert data["auth_failures"] == 88
    assert data["rate_limited"] == 310
    assert data["admin_attempts"] == 6
    assert data["threat_events"] == 1240 + 88 + 310 + 6


def test_window_excludes_older_events(seeded):
    """A 9-day-old spike must not inflate the 24h view."""
    assert seeded.overview(24)["injections_blocked"] == 1240
    assert seeded.overview(24 * 30)["injections_blocked"] == 1240 + 99999


def test_normal_traffic_is_not_counted_as_hostile(seeded):
    data = seeded.overview(24)
    assert "scan.accepted" not in seeded.THREAT_KINDS
    # 3 hostile sources, plus the benign scanner = 4 distinct sources overall.
    assert data["unique_attackers"] == 3
    assert data["unique_sources"] == 4


# ── Threat ranking ───────────────────────────────────────────────────────────

def test_sources_rank_by_hostile_volume(seeded):
    sources = seeded.threats(24, 20)["sources"]
    assert [s["ip"] for s in sources] == ["45.9.148.2", "103.21.44.9", "8.8.4.4"]
    assert sources[0]["events"] == 1240 + 88


def test_source_severity_is_its_worst_class(seeded):
    """An admin login attempt outranks a rate limit even at lower volume."""
    by_ip = {s["ip"]: s for s in seeded.threats(24, 20)["sources"]}
    assert by_ip["8.8.4.4"]["severity"] == "critical"
    assert by_ip["45.9.148.2"]["severity"] == "high"
    assert by_ip["103.21.44.9"]["severity"] == "medium"


def test_source_carries_its_attack_classes(seeded):
    by_ip = {s["ip"]: s for s in seeded.threats(24, 20)["sources"]}
    assert set(by_ip["45.9.148.2"]["kinds"]) == {"injection.blocked", "auth.failed"}


def test_attack_classes_separate_hostile_from_normal(seeded):
    classes = {c["kind"]: c for c in seeded.attack_classes(24)["classes"]}
    assert classes["injection.blocked"]["hostile"] is True
    assert classes["scan.accepted"]["hostile"] is False
    assert classes["injection.blocked"]["events"] == 1240


# ── Scan attribution ─────────────────────────────────────────────────────────

def test_scan_view_answers_who_scanned_what(seeded):
    scans = {s["target"]: s for s in seeded.scans(168, 50)["scans"]}
    assert scans["example.com"]["client_ip"] == "49.36.20.11"
    assert scans["example.com"]["api_key_id"] == "k_9f2a11bc"
    assert scans["example.com"]["critical"] == 1
    assert scans["example.com"]["high"] == 2


def test_scan_view_surfaces_failures(seeded):
    scans = {s["target"]: s for s in seeded.scans(168, 50)["scans"]}
    assert scans["test.internal"]["status"] == "failed"
    assert scans["test.internal"]["error"] == "ceiling"


def test_targets_correlate_scans_to_sources(seeded):
    targets = {t["target"]: t for t in seeded.targets(168, 25)["targets"]}
    assert targets["example.com"]["sources"] == ["49.36.20.11"]
    assert targets["example.com"]["profiles"] == ["danger"]


def test_an_attacker_is_correlatable_across_both_views(seeded):
    """45.9.148.2 both attacks the API and runs scans — the console must link them."""
    attackers = {s["ip"] for s in seeded.threats(24, 20)["sources"]}
    scanners = {s["client_ip"] for s in seeded.scans(168, 50)["scans"]}
    assert "45.9.148.2" in attackers & scanners


# ── Degraded mode ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("endpoint,key", [
    ("overview", "available"), ("threats", "sources"), ("attack_classes", "classes"),
    ("timeline", "buckets"), ("events", "events"), ("scans", "scans"), ("targets", "targets"),
])
def test_endpoints_degrade_without_mongo(monkeypatch, endpoint, key):
    """The console must render an empty state, not a 500, when the DB is down."""
    import app.database as database
    from app.admin import api as admin_api

    monkeypatch.setattr(database, "_db", None)
    monkeypatch.setattr(database, "MongoClient", None)
    result = getattr(admin_api, endpoint)(24) if endpoint in {"overview", "attack_classes", "timeline"} \
        else getattr(admin_api, endpoint)(24, 10)
    assert result["available"] is False
    assert key in result


# ── Public API must not serve scan history ───────────────────────────────────

def test_public_api_no_longer_lists_scans():
    """Any key holder could previously enumerate every target ever scanned."""
    source = (REPO_ROOT / "backend/app/routers/scans.py").read_text(encoding="utf-8")
    assert '@router.get("/scans")' not in source


def test_public_frontend_has_no_scan_history():
    html = (REPO_ROOT / "frontend/index.html").read_text(encoding="utf-8")
    js = (REPO_ROOT / "frontend/dashboard.js").read_text(encoding="utf-8")
    assert "history-section" not in html
    assert "historyBody" not in html
    for symbol in ("renderHistory", "historyData", "rt_history"):
        assert symbol not in js, f"{symbol} still present in the public dashboard"


def test_scan_history_is_served_only_from_the_admin_console():
    source = (REPO_ROOT / "backend/app/admin/api.py").read_text(encoding="utf-8")
    assert '@router.get("/scans")' in source
    assert 'prefix="/api"' in source


# ── Console wiring ───────────────────────────────────────────────────────────

def test_admin_modules_do_not_import_circularly():
    """api needed require_admin from main while main needed api's router.

    The break only appeared when something imported the router first, which is
    exactly what a test or a script does.
    """
    api_source = (REPO_ROOT / "backend/app/admin/api.py").read_text(encoding="utf-8")
    assert "from app.admin.main import" not in api_source
    assert "from app.admin.deps import require_admin" in api_source


def test_every_admin_api_route_requires_authentication():
    from app.admin.api import router

    assert router.dependencies, "router must carry a global auth dependency"
    for route in router.routes:
        assert route.path.startswith("/api/")


def test_console_page_carries_no_data():
    """The shell authenticates client-side; data arrives only over the API."""
    html = (REPO_ROOT / "frontend/admin.html").read_text(encoding="utf-8")
    assert "noindex" in html
    assert "<script src=" in html
    # No inline script: the admin CSP is script-src 'self'.
    assert "<script>" not in html


def test_console_escapes_untrusted_values():
    """User agents, paths and payload excerpts all render in these tables."""
    js = (REPO_ROOT / "frontend/admin.js").read_text(encoding="utf-8")
    assert "function esc(" in js
    assert "&amp;" in js and "&lt;" in js
    # The zero-rendering bug fixed earlier in report.js must not reappear here.
    assert "String(value ?? '')" in js
