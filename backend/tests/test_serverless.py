"""Serverless deployment: shared counters, honest capability reporting, and
refusing to queue work no worker will ever collect.

Three things break silently when this app runs as many short-lived instances
instead of one long-lived process, and silence is the problem in each case:

* rate limits and admin lockout live in per-process dicts, so N instances mean
  a limit of N x the configured ceiling and an attacker can sidestep lockout by
  landing on a fresh instance. Nothing errors; the protection just stops;
* ``POST /api/scan`` hands work to Celery. With no worker the scan is accepted
  and stays queued forever, which looks like a hang rather than a refusal;
* modules that shell out to a binary are skipped when it is absent. An empty
  result then reads identically to "the target is fine".
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from app.config import Settings
from app.services import sharedstate

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(autouse=True)
def _clean_shared_state():
    sharedstate.reset()
    yield
    sharedstate.reset()


# ── Deployment detection ─────────────────────────────────────────────────────

def test_vercel_is_detected_automatically(monkeypatch):
    """Vercel sets VERCEL=1; the app must not need separate configuration."""
    monkeypatch.setenv("VERCEL", "1")
    assert Settings().SERVERLESS is True


def test_a_normal_server_is_not_serverless(monkeypatch):
    monkeypatch.delenv("VERCEL", raising=False)
    monkeypatch.delenv("SERVERLESS", raising=False)
    assert Settings().SERVERLESS is False


def test_managed_redis_url_is_used_verbatim(monkeypatch):
    """Upstash and friends hand out one connection string, not host/port/pass."""
    monkeypatch.setenv("REDIS_URL", "rediss://default:secret@eu1.upstash.io:6379")
    assert Settings().REDIS_URL == "rediss://default:secret@eu1.upstash.io:6379"


def test_local_redis_settings_still_build_a_url(monkeypatch):
    monkeypatch.delenv("REDIS_URL", raising=False)
    monkeypatch.setenv("REDIS_HOST", "redis")
    monkeypatch.setenv("REDIS_PASSWORD", "hunter2")
    url = Settings().REDIS_URL
    assert url.startswith("redis://:hunter2@redis:")


# ── Shared counters ──────────────────────────────────────────────────────────

def test_counters_fall_back_to_process_memory_without_redis(monkeypatch):
    """A single node must keep working exactly as before."""
    monkeypatch.setattr(sharedstate.settings, "SHARED_STATE_ENABLED", False)
    assert sharedstate.is_shared() is False
    assert [sharedstate.hit("ip:1.2.3.4", 60) for _ in range(3)] == [1, 2, 3]


def test_counters_are_shared_when_redis_is_available(monkeypatch):
    """Two instances must see one counter, not one each."""
    fake = _FakeRedis()
    monkeypatch.setattr(sharedstate.settings, "SHARED_STATE_ENABLED", True)
    monkeypatch.setattr(sharedstate, "_redis", fake)
    monkeypatch.setattr(sharedstate, "_redis_checked", True)

    assert sharedstate.hit("ip:9.9.9.9", 60) == 1
    assert sharedstate.hit("ip:9.9.9.9", 60) == 2
    assert sharedstate.hit("ip:9.9.9.9", 60) == 3


def test_rate_limiting_fails_open_when_redis_breaks(monkeypatch):
    """A broker outage must not lock every user out of the product."""
    monkeypatch.setattr(sharedstate.settings, "SHARED_STATE_ENABLED", True)
    monkeypatch.setattr(sharedstate, "_redis", _BrokenRedis())
    monkeypatch.setattr(sharedstate, "_redis_checked", True)
    assert sharedstate.hit("ip:5.5.5.5", 60) == 1  # served from local fallback


def test_lockout_survives_across_instances(monkeypatch):
    fake = _FakeRedis()
    monkeypatch.setattr(sharedstate.settings, "SHARED_STATE_ENABLED", True)
    monkeypatch.setattr(sharedstate, "_redis", fake)
    monkeypatch.setattr(sharedstate, "_redis_checked", True)

    sharedstate.lock_out("admin:203.0.113.7", 900)
    assert sharedstate.locked_for("admin:203.0.113.7") == 900
    sharedstate.clear_lock("admin:203.0.113.7")
    assert sharedstate.locked_for("admin:203.0.113.7") == 0


def test_admin_lockout_consults_shared_state(monkeypatch):
    """Per-process lockout is worthless when instances are disposable."""
    from app.admin import auth

    fake = _FakeRedis()
    monkeypatch.setattr(sharedstate.settings, "SHARED_STATE_ENABLED", True)
    monkeypatch.setattr(sharedstate, "_redis", fake)
    monkeypatch.setattr(sharedstate, "_redis_checked", True)

    sharedstate.lock_out("admin:198.51.100.3", 600)
    # A different instance, with an empty local table, must still see the lock.
    auth._failures.clear()
    assert auth.lockout_remaining("198.51.100.3") == 600


def test_rate_limiter_routes_through_shared_state():
    import inspect

    from app.middleware.security import RateLimiter

    source = inspect.getsource(RateLimiter._count)
    assert "shared_state.is_shared()" in source
    assert "shared_state.hit" in source


# ── Refusing to queue work nothing will collect ──────────────────────────────

def test_async_scan_is_refused_on_serverless(monkeypatch):
    """Accepting it would leave the scan queued forever, looking like a hang."""
    from fastapi import HTTPException

    from app.models.schemas import ScanRequest, ScanType
    from app.routers import scans as scans_router

    monkeypatch.setattr(scans_router.settings, "SERVERLESS", True)
    request = ScanRequest(target="example.com", scan_type=ScanType.FULL)

    with pytest.raises(HTTPException) as excinfo:
        scans_router.initiate_scan(request, _FakeRequest())
    assert excinfo.value.status_code == 503
    assert "/api/test-scan" in excinfo.value.detail


def test_the_public_ui_already_uses_the_synchronous_endpoint():
    """Which is why the console keeps working without a worker."""
    js = (REPO_ROOT / "frontend/dashboard.js").read_text(encoding="utf-8")
    assert "/api/test-scan" in js


# ── Honest capability reporting ──────────────────────────────────────────────

def test_runtime_report_names_unavailable_modules():
    """A skipped module must not be indistinguishable from a clean result."""
    from app.services.capabilities import runtime_report

    report = runtime_report()
    assert set(report["binary_modules_available"]) & set(report["binary_modules_unavailable"]) == set()
    assert "not evidence that the target is unaffected" in report["note"]


def test_runtime_report_states_the_deployment_shape(monkeypatch):
    from app.services import capabilities

    monkeypatch.setattr(capabilities.settings, "SERVERLESS", True)
    report = capabilities.runtime_report()
    assert report["deployment"] == "serverless"
    assert report["async_scans"] is False
    assert report["sync_scan_endpoint"] == "/api/test-scan"


def test_capabilities_payload_exposes_the_runtime_block():
    from app.services.capabilities import capabilities_payload

    assert "runtime" in capabilities_payload("0.5.0")


def test_every_binary_module_is_declared():
    """A new shell-out module must be added here or it reports as available."""
    from app.services.capabilities import BINARY_MODULES

    for module in ("port_scan", "subfinder", "amass", "nuclei", "sqlmap"):
        assert module in BINARY_MODULES


def test_modules_without_a_binary_are_not_declared():
    """The inverse guard: declaring a pure-Python module reports it as broken.

    ``waf_detect`` was listed here against ``wafw00f`` even though
    ``run_wafw00f`` only matches response headers and never spawns a process.
    On any host without that binary the capability report called a fully
    working module unavailable, which is the opposite of what this report is
    for.
    """
    from app.services.capabilities import BINARY_MODULES

    assert "waf_detect" not in BINARY_MODULES

    source = (REPO_ROOT / "backend/app/tasks/osint/waf_detect.py").read_text(encoding="utf-8")
    assert "subprocess.run" not in source
    assert "shutil.which" not in source


# ── Deployment manifest ──────────────────────────────────────────────────────

def test_vercel_manifest_is_valid_json_and_routes_to_the_app():
    import json

    manifest = json.loads((REPO_ROOT / "vercel.json").read_text(encoding="utf-8"))
    assert "api/index.py" in manifest["functions"]
    assert manifest["functions"]["api/index.py"]["maxDuration"] >= 60
    assert any(r["destination"] == "/api/index" for r in manifest["rewrites"])


def test_entry_point_imports_the_app():
    source = (REPO_ROOT / "api/index.py").read_text(encoding="utf-8")
    assert "from app.main import app" in source
    assert "sys.path.insert" in source


def _pins(path):
    """Package pins from a requirements file, ignoring comments and blanks."""
    lines = path.read_text(encoding="utf-8").splitlines()
    return {
        line.strip() for line in lines
        if line.strip() and not line.strip().startswith("#")
    }


def test_root_requirements_match_the_backend_set():
    """Vercel resolves from the repo root, and a relative ``-r`` include is not
    reliably honoured there -- an unresolved include installs nothing and the
    function dies on first import. The root file therefore carries the pins
    itself, which only stays correct while the two files agree.
    """
    root = _pins(REPO_ROOT / "requirements.txt")
    backend = _pins(REPO_ROOT / "backend" / "requirements.txt")
    assert not backend - root, f"missing from root requirements.txt: {sorted(backend - root)}"
    assert not root - backend, f"only in root requirements.txt: {sorted(root - backend)}"


# ── Doubles ──────────────────────────────────────────────────────────────────

class _FakeRedis:
    """Minimal INCR/EXPIRE/TTL/SETEX behaviour, enough for these paths."""

    def __init__(self):
        self.store: dict[str, int] = {}
        self.ttls: dict[str, int] = {}

    def pipeline(self):
        return _FakePipeline(self)

    def setex(self, key, seconds, _value):
        self.ttls[key] = seconds

    def ttl(self, key):
        return self.ttls.get(key, -2)

    def delete(self, key):
        self.ttls.pop(key, None)
        self.store.pop(key, None)


class _FakePipeline:
    def __init__(self, client):
        self.client = client
        self.result = 0

    def incr(self, key):
        self.client.store[key] = self.client.store.get(key, 0) + 1
        self.result = self.client.store[key]

    def expire(self, key, seconds):
        self.client.ttls[key] = seconds

    def execute(self):
        return [self.result]


class _BrokenRedis:
    def pipeline(self):
        raise ConnectionError("redis down")

    def setex(self, *_a):
        raise ConnectionError("redis down")

    def ttl(self, *_a):
        raise ConnectionError("redis down")

    def delete(self, *_a):
        raise ConnectionError("redis down")


class _FakeRequest:
    client = type("C", (), {"host": "203.0.113.1"})()
    method = "POST"
    headers: dict = {}
    url = type("U", (), {"path": "/api/scan"})()


# ── Admin console reachability differs by deployment ─────────────────────────

PROBE = """
import json, os, sys
sys.path.insert(0, os.environ["BACKEND"])
from app.main import app
from app.admin import auth
from fastapi.testclient import TestClient
client = TestClient(app)
token = {auth.ADMIN_HEADER: "T" * 64}
print(json.dumps({
    "console":   client.get("/admin/").status_code,
    "health":    client.get("/admin/health").status_code,
    "api_open":  client.get("/admin/api/overview").status_code,
    "api_auth":  client.get("/admin/api/overview", headers=token).status_code,
    "wp_admin":  client.get("/wp-admin").status_code,
    "phpmyadmin":client.get("/phpmyadmin").status_code,
    "dotenv":    client.get("/.env").status_code,
}))
"""


def _probe(serverless: bool) -> dict:
    """Import the app in a clean process for one deployment shape.

    The mount decision happens at import time, so reloading modules in-process
    leaves other modules holding a stale settings object. A subprocess is the
    only faithful way to exercise it.
    """
    import json
    import subprocess

    env = {
        **os.environ,
        "BACKEND": str(REPO_ROOT / "backend"),
        "RECONTITAN_SKIP_DOTENV": "1",
        "ADMIN_ENABLED": "true",
        "ADMIN_TOKEN": "T" * 64,
    }
    env.pop("VERCEL", None)
    env.pop("SERVERLESS", None)
    if serverless:
        env["VERCEL"] = "1"

    result = subprocess.run(
        [sys.executable, "-c", PROBE], capture_output=True, text=True, env=env, timeout=180,
    )
    assert result.returncode == 0, result.stderr[-1500:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_admin_console_is_not_on_the_public_origin_on_a_server():
    """The whole isolation guarantee: no public path reaches admin on a VPS."""
    codes = _probe(serverless=False)
    assert codes["console"] == 404
    assert codes["health"] == 404
    assert codes["api_open"] == 404
    assert codes["api_auth"] == 404, "even a valid token must find nothing here"


def test_admin_console_is_mounted_when_serverless():
    """A serverless platform has one origin, so the console has nowhere else."""
    codes = _probe(serverless=True)
    assert codes["console"] == 200
    assert codes["health"] == 200
    assert codes["api_open"] == 401, "mounted, but still gated"
    assert codes["api_auth"] == 200


def test_panel_probing_is_still_blocked_when_admin_is_mounted():
    """Exempting the real prefix must not unblock the decoys around it."""
    codes = _probe(serverless=True)
    assert codes["wp_admin"] == 404
    assert codes["phpmyadmin"] == 404
    assert codes["dotenv"] == 404


def test_console_assets_use_relative_paths():
    """One build has to work at the root and under /admin."""
    html = (REPO_ROOT / "frontend/admin.html").read_text(encoding="utf-8")
    # Matched by prefix, not exact string: a cache-busting query is fine, a
    # leading slash is not. It is the relative-ness that has to hold.
    assert 'href="static/admin.css' in html
    assert 'src="static/admin.js' in html
    assert "/admin/static/" not in html
    assert 'href="/static/' not in html
    assert 'src="/static/' not in html

    js = (REPO_ROOT / "frontend/admin.js").read_text(encoding="utf-8")
    assert "const BASE = window.location.pathname" in js
    assert "`${BASE}/api/" in js
