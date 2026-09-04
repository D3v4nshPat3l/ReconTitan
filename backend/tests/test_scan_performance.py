"""Regressions for the two failures that stopped Danger Mode completing on Linux.

The danger profile runs every phase inline inside one Celery task. Two things
made that fail on a real deployment but not on a Windows dev box, where the
synchronous ``/api/test-scan`` path is used and Celery is never involved:

1. the orchestrator inherited the *per-tool* Celery time limit, so the worker
   hard-killed the scan partway through — often before the danger phase started;
2. every probe re-resolved DNS and opened a fresh TCP+TLS connection, so the
   pipeline was slow enough to reach that ceiling in the first place.
"""

from __future__ import annotations

import inspect
import os
import re
from pathlib import Path

import pytest

from app.config import RECON_TOOL_COUNT, OSINT_TOOL_COUNT, Settings, settings

REPO_ROOT = Path(__file__).resolve().parents[2]


def _worst_case_pipeline_seconds(cfg: Settings) -> int:
    """Wall clock the danger profile can consume with every tool timing out."""
    lanes = max(1, cfg.SCAN_TOOL_CONCURRENCY)
    waves = -(-RECON_TOOL_COUNT // lanes) + -(-OSINT_TOOL_COUNT // lanes)
    active = cfg.SCAN_TIMEOUT_NMAP + (
        cfg.SCAN_TIMEOUT_NUCLEI if cfg.ENABLE_ACTIVE_VULN_TOOLS else cfg.SCAN_TIMEOUT_DEFAULT
    )
    return waves * cfg.SCAN_TIMEOUT_DEFAULT + active + cfg.DANGER_MAX_SCAN_SECONDS


# ── The orchestrator ceiling must cover the whole pipeline ───────────────────

def test_orchestrator_ceiling_covers_worst_case_pipeline():
    """The regression itself: a 900s limit against a ~3400s pipeline."""
    assert settings.SCAN_SOFT_TIME_LIMIT >= _worst_case_pipeline_seconds(settings)


def test_orchestrator_ceiling_exceeds_the_per_tool_default():
    # The per-tool default is correct for a single phase task and far too small
    # for the orchestrator, which is exactly why it needs its own annotation.
    assert settings.SCAN_HARD_TIME_LIMIT > settings.CELERY_TASK_TIME_LIMIT


@pytest.mark.parametrize("concurrency,active", [("1", "true"), ("1", "false"), ("8", "true")])
def test_ceiling_still_covers_pipeline_under_other_configs(monkeypatch, concurrency, active):
    """Turning off parallelism or on the active tools must not outrun the ceiling."""
    monkeypatch.setenv("SCAN_TOOL_CONCURRENCY", concurrency)
    monkeypatch.setenv("ENABLE_ACTIVE_VULN_TOOLS", active)
    cfg = Settings()
    assert cfg.SCAN_SOFT_TIME_LIMIT >= _worst_case_pipeline_seconds(cfg)


def test_hard_limit_leaves_room_for_the_soft_handler():
    # orchestrate_scan writes the failure record when the soft limit fires; a
    # hard kill skips every handler, so there must be a gap between them.
    assert settings.SCAN_HARD_TIME_LIMIT - settings.SCAN_SOFT_TIME_LIMIT >= 30


def test_orchestrator_is_annotated_with_the_pipeline_ceiling():
    from app.celery_app import celery_app

    annotation = celery_app.conf.task_annotations["app.tasks.scan_tasks.orchestrate_scan"]
    assert annotation["time_limit"] == settings.SCAN_HARD_TIME_LIMIT
    assert annotation["soft_time_limit"] == settings.SCAN_SOFT_TIME_LIMIT


def test_timed_out_scan_is_not_redelivered():
    """A killed scan must not be retried, or the target is scanned forever."""
    from app.celery_app import celery_app

    assert celery_app.conf.task_acks_on_failure_or_timeout is True
    assert celery_app.conf.task_reject_on_worker_lost is False


def test_soft_time_limit_marks_the_scan_failed(monkeypatch):
    """Without this the scan record stays 'running' forever and the UI hangs."""
    from celery.exceptions import SoftTimeLimitExceeded

    from app.tasks import scan_tasks

    recorded: dict = {}

    monkeypatch.setattr(scan_tasks, "_validated_task_target", lambda target: target)
    monkeypatch.setattr(
        scan_tasks, "_update_scan_status",
        lambda scan_id, status, **kw: recorded.update({"status": status, **kw}),
    )

    def boom(scan_id, target):
        raise SoftTimeLimitExceeded()

    monkeypatch.setattr(scan_tasks.run_recon, "run", boom)

    with pytest.raises(SoftTimeLimitExceeded):
        scan_tasks.orchestrate_scan.run("scan_abc123abc123", "example.com", "danger")

    assert recorded["status"] == "failed"
    assert recorded["completed"] is True
    assert "ceiling" in recorded["error"]


# ── Danger Mode env plumbing ─────────────────────────────────────────────────

def test_compose_passes_every_danger_setting_the_env_sample_documents():
    """DANGER_MAX_SCAN_SECONDS was documented but never reached the container."""
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    sample = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")

    documented = {
        line.split("=", 1)[0].strip()
        for line in sample.splitlines()
        if line.strip() and not line.strip().startswith("#") and "=" in line
    }
    danger_keys = {key for key in documented if key.startswith("DANGER_")}
    assert danger_keys, "expected .env.example to document the danger knobs"

    missing = sorted(key for key in danger_keys if f"{key}:" not in compose)
    assert not missing, f"documented but never passed to the containers: {missing}"


def test_deploy_script_writes_the_danger_gate_into_env():
    """deploy.sh generated a .env with no ALLOW_DANGER_MODE line at all.

    The gate then fell back to its false default, so Danger Mode was disabled
    on every fresh production deploy with no indication why.
    """
    deploy = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")
    assert "ALLOW_DANGER_MODE=" in deploy


def test_deploy_script_enables_danger_mode_deliberately():
    """Danger Mode ships enabled, by an explicit decision of this project's owner.

    It was previously forced off in every generated .env. That is the safer
    default and the reason the original test existed, but it meant the operator
    had to re-enable it after every deploy, and the UI reported the scan as
    rejected with no obvious cause. The choice was made knowingly: the flag is
    on in .env, .env.example, deploy.sh, and the Compose fallback.

    The two-step runtime gate is what actually protects a target, and it is
    untouched — a scan still requires the checkbox plus the typed
    acknowledgement, checked again inside the worker. This test exists so the
    value cannot drift back silently in either direction.
    """
    deploy = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")
    assert "ALLOW_DANGER_MODE=true" in deploy
    assert "ALLOW_DANGER_MODE=false" not in deploy


def test_the_typed_acknowledgement_gate_is_still_enforced():
    """Enabling the flag must not have weakened the gate behind it."""
    from app.services.danger_mode import check_danger_gate

    assert not check_danger_gate("danger", acknowledgement=None).allowed
    assert not check_danger_gate("danger", acknowledgement="").allowed
    assert not check_danger_gate("danger", acknowledgement="i am authorised").allowed


def test_deploy_script_preserves_an_existing_env():
    """Re-running deploy.sh used to silently overwrite a tuned .env."""
    deploy = (REPO_ROOT / "deploy.sh").read_text(encoding="utf-8")
    # A backup alone did not preserve credentials used by an existing volume.
    # The setup-script tests also execute this branch against a temporary .env.
    existing_branch = deploy.split("if [[ -f .env ]]; then", 1)[1].split("\nelse", 1)[0]
    assert "Preserving existing .env" in existing_branch
    assert "cat > .env" not in existing_branch


def test_compose_wires_danger_settings_into_both_api_and_worker():
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    # The worker actually runs the scan; the API serves the bounds to the UI.
    assert len(re.findall(r"^\s+DANGER_MAX_SCAN_SECONDS:", compose, re.M)) == 2


# ── .env is actually read outside Docker ─────────────────────────────────────

def test_env_file_sets_danger_mode_for_a_local_operator(monkeypatch):
    """A local operator's .env was silently ignored outside Docker.

    Compose interpolates .env itself, so containers were always configured
    correctly. Nothing loaded it for a bare uvicorn/celery run, so setting
    ALLOW_DANGER_MODE=true in .env had no effect and every danger scan was
    rejected by the gate with "ALLOW_DANGER_MODE=false".
    """
    from dotenv import load_dotenv

    from app.config import Settings

    import tempfile

    monkeypatch.delenv("ALLOW_DANGER_MODE", raising=False)
    assert Settings().ALLOW_DANGER_MODE is False

    with tempfile.TemporaryDirectory() as scratch:
        env_file = Path(scratch) / ".env"
        env_file.write_text("ALLOW_DANGER_MODE=true\n", encoding="utf-8")
        load_dotenv(env_file, override=False)

    assert Settings().ALLOW_DANGER_MODE is True


def test_suite_is_isolated_from_a_developers_env_file():
    """Loading .env made results depend on the developer's machine.

    A local API_ACCESS_KEY 401s every API test and a local
    ALLOW_DANGER_MODE=true inverts the gate tests, so conftest opts out and
    config must honour that.
    """
    from app import config

    assert os.environ.get("RECONTITAN_SKIP_DOTENV") == "1"
    assert "RECONTITAN_SKIP_DOTENV" in inspect.getsource(config._load_env_file)


def test_repo_env_loader_targets_the_repository_root():
    """The loader must look beside docker-compose.yml, not inside backend/app."""
    from app import config

    expected = REPO_ROOT / ".env"
    resolved = Path(config.__file__).resolve().parent.parent.parent / ".env"
    assert resolved == expected


def test_dotenv_is_a_declared_dependency():
    """It was in requirements.txt but nothing ever imported it."""
    requirements = (REPO_ROOT / "backend" / "requirements.txt").read_text(encoding="utf-8")
    assert "python-dotenv" in requirements

    source = (REPO_ROOT / "backend" / "app" / "config.py").read_text(encoding="utf-8")
    assert "load_dotenv" in source, "config must actually load the .env file"


def test_real_environment_wins_over_the_env_file(monkeypatch):
    """Compose and systemd set real env vars; the file must not override them."""
    from app import config

    monkeypatch.setenv("ALLOW_DANGER_MODE", "false")
    config._load_env_file()
    assert os.environ["ALLOW_DANGER_MODE"] == "false"


def test_missing_env_file_is_not_an_error(monkeypatch):
    """A fresh clone has no .env; startup must not blow up."""
    from app import config

    monkeypatch.setattr(config, "load_dotenv", None)
    config._load_env_file()  # must not raise


# ── Connection reuse and DNS caching ─────────────────────────────────────────

@pytest.fixture(autouse=True)
def _clean_http_caches():
    from app.tasks.http_client import reset_http_client

    reset_http_client()
    yield
    reset_http_client()


def test_pool_is_reused_for_the_same_pinned_destination():
    """Each probe used to pay a full TCP+TLS handshake."""
    from app.tasks import http_client

    first, cached = http_client._get_pool("https", "93.184.216.34", 443, "example.com", 12)
    second, _ = http_client._get_pool("https", "93.184.216.34", 443, "example.com", 12)
    assert cached is True
    assert first is second


@pytest.mark.parametrize(
    "other",
    [
        ("https", "93.184.216.34", 443, "evil.test"),   # same IP, different SNI/cert host
        ("https", "1.2.3.4", 443, "example.com"),       # different pinned address
        ("http", "93.184.216.34", 443, "example.com"),  # different scheme
        ("https", "93.184.216.34", 8443, "example.com"),  # different port
    ],
)
def test_pool_reuse_never_crosses_destinations(other):
    """Reuse must be keyed to the exact destination that was validated."""
    from app.tasks import http_client

    base, _ = http_client._get_pool("https", "93.184.216.34", 443, "example.com", 12)
    assert http_client._get_pool(*other, 12)[0] is not base


def test_pool_cache_is_bounded(monkeypatch):
    from app.tasks import http_client

    monkeypatch.setattr(http_client.settings, "HTTP_POOL_MAX_IDLE", 3)
    for octet in range(10):
        http_client._get_pool("https", f"93.184.216.{octet}", 443, "example.com", 12)
    assert len(http_client._pools) <= 3


def test_pool_caching_can_be_disabled(monkeypatch):
    from app.tasks import http_client

    monkeypatch.setattr(http_client.settings, "HTTP_POOL_MAX_IDLE", 0)
    pool, cached = http_client._get_pool("https", "93.184.216.34", 443, "example.com", 12)
    assert cached is False
    assert http_client._pools == {}


def test_dns_result_is_cached_within_the_ttl(monkeypatch):
    from app.tasks import http_client

    calls = []
    monkeypatch.setattr(http_client.settings, "DNS_CACHE_TTL_SECONDS", 30)
    monkeypatch.setattr(
        http_client, "validate_scan_target",
        lambda host, resolve_dns=True: (calls.append(host), (True, host, ""))[1],
    )
    monkeypatch.setattr(http_client, "resolve_target_addresses", lambda host: ["93.184.216.34"])

    assert http_client._resolve_validated("example.com") == ("example.com", ("93.184.216.34",))
    http_client._resolve_validated("example.com")
    assert len(calls) == 1, "validation should not re-run inside the TTL"


def test_dns_cache_can_be_disabled_for_per_request_revalidation(monkeypatch):
    """TTL=0 restores the original behaviour for the strictest deployments."""
    from app.tasks import http_client

    calls = []
    monkeypatch.setattr(http_client.settings, "DNS_CACHE_TTL_SECONDS", 0)
    monkeypatch.setattr(
        http_client, "validate_scan_target",
        lambda host, resolve_dns=True: (calls.append(host), (True, host, ""))[1],
    )
    monkeypatch.setattr(http_client, "resolve_target_addresses", lambda host: ["93.184.216.34"])

    http_client._resolve_validated("example.com")
    http_client._resolve_validated("example.com")
    assert len(calls) == 2


def test_dns_cache_expires(monkeypatch):
    from app.tasks import http_client

    calls = []
    clock = [1000.0]
    monkeypatch.setattr(http_client.settings, "DNS_CACHE_TTL_SECONDS", 30)
    monkeypatch.setattr(http_client.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(
        http_client, "validate_scan_target",
        lambda host, resolve_dns=True: (calls.append(host), (True, host, ""))[1],
    )
    monkeypatch.setattr(http_client, "resolve_target_addresses", lambda host: ["93.184.216.34"])

    http_client._resolve_validated("example.com")
    clock[0] += 31
    http_client._resolve_validated("example.com")
    assert len(calls) == 2


def test_rejected_target_is_never_cached(monkeypatch):
    """A cached rejection would be a cached security decision. Don't."""
    from app.tasks import http_client

    monkeypatch.setattr(http_client.settings, "DNS_CACHE_TTL_SECONDS", 30)
    monkeypatch.setattr(
        http_client, "validate_scan_target",
        lambda host, resolve_dns=True: (False, host, "private address"),
    )
    for _ in range(2):
        with pytest.raises(http_client.UnsafeURL):
            http_client._resolve_validated("internal.test")
    assert http_client._dns_cache == {}


# ── Parallel phase execution ─────────────────────────────────────────────────

def _tools(names, *, failing=()):
    return [
        (
            name,
            10 + index,
            (lambda n=name: (_ for _ in ()).throw(RuntimeError(n)))
            if name in failing
            else (lambda n=name: [{"tool": n, "title": n}]),
        )
        for index, name in enumerate(names)
    ]


@pytest.fixture
def _no_db(monkeypatch):
    from app.tasks import scan_tasks

    saved: list[dict] = []
    monkeypatch.setattr(scan_tasks, "_update_scan_status", lambda *a, **k: None)
    monkeypatch.setattr(scan_tasks, "_save_findings", lambda scan_id, f: saved.extend(f))
    return saved


def test_parallel_phase_preserves_declared_tool_order(_no_db, monkeypatch):
    """Report ordering must not depend on which tool happens to finish first."""
    from app.tasks import scan_tasks

    monkeypatch.setattr(scan_tasks.settings, "SCAN_TOOL_CONCURRENCY", 8)
    names = [f"tool_{i}" for i in range(12)]
    scan_tasks._run_tools("scan_a", "recon", _tools(names), parallel=True)
    assert [f["title"] for f in _no_db] == names


def test_parallel_phase_is_fail_soft(_no_db, monkeypatch):
    """One dead tool must not take the phase down with it."""
    from app.tasks import scan_tasks

    monkeypatch.setattr(scan_tasks.settings, "SCAN_TOOL_CONCURRENCY", 4)
    completed: list[str] = []
    failed: list[str] = []
    scan_tasks._run_tools(
        "scan_a", "recon", _tools(["a", "b", "c"], failing={"b"}),
        completed=completed, failed=failed, parallel=True,
    )
    assert completed == ["a", "c"]
    assert failed == ["b"]
    assert [f["title"] for f in _no_db] == ["a", "c"]


def test_parallel_phase_actually_overlaps(_no_db, monkeypatch):
    """Guards against the flag silently degrading to sequential execution.

    This used a wall-clock assertion. It failed on a busy GitHub runner even
    though the executor submitted every tool concurrently, because thread
    scheduling delayed the workers. A rendezvous directly tests overlap rather
    than the speed of the runner.
    """
    import threading

    from app.tasks import scan_tasks

    monkeypatch.setattr(scan_tasks.settings, "SCAN_TOOL_CONCURRENCY", 8)
    rendezvous = threading.Barrier(2)
    overlapped = threading.Event()

    def tool():
        try:
            rendezvous.wait(timeout=1)
            overlapped.set()
        except threading.BrokenBarrierError:
            # A sequential implementation makes the first tool time out. The
            # assertion below reports that deterministically without depending
            # on CPU load or a runner's clock granularity.
            pass
        return []

    scan_tasks._run_tools(
        "scan_a", "recon", [("first", 10, tool), ("second", 10, tool)], parallel=True,
    )
    assert overlapped.is_set(), "parallel tools never overlapped"


@pytest.mark.parametrize("phase,task_name", [("recon", "run_recon"), ("osint", "run_osint")])
def test_independent_phases_request_parallel_execution(monkeypatch, phase, task_name):
    """Guards the call sites, not just the executor.

    The executor tests above pass ``parallel=True`` themselves, so they would
    still pass if the phase tasks quietly stopped asking for it.
    """
    from app.tasks import scan_tasks

    seen: dict = {}
    monkeypatch.setattr(scan_tasks, "_validated_task_target", lambda target: target)
    monkeypatch.setattr(
        scan_tasks, "_run_tools",
        lambda scan_id, name, tools, **kw: seen.update({"phase": name, **kw}) or 0,
    )
    getattr(scan_tasks, task_name).run("scan_abc123abc123", "example.com")
    assert seen["phase"] == phase
    assert seen.get("parallel") is True


def test_danger_phase_never_requests_parallel_execution(monkeypatch):
    """Danger stages share mutable session state and must stay ordered."""
    from app.tasks import scan_tasks

    seen: dict = {}
    monkeypatch.setattr(scan_tasks, "_validated_task_target", lambda target: target)
    monkeypatch.setattr(scan_tasks, "_save_danger_summary", lambda *a, **k: None)
    monkeypatch.setattr(
        scan_tasks, "_run_tools",
        lambda scan_id, name, tools, **kw: seen.update({"phase": name, **kw}) or 0,
    )
    scan_tasks.run_danger_scan.run("scan_abc123abc123", "example.com")
    assert seen["phase"] == "danger"
    assert seen.get("parallel", False) is False


def test_danger_stages_still_run_sequentially(_no_db, monkeypatch):
    """Danger stages feed each other, so ordering is load-bearing, not cosmetic."""
    from app.tasks import scan_tasks

    monkeypatch.setattr(scan_tasks.settings, "SCAN_TOOL_CONCURRENCY", 8)
    order: list[str] = []

    def stage(name):
        def run():
            order.append(f"start:{name}")
            order.append(f"end:{name}")
            return []
        return run

    tools = [(name, 10, stage(name)) for name in ("recon", "surface", "sqli")]
    scan_tasks._run_tools("scan_a", "danger", tools)  # parallel defaults to False
    assert order == [
        "start:recon", "end:recon",
        "start:surface", "end:surface",
        "start:sqli", "end:sqli",
    ]
