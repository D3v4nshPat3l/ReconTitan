"""Live local progress; every scanner and AI call is stubbed (no target traffic)."""
import asyncio
import json
import threading

import pytest
from fastapi import Request
from fastapi.testclient import TestClient

from app.main import app
from app.middleware.security import rate_limiter
from app.models.schemas import ScanType
from app.routers import test_scan as scans
from app.tasks import ai_analysis
from app.tasks.recon.port_scan import DANGER_ACTIVE


@pytest.fixture(autouse=True)
def isolated_scan(monkeypatch):
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()
    monkeypatch.setattr(scans.settings, "MAX_SYNC_SCAN_SECONDS", 0)
    monkeypatch.setattr(scans, "validate_scan_target", lambda target, **_: (True, target, ""))
    monkeypatch.setattr(scans.audit, "record_scan_event", lambda *a, **kw: None)
    monkeypatch.setattr(scans, "_selected_tools", lambda _: [("first", lambda _: [{"title": "Found", "severity": "low"}]), ("second", lambda _: [])])
    monkeypatch.setattr(ai_analysis, "generate_scan_summary", lambda *a: {"executive_summary": "Test summary"})
    monkeypatch.setattr(ai_analysis, "explain_findings_bulk", lambda *a: None)
    monkeypatch.setattr(ai_analysis, "ai_status", lambda: {"active_backend": "fallback"})


def events():
    return scans._scan_events(Request({"type": "http"}), "example.com", ScanType.FULL)


def test_stream_has_incremental_progress_and_final_report():
    response = TestClient(app).get("/api/test-scan?target=example.com&stream=true")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/x-ndjson")
    assert response.headers["x-accel-buffering"] == "no"
    data = [json.loads(line) for line in response.text.splitlines()]
    percentages = [event["progress"] for event in data]
    assert percentages == sorted(percentages)
    assert {0, 25, 50, 75, 99, 100} <= set(percentages)
    assert all(event["progress"] < 100 for event in data[:-1])
    assert data[-1]["report"]["total_findings"] == 1
    assert data[-1]["report"]["severity_counts"]["low"] == 1
    assert "Building scan summary" in [event.get("phase") for event in data]
    assert "Explaining findings" in [event.get("phase") for event in data]


def test_existing_json_api_stays_compatible():
    response = TestClient(app).get("/api/test-scan?target=example.com")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json()["total_findings"] == 1
    assert response.json()["tools_run"] == 2


def test_updates_are_delivered_through_middleware_before_scan_finishes(monkeypatch):
    """Unlike TestClient's buffered response, ASGI send observes live chunks."""
    running_delivered = threading.Event()
    completed_delivered = threading.Event()

    def first(_):
        assert running_delivered.wait(3), "Start update was buffered"
        return []

    def second(_):
        assert completed_delivered.wait(3), "Completion update was buffered"
        return []

    monkeypatch.setattr(scans, "_selected_tools", lambda _: [("first", first), ("second", second)])
    messages = []

    async def run():
        requested = False

        async def receive():
            nonlocal requested
            if not requested:
                requested = True
                return {"type": "http.request", "body": b"", "more_body": False}
            await asyncio.Event().wait()

        async def send(message):
            messages.append(message)
            for line in message.get("body", b"").splitlines():
                event = json.loads(line)
                if event.get("tool") == "first":
                    if event.get("status") == "running":
                        running_delivered.set()
                    elif event.get("status") == "ok":
                        completed_delivered.set()

        scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
                 "method": "GET", "scheme": "http", "path": "/api/test-scan", "root_path": "",
                 "query_string": b"target=example.com&stream=true",
                 "headers": [(b"host", b"testserver")], "client": ("127.0.0.1", 1234),
                 "server": ("testserver", 80)}
        await asyncio.wait_for(app(scope, receive, send), timeout=10)

    asyncio.run(run())
    body = b"".join(message.get("body", b"") for message in messages)
    report = json.loads(body.splitlines()[-1])["report"]
    assert all(result["status"] == "ok" for result in report["tool_results"].values())


def test_failed_check_advances_progress_and_preserves_other_findings(monkeypatch):
    def broken(_):
        raise RuntimeError("private exception detail")
    monkeypatch.setattr(scans, "_selected_tools", lambda _: [("broken", broken), ("ok", lambda _: [{"title": "Kept"}])])
    data = list(events())
    assert any(event.get("status") == "error" and event["progress"] == 25 for event in data)
    assert data[-1]["report"]["total_findings"] == 1
    assert data[-1]["report"]["tool_results"]["broken"]["error"] == "RuntimeError"


def test_time_limit_reports_skipped_checks_and_finishes(monkeypatch):
    monkeypatch.setattr(scans.settings, "MAX_SYNC_SCAN_SECONDS", 1)
    ticks = iter([0, 2, 3])
    monkeypatch.setattr(scans.time, "monotonic", lambda: next(ticks, 3))
    data = list(events())
    assert [e["tool"] for e in data if e.get("status") == "skipped"] == ["first", "second"]
    assert data[-1]["report"]["time_limited"] is True
    assert data[-1]["progress"] == 100


def test_report_failure_is_an_error_event_not_a_false_completion(monkeypatch):
    def broken(*_):
        raise RuntimeError("private AI credentials")
    monkeypatch.setattr(ai_analysis, "generate_scan_summary", broken)
    data = [json.loads(line) for line in scans._encode_scan_events(events())]
    assert data[-1]["type"] == "error"
    assert not any(e["type"] == "complete" for e in data)
    assert "private AI credentials" not in json.dumps(data)


@pytest.mark.parametrize("stream", [False, True])
def test_invalid_target_still_returns_400_before_streaming(monkeypatch, stream):
    monkeypatch.setattr(scans, "validate_scan_target", lambda *a, **k: (False, "bad", "Invalid target"))
    response = TestClient(app).get("/api/test-scan", params={"target": "example.com", "stream": stream})
    assert response.status_code == 400


def test_danger_gate_is_not_bypassed_by_streaming(monkeypatch):
    monkeypatch.setattr(scans.settings, "ALLOW_DANGER_MODE", False)
    response = TestClient(app).get("/api/test-scan?target=example.com&scan_type=danger&stream=true")
    assert response.status_code == 403


def test_context_is_scoped_to_each_tool_and_restored_at_yields(monkeypatch):
    from app.tasks.vulnscan.danger import pipeline
    seen = []
    monkeypatch.setattr(pipeline, "danger_stages", lambda _: (None, []))
    monkeypatch.setattr(scans, "_selected_tools", lambda _: [("context", lambda _: seen.append(DANGER_ACTIVE.get()) or [])])
    for scan_type, expected in [(ScanType.DANGER, True), (ScanType.FULL, False)]:
        for _ in scans._scan_events(Request({"type": "http"}), "example.com", scan_type):
            assert DANGER_ACTIVE.get() is False
        assert seen[-1] is expected


def test_closing_stream_between_checks_does_not_start_next_tool(monkeypatch):
    calls = []
    monkeypatch.setattr(scans, "_selected_tools", lambda _: [("first", lambda _: calls.append(1) or []), ("second", lambda _: calls.append(2) or [])])
    stream = scans._encode_scan_events(events())
    for line in stream:
        if json.loads(line).get("status") == "ok":
            break
    stream.close()
    assert calls == [1]
