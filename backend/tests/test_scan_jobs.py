"""Queued scan lifecycle: dispatch, truthful status, reports, and cancellation."""

from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.middleware.security import rate_limiter
from app.routers import scans
from app.tasks import scan_tasks


def _client() -> TestClient:
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()
    return TestClient(app)


class _Collection:
    def __init__(self):
        self.documents = []

    @staticmethod
    def _matches(document, query):
        for key, expected in query.items():
            actual = document.get(key)
            if isinstance(expected, dict):
                if "$in" in expected and actual not in expected["$in"]:
                    return False
                if "$ne" in expected and actual == expected["$ne"]:
                    return False
            elif actual != expected:
                return False
        return True

    def insert_one(self, document):
        self.documents.append(deepcopy(document))
        return SimpleNamespace(inserted_id=len(self.documents))

    def find_one(self, query, projection=None):
        document = next((item for item in self.documents if self._matches(item, query)), None)
        if document is None:
            return None
        result = deepcopy(document)
        if projection and any(value == 1 for value in projection.values()):
            result = {key: result[key] for key, value in projection.items() if value == 1 and key in result}
        if projection and projection.get("_id") == 0:
            result.pop("_id", None)
        return result

    def update_one(self, query, update):
        document = next((item for item in self.documents if self._matches(item, query)), None)
        if document is None:
            return SimpleNamespace(matched_count=0)
        document.update(deepcopy(update.get("$set", {})))
        return SimpleNamespace(matched_count=1)


class _Database:
    def __init__(self):
        self.collections = {}

    def __getitem__(self, name):
        return self.collections.setdefault(name, _Collection())


def _database():
    return _Database()


def test_scan_is_dispatched_with_a_persisted_task_id(monkeypatch):
    db = _database()
    dispatched = {}
    monkeypatch.setattr(scans, "get_db", lambda: db)
    monkeypatch.setattr(scans, "validate_scan_target", lambda target, **_: (True, target, ""))
    monkeypatch.setattr(scans.settings, "SERVERLESS", False)

    def fake_apply_async(*, args, task_id):
        dispatched.update({"args": args, "task_id": task_id})

    monkeypatch.setattr(scan_tasks.orchestrate_scan, "apply_async", fake_apply_async)
    with _client() as client:
        response = client.post("/api/scan", json={"target": "example.com", "scan_type": "full"})

    assert response.status_code == 202
    scan_id = response.json()["scan_id"]
    record = db["scans"].find_one({"scan_id": scan_id})
    assert record["task_id"] == dispatched["task_id"]
    assert dispatched["args"] == [scan_id, "example.com", "full"]
    assert record["cancel_requested"] is False


def test_status_exposes_a_worker_failure_reason(monkeypatch):
    db = _database()
    scan_id = "scan_0123456789ab"
    db["scans"].insert_one({
        "scan_id": scan_id,
        "target": "example.com",
        "status": "failed",
        "phase": "recon",
        "progress": 12,
        "error": "Scanner process exited unexpectedly",
    })
    monkeypatch.setattr(scans, "get_db", lambda: db)
    with _client() as client:
        response = client.get(f"/api/scan/{scan_id}/status")

    assert response.status_code == 200
    assert response.json()["error"] == "Scanner process exited unexpectedly"


def test_cancel_marks_the_record_and_revokes_without_terminating(monkeypatch):
    db = _database()
    scan_id = "scan_0123456789ab"
    db["scans"].insert_one({
        "scan_id": scan_id,
        "target": "example.com",
        "status": "running",
        "progress": 34,
        "task_id": "task-123",
    })
    revoked = {}
    monkeypatch.setattr(scans, "get_db", lambda: db)
    monkeypatch.setattr(
        scan_tasks.celery_app.control,
        "revoke",
        lambda task_id, terminate: revoked.update({"task_id": task_id, "terminate": terminate}),
    )

    with _client() as client:
        response = client.post(f"/api/scan/{scan_id}/cancel")

    assert response.status_code == 200
    assert response.json()["status"] == "cancelled"
    record = db["scans"].find_one({"scan_id": scan_id})
    assert record["cancel_requested"] is True
    assert record["status"] == "cancelled"
    assert record["tools_running"] == []
    assert revoked == {"task_id": "task-123", "terminate": False}


def test_late_cancel_does_not_replace_a_completed_status(monkeypatch):
    db = _database()
    scan_id = "scan_0123456789ab"
    db["scans"].insert_one({
        "scan_id": scan_id,
        "target": "example.com",
        "status": "completed",
        "progress": 100,
    })
    monkeypatch.setattr(scans, "get_db", lambda: db)
    with _client() as client:
        response = client.post(f"/api/scan/{scan_id}/cancel")

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert db["scans"].find_one({"scan_id": scan_id})["status"] == "completed"


def test_cancelled_status_cannot_be_overwritten_by_a_finishing_tool(monkeypatch):
    db = _database()
    scan_id = "scan_0123456789ab"
    db["scans"].insert_one({"scan_id": scan_id, "status": "cancelled", "progress": 40})
    monkeypatch.setattr(scan_tasks, "get_db", lambda: db)

    scan_tasks._update_scan_status(scan_id, "running", phase="osint", progress=70)

    record = db["scans"].find_one({"scan_id": scan_id})
    assert record["status"] == "cancelled"
    assert record["progress"] == 40


def test_worker_revalidation_failure_marks_the_scan_failed(monkeypatch):
    updates = []
    monkeypatch.setattr(scan_tasks, "_scan_cancelled", lambda _scan_id: False)
    monkeypatch.setattr(
        scan_tasks,
        "_validated_task_target",
        lambda _target: (_ for _ in ()).throw(ValueError("Unsafe scan target")),
    )
    monkeypatch.setattr(
        scan_tasks,
        "_update_scan_status",
        lambda scan_id, status, **fields: updates.append((scan_id, status, fields)),
    )

    with pytest.raises(ValueError, match="Unsafe scan target"):
        scan_tasks.orchestrate_scan.run("scan_0123456789ab", "example.com", "full")

    assert updates == [(
        "scan_0123456789ab",
        "failed",
        {"progress": 100, "error": "ValueError", "completed": True},
    )]


def test_persisted_report_has_the_shape_used_by_the_frontend(monkeypatch):
    db = _database()
    scan_id = "scan_0123456789ab"
    now = datetime.now(timezone.utc)
    db["scans"].insert_one({
        "scan_id": scan_id,
        "target": "example.com",
        "scan_type": "full",
        "status": "completed",
        "created_at": now,
        "started_at": now,
        "completed_at": now,
        "tools_completed": ["whois", "ai_report"],
        "findings": [{
            "id": "finding_1",
            "tool": "whois",
            "category": "registration",
            "severity": "medium",
            "title": "Example",
            "description": "Example finding",
        }],
        "ai_summary": {"executive_summary": "Review the finding.", "risk_level": "MEDIUM"},
    })
    monkeypatch.setattr(scans, "get_db", lambda: db)
    with _client() as client:
        response = client.get(f"/api/scan/{scan_id}/report")

    assert response.status_code == 200
    body = response.json()
    assert body["severity_counts"]["medium"] == 1
    assert body["tools_run"] == 2
    assert body["total_time_seconds"] == 0
    assert body["ai_summary"]["risk_level"] == "MEDIUM"
