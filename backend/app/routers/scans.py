"""Scan API endpoints."""

from __future__ import annotations

import logging
import re
import uuid
from time import perf_counter
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import Response

from app.config import settings
from app.database import get_db
from app.services import audit
from app.models.schemas import (
    ScanReport,
    ScanRequest,
    ScanResponse,
    ScanStatus,
    ScanStatusResponse,
)
from app.services.capabilities import tools_for_profile
from app.services.danger_mode import check_danger_gate
from app.services.pdf_report import build_pdf_report
from app.targeting import validate_scan_target

logger = logging.getLogger("recontitan.scans")
router = APIRouter(prefix="/api", tags=["scans"])

_active_scans: dict[str, dict] = {}
SCAN_ID_RE = re.compile(r"^scan_[a-f0-9]{12}$")
def tools_for_scan_type(scan_type: str) -> list[str]:
    return tools_for_profile(scan_type)



def load_scan_record(scan_id: str) -> dict | None:
    if not SCAN_ID_RE.fullmatch(scan_id):
        return None
    db = get_db()
    record = None
    if db is not None:
        record = db["scans"].find_one({"scan_id": scan_id}, {"_id": 0})
    return record or _active_scans.get(scan_id)


def _report_payload(record: dict) -> dict:
    findings = record.get("findings", [])
    started = record.get("started_at") or record.get("created_at") or datetime.now(timezone.utc)
    completed = record.get("completed_at")
    duration = None
    if started and completed:
        duration = max(0, int((completed - started).total_seconds()))
    counts = {
        level: sum(1 for finding in findings if str(finding.get("severity", "info")) == level)
        for level in ("critical", "high", "medium", "low", "info")
    }
    ai_summary = record.get("ai_summary")
    return {
        "scan_id": record["scan_id"],
        "target": record["target"],
        "scan_type": record.get("scan_type", "full"),
        "status": record.get("status", ScanStatus.QUEUED),
        "started_at": started,
        "completed_at": completed,
        "duration_seconds": duration,
        "findings": findings,
        "summary": record.get("summary") or (ai_summary or {}).get("executive_summary"),
        "tools_used": record.get("tools_completed", []),
        "tool_results": record.get("tool_results") or {
            tool: {"status": "ok"} for tool in record.get("tools_completed", [])
        },
        "danger_summary": record.get("danger_summary"),
        "ai_summary": ai_summary,
        "severity_counts": counts,
        "total_time_seconds": duration,
        "tools_run": len(record.get("tools_completed", [])),
        "total_findings": len(findings),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "info_count": counts["info"],
    }


@router.post("/scan", response_model=ScanResponse, status_code=202)
def initiate_scan(request: ScanRequest, http_request: Request):
    gate = check_danger_gate(request.scan_type.value, acknowledgement=request.danger_acknowledgement)
    if not gate.allowed:
        audit.record_scan_event(
            audit.SCAN_GATE_DENIED, http_request,
            target=request.target, scan_type=request.scan_type.value, reason=gate.reason,
        )
        raise HTTPException(status_code=403, detail=gate.reason)

    ok, target, error = validate_scan_target(request.target, resolve_dns=True)
    if not ok:
        audit.record_scan_event(
            audit.SCAN_REJECTED, http_request,
            target=request.target, scan_type=request.scan_type.value, reason=error,
        )
        raise HTTPException(status_code=400, detail=error)

    if settings.SERVERLESS or not settings.ASYNC_SCANS_ENABLED:
        # No worker process exists to consume the queue here, so accepting the
        # scan would leave it queued forever. Fail loudly and name the endpoint
        # that does work in this deployment.
        raise HTTPException(
            status_code=503,
            detail=(
                "Asynchronous scans are disabled for this deployment; they need a Celery worker. "
                "Use GET /api/test-scan, which performs the scan synchronously."
            ),
        )

    scan_id = f"scan_{uuid.uuid4().hex[:12]}"
    task_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    scan_record = {
        "scan_id": scan_id,
        "target": target,
        "scan_type": request.scan_type.value,
        "status": ScanStatus.QUEUED.value,
        "phase": None,
        "progress": 0,
        "tools_completed": [],
        "tools_running": [],
        "tools_remaining": tools_for_scan_type(request.scan_type.value),
        "findings": [],
        "total_findings": 0,
        "created_at": now,
        "started_at": None,
        "completed_at": None,
        "task_id": task_id,
        "cancel_requested": False,
        # Attribution. Without these the admin view cannot answer who ran a
        # scan, and an abusive target cannot be traced back to a source.
        "client_ip": audit.client_ip(http_request),
        "user_agent": audit._clip(http_request.headers.get("user-agent", ""), 256),
        "api_key_id": audit.key_fingerprint(http_request.headers.get("x-recontitan-key", "")),
    }

    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="MongoDB is required for asynchronous scans; use /api/test-scan for local scans")
    db["scans"].insert_one(scan_record.copy())
    _active_scans[scan_id] = scan_record
    if len(_active_scans) > 1000:
        _active_scans.pop(next(iter(_active_scans)))

    try:
        from app.tasks.scan_tasks import orchestrate_scan
        orchestrate_scan.apply_async(
            args=[scan_id, target, request.scan_type.value],
            task_id=task_id,
        )
    except Exception as exc:
        logger.error("Scan queue unavailable for %s: %s", scan_id, str(exc)[:160])
        scan_record["status"] = ScanStatus.FAILED.value
        scan_record["error"] = "Scan queue unavailable"
        if db is not None:
            db["scans"].update_one(
                {"scan_id": scan_id},
                {"$set": {"status": ScanStatus.FAILED.value, "error": "Scan queue unavailable", "completed_at": datetime.now(timezone.utc)}},
            )
        raise HTTPException(status_code=503, detail="Scan worker is unavailable") from exc

    audit.record_scan_event(
        audit.SCAN_ACCEPTED, http_request,
        scan_id=scan_id, target=target, scan_type=request.scan_type.value,
        api_key_id=scan_record["api_key_id"],
    )
    logger.info("Scan accepted: %s -> %s (%s)", scan_id, target, request.scan_type.value)
    return ScanResponse(message=f"Scan queued for {target}", scan_id=scan_id, target=target)


@router.get("/scan/{scan_id}/status", response_model=ScanStatusResponse)
def get_scan_status(scan_id: str):
    record = load_scan_record(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanStatusResponse(
        scan_id=record["scan_id"],
        target=record["target"],
        status=record["status"],
        phase=record.get("phase"),
        progress=record.get("progress", 0),
        tools_completed=record.get("tools_completed", []),
        tools_running=record.get("tools_running", []),
        tools_remaining=record.get("tools_remaining", []),
        started_at=record.get("started_at"),
        completed_at=record.get("completed_at"),
        error=record.get("error"),
    )


@router.post("/scan/{scan_id}/cancel")
def cancel_scan(scan_id: str, http_request: Request):
    """Request cooperative cancellation of a queued or running scan.

    Revocation prevents a queued task from starting. A task already executing
    stops at the next phase/tool boundary, so a scanner subprocess is never
    killed underneath another job sharing the same worker process.
    """
    record = load_scan_record(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")

    current = str(record.get("status", ScanStatus.QUEUED.value))
    if current in {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.CANCELLED.value}:
        return {
            "scan_id": scan_id,
            "status": current,
            "message": "Scan is already in a terminal state.",
        }

    now = datetime.now(timezone.utc)
    update = {
        "status": ScanStatus.CANCELLED.value,
        "cancel_requested": True,
        "completed_at": now,
        "last_updated": now,
        "tools_running": [],
    }
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Persistent scan storage is unavailable")
    result = db["scans"].update_one(
        {"scan_id": scan_id, "status": {"$in": [ScanStatus.QUEUED.value, ScanStatus.RUNNING.value]}},
        {"$set": update},
    )
    if not result.matched_count:
        latest = db["scans"].find_one({"scan_id": scan_id}, {"_id": 0, "status": 1}) or {}
        latest_status = str(latest.get("status", current))
        return {
            "scan_id": scan_id,
            "status": latest_status,
            "message": "Scan reached a terminal state before cancellation was applied.",
        }
    if scan_id in _active_scans:
        _active_scans[scan_id].update(update)

    task_id = str(record.get("task_id", ""))
    if task_id:
        try:
            from app.celery_app import celery_app

            celery_app.control.revoke(task_id, terminate=False)
        except Exception as exc:
            # The durable cancellation flag is authoritative; a running worker
            # will observe it even if Redis is briefly unavailable here.
            logger.warning("Could not revoke queued task %s: %s", task_id, str(exc)[:160])

    audit.record_scan_event(audit.SCAN_CANCELLED, http_request, scan_id=scan_id, target=record.get("target", ""))
    return {
        "scan_id": scan_id,
        "status": ScanStatus.CANCELLED.value,
        "message": "Cancellation requested. In-flight tool work may finish before the worker stops.",
    }


@router.get("/scan/{scan_id}/report", response_model=ScanReport)
def get_scan_report(scan_id: str):
    record = load_scan_record(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanReport(**_report_payload(record))


@router.get("/scan/{scan_id}/report.pdf")
def get_scan_report_pdf(scan_id: str):
    record = load_scan_record(scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    payload = _report_payload(record)
    payload["severity_counts"] = {
        "critical": payload["critical_count"], "high": payload["high_count"],
        "medium": payload["medium_count"], "low": payload["low_count"], "info": payload["info_count"],
    }
    payload["total_time_seconds"] = payload["duration_seconds"]
    payload["ai_summary"] = record.get("ai_summary") or ({"executive_summary": payload.get("summary")} if payload.get("summary") else None)
    payload["danger_summary"] = record.get("danger_summary")
    started = perf_counter()
    content = build_pdf_report(payload)
    elapsed_ms = max(1, round((perf_counter() - started) * 1000))
    safe_target = re.sub(r"[^a-zA-Z0-9._-]+", "_", record["target"])
    safe_target = re.sub(r"\.{2,}", "_", safe_target).strip("._") or "target"
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="recontitan_{safe_target}.pdf"',
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
            "Content-Length": str(len(content)),
            "X-Report-Generation-Ms": str(elapsed_ms),
        },
    )


# Scan history is deliberately not exposed here. The former GET /api/scans let
# any holder of the shared access key enumerate every target anyone had ever
# scanned, which the shared-key model was never meant to authorise. It now
# lives on the isolated admin console as GET /admin/api/scans, served with
# attribution to an authenticated operator over an SSH tunnel.
