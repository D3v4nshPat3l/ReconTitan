"""Direct synchronous scan endpoint for local/degraded deployments."""

from __future__ import annotations

import json
import logging
import re
import time
import uuid
from collections.abc import Callable

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.responses import StreamingResponse

from app.config import settings
from app.models.schemas import ScanType, VerifyRequest
from app.services import audit
from app.services.danger_mode import check_danger_gate
from app.targeting import validate_scan_target

logger = logging.getLogger("recontitan.test")
router = APIRouter(prefix="/api", tags=["test"])

Tool = tuple[str, Callable[[str], list[dict]]]


def _tool_groups() -> dict[str, list[Tool]]:
    """Import scanner functions lazily so quick-start mode remains lightweight."""
    from app.tasks.osint.cookie_check import run_cookie_check
    from app.tasks.osint.cors_check import run_cors_check
    from app.tasks.osint.robots_sitemap import run_robots_sitemap
    from app.tasks.osint.security_headers import run_security_headers
    from app.tasks.osint.ssl_check import run_ssl_check
    from app.tasks.osint.waf_detect import run_wafw00f
    from app.tasks.osint.threat_intel import run_censys, run_greynoise, run_shodan, run_virustotal
    from app.tasks.osint.username_osint import run_theharvester
    from app.tasks.recon.crtsh import run_crtsh
    from app.tasks.recon.dns_lookup import run_dns_lookup
    from app.tasks.recon.favicon_hash import run_favicon_hash_lookup
    from app.tasks.recon.httpx_probe import run_httpx_probe
    from app.tasks.recon.ipinfo import run_ipinfo
    from app.tasks.recon.js_analysis import run_js_file_analysis
    from app.tasks.recon.port_scan import run_port_scan
    from app.tasks.recon.subdomain_takeover import run_subdomain_takeover
    from app.tasks.recon.subfinder_amass import run_amass, run_subfinder
    from app.tasks.recon.tech_stack import run_tech_stack_detection
    from app.tasks.recon.wayback import run_wayback
    from app.tasks.recon.whois_lookup import run_whois
    from app.tasks.vulnscan.nvd_lookup import run_nvd_for_target
    from app.tasks.vulnscan.vuln_tools import run_dir_fuzzing, run_nikto, run_nuclei, run_sqlmap_check

    vuln_tools: list[Tool] = [
        ("port_scan", run_port_scan),
        ("nvd_cve", run_nvd_for_target),
    ]
    if settings.ENABLE_ACTIVE_VULN_TOOLS:
        vuln_tools.extend([
            ("nuclei", run_nuclei),
            ("nikto", run_nikto),
            ("dir_fuzzing", run_dir_fuzzing),
            ("sqlmap", run_sqlmap_check),
        ])

    return {
        "recon": [
            ("whois", run_whois),
            ("dns_lookup", run_dns_lookup),
            ("crt.sh", run_crtsh),
            ("wayback", run_wayback),
            ("ipinfo", run_ipinfo),
            ("httpx_probe", run_httpx_probe),
            ("subfinder", run_subfinder),
            ("amass", run_amass),
        ],
        "osint": [
            ("tech_stack", run_tech_stack_detection),
            ("favicon_hash", run_favicon_hash_lookup),
            ("js_analysis", run_js_file_analysis),
            ("subdomain_takeover", run_subdomain_takeover),
            ("security_headers", run_security_headers),
            ("ssl_check", run_ssl_check),
            ("robots_sitemap", run_robots_sitemap),
            ("cors_check", run_cors_check),
            ("cookie_check", run_cookie_check),
            ("waf_detect", run_wafw00f),
            ("virustotal", run_virustotal),
            ("shodan", run_shodan),
            ("greynoise", run_greynoise),
            ("censys", run_censys),
            ("theharvester", run_theharvester),
        ],
        "vuln": vuln_tools,
    }


def _selected_tools(scan_type: ScanType) -> list[Tool]:
    groups = _tool_groups()
    selected_groups = {
        ScanType.RECON_ONLY: ("recon",),
        ScanType.OSINT_ONLY: ("osint",),
        ScanType.VULN_ONLY: ("vuln",),
        ScanType.FULL: ("recon", "osint", "vuln"),
        # Danger runs every safe group first; the danger stages are appended
        # separately because they share state through a DangerSession.
        ScanType.DANGER: ("recon", "osint", "vuln"),
    }[scan_type]
    tools: list[Tool] = []
    for group in selected_groups:
        tools.extend(groups.get(group, []))
    return tools


@router.get("/test-scan")
def test_scan(
    http_request: Request,
    target: str = Query(..., min_length=3, max_length=253),
    scan_type: ScanType = Query(default=ScanType.FULL),
    danger_acknowledgement: str | None = Query(default=None, max_length=120),
    stream: bool = False,
):
    """Run a selected scan profile synchronously without MongoDB or Celery."""
    # Only the queued path used to record scan events, but this is the endpoint
    # the browser actually calls and the only one that works without Celery. The
    # SOC console's scan-activity and target panels were therefore empty on every
    # real deployment, while advertising attribution they never received.
    gate = check_danger_gate(scan_type.value, acknowledgement=danger_acknowledgement)
    if not gate.allowed:
        audit.record_scan_event(
            audit.SCAN_GATE_DENIED, http_request,
            target=target, scan_type=scan_type.value, detail=gate.reason,
        )
        raise HTTPException(status_code=403, detail=gate.reason)

    ok, target, error = validate_scan_target(target, resolve_dns=True)
    if not ok:
        audit.record_scan_event(
            audit.SCAN_REJECTED, http_request,
            target=target, scan_type=scan_type.value, detail=error,
        )
        raise HTTPException(status_code=400, detail=error)

    events = _scan_events(http_request, target, scan_type)
    if stream:
        return StreamingResponse(
            _encode_scan_events(events),
            media_type="application/x-ndjson",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )
    # Existing API clients still receive the original single JSON report.
    for event in events:
        if event["type"] == "complete":
            return event["report"]


def _encode_scan_events(events):
    try:
        for event in events:
            yield json.dumps(jsonable_encoder(event), ensure_ascii=False) + "\n"
    except Exception:
        # HTTP headers have already been sent. Signal failure in the stream,
        # without exposing internal exceptions or pretending it completed.
        logger.exception("[test] streaming scan failed")
        yield json.dumps({"type": "error", "message": "Scan failed while building the report. Check the server logs."}) + "\n"
    finally:
        events.close()


def _scan_events(http_request: Request, target: str, scan_type: ScanType):
    """Run once, yielding real milestones before/after each blocking stage."""
    scan_id = f"test_{uuid.uuid4().hex[:8]}"
    start = time.monotonic()
    all_findings: list[dict] = []
    tool_results: dict[str, dict] = {}
    tools = _selected_tools(scan_type)

    danger_session = None
    danger_stage_names: set[str] = set()
    if scan_type is ScanType.DANGER:
        from app.tasks.vulnscan.danger.pipeline import danger_stages

        danger_session, danger_tools = danger_stages(target)
        danger_stage_names = {name for name, _ in danger_tools}
        tools = tools + list(danger_tools)

    # Wall-clock ceiling for the whole scan. Without it the loop runs every tool
    # to completion and a serverless platform kills the request part-way, so the
    # caller gets a 500 and loses every finding already gathered. Stopping here
    # keeps them: the remaining stages are recorded as skipped and the report is
    # still produced, which is the behaviour the UI advertises.
    budget_seconds = settings.MAX_SYNC_SCAN_SECONDS
    skipped_for_time: list[str] = []
    total_steps = len(tools) + 2  # Scanner checks, summary, finding explanations.

    def progress(completed, phase, **details):
        return {
            "type": "progress", "scan_id": scan_id,
            "progress": min(99, int(completed * 100 / total_steps)),
            "completed_steps": completed, "total_steps": total_steps,
            "phase": phase, **details,
        }

    yield progress(0, "Starting scan")

    for index, (tool_name, tool_fn) in enumerate(tools):
        if budget_seconds and time.monotonic() - start >= budget_seconds:
            skipped_for_time = [name for name, _ in tools[index:]]
            for offset, name in enumerate(skipped_for_time):
                tool_results[name] = {"status": "skipped", "reason": "time_limit", "findings": 0}
                if danger_session is not None and name in danger_stage_names:
                    if name not in danger_session.stages_skipped:
                        danger_session.stages_skipped.append(name)
                yield progress(index + offset + 1, f"Skipped {name}: scan time limit", tool=name, status="skipped")
            logger.warning(
                "[test] %s: %.1fs budget reached, skipping %d of %d stages",
                target, budget_seconds, len(skipped_for_time), len(tools),
            )
            break

        yield progress(index, f"Running {tool_name}", tool=tool_name, status="running")
        tool_start = time.monotonic()
        try:
            # Streaming iterators can resume on different pool threads. Scope
            # the deep-scan context to the tool call, never across a yield.
            from app.tasks.recon.port_scan import DANGER_ACTIVE
            token = DANGER_ACTIVE.set(scan_type is ScanType.DANGER)
            try:
                results = tool_fn(target) or []
            finally:
                DANGER_ACTIVE.reset(token)
            elapsed = round(time.monotonic() - tool_start, 2)
            tool_results[tool_name] = {"status": "ok", "findings": len(results), "time_seconds": elapsed}
            for finding in results:
                finding = dict(finding)
                finding.setdefault("id", f"finding_{uuid.uuid4().hex[:10]}")
                finding.setdefault("severity", "info")
                finding.setdefault("description", "")
                finding.setdefault("title", tool_name)
                finding.setdefault("category", "general")
                finding.setdefault("tool", tool_name)
                all_findings.append(finding)
            # Only danger stages belong in the danger summary; the safe profiles
            # that run first are already reported through tool_results.
            if (
                danger_session is not None
                and tool_name in danger_stage_names
                and tool_name not in danger_session.stages_completed
                and tool_name not in danger_session.stages_skipped
            ):
                danger_session.stages_completed.append(tool_name)
        except Exception as exc:
            elapsed = round(time.monotonic() - tool_start, 2)
            tool_results[tool_name] = {"status": "error", "error": type(exc).__name__, "time_seconds": elapsed}
            if danger_session is not None and tool_name in danger_stage_names:
                danger_session.stages_failed.append(tool_name)
            logger.exception("[test] %s failed", tool_name)
        result = tool_results[tool_name]
        yield progress(
            index + 1, f"Finished {tool_name}" if result["status"] == "ok" else f"Check failed: {tool_name}",
            tool=tool_name, status=result["status"], findings=result.get("findings", 0),
        )

    if danger_session is not None and danger_session.stages_skipped:
        notice = dict(danger_session.deadline_finding())
        notice.setdefault("id", f"finding_{uuid.uuid4().hex[:10]}")
        all_findings.append(notice)

    severity_counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in all_findings:
        severity = str(finding.get("severity", "info")).lower()
        severity_counts[severity if severity in severity_counts else "info"] += 1

    from app.tasks.ai_analysis import ai_status, explain_findings_bulk, generate_scan_summary

    yield progress(len(tools), "Building scan summary")
    ai_summary = generate_scan_summary(target, all_findings, severity_counts)
    # Bounded in count, wall-clock, and concurrency inside the helper, so a slow
    # local model cannot hold this synchronous request open indefinitely.
    yield progress(len(tools) + 1, "Explaining findings")
    explain_findings_bulk(all_findings)
    yield progress(total_steps, "Finalizing report")

    payload = {
        "time_limited": bool(skipped_for_time),
        "stages_skipped_for_time": skipped_for_time,
        "scan_id": scan_id,
        "target": target,
        "scan_type": scan_type.value,
        "total_time_seconds": round(time.monotonic() - start, 2),
        "tools_run": len(tools),
        "total_findings": len(all_findings),
        "severity_counts": severity_counts,
        "ai_summary": ai_summary,
        "ai_backend": ai_status().get("active_backend", "fallback"),
        "tool_results": tool_results,
        "findings": all_findings,
    }
    if danger_session is not None:
        payload["danger_summary"] = danger_session.summary().model_dump(mode="json")

    audit.record_scan_event(
        audit.SCAN_ACCEPTED, http_request,
        scan_id=scan_id, target=target, scan_type=scan_type.value,
        status="completed",
        findings=len(all_findings),
        duration_seconds=payload["total_time_seconds"],
    )
    yield {"type": "complete", "progress": 100, "report": payload}


@router.get("/rescan")
def rescan_one_tool(
    http_request: Request,
    target: str = Query(..., min_length=3, max_length=253),
    tool: str = Query(..., min_length=2, max_length=40),
):
    """Re-run a single scanner and return just its findings.

    This backs the refresh control on each report card, so a section that
    failed or returned stale data can be retried on its own instead of
    re-running the whole scan.

    Two limits are deliberate. The tool must be one of the named safe-profile
    scanners -- the danger stages are not reachable here, because they are
    gated on a typed acknowledgement that a refresh button cannot collect.
    And DANGER_ACTIVE is left unset, so the port scanner runs its bounded
    profile rather than the deep one for the same reason.
    """
    tools = {name: fn for group in _tool_groups().values() for name, fn in group}

    # Accept an alphanumeric alias for every scanner alongside its real name.
    # "crt.sh" is the reason: the injection filter blocks a query value ending
    # in .sh, correctly, since it cannot know this one is a certificate log
    # rather than a shell script. Naming it "crtsh" in the URL sidesteps that
    # without loosening the filter for everything else.
    aliases = {re.sub(r"[^a-z0-9]", "", name.lower()): name for name in tools}
    resolved = tool if tool in tools else aliases.get(re.sub(r"[^a-z0-9]", "", tool.lower()))
    if resolved is None:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown or non-refreshable scanner: {tool}",
        )
    tool = resolved

    ok, target, error = validate_scan_target(target, resolve_dns=True)
    if not ok:
        audit.record_scan_event(
            audit.SCAN_REJECTED, http_request, target=target, detail=error,
        )
        raise HTTPException(status_code=400, detail=error)

    start = time.monotonic()
    try:
        results = tools[tool](target) or []
    except Exception as exc:
        # Report the failure rather than 500-ing. The card needs something to
        # display either way, and "this check failed, here is why" is a more
        # useful answer than a browser-level error the user cannot act on.
        logger.exception("[rescan] %s failed for %s", tool, target)
        return {
            "status": "error",
            "tool": tool,
            "target": target,
            "error": type(exc).__name__,
            "time_seconds": round(time.monotonic() - start, 2),
            "findings": [],
        }

    findings = []
    for finding in results:
        finding = dict(finding)
        finding.setdefault("id", f"finding_{uuid.uuid4().hex[:10]}")
        finding.setdefault("severity", "info")
        finding.setdefault("description", "")
        finding.setdefault("title", tool)
        finding.setdefault("category", "general")
        finding.setdefault("tool", tool)
        findings.append(finding)

    return {
        "status": "ok",
        "tool": tool,
        "target": target,
        "time_seconds": round(time.monotonic() - start, 2),
        "findings": findings,
    }


@router.post("/verify")
def verify_finding_endpoint(request: VerifyRequest):
    from app.tasks.ai_analysis import verify_finding

    finding = {
        "title": request.finding_text or request.finding_id,
        "severity": request.severity.value,
        "description": request.description or request.finding_text,
    }
    result = verify_finding(finding, request.target)
    return {"status": "ok", "scan_id": request.scan_id, "finding_id": request.finding_id, **result}
