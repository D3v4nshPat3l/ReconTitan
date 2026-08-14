"""Celery scan orchestration and phase tasks."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Callable

from app.celery_app import celery_app
from app.config import settings
from app.services.danger_mode import danger_mode_enabled
from app.targeting import validate_scan_target
from app.database import get_db

from app.tasks.recon.whois_lookup import run_whois
from app.tasks.recon.dns_lookup import run_dns_lookup
from app.tasks.recon.crtsh import run_crtsh
from app.tasks.recon.wayback import run_wayback
from app.tasks.recon.ipinfo import run_ipinfo
from app.tasks.recon.httpx_probe import run_httpx_probe
from app.tasks.recon.subfinder_amass import run_subfinder, run_amass
from app.tasks.recon.port_scan import run_port_scan
from app.tasks.recon.tech_stack import run_tech_stack_detection
from app.tasks.recon.favicon_hash import run_favicon_hash_lookup
from app.tasks.recon.js_analysis import run_js_file_analysis
from app.tasks.recon.subdomain_takeover import run_subdomain_takeover

from app.tasks.osint.security_headers import run_security_headers
from app.tasks.osint.ssl_check import run_ssl_check
from app.tasks.osint.robots_sitemap import run_robots_sitemap
from app.tasks.osint.cors_check import run_cors_check
from app.tasks.osint.cookie_check import run_cookie_check
from app.tasks.osint.waf_detect import run_wafw00f
from app.tasks.osint.threat_intel import run_virustotal, run_shodan, run_greynoise, run_censys
from app.tasks.osint.username_osint import run_theharvester

from app.tasks.vulnscan.nvd_lookup import run_nvd_for_target
from app.tasks.vulnscan.vuln_tools import (
    run_nuclei, run_nikto, run_dir_fuzzing, run_sqlmap_check,
)

logger = logging.getLogger("recontitan.tasks")


def _validated_task_target(target: str) -> str:
    """Revalidate queued targets at execution time to resist stale/rebound DNS."""
    ok, normalized, error = validate_scan_target(target, resolve_dns=True)
    if not ok:
        raise ValueError(f"Unsafe scan target: {error}")
    return normalized


@celery_app.task(bind=True, name="app.tasks.scan_tasks.orchestrate_scan")
def orchestrate_scan(self, scan_id: str, target: str, scan_type: str):
    target = _validated_task_target(target)
    logger.info("[%s] scan started for %s (%s)", scan_id, target, scan_type)
    _update_scan_status(scan_id, "running", phase="recon", progress=2, started=True)
    try:
        if scan_type in {"full", "recon_only", "danger"}:
            run_recon.run(scan_id, target)
        if scan_type in {"full", "osint_only", "danger"}:
            run_osint.run(scan_id, target)
        if scan_type in {"full", "vuln_only", "danger"}:
            run_portscan.run(scan_id, target)
            run_vuln_scan.run(scan_id, target)
        if scan_type == "danger":
            run_danger_scan.run(scan_id, target)
        run_ai_analysis.run(scan_id)
        logger.info("[%s] scan complete", scan_id)
        return {"scan_id": scan_id, "status": "completed"}
    except Exception as exc:
        logger.exception("[%s] scan pipeline failed", scan_id)
        _update_scan_status(scan_id, "failed", progress=100, error=type(exc).__name__, completed=True)
        raise


@celery_app.task(bind=True, name="app.tasks.scan_tasks.run_recon")
def run_recon(self, scan_id: str, target: str):
    target = _validated_task_target(target)
    tools = [
        ("whois", 9, lambda: run_whois(target)),
        ("dns_lookup", 12, lambda: run_dns_lookup(target)),
        ("crt.sh", 15, lambda: run_crtsh(target)),
        ("wayback", 18, lambda: run_wayback(target)),
        ("ipinfo", 21, lambda: run_ipinfo(target)),
        ("httpx_probe", 24, lambda: run_httpx_probe(target)),
        ("subfinder", 27, lambda: run_subfinder(target)),
        ("amass", 30, lambda: run_amass(target)),
    ]
    count = _run_tools(scan_id, "recon", tools)
    return {"phase": "recon", "status": "complete", "findings": count}


@celery_app.task(bind=True, name="app.tasks.scan_tasks.run_osint")
def run_osint(self, scan_id: str, target: str):
    target = _validated_task_target(target)
    tools = [
        ("security_headers", 34, lambda: run_security_headers(target)),
        ("ssl_check", 37, lambda: run_ssl_check(target)),
        ("robots_sitemap", 40, lambda: run_robots_sitemap(target)),
        ("cors_check", 43, lambda: run_cors_check(target)),
        ("cookie_check", 46, lambda: run_cookie_check(target)),
        ("waf_detect", 49, lambda: run_wafw00f(target)),
        ("tech_stack", 52, lambda: run_tech_stack_detection(target)),
        ("favicon_hash", 55, lambda: run_favicon_hash_lookup(target)),
        ("js_analysis", 58, lambda: run_js_file_analysis(target)),
        ("subdomain_takeover", 61, lambda: run_subdomain_takeover(target)),
        ("virustotal", 63, lambda: run_virustotal(target)),
        ("shodan", 65, lambda: run_shodan(target)),
        ("greynoise", 67, lambda: run_greynoise(target)),
        ("censys", 69, lambda: run_censys(target)),
        ("theharvester", 71, lambda: run_theharvester(target)),
    ]
    count = _run_tools(scan_id, "osint", tools)
    return {"phase": "osint", "status": "complete", "findings": count}


@celery_app.task(bind=True, name="app.tasks.scan_tasks.run_portscan")
def run_portscan(self, scan_id: str, target: str):
    target = _validated_task_target(target)
    count = _run_tools(scan_id, "portscan", [("port_scan", 76, lambda: run_port_scan(target))])
    return {"phase": "portscan", "status": "complete", "findings": count}


@celery_app.task(bind=True, name="app.tasks.scan_tasks.run_vuln_scan")
def run_vuln_scan(self, scan_id: str, target: str):
    target = _validated_task_target(target)
    tools: list[tuple[str, int, Callable[[], list[dict]]]] = [
        ("nvd_cve", 94, lambda: run_nvd_for_target(target)),
    ]
    if settings.ENABLE_ACTIVE_VULN_TOOLS:
        tools = [
            ("nuclei", 80, lambda: run_nuclei(target)),
            ("nikto", 84, lambda: run_nikto(target)),
            ("dir_fuzzing", 87, lambda: run_dir_fuzzing(target)),
            ("sqlmap", 90, lambda: run_sqlmap_check(target)),
            *tools,
        ]
    else:
        _save_findings(scan_id, [_to_finding({
            "tool": "active_vuln_tools",
            "category": "scan_configuration",
            "severity": "info",
            "title": "Active Vulnerability Tools Disabled",
            "description": (
                "Nuclei, Nikto, directory fuzzing, and SQLMap are disabled by default because they can send "
                "intrusive traffic. Set ENABLE_ACTIVE_VULN_TOOLS=true only for explicitly authorized targets."
            ),
            "evidence": "ENABLE_ACTIVE_VULN_TOOLS=false",
        })])
        _update_scan_status(
            scan_id, "running", phase="vulnscan", progress=92,
            tools_completed=["nuclei", "nikto", "dir_fuzzing", "sqlmap"], tools_running=[],
        )
    count = _run_tools(scan_id, "vulnscan", tools)
    return {"phase": "vulnscan", "status": "complete", "findings": count}



@celery_app.task(bind=True, name="app.tasks.scan_tasks.run_danger_scan")
def run_danger_scan(self, scan_id: str, target: str):
    """Run the Danger Mode staged pipeline.

    Stages execute in dependency order (recon -> attack surface -> bounded
    per-module testing -> normalization -> coverage matrix). The gate is checked
    again here so a queued task can never run after the operator disabled the
    profile.
    """
    target = _validated_task_target(target)
    from app.tasks.vulnscan.danger.pipeline import danger_stages

    session, stages = danger_stages(target)
    if not danger_mode_enabled():
        logger.warning("[%s] danger scan requested while ALLOW_DANGER_MODE is false", scan_id)

    total = max(1, len(stages))
    tools: list[tuple[str, int, Callable[[], list[dict]]]] = []
    for index, (name, stage) in enumerate(stages, 1):
        progress = 76 + int((index / total) * 18)
        tools.append((name, progress, lambda stage=stage: stage(target)))

    count = _run_tools(scan_id, "danger", tools, completed=session.stages_completed, failed=session.stages_failed)
    if session.stages_skipped:
        # Stages that never ran must not be reported as completed.
        session.stages_completed[:] = [
            name for name in session.stages_completed if name not in session.stages_skipped
        ]
        _save_findings(scan_id, [_to_finding(session.deadline_finding())])
        count += 1
    _save_danger_summary(scan_id, session.summary().model_dump(mode="json"))
    return {"phase": "danger", "status": "complete", "findings": count}


@celery_app.task(bind=True, name="app.tasks.scan_tasks.run_ai_analysis")
def run_ai_analysis(self, scan_id: str):
    _update_scan_status(scan_id, "running", phase="ai_analysis", progress=96, tools_running=["ai_report"])
    db = get_db()
    ai_summary = None
    if db is not None:
        record = db["scans"].find_one({"scan_id": scan_id}, {"_id": 0}) or {}
        findings = record.get("findings", [])
        counts = {level: sum(1 for f in findings if f.get("severity") == level) for level in ("critical", "high", "medium", "low", "info")}
        from app.tasks.ai_analysis import generate_scan_summary
        ai_summary = generate_scan_summary(record.get("target", "unknown"), findings, counts)
        db["scans"].update_one({"scan_id": scan_id}, {"$set": {"ai_summary": ai_summary, "summary": ai_summary.get("executive_summary")}})
    _update_scan_status(
        scan_id, "completed", phase="ai_analysis", progress=100,
        tools_completed=["ai_report"], tools_running=[], completed=True,
    )
    return {"phase": "ai_analysis", "status": "complete", "ai_summary": ai_summary}


def _run_tools(
    scan_id: str,
    phase: str,
    tools: list[tuple[str, int, Callable[[], list[dict]]]],
    *,
    completed: list[str] | None = None,
    failed: list[str] | None = None,
) -> int:
    all_raw: list[dict] = []
    for tool_name, progress, tool_fn in tools:
        _update_scan_status(scan_id, "running", phase=phase, progress=progress, tools_running=[tool_name])
        try:
            results = tool_fn() or []
            all_raw.extend(results)
            if completed is not None:
                completed.append(tool_name)
            _update_scan_status(
                scan_id, "running", phase=phase, progress=progress,
                tools_completed=[tool_name], tools_running=[],
            )
            logger.info("[%s] %s: %d findings", scan_id, tool_name, len(results))
        except Exception:
            logger.exception("[%s] %s failed", scan_id, tool_name)
            if failed is not None:
                failed.append(tool_name)
            _update_scan_status(scan_id, "running", phase=phase, progress=progress, tools_completed=[tool_name], tools_running=[])
    findings = [_to_finding(raw) for raw in all_raw]
    if findings:
        _save_findings(scan_id, findings)
    return len(findings)


def _to_finding(raw: dict) -> dict:
    severity = str(raw.get("severity", "info")).lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "info"
    finding = {
        "id": f"finding_{uuid.uuid4().hex[:10]}",
        "tool": str(raw.get("tool", "unknown"))[:100],
        "category": str(raw.get("category", "general"))[:100],
        "severity": severity,
        "title": str(raw.get("title", ""))[:500],
        "description": str(raw.get("description", ""))[:20_000],
        "evidence": str(raw.get("evidence", ""))[:50_000],
        "cve_id": raw.get("cve_id"),
        "cvss_score": raw.get("cvss_score"),
        "remediation": str(raw.get("remediation", ""))[:10_000] or None,
        "ai_explanation": None,
        "verified": False,
        "requires_manual_validation": bool(raw.get("requires_manual_validation", False)),
        "exploited": bool(raw.get("exploited", False)),
    }
    # Danger Mode metadata is optional; carry it through only when supplied so
    # existing modules keep producing exactly the same shape.
    for key, limit in (
        ("owasp_category", 100), ("attack_vector", 200), ("confidence", 100), ("affected_asset", 2_000),
        ("exploit_technique", 200), ("exploit_proof", 2_000), ("exploit_impact", 2_000),
    ):
        value = raw.get(key)
        if value:
            finding[key] = str(value)[:limit]
    return finding


def _save_danger_summary(scan_id: str, summary: dict) -> None:
    db = get_db()
    if db is None:
        logger.warning("[%s] danger summary not persisted because MongoDB is unavailable", scan_id)
        return
    db["scans"].update_one({"scan_id": scan_id}, {"$set": {"danger_summary": summary}})


def _save_findings(scan_id: str, findings: list[dict]) -> None:
    db = get_db()
    if db is None:
        logger.warning("[%s] findings not persisted because MongoDB is unavailable", scan_id)
        return
    db["scans"].update_one(
        {"scan_id": scan_id},
        {"$push": {"findings": {"$each": findings}}, "$inc": {"total_findings": len(findings)}, "$set": {"last_updated": datetime.now(timezone.utc)}},
    )


def _update_scan_status(
    scan_id: str,
    status: str,
    *,
    phase: str | None = None,
    progress: int = 0,
    tools_running: list[str] | None = None,
    tools_completed: list[str] | None = None,
    error: str | None = None,
    started: bool = False,
    completed: bool = False,
) -> None:
    db = get_db()
    if db is None:
        return
    now = datetime.now(timezone.utc)
    set_doc: dict = {"status": status, "progress": max(0, min(100, progress)), "last_updated": now}
    if phase:
        set_doc["phase"] = phase
    if tools_running is not None:
        set_doc["tools_running"] = tools_running
    if error:
        set_doc["error"] = error
    if started:
        set_doc["started_at"] = now
    if completed:
        set_doc["completed_at"] = now
        set_doc["tools_running"] = []
    update: dict = {"$set": set_doc}
    if tools_completed:
        update["$addToSet"] = {"tools_completed": {"$each": tools_completed}}
        update["$pullAll"] = {"tools_remaining": tools_completed}
    db["scans"].update_one({"scan_id": scan_id}, update)
