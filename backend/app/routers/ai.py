"""AI narration endpoints.

These endpoints never touch the target. They take data the deterministic
scanners already produced and ask the configured model (local Ollama by
default) to explain it. When no model is reachable every route still returns a
usable static answer, so the UI never has to special-case an AI outage.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter

from app.models.schemas import TopicExplainRequest, VerifyRequest

logger = logging.getLogger("recontitan.ai.api")
router = APIRouter(prefix="/api/ai", tags=["ai"])


@router.get("/status")
def ai_status_endpoint():
    """Which AI backend is live, and why not, if it isn't.

    The report page calls this on load to decide whether to advertise the AI
    buttons as live or as degraded-to-static.
    """
    from app.tasks.ai_analysis import ai_status

    return ai_status()


@router.post("/explain")
def explain_topic_endpoint(request: TopicExplainRequest):
    """Explain a security topic, scan category, or tool in plain English."""
    from app.tasks.ai_analysis import explain_topic

    result = explain_topic(request.topic, request.context, request.audience)
    return {"status": "ok", **result}


@router.post("/explain-finding")
def explain_finding_endpoint(request: VerifyRequest):
    """Short plain-English explanation of a single finding.

    Cheaper and faster than POST /api/verify: prose only, no triage verdict and
    no remediation list, so it is the one to call when the user just wants to
    know what a finding means.
    """
    from app.tasks.ai_analysis import _active_backend_name, explain_finding

    finding = {
        "title": request.finding_text or request.finding_id,
        "severity": request.severity.value,
        "description": request.description or request.finding_text,
    }
    return {
        "status": "ok",
        "scan_id": request.scan_id,
        "finding_id": request.finding_id,
        "explanation": explain_finding(finding),
        "ai_backend": _active_backend_name(),
    }
