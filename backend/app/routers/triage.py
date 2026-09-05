"""Recording and reading triage decisions."""

from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.services import audit, triage
from app.targeting import validate_scan_target

logger = logging.getLogger("recontitan.triage")
router = APIRouter(prefix="/api", tags=["triage"])


class TriageRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    fingerprint: str = Field(min_length=32, max_length=32, pattern=r"^[0-9a-f]{32}$")
    state: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=triage.MAX_REASON)
    author: str = Field(default="", max_length=triage.MAX_AUTHOR)


def _checked_target(target: str) -> str:
    """Run the target through the same rules a scan does.

    The store is keyed by target, so an unvalidated value would let anything
    become a key. Resolution is skipped: a decision about a host that has since
    stopped resolving is still a decision worth keeping.
    """
    ok, cleaned, error = validate_scan_target(target, resolve_dns=False)
    if not ok:
        raise HTTPException(status_code=400, detail=error)
    return cleaned


@router.get("/triage")
def read_triage(target: str = Query(..., min_length=1, max_length=253)):
    """Every recorded decision for one target."""
    cleaned = _checked_target(target)
    decisions = triage.decisions_for(cleaned)
    return {"target": cleaned, "count": len(decisions), "decisions": decisions}


@router.post("/triage")
def write_triage(request: TriageRequest, http_request: Request):
    """Record one decision, or clear it by sending state="open".

    A suppressing state without a written reason is rejected, not silently
    stored: an unexplained suppression is indistinguishable from hiding a
    finding, and this feature is only defensible if it cannot be used that way.
    """
    cleaned = _checked_target(request.target)
    try:
        stored = triage.record(
            cleaned, request.fingerprint, request.state, request.reason, request.author,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        logger.exception("[triage] cannot persist a decision for %s", cleaned)
        raise HTTPException(
            status_code=503,
            detail="The triage store could not be written. The decision was not saved.",
        ) from exc

    # Suppressing a finding changes what the report claims, so it belongs in
    # the same audit trail as running a scan.
    audit.record_scan_event(
        audit.SCAN_ACCEPTED, http_request,
        target=cleaned,
        detail=f"triage {request.state}: {request.fingerprint}",
    )
    return {"status": "ok", "target": cleaned, "fingerprint": request.fingerprint, **stored}
