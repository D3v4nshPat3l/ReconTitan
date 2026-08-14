"""Report export endpoints."""

from __future__ import annotations

import re
from time import perf_counter

from fastapi import APIRouter, HTTPException
from fastapi.responses import Response

from app.models.schemas import ReportExportRequest
from app.services.pdf_report import build_pdf_report

router = APIRouter(prefix="/api", tags=["reports"])


def _safe_filename(target: str) -> str:
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", target)
    safe = re.sub(r"\.{2,}", "_", safe).strip("._") or "target"
    return f"recontitan_{safe[:120]}.pdf"


@router.post("/report/pdf")
def export_pdf_report(request: ReportExportRequest):
    """Render scan data as a PDF. The data is not persisted by this endpoint."""
    started = perf_counter()
    try:
        content = build_pdf_report(request.model_dump(mode="json"))
    except Exception as exc:
        raise HTTPException(status_code=500, detail="Could not generate PDF report") from exc
    elapsed_ms = max(1, round((perf_counter() - started) * 1000))
    return Response(
        content=content,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{_safe_filename(request.target)}"',
            "X-Content-Type-Options": "nosniff",
            "Cache-Control": "no-store",
            "Content-Length": str(len(content)),
            "X-Report-Generation-Ms": str(elapsed_ms),
        },
    )
