"""ReconTitan — Pydantic request and response schemas."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanPhase(str, Enum):
    RECON = "recon"
    OSINT = "osint"
    PORTSCAN = "portscan"
    VULNSCAN = "vulnscan"
    DANGER = "danger"
    AI_ANALYSIS = "ai_analysis"


class ScanType(str, Enum):
    FULL = "full"
    RECON_ONLY = "recon_only"
    OSINT_ONLY = "osint_only"
    VULN_ONLY = "vuln_only"
    DANGER = "danger"


class OwaspCategory(str, Enum):
    """OWASP Top 10 (2021) identifiers used to tag Danger Mode findings."""

    A01 = "A01:2021-Broken Access Control"
    A02 = "A02:2021-Cryptographic Failures"
    A03 = "A03:2021-Injection"
    A04 = "A04:2021-Insecure Design"
    A05 = "A05:2021-Security Misconfiguration"
    A06 = "A06:2021-Vulnerable and Outdated Components"
    A07 = "A07:2021-Identification and Authentication Failures"
    A08 = "A08:2021-Software and Data Integrity Failures"
    A09 = "A09:2021-Security Logging and Monitoring Failures"
    A10 = "A10:2021-Server-Side Request Forgery"


class InputPointType(str, Enum):
    """Classification applied to every discovered attack-surface input point."""

    LOGIN_FORM = "login_form"
    SEARCH_FORM = "search_form"
    UPLOAD_FORM = "upload_form"
    GENERIC_FORM = "generic_form"
    QUERY_PARAM = "query_param"
    API_ENDPOINT = "api_endpoint"
    OBJECT_REFERENCE = "object_reference"
    URL_PARAM = "url_param"
    HEADER = "header"


class InjectionSignal(str, Enum):
    """How a bounded injection probe was classified. Never proof of exploitation."""

    REFLECTED = "reflected"
    ERROR = "error"
    TIMING = "timing"
    DIFFERENTIAL = "differential"
    NONE = "none"


class ScanRequest(BaseModel):
    target: str = Field(
        ...,
        min_length=3,
        max_length=253,
        description="Public target domain or IP address to scan",
        examples=["example.com", "1.1.1.1"],
    )
    scan_type: ScanType = ScanType.FULL
    danger_acknowledgement: Optional[str] = Field(
        default=None,
        max_length=120,
        description=(
            "Required for scan_type=danger. Must equal the acknowledgement phrase "
            "published by GET /api/capabilities."
        ),
    )


class VerifyRequest(BaseModel):
    scan_id: str = Field(min_length=1, max_length=100)
    finding_id: str = Field(min_length=1, max_length=100)
    finding_text: str = Field(default="", max_length=20_000)
    target: str = Field(default="unknown", max_length=253)
    severity: SeverityLevel = SeverityLevel.INFO
    description: str = Field(default="", max_length=20_000)


class TopicExplainRequest(BaseModel):
    """Ask the AI layer to explain a security topic, category, or tool."""

    topic: str = Field(min_length=1, max_length=200)
    context: str = Field(default="", max_length=4_000)
    audience: str = Field(default="developer", max_length=40)


class ReportExportRequest(BaseModel):
    """Browser-supplied scan result used only to render a PDF."""

    scan_id: str = Field(default="manual", max_length=100)
    target: str = Field(min_length=1, max_length=253)
    scan_type: ScanType = ScanType.FULL
    version: str = Field(default="0.5.0", max_length=40)
    status: str = Field(default="completed", max_length=40)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_time_seconds: Optional[float] = Field(default=None, ge=0, le=86_400)
    tools_run: Optional[int] = Field(default=None, ge=0, le=1_000)
    tools_used: list[str] = Field(default_factory=list, max_length=1_000)
    total_findings: int = Field(default=0, ge=0, le=10_000)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    summary: Optional[str] = Field(default=None, max_length=20_000)
    ai_summary: Optional[dict[str, Any]] = None
    tool_results: dict[str, Any] = Field(default_factory=dict)
    findings: list[dict[str, Any]] = Field(default_factory=list, max_length=1000)
    danger_summary: Optional[dict[str, Any]] = None


class ScanResponse(BaseModel):
    status: str = "success"
    message: str
    scan_id: str
    target: str


class ScanStatusResponse(BaseModel):
    scan_id: str
    target: str
    status: ScanStatus
    phase: Optional[ScanPhase] = None
    progress: int = Field(default=0, ge=0, le=100)
    tools_completed: list[str] = Field(default_factory=list)
    tools_running: list[str] = Field(default_factory=list)
    tools_remaining: list[str] = Field(default_factory=list)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class Finding(BaseModel):
    id: str
    tool: str
    category: str
    severity: SeverityLevel
    title: str
    description: str
    evidence: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    ai_explanation: Optional[str] = None
    verified: bool = False
    # Danger Mode metadata. Simulation output is always a candidate, never a
    # confirmed exploitation, so these fields travel with the finding.
    requires_manual_validation: bool = False
    owasp_category: Optional[str] = None
    attack_vector: Optional[str] = None
    confidence: Optional[str] = None
    affected_asset: Optional[str] = None
    # Set when the engine proved the issue rather than merely detecting it.
    exploited: bool = False
    exploit_technique: Optional[str] = None
    exploit_proof: Optional[str] = None
    exploit_impact: Optional[str] = None


class AttackSurfaceItem(BaseModel):
    """One classified input point discovered during Danger Mode recon."""

    id: str
    url: str = Field(max_length=2_000)
    method: str = Field(default="GET", max_length=10)
    input_type: InputPointType = InputPointType.QUERY_PARAM
    parameters: list[str] = Field(default_factory=list, max_length=100)
    content_type: Optional[str] = Field(default=None, max_length=120)
    source: str = Field(default="crawl", max_length=60)


class InjectionTestResult(BaseModel):
    """A single bounded injection probe result, stored without secret values."""

    endpoint: str = Field(max_length=2_000)
    method: str = Field(default="GET", max_length=10)
    parameter: str = Field(default="", max_length=200)
    injection_type: str = Field(max_length=60)
    payload_category: str = Field(max_length=120)
    signal: InjectionSignal = InjectionSignal.NONE
    status_code: Optional[int] = None
    response_bytes: Optional[int] = None
    elapsed_seconds: Optional[float] = None
    requires_manual_validation: bool = True


class OwaspCoverageEntry(BaseModel):
    """Tested/not-tested state for one OWASP Top 10 category."""

    category: OwaspCategory
    tested: bool = False
    modules: list[str] = Field(default_factory=list, max_length=40)
    findings: int = Field(default=0, ge=0)
    note: str = Field(default="", max_length=1_000)


class DangerModeSummary(BaseModel):
    """Machine-readable roll-up rendered by the UI and the PDF danger section."""

    enabled: bool = False
    target: str = Field(default="", max_length=253)
    stages_completed: list[str] = Field(default_factory=list, max_length=60)
    stages_failed: list[str] = Field(default_factory=list, max_length=60)
    stages_skipped: list[str] = Field(default_factory=list, max_length=60)
    elapsed_seconds: float = Field(default=0.0, ge=0)
    timed_out: bool = False
    attack_surface: list[AttackSurfaceItem] = Field(default_factory=list, max_length=500)
    injection_matrix: list[InjectionTestResult] = Field(default_factory=list, max_length=2_000)
    owasp_coverage: list[OwaspCoverageEntry] = Field(default_factory=list, max_length=10)
    requests_sent: int = Field(default=0, ge=0)
    payloads_sent: int = Field(default=0, ge=0)
    budget_exhausted: bool = False
    exploits_confirmed: int = Field(default=0, ge=0)
    exploit_techniques: dict[str, int] = Field(default_factory=dict)
    platforms_identified: list[str] = Field(default_factory=list, max_length=20)


class ScanReport(BaseModel):
    scan_id: str
    target: str
    scan_type: ScanType = ScanType.FULL
    status: ScanStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    findings: list[Finding] = Field(default_factory=list)
    summary: Optional[str] = None
    tools_used: list[str] = Field(default_factory=list)
    tool_results: dict[str, Any] = Field(default_factory=dict)
    danger_summary: Optional[dict[str, Any]] = None
    ai_summary: Optional[dict[str, Any]] = None
    severity_counts: dict[str, int] = Field(default_factory=dict)
    total_time_seconds: Optional[int] = None
    tools_run: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0


class NewsItem(BaseModel):
    title: str
    summary: str
    source: str
    source_key: str
    url: Optional[str] = None
    published_at: Optional[str] = None
    severity: SeverityLevel = SeverityLevel.INFO
    tags: list[str] = Field(default_factory=list)
    category: str = "general"


class NewsResponse(BaseModel):
    news: list[NewsItem]
    last_updated: Optional[datetime] = None
