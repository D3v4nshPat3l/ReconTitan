"""Shared request budget, pacing, and evidence helpers for Danger Mode.

Every outbound danger probe goes through :class:`DangerBudget`. The budget is a
hard ceiling on requests and payloads for the whole scan and for each module, it
paces traffic between requests, and it backs off when the target signals rate
limiting. Modules never call ``safe_request`` directly.
"""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field

from app.config import settings
from app.models.schemas import InjectionSignal
from app.services.danger_mode import MANUAL_VALIDATION_NOTE
from app.tasks.http_client import SafeResponse, safe_request

logger = logging.getLogger("recontitan.danger.budget")

#: Unique, harmless marker embedded in probes so reflections are unambiguous.
CANARY = "RT7CANARY7RT"

#: Response bodies are read with a small ceiling; danger modules only need signals.
MAX_PROBE_BYTES = 256 * 1024


@dataclass
class ProbeResult:
    """Outcome of one bounded probe. ``response`` is ``None`` when it failed soft."""

    ok: bool
    response: SafeResponse | None = None
    elapsed: float = 0.0
    error: str = ""

    @property
    def status(self) -> int | None:
        return self.response.status_code if self.response else None

    @property
    def text(self) -> str:
        return self.response.text if self.response else ""

    @property
    def size(self) -> int:
        return len(self.response.content) if self.response else 0


@dataclass
class DangerBudget:
    """Hard per-scan ceilings shared by every danger module.

    Two independent ceilings apply: a request/payload count and a wall-clock
    deadline. The deadline matters most in practice — pacing plus per-probe
    timeouts mean a slow target can consume far more time than requests, and
    without it the caller waits with no report to show for it.
    """

    max_requests_total: int = field(default_factory=lambda: settings.DANGER_MAX_REQUESTS_TOTAL)
    max_requests_per_module: int = field(default_factory=lambda: settings.DANGER_MAX_REQUESTS_PER_MODULE)
    max_payloads: int = field(default_factory=lambda: settings.DANGER_MAX_PAYLOADS_PER_SCAN)
    delay_seconds: float = field(default_factory=lambda: settings.DANGER_REQUEST_DELAY_MS / 1000.0)
    timeout: float = field(default_factory=lambda: float(settings.DANGER_REQUEST_TIMEOUT))
    max_seconds: float = field(default_factory=lambda: float(settings.DANGER_MAX_SCAN_SECONDS))

    requests_sent: int = 0
    payloads_sent: int = 0
    exhausted: bool = False
    timed_out: bool = False
    per_module: dict[str, int] = field(default_factory=dict)
    started_at: float = field(default_factory=time.monotonic)
    clock_started: bool = False
    _backoff: float = 0.0
    _last_request: float = 0.0

    def begin(self) -> None:
        """Start the wall-clock budget at the first danger stage, not at construction.

        In the ``danger`` profile the recon, OSINT, and vulnerability groups run
        before any danger stage. Timing from construction let that safe work
        consume the danger budget, so the deadline fired with stages still
        pending even though danger itself had barely run.
        """
        if not self.clock_started:
            self.clock_started = True
            self.started_at = time.monotonic()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def time_left(self) -> float:
        return max(0.0, self.max_seconds - self.elapsed)

    @property
    def expired(self) -> bool:
        """True once the wall-clock ceiling is reached."""
        if self.time_left <= 0:
            self.timed_out = True
            return True
        return False

    def remaining(self, module: str) -> int:
        """Requests still available to ``module`` under the tightest ceiling."""
        if self.expired:
            return 0
        overall = self.max_requests_total - self.requests_sent
        module_left = self.max_requests_per_module - self.per_module.get(module, 0)
        payload_left = self.max_payloads - self.payloads_sent
        return max(0, min(overall, module_left, payload_left))

    def can_spend(self, module: str) -> bool:
        return self.remaining(module) > 0

    def _pace(self) -> None:
        """Sleep between probes so the target is never flooded.

        The sleep is clamped to the remaining wall-clock budget so pacing can
        never be the reason a scan overruns its deadline.
        """
        wait = self.delay_seconds + self._backoff
        if wait <= 0:
            return
        since_last = time.monotonic() - self._last_request
        remaining_wait = min(wait - since_last, self.time_left)
        if remaining_wait > 0:
            time.sleep(remaining_wait)

    def _observe(self, status: int | None) -> None:
        """Slow down when the target signals throttling; recover gradually."""
        if status in {429, 503}:
            self._backoff = min(5.0, (self._backoff or 0.5) * 2)
            logger.info("[danger] target signalled throttling (%s); backoff now %.1fs", status, self._backoff)
        elif self._backoff:
            self._backoff = max(0.0, self._backoff / 2)

    def probe(
        self,
        module: str,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        timeout: float | None = None,
        counts_as_payload: bool = True,
        follow_redirects: bool = True,
    ) -> ProbeResult:
        """Send one bounded probe, or return a failed result when out of budget.

        Never raises: danger modules must fail soft so one dead endpoint cannot
        abort the scan.
        """
        if not self.can_spend(module):
            self.exhausted = True
            return ProbeResult(ok=False, error="deadline_reached" if self.timed_out else "budget_exhausted")

        self._pace()
        # A single probe must not be able to overrun the deadline by its full
        # timeout, so the per-request timeout is clamped to what time is left.
        effective_timeout = max(1.0, min(timeout or self.timeout, self.time_left))
        self.requests_sent += 1
        self.per_module[module] = self.per_module.get(module, 0) + 1
        if counts_as_payload:
            self.payloads_sent += 1

        started = time.monotonic()
        try:
            response = safe_request(
                method,
                url,
                timeout=effective_timeout,
                max_bytes=MAX_PROBE_BYTES,
                headers=headers,
                body=body,
                follow_redirects=follow_redirects,
            )
            elapsed = time.monotonic() - started
            self._last_request = time.monotonic()
            self._observe(response.status_code)
            return ProbeResult(ok=True, response=response, elapsed=elapsed)
        except Exception as exc:  # danger modules fail soft by design
            elapsed = time.monotonic() - started
            self._last_request = time.monotonic()
            logger.debug("[danger:%s] probe failed %s: %s", module, url[:120], str(exc)[:160])
            return ProbeResult(ok=False, elapsed=elapsed, error=type(exc).__name__)

    def snapshot(self) -> dict[str, int | float | bool]:
        return {
            "requests_sent": self.requests_sent,
            "payloads_sent": self.payloads_sent,
            "budget_exhausted": self.exhausted,
            "timed_out": self.timed_out,
            "elapsed_seconds": round(self.elapsed, 1),
        }


def fingerprint(value: str | bytes) -> str:
    """Return a short, non-reversible fingerprint used instead of raw content.

    Danger Mode never stores response bodies, object contents, secrets, or
    session material. It stores this fingerprint so an analyst can still tell
    two responses apart.
    """
    raw = value.encode("utf-8", errors="ignore") if isinstance(value, str) else value
    return f"sha256:{hashlib.sha256(raw).hexdigest()[:16]}"


def truncated(value: str, limit: int = 160) -> str:
    """Bounded, single-line excerpt safe to place in evidence."""
    collapsed = " ".join(str(value or "").split())
    return collapsed[:limit] + ("..." if len(collapsed) > limit else "")


def evidence_block(pairs: list[tuple[str, object]]) -> str:
    """Render ``Key: value`` evidence lines matching the existing report format."""
    lines = []
    for key, value in pairs:
        if value is None or value == "":
            continue
        lines.append(f"{key}: {value}")
    return "\n".join(lines)


def danger_finding(
    *,
    tool: str,
    category: str,
    severity: str,
    title: str,
    description: str,
    evidence: str,
    remediation: str | None = None,
    owasp: str | None = None,
    attack_vector: str | None = None,
    confidence: str = "Candidate - requires manual validation",
    asset: str | None = None,
) -> dict:
    """Build a normalized danger finding.

    Danger findings are always candidates. The wording never claims confirmed
    exploitation and ``requires_manual_validation`` is unconditionally true.
    """
    return {
        "tool": tool,
        "category": category,
        "severity": severity,
        "title": title,
        "description": f"{description} {MANUAL_VALIDATION_NOTE}".strip(),
        "evidence": evidence,
        "remediation": remediation,
        "requires_manual_validation": True,
        "owasp_category": owasp,
        "attack_vector": attack_vector,
        "confidence": confidence,
        "affected_asset": asset,
    }


def classify_signal(
    baseline: ProbeResult,
    probe: ProbeResult,
    *,
    error_markers: tuple[str, ...] = (),
    reflection: str | None = None,
    timing_threshold: float | None = None,
    size_delta_ratio: float = 0.25,
) -> InjectionSignal:
    """Classify a probe response against its baseline without storing content."""
    if not probe.ok or probe.response is None:
        return InjectionSignal.NONE

    body = probe.text
    lowered = body.lower()

    if reflection and reflection in body:
        return InjectionSignal.REFLECTED
    for marker in error_markers:
        if marker.lower() in lowered:
            return InjectionSignal.ERROR
    if timing_threshold is not None and probe.elapsed >= timing_threshold:
        return InjectionSignal.TIMING
    if baseline.ok and baseline.response is not None:
        if probe.status != baseline.status:
            return InjectionSignal.DIFFERENTIAL
        base_size = max(1, baseline.size)
        if abs(probe.size - base_size) / base_size > size_delta_ratio:
            return InjectionSignal.DIFFERENTIAL
    return InjectionSignal.NONE
