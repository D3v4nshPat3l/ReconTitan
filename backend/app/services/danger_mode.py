"""Danger Mode opt-in gate, safety bounds, and OWASP catalogue metadata.

Danger Mode is a *simulation* profile. It sends bounded, non-destructive probes
and records the response signal. It never confirms exploitation, never modifies
or deletes target data, never authenticates against live accounts, and never
opens a shell. This module owns the single authoritative answer to "may a danger
scan run at all", so routers, Celery tasks, and scan modules all fail closed the
same way.
"""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass

from app.config import settings

logger = logging.getLogger("recontitan.danger")

#: Phrase the operator must type in the UI (and send to ``POST /api/scan``)
#: before a danger scan is accepted. Published via ``GET /api/capabilities``.
DANGER_ACKNOWLEDGEMENT = "I am authorized"

DANGER_DISABLED_MESSAGE = (
    "Danger Mode is disabled. This profile sends bounded penetration-test simulation traffic and "
    "must be enabled deliberately by an operator with written authorization for the target. "
    "Set ALLOW_DANGER_MODE=true in the environment to enable it."
)
DANGER_ACK_MESSAGE = (
    f"Danger Mode requires a typed authorization acknowledgement. Send danger_acknowledgement="
    f'"{DANGER_ACKNOWLEDGEMENT}" to confirm you own the target or hold written permission to assess it.'
)

MANUAL_VALIDATION_NOTE = (
    "Danger Mode reports detection candidates, not confirmed exploitation. Reproduce this observation "
    "manually from an authorized test system before treating it as a vulnerability."
)

#: OWASP Top 10 (2021) categories with the danger modules that exercise them.
OWASP_CATALOGUE: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("A01:2021-Broken Access Control", "Broken Access Control",
     ("idor_testing", "directory_fuzzing", "owasp_matrix")),
    ("A02:2021-Cryptographic Failures", "Cryptographic Failures",
     ("owasp_matrix", "ssl_check", "js_analysis")),
    ("A03:2021-Injection", "Injection",
     ("injection_sqli", "injection_command", "injection_html", "injection_xss",
      "injection_ssti", "injection_xxe", "injection_nosql")),
    ("A04:2021-Insecure Design", "Insecure Design", ("owasp_matrix", "attack_surface")),
    ("A05:2021-Security Misconfiguration", "Security Misconfiguration",
     ("directory_fuzzing", "owasp_matrix", "security_headers")),
    ("A06:2021-Vulnerable and Outdated Components", "Vulnerable and Outdated Components",
     ("nvd_cve", "owasp_matrix", "tech_stack")),
    ("A07:2021-Identification and Authentication Failures", "Identification and Authentication Failures",
     ("owasp_matrix", "attack_surface")),
    ("A08:2021-Software and Data Integrity Failures", "Software and Data Integrity Failures",
     ("owasp_matrix",)),
    ("A09:2021-Security Logging and Monitoring Failures", "Security Logging and Monitoring Failures",
     ("owasp_matrix",)),
    ("A10:2021-Server-Side Request Forgery", "Server-Side Request Forgery", ("injection_ssrf",)),
)


class DangerModeDisabled(RuntimeError):
    """Raised when danger-mode work is attempted while the gate is closed."""


@dataclass(frozen=True)
class DangerGateResult:
    """Outcome of an opt-in check. ``allowed`` is the only field callers act on."""

    allowed: bool
    reason: str = ""


def danger_mode_enabled() -> bool:
    """Return whether the operator has explicitly opted in to Danger Mode."""
    return bool(settings.ALLOW_DANGER_MODE)


def acknowledgement_is_valid(supplied: str | None) -> bool:
    """Constant-time comparison of the typed authorization acknowledgement."""
    if not supplied:
        return False
    return secrets.compare_digest(supplied.strip(), DANGER_ACKNOWLEDGEMENT)


def check_danger_gate(scan_type: str, *, acknowledgement: str | None = None) -> DangerGateResult:
    """Validate a scan request against the Danger Mode opt-in gate.

    Non-danger profiles always pass. Danger requires both the environment opt-in
    and the typed acknowledgement.
    """
    if scan_type != "danger":
        return DangerGateResult(allowed=True)
    if not danger_mode_enabled():
        logger.warning("[danger] rejected: ALLOW_DANGER_MODE is false")
        return DangerGateResult(allowed=False, reason=DANGER_DISABLED_MESSAGE)
    if not acknowledgement_is_valid(acknowledgement):
        logger.warning("[danger] rejected: missing or invalid authorization acknowledgement")
        return DangerGateResult(allowed=False, reason=DANGER_ACK_MESSAGE)
    return DangerGateResult(allowed=True)


def require_danger_enabled() -> None:
    """Fail closed inside worker/task code that must never run while disabled."""
    if not danger_mode_enabled():
        raise DangerModeDisabled(DANGER_DISABLED_MESSAGE)


def danger_bounds() -> dict[str, int | bool]:
    """Return the effective per-scan safety bounds for reporting and the UI."""
    return {
        "max_scan_seconds": settings.DANGER_MAX_SCAN_SECONDS,
        "max_targets": settings.DANGER_MODE_MAX_TARGETS,
        "max_hosts": settings.DANGER_MAX_HOSTS,
        "max_requests_total": settings.DANGER_MAX_REQUESTS_TOTAL,
        "max_requests_per_module": settings.DANGER_MAX_REQUESTS_PER_MODULE,
        "max_payloads_per_scan": settings.DANGER_MAX_PAYLOADS_PER_SCAN,
        "max_endpoints": settings.DANGER_MAX_ENDPOINTS,
        "max_crawl_pages": settings.DANGER_MAX_CRAWL_PAGES,
        "request_delay_ms": settings.DANGER_REQUEST_DELAY_MS,
        "time_delay_seconds": settings.DANGER_TIME_DELAY_SECONDS,
        "subdomain_brute_limit": settings.DANGER_SUBDOMAIN_BRUTE_LIMIT,
        "dir_bust_wordlist": settings.DANGER_DIR_BUST_WORDLIST,
        "idor_max_ids": settings.DANGER_IDOR_MAX_IDS,
        "xxe_oob_enabled": settings.DANGER_ENABLE_XXE_OOB,
    }


def danger_mode_metadata() -> dict:
    """Public, non-sensitive Danger Mode description for ``/api/capabilities``."""
    return {
        "enabled": danger_mode_enabled(),
        "acknowledgement_phrase": DANGER_ACKNOWLEDGEMENT,
        "disabled_reason": None if danger_mode_enabled() else DANGER_DISABLED_MESSAGE,
        "bounds": danger_bounds(),
        "owasp_coverage": [
            {"category": key, "name": name, "modules": list(modules)}
            for key, name, modules in OWASP_CATALOGUE
        ],
        "safety": [
            "No data on the target is created, modified, or deleted.",
            "No credential stuffing or authentication attempts against live accounts.",
            "No reverse shell is ever connected; command-injection vectors are reported only.",
            "Secrets, tokens, and object contents are fingerprinted, never stored verbatim.",
            "Every finding is labeled requires_manual_validation and is a candidate, not a confirmation.",
        ],
    }
