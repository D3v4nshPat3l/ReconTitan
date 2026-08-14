"""Danger Mode stage coordinator.

A :class:`DangerSession` runs the stages in dependency order — recon, then the
attack-surface inventory, then per-module bounded testing, then normalization
and the coverage matrix. Every stage is exposed as a ``fn(target) -> list[dict]``
so the synchronous ``/api/test-scan`` endpoint and the Celery worker drive the
exact same code, and so a failure in one stage never aborts the others.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from app.models.schemas import AttackSurfaceItem, DangerModeSummary
from app.services.danger_mode import (
    DANGER_DISABLED_MESSAGE,
    danger_mode_enabled,
)
from app.tasks.vulnscan.danger import advanced as advanced_module
from app.tasks.vulnscan.danger import attack_surface as attack_surface_module
from app.tasks.vulnscan.danger import business_logic as business_logic_module
from app.tasks.vulnscan.danger import data_exposure as data_exposure_module
from app.tasks.vulnscan.danger import directory as directory_module
from app.tasks.vulnscan.danger import dns_axfr as dns_module
from app.tasks.vulnscan.danger import dom as dom_module
from app.tasks.vulnscan.danger import idor as idor_module
from app.tasks.vulnscan.danger import injection as injection_module
from app.tasks.vulnscan.danger import owasp as owasp_module
from app.tasks.vulnscan.danger import recon as recon_module
from app.tasks.vulnscan.danger import reverse_shell as reverse_shell_module
from app.tasks.vulnscan.danger.budget import (
    DangerBudget,
    danger_finding,
    evidence_block,
)

logger = logging.getLogger("recontitan.danger.pipeline")

Stage = tuple[str, Callable[[str], list[dict]]]


def _disabled_finding(target: str) -> dict:
    return danger_finding(
        tool="danger_mode",
        category="scan_configuration",
        severity="info",
        title="Danger Mode Disabled",
        description=DANGER_DISABLED_MESSAGE,
        evidence=evidence_block([
            ("Target", target),
            ("ALLOW_DANGER_MODE", "false"),
            ("Probes sent", 0),
        ]),
        remediation=(
            "Enable Danger Mode only for systems you own or hold written permission to assess, then set "
            "ALLOW_DANGER_MODE=true and supply the typed authorization acknowledgement."
        ),
        confidence="Configuration notice",
        asset=target,
    )


@dataclass
class DangerSession:
    """Shared state for one danger scan. Stages mutate it in dependency order."""

    target: str
    budget: DangerBudget = field(default_factory=DangerBudget)
    seeds: list[str] = field(default_factory=list)
    items: list[AttackSurfaceItem] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    stages_completed: list[str] = field(default_factory=list)
    stages_failed: list[str] = field(default_factory=list)
    stages_skipped: list[str] = field(default_factory=list)
    rate_limiting_observed: bool = False
    _injection: injection_module.InjectionContext | None = None

    @property
    def injection(self) -> injection_module.InjectionContext:
        if self._injection is None:
            self._injection = injection_module.InjectionContext(
                target=self.target, budget=self.budget, items=self.items
            )
        self._injection.items = self.items
        return self._injection

    def _collect(self, findings: list[dict]) -> list[dict]:
        self.findings.extend(findings)
        return findings

    # ── Stage implementations ────────────────────────────────────────────────

    def stage_disabled(self, target: str) -> list[dict]:
        """Single notice emitted in place of every stage while the gate is closed."""
        return self._collect([_disabled_finding(target)])

    def stage_recon(self, target: str) -> list[dict]:
        self.seeds, findings = recon_module.run_danger_recon(target, self.budget)
        return self._collect(findings)

    def stage_axfr(self, target: str) -> list[dict]:
        return self._collect(dns_module.run_dns_axfr(target))

    def stage_attack_surface(self, target: str) -> list[dict]:
        self.items, findings = attack_surface_module.run_attack_surface(
            target, self.budget, seeds=self.seeds or None
        )
        return self._collect(findings)

    def stage_sqli(self, target: str) -> list[dict]:
        return self._collect(injection_module.run_sql_injection(self.injection))

    def stage_command(self, target: str) -> list[dict]:
        return self._collect(injection_module.run_command_injection(self.injection))

    def stage_html(self, target: str) -> list[dict]:
        return self._collect(injection_module.run_html_injection(self.injection))

    def stage_xss(self, target: str) -> list[dict]:
        return self._collect(injection_module.run_xss(self.injection))

    def stage_ssti(self, target: str) -> list[dict]:
        return self._collect(injection_module.run_ssti(self.injection))

    def stage_xxe(self, target: str) -> list[dict]:
        return self._collect(injection_module.run_xxe(self.injection))

    def stage_ssrf(self, target: str) -> list[dict]:
        return self._collect(injection_module.run_ssrf(self.injection))

    def stage_nosql(self, target: str) -> list[dict]:
        return self._collect(injection_module.run_nosql_injection(self.injection))

    def stage_reverse_shell(self, target: str) -> list[dict]:
        return self._collect(
            reverse_shell_module.assess_reverse_shell_vectors(target, self.injection.command_candidates)
        )

    def stage_directory(self, target: str) -> list[dict]:
        return self._collect(directory_module.run_directory_fuzzing(target, self.budget, self.seeds))

    def stage_traversal(self, target: str) -> list[dict]:
        return self._collect(directory_module.run_path_traversal(target, self.budget, self.items))

    def stage_idor(self, target: str) -> list[dict]:
        return self._collect(idor_module.run_idor_tests(target, self.budget, self.items))

    def stage_dom(self, target: str) -> list[dict]:
        return self._collect(dom_module.run_dom_analysis(target, self.budget, self.seeds))

    def stage_business_logic(self, target: str) -> list[dict]:
        return self._collect(business_logic_module.run_business_logic(target, self.budget, self.items))

    def stage_data_exposure(self, target: str) -> list[dict]:
        return self._collect(
            data_exposure_module.run_data_exposure(target, self.budget, self.items, self.seeds)
        )

    def stage_advanced(self, target: str) -> list[dict]:
        return self._collect(
            advanced_module.run_advanced_checks(target, self.budget, self.items, self.seeds)
        )

    def stage_owasp(self, target: str) -> list[dict]:
        """Remaining OWASP categories plus the coverage matrix and test matrix."""
        findings: list[dict] = []
        findings.extend(owasp_module.check_cryptographic_failures(target, self.budget, self.seeds))
        design_findings, rate_limited = owasp_module.check_insecure_design(target, self.budget, self.items)
        self.rate_limiting_observed = rate_limited
        findings.extend(design_findings)
        findings.extend(owasp_module.check_misconfiguration(target, self.budget, self.seeds))
        findings.extend(owasp_module.check_outdated_components(target))
        findings.extend(owasp_module.check_authentication_and_integrity(
            target, self.budget, self.items, self.seeds
        ))
        findings.extend(owasp_module.check_logging_monitoring(target, self.rate_limiting_observed, self.budget))
        findings.append(injection_module.injection_matrix_finding(self.injection))
        self._collect(findings)

        # The matrix is built last so it can see every finding produced above.
        matrix = owasp_module.build_owasp_matrix(self.findings, self.stages_completed + ["owasp_matrix"])
        self.owasp_coverage = matrix
        matrix_finding = owasp_module.owasp_matrix_finding(target, matrix)
        self.findings.append(matrix_finding)
        return findings + [matrix_finding]

    # ── Stage table and summary ──────────────────────────────────────────────

    def _guarded(self, name: str, stage: Callable[[str], list[dict]]) -> Callable[[str], list[dict]]:
        """Wrap a stage so it becomes a no-op once the wall-clock ceiling passes.

        The guard lives here rather than in a driver loop so the synchronous
        endpoint, the Celery task, and :func:`run_danger_pipeline` all inherit
        the same deadline behaviour.
        """

        def run(target: str) -> list[dict]:
            # The clock starts here so the safe profiles that precede the danger
            # phase do not consume the danger budget.
            self.budget.begin()
            # owasp_matrix builds the coverage report, so it always runs.
            if name != "owasp_matrix" and self.budget.expired:
                if name not in self.stages_skipped:
                    self.stages_skipped.append(name)
                logger.info("[danger] skipping %s: %.0fs deadline reached", name, self.budget.max_seconds)
                return []
            return stage(target)

        return run

    def stages(self) -> list[Stage]:
        """Danger stages in dependency order, each guarded by the deadline."""
        ordered: list[Stage] = [
            ("danger_recon", self.stage_recon),
            ("danger_axfr", self.stage_axfr),
            ("attack_surface", self.stage_attack_surface),
            ("injection_sqli", self.stage_sqli),
            ("injection_command", self.stage_command),
            ("injection_html", self.stage_html),
            ("injection_xss", self.stage_xss),
            ("injection_ssti", self.stage_ssti),
            ("injection_xxe", self.stage_xxe),
            ("injection_ssrf", self.stage_ssrf),
            ("injection_nosql", self.stage_nosql),
            ("reverse_shell_assessment", self.stage_reverse_shell),
            ("dom_injection", self.stage_dom),
            ("directory_fuzzing", self.stage_directory),
            ("path_traversal", self.stage_traversal),
            ("idor_testing", self.stage_idor),
            ("business_logic", self.stage_business_logic),
            ("data_exposure", self.stage_data_exposure),
            ("advanced_checks", self.stage_advanced),
            ("owasp_matrix", self.stage_owasp),
        ]
        return [(name, self._guarded(name, stage)) for name, stage in ordered]

    def summary(self) -> DangerModeSummary:
        exploits = injection_module.exploitation_summary(self._injection.exploits if self._injection else [])
        confirmed_from_findings = sum(1 for finding in self.findings if finding.get("exploited"))
        return DangerModeSummary(
            exploits_confirmed=max(exploits["confirmed"], confirmed_from_findings),
            exploit_techniques=exploits["techniques"],
            platforms_identified=exploits["platforms"],
            enabled=danger_mode_enabled(),
            target=self.target,
            stages_completed=self.stages_completed,
            stages_failed=self.stages_failed,
            stages_skipped=self.stages_skipped,
            elapsed_seconds=round(self.budget.elapsed, 1),
            timed_out=self.budget.timed_out,
            attack_surface=self.items[:500],
            injection_matrix=self.injection.matrix[:2000],
            owasp_coverage=getattr(self, "owasp_coverage", []),
            requests_sent=self.budget.requests_sent,
            payloads_sent=self.budget.payloads_sent,
            budget_exhausted=self.budget.exhausted,
        )

    def deadline_finding(self) -> dict:
        """Explain partial coverage when the wall-clock ceiling stopped the scan."""
        return danger_finding(
            tool="danger_mode",
            category="danger_coverage",
            severity="info",
            title=f"Danger Mode Stopped at Time Limit - {len(self.stages_skipped)} stage(s) skipped",
            description=(
                f"The danger phase reached its {self.budget.max_seconds:.0f}-second wall-clock ceiling after "
                f"{self.budget.requests_sent} request(s), so the remaining stages were skipped and the report was "
                "produced from the work already completed. Coverage is partial: the skipped stages were not run at "
                "all, which is not the same as their finding nothing. Raise DANGER_MAX_SCAN_SECONDS or narrow the "
                "target to complete them."
            ),
            evidence=evidence_block([
                ("Target", self.target),
                ("Time limit", f"{self.budget.max_seconds:.0f}s"),
                ("Elapsed", f"{self.budget.elapsed:.1f}s"),
                ("Requests sent", self.budget.requests_sent),
                ("Stages completed", ", ".join(self.stages_completed) or "none"),
                ("Stages skipped", ", ".join(self.stages_skipped) or "none"),
            ]),
            remediation=(
                "Increase DANGER_MAX_SCAN_SECONDS for a longer engagement, or scan a narrower target so every stage "
                "fits inside the ceiling."
            ),
            confidence="Coverage notice",
            asset=self.target,
        )


def danger_stages(target: str) -> tuple[DangerSession, list[Stage]]:
    """Build a session and its stage list, or a single notice when disabled."""
    session = DangerSession(target=target)
    if not danger_mode_enabled():
        return session, [("danger_mode", session.stage_disabled)]
    return session, session.stages()


def run_danger_pipeline(target: str) -> tuple[list[dict], DangerModeSummary]:
    """Run every danger stage fail-soft and return findings plus the summary.

    A stage that raises is recorded in ``stages_failed`` and the pipeline
    continues, matching the existing fail-soft scan contract.
    """
    session, stages = danger_stages(target)
    for name, stage in stages:
        try:
            stage(target)
            if name not in session.stages_skipped:
                session.stages_completed.append(name)
        except Exception:
            logger.exception("[danger] stage %s failed", name)
            session.stages_failed.append(name)
    if session.stages_skipped:
        session.findings.append(session.deadline_finding())
    return session.findings, session.summary()
