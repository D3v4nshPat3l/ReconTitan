"""Business logic flaw detection.

Automated scanners rarely find these because there is no malformed payload to
match on — the request is perfectly well-formed and the application simply agrees
to something it should refuse. This module probes the decisions rather than the
parsing: does the server recompute price, does it bound quantity, does it enforce
step order, can a one-time value be replayed, does it bind fields the interface
never exposes.

Every probe here is non-destructive. State-changing flows are probed with GET or
with an unauthenticated request whose failure is the expected outcome; the module
reports the *absence of a control*, and never completes a transaction, redeems a
voucher, or writes a record to prove it.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.config import settings
from app.models.schemas import AttackSurfaceItem, InputPointType
from app.tasks.vulnscan.danger.budget import (
    DangerBudget,
    ProbeResult,
    danger_finding,
    evidence_block,
    truncated,
)
from app.tasks.vulnscan.danger.remediation import remediation_for

logger = logging.getLogger("recontitan.danger.business_logic")

MODULE = "business_logic"
A01 = "A01:2021-Broken Access Control"
A04 = "A04:2021-Insecure Design"

#: Parameters whose value should always be derived server-side.
MONETARY_PARAMS = re.compile(
    r"(?i)^(price|unit_?price|amount|total|subtotal|cost|fee|charge|value|"
    r"discount|discount_?(?:pct|percent|rate)|balance|credit|points|rate)$"
)
QUANTITY_PARAMS = re.compile(r"(?i)^(qty|quantity|count|items?|num(?:ber)?|seats?|units?|limit|per_?page)$")
PRIVILEGE_PARAMS = re.compile(
    r"(?i)^(role|roles|is_?admin|admin|is_?staff|permission|permissions|scope|scopes|"
    r"group|groups|level|tier|plan|verified|is_?verified|active|enabled|status|owner_?id|user_?id|account_?id)$"
)
ONE_TIME_PARAMS = re.compile(r"(?i)^(coupon|voucher|promo|promo_?code|discount_?code|gift_?card|referral|invite|token|otp)$")
STEP_PARAMS = re.compile(r"(?i)^(step|stage|phase|page|state|status|screen|wizard)$")

#: Values that a correctly validated numeric field must reject.
BOUNDARY_VALUES: tuple[tuple[str, str, str], ...] = (
    ("negative", "-1", "Negative value; on a quantity or amount this can invert a total into a credit"),
    ("zero", "0", "Zero value; can bypass minimum-order and payment checks"),
    ("large", "999999999", "Very large value; tests for overflow and missing upper bounds"),
    ("float_precision", "0.0000001", "Sub-cent precision; tests rounding and truncation handling"),
    ("scientific", "1e5", "Scientific notation; often parsed by loose casts that reject plain text"),
    ("hex", "0x10", "Hex literal; accepted by some loose integer parsers"),
    ("leading_space", " 1", "Whitespace padding; tests trimming before validation"),
)

#: Privileged fields probed for mass assignment. Sending them is harmless when
#: the request is unauthenticated - the finding is that they are *accepted*.
MASS_ASSIGNMENT_FIELDS: tuple[tuple[str, str], ...] = (
    ("role", "admin"),
    ("is_admin", "true"),
    ("is_staff", "true"),
    ("verified", "true"),
    ("email_verified", "true"),
    ("balance", "999999"),
    ("credits", "999999"),
    ("plan", "enterprise"),
    ("permissions", "all"),
)

#: Response markers suggesting the server echoed the tampered field back.
_ACCEPTED_MARKERS = ("\"role\"", "\"is_admin\"", "\"balance\"", "\"plan\"", "\"permissions\"", "\"verified\"")


@dataclass
class LogicProbe:
    """One business-rule probe and what the response implied."""

    endpoint: str
    parameter: str
    variant: str
    value: str
    status: int | None
    size: int
    accepted: bool
    note: str


def _with_param(url: str, parameter: str, value: str) -> str:
    split = urlsplit(url)
    pairs = list(parse_qsl(split.query, keep_blank_values=True))
    replaced = False
    updated = []
    for name, existing in pairs:
        if name == parameter:
            updated.append((name, value))
            replaced = True
        else:
            updated.append((name, existing))
    if not replaced:
        updated.append((parameter, value))
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(updated), split.fragment))


def _rejected(probe: ProbeResult) -> bool:
    """A correctly validating endpoint answers a bad value with a client error."""
    return probe.ok and probe.status is not None and 400 <= probe.status < 500


def _accepted_like_baseline(baseline: ProbeResult, probe: ProbeResult) -> bool:
    if not (baseline.ok and probe.ok):
        return False
    if probe.status != 200:
        return False
    base = max(1, baseline.size)
    return abs(probe.size - base) / base < 0.5


# ── Numeric boundary handling ─────────────────────────────────────────────────

def check_numeric_boundaries(
    budget: DangerBudget, items: list[AttackSurfaceItem]
) -> tuple[list[dict], list[LogicProbe]]:
    """Send out-of-domain numeric values to quantity and money parameters."""
    findings: list[dict] = []
    probes: list[LogicProbe] = []

    targets = [
        (item, parameter)
        for item in items[: settings.DANGER_MAX_ENDPOINTS]
        for parameter in item.parameters[:6]
        if QUANTITY_PARAMS.fullmatch(parameter) or MONETARY_PARAMS.fullmatch(parameter)
    ]
    if not targets:
        return findings, probes

    for item, parameter in targets:
        if not budget.can_spend(MODULE):
            break
        baseline = budget.probe(MODULE, "GET", item.url, counts_as_payload=False)
        if not baseline.ok:
            continue
        monetary = bool(MONETARY_PARAMS.fullmatch(parameter))
        accepted: list[LogicProbe] = []

        for variant, value, note in BOUNDARY_VALUES:
            if not budget.can_spend(MODULE):
                break
            probe = budget.probe(MODULE, "GET", _with_param(item.url, parameter, value))
            record = LogicProbe(
                endpoint=item.url, parameter=parameter, variant=variant, value=value,
                status=probe.status, size=probe.size,
                accepted=not _rejected(probe) and _accepted_like_baseline(baseline, probe),
                note=note,
            )
            probes.append(record)
            if record.accepted:
                accepted.append(record)

        dangerous = [record for record in accepted if record.variant in {"negative", "zero", "large", "scientific", "hex"}]
        if dangerous:
            findings.append(danger_finding(
                tool=MODULE,
                category="danger_business_logic",
                severity="high" if monetary or any(r.variant == "negative" for r in dangerous) else "medium",
                title=f"Missing Numeric Validation - {parameter} accepts out-of-domain values",
                description=(
                    f"The parameter '{parameter}' was accepted with {len(dangerous)} value(s) that a correctly "
                    "validated field would reject, and the response was equivalent to the baseline rather than a "
                    "client error. "
                    + (
                        "On a monetary field this is how totals get inverted into credits and how discounts exceed "
                        "the order value."
                        if monetary else
                        "On a quantity field this is how inventory, seat, and rate limits get bypassed, and negative "
                        "quantities are a well-known route to a refund the buyer never paid for."
                    )
                    + " No order was placed and no state was changed; only the validation response was observed."
                ),
                evidence=evidence_block([
                    ("Endpoint", truncated(item.url, 300)),
                    ("Parameter", parameter),
                    ("Parameter class", "monetary" if monetary else "quantity"),
                    ("Baseline", f"HTTP {baseline.status}, {baseline.size} bytes"),
                    ("Accepted values", "\n" + "\n".join(
                        f"  {record.value!r} ({record.variant}) -> HTTP {record.status}, {record.size} bytes - {record.note}"
                        for record in dangerous
                    )),
                    ("Rejected values", ", ".join(
                        record.variant for record in probes
                        if record.parameter == parameter and record.endpoint == item.url and not record.accepted
                    ) or "none"),
                    ("Exploitation status", "CONFIRMED missing validation"),
                    ("Proof type", "Out-of-domain value accepted with a success response"),
                    ("State changed on target", "no"),
                ]),
                remediation=remediation_for("business_logic"),
                owasp=A04,
                attack_vector=f"Business logic - unvalidated {'monetary' if monetary else 'quantity'} parameter",
                asset=item.url,
            ))
    return findings, probes


# ── Parameter tampering / privilege fields ────────────────────────────────────

def check_privilege_parameters(items: list[AttackSurfaceItem]) -> list[dict]:
    """Report client-visible parameters that decide privilege or ownership."""
    exposed: list[tuple[str, str, str]] = []
    for item in items:
        for parameter in item.parameters:
            if PRIVILEGE_PARAMS.fullmatch(parameter):
                exposed.append((item.method, item.url, parameter))
    if not exposed:
        return []

    return [danger_finding(
        tool=MODULE,
        category="danger_business_logic",
        severity="medium",
        title=f"Privilege-Deciding Parameters Exposed To The Client - {len(exposed)}",
        description=(
            "Parameters that determine role, ownership, entitlement, or verification state are present in the "
            "client-visible request surface. If any of these are honoured server-side, a caller can grant "
            "themselves privileges or act on another account's objects simply by editing the request. The "
            "presence of the parameter is not proof it is honoured - confirm each one against the handler."
        ),
        evidence=evidence_block([
            ("Parameters found", len(exposed)),
            *[(f"{method} {truncated(url, 160)}", parameter) for method, url, parameter in exposed[:25]],
            ("Proof type", "Attack-surface inventory analysis"),
        ]),
        remediation=remediation_for("mass_assignment"),
        owasp=A01,
        attack_vector="Parameter tampering on a privilege field",
        asset=exposed[0][1],
    )]


# ── Mass assignment ───────────────────────────────────────────────────────────

def check_mass_assignment(budget: DangerBudget, items: list[AttackSurfaceItem]) -> list[dict]:
    """Probe whether the API accepts fields the interface never sends.

    Requests are unauthenticated, so a success response indicates the endpoint
    binds unknown fields rather than that any account was modified.
    """
    findings: list[dict] = []
    api_items = [
        item for item in items[: settings.DANGER_MAX_ENDPOINTS]
        if item.method == "POST" and item.input_type in {
            InputPointType.API_ENDPOINT, InputPointType.GENERIC_FORM, InputPointType.LOGIN_FORM
        }
    ][:5]

    for item in api_items:
        if not budget.can_spend(MODULE):
            break
        legitimate = {name: "recontitan-probe" for name in item.parameters}
        baseline = budget.probe(
            MODULE, "POST", item.url,
            headers={"Content-Type": "application/json"},
            body=json.dumps(legitimate).encode("utf-8"),
            counts_as_payload=False,
        )
        if not baseline.ok:
            continue

        tampered = dict(legitimate)
        tampered.update({field: value for field, value in MASS_ASSIGNMENT_FIELDS})
        probe = budget.probe(
            MODULE, "POST", item.url,
            headers={"Content-Type": "application/json"},
            body=json.dumps(tampered).encode("utf-8"),
        )
        if not probe.ok:
            continue

        echoed = [marker.strip('"') for marker in _ACCEPTED_MARKERS if marker in probe.text]
        # A strict endpoint rejects unknown fields; a permissive one answers the
        # same as the clean request, or reflects the injected field names back.
        same_as_clean = probe.status == baseline.status and probe.status not in (400, 422)
        if not (echoed or same_as_clean):
            continue

        findings.append(danger_finding(
            tool=MODULE,
            category="danger_mass_assignment",
            severity="high" if echoed else "medium",
            title=f"Mass Assignment Surface - unknown privileged fields accepted",
            description=(
                "The endpoint accepted a request body containing privileged fields that the interface never "
                "sends, without returning a validation error. "
                + (
                    f"The response also referenced {', '.join(echoed)}, which indicates the fields were bound "
                    "rather than ignored. "
                    if echoed else
                    "The response matched the clean request, so unknown fields are silently accepted rather than "
                    "rejected. "
                )
                + "Where an authenticated version of this endpoint persists the bound object, a caller can set "
                "their own role, entitlement, or balance. The probe was unauthenticated, so no account was "
                "modified."
            ),
            evidence=evidence_block([
                ("Endpoint", truncated(item.url, 300)),
                ("Method", "POST"),
                ("Legitimate fields", ", ".join(item.parameters[:12]) or "none"),
                ("Injected privileged fields", ", ".join(name for name, _ in MASS_ASSIGNMENT_FIELDS)),
                ("Clean request", f"HTTP {baseline.status}, {baseline.size} bytes"),
                ("Tampered request", f"HTTP {probe.status}, {probe.size} bytes"),
                ("Fields echoed in response", ", ".join(echoed) or "none"),
                ("Exploitation status", "CONFIRMED binding" if echoed else "CONFIRMED unknown fields accepted"),
                ("Proof type", "Differential response to injected fields"),
                ("Authenticated", "no - no account was modified"),
            ]),
            remediation=remediation_for("mass_assignment"),
            owasp=A01,
            attack_vector="Mass assignment of privileged fields",
            asset=item.url,
        ))
    return findings


# ── Workflow step enforcement ─────────────────────────────────────────────────

def check_workflow_bypass(budget: DangerBudget, items: list[AttackSurfaceItem]) -> list[dict]:
    """Request a later workflow step directly, without completing earlier ones."""
    findings: list[dict] = []
    step_targets = [
        (item, parameter)
        for item in items[: settings.DANGER_MAX_ENDPOINTS]
        for parameter in item.parameters[:6]
        if STEP_PARAMS.fullmatch(parameter)
    ][:4]

    for item, parameter in step_targets:
        if not budget.can_spend(MODULE):
            break
        first = budget.probe(MODULE, "GET", _with_param(item.url, parameter, "1"), counts_as_payload=False)
        if not first.ok:
            continue
        reachable: list[str] = []
        for step in ("3", "4", "confirm", "complete", "review"):
            if not budget.can_spend(MODULE):
                break
            probe = budget.probe(MODULE, "GET", _with_param(item.url, parameter, step))
            if probe.ok and probe.status == 200 and not _rejected(probe):
                base = max(1, first.size)
                if abs(probe.size - base) / base > 0.05:
                    reachable.append(f"{parameter}={step} -> HTTP {probe.status}, {probe.size} bytes")

        if len(reachable) >= 2:
            findings.append(danger_finding(
                tool=MODULE,
                category="danger_business_logic",
                severity="medium",
                title=f"Workflow Step Not Enforced - {parameter} is caller-controlled",
                description=(
                    "Later steps of a multi-step flow returned distinct content when requested directly, without "
                    "the earlier steps having been completed in this session. Where a flow relies on step order "
                    "for validation - address before payment, payment before fulfilment - a caller can skip the "
                    "steps that enforce the rules. Only GET requests were sent; nothing was submitted or "
                    "completed."
                ),
                evidence=evidence_block([
                    ("Endpoint", truncated(item.url, 300)),
                    ("Step parameter", parameter),
                    ("First step", f"HTTP {first.status}, {first.size} bytes"),
                    ("Directly reachable later steps", "\n" + "\n".join(f"  {entry}" for entry in reachable)),
                    ("Exploitation status", "CONFIRMED direct step access"),
                    ("Proof type", "Out-of-order step returns distinct content"),
                    ("State changed on target", "no - GET only"),
                ]),
                remediation=remediation_for("business_logic"),
                owasp=A04,
                attack_vector="Workflow step bypass",
                asset=item.url,
            ))
    return findings


# ── One-time values and race susceptibility ───────────────────────────────────

def check_replay_and_race(budget: DangerBudget, items: list[AttackSurfaceItem]) -> list[dict]:
    """Report one-time-value endpoints that show no idempotency or replay control."""
    findings: list[dict] = []
    one_time = [
        (item, parameter)
        for item in items[: settings.DANGER_MAX_ENDPOINTS]
        for parameter in item.parameters[:6]
        if ONE_TIME_PARAMS.fullmatch(parameter)
    ][:4]
    if not one_time:
        return findings

    for item, parameter in one_time:
        if not budget.can_spend(MODULE):
            break
        # Two identical reads of an invalid code. This never redeems anything -
        # it observes whether the endpoint signals rate limiting or idempotency.
        probes = [
            budget.probe(MODULE, "GET", _with_param(item.url, parameter, "RECONTITAN-INVALID-PROBE"))
            for _ in range(3)
            if budget.can_spend(MODULE)
        ]
        answered = [probe for probe in probes if probe.ok]
        if len(answered) < 2:
            continue
        throttled = any(probe.status in {429, 423} for probe in answered)
        idempotency_header = False
        for probe in answered:
            if probe.response is not None and any(
                header.lower() in {"idempotency-key", "x-idempotency-key", "x-request-id"}
                for header in probe.response.headers
            ):
                idempotency_header = True
                break
        if throttled or idempotency_header:
            continue

        findings.append(danger_finding(
            tool=MODULE,
            category="danger_business_logic",
            severity="medium",
            title=f"One-Time Value Endpoint Without Replay Control - {parameter}",
            description=(
                f"The endpoint accepts a '{parameter}' value and answered repeated identical submissions with no "
                "throttling status and no idempotency header. One-time values such as coupons, vouchers, gift "
                "cards, and invites need an atomic single-use claim; without one, concurrent requests can redeem "
                "the same value more than once. An invalid probe value was used, so nothing was redeemed."
            ),
            evidence=evidence_block([
                ("Endpoint", truncated(item.url, 300)),
                ("Parameter", parameter),
                ("Identical submissions", len(answered)),
                ("Status codes", ", ".join(str(probe.status) for probe in answered)),
                ("Throttling observed", "none"),
                ("Idempotency header observed", "none"),
                ("Value used", "RECONTITAN-INVALID-PROBE (not a real code)"),
                ("Proof type", "Absence of replay and idempotency controls"),
                ("State changed on target", "no"),
            ]),
            remediation=remediation_for("business_logic"),
            owasp=A04,
            attack_vector="One-time value replay / race condition",
            asset=item.url,
        ))
    return findings


def run_business_logic(target: str, budget: DangerBudget, items: list[AttackSurfaceItem]) -> list[dict]:
    """Run every business-logic probe and summarize coverage."""
    findings: list[dict] = []
    boundary_findings, probes = check_numeric_boundaries(budget, items)
    findings.extend(boundary_findings)
    findings.extend(check_privilege_parameters(items))
    findings.extend(check_mass_assignment(budget, items))
    findings.extend(check_workflow_bypass(budget, items))
    findings.extend(check_replay_and_race(budget, items))

    monetary = sum(1 for item in items for name in item.parameters if MONETARY_PARAMS.fullmatch(name))
    quantity = sum(1 for item in items for name in item.parameters if QUANTITY_PARAMS.fullmatch(name))
    privilege = sum(1 for item in items for name in item.parameters if PRIVILEGE_PARAMS.fullmatch(name))
    one_time = sum(1 for item in items for name in item.parameters if ONE_TIME_PARAMS.fullmatch(name))

    findings.append(danger_finding(
        tool=MODULE,
        category="danger_business_logic_summary",
        severity="info",
        title=f"Business Logic Analysis - {len(probes)} boundary probe(s)",
        description=(
            "Business rules were probed rather than parsing: numeric domain validation, privilege-deciding "
            "parameters, mass-assignment binding, workflow step enforcement, and replay controls on one-time "
            "values. Logic flaws are highly application-specific, so a clean result here means the generic "
            "patterns were not present - it is not a substitute for a manual review of the flows that matter to "
            "the business."
        ),
        evidence=evidence_block([
            ("Target", target),
            ("Input points inspected", len(items)),
            ("Monetary parameters", monetary),
            ("Quantity parameters", quantity),
            ("Privilege parameters", privilege),
            ("One-time value parameters", one_time),
            ("Boundary probes sent", len(probes)),
            ("Values accepted that should be rejected", sum(1 for probe in probes if probe.accepted)),
            ("State changed on target", "none - no transaction, redemption, or write was completed"),
        ]),
        owasp=A04,
        asset=target,
    ))
    logger.info("[danger:business_logic] %s: %d probes, %d findings", target, len(probes), len(findings) - 1)
    return findings
