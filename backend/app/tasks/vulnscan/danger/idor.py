"""Advanced IDOR (insecure direct object reference) candidate detection.

Object-referencing endpoints are enumerated with a small, bounded set of
adjacent identifiers and compared against a baseline. Only response *metadata*
is retained — status, size, and a content fingerprint. Object contents are never
read into evidence, stored, or transmitted anywhere.
"""

from __future__ import annotations

import base64
import binascii
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
    fingerprint,
    truncated,
)

logger = logging.getLogger("recontitan.danger.idor")

MODULE = "idor_testing"
A01 = "A01:2021-Broken Access Control"

OBJECT_PARAM_RE = re.compile(
    r"(?i)^(id|uid|uuid|guid|user_?id|account_?id|file_?id|doc(?:ument)?_?id|order(?:_?id)?|"
    r"invoice|record|item_?id|profile_?id|customer_?id|num(?:ber)?)$"
)
NUMERIC_RE = re.compile(r"^\d{1,12}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-([1-5])[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE)
PATH_ID_RE = re.compile(r"/(\d{1,12})(?=/|$)")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]{4,}={0,2}$")


@dataclass
class ObjectReference:
    """One enumerable object reference discovered on an endpoint."""

    item: AttackSurfaceItem
    location: str          # "query" or "path"
    parameter: str
    value: str
    id_format: str         # numeric | uuidv1 | uuidv4 | base64_numeric | opaque


def _id_format(value: str) -> str:
    if NUMERIC_RE.fullmatch(value):
        return "numeric"
    uuid_match = UUID_RE.fullmatch(value)
    if uuid_match:
        return f"uuidv{uuid_match.group(1)}"
    if BASE64_RE.fullmatch(value) and len(value) % 4 == 0:
        try:
            decoded = base64.b64decode(value, validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return "opaque"
        if NUMERIC_RE.fullmatch(decoded):
            return "base64_numeric"
    return "opaque"


def _adjacent_ids(value: str, id_format: str, count: int) -> list[str]:
    """Generate a small, bounded set of adjacent identifiers to compare against."""
    if id_format == "numeric":
        base = int(value)
        candidates = [base + offset for offset in range(1, count + 1)]
        candidates += [base - offset for offset in range(1, count // 2 + 1) if base - offset > 0]
        return [str(candidate) for candidate in candidates][:count]
    if id_format == "base64_numeric":
        base = int(base64.b64decode(value).decode("ascii"))
        return [
            base64.b64encode(str(base + offset).encode("ascii")).decode("ascii")
            for offset in range(1, count + 1)
        ][:count]
    if id_format.startswith("uuid"):
        # UUIDs are not sequential. Probe a small set of structurally valid but
        # unrelated values to confirm the endpoint rejects unknown references.
        suffixes = "0123456789abcdef"
        return [value[:-1] + suffixes[index % 16] for index in range(count) if value[:-1] + suffixes[index % 16] != value][:count]
    return []


def find_object_references(items: list[AttackSurfaceItem]) -> list[ObjectReference]:
    """Extract enumerable object references from the attack-surface inventory."""
    references: list[ObjectReference] = []
    for item in items:
        split = urlsplit(item.url)
        for name, value in parse_qsl(split.query, keep_blank_values=True):
            if not value or not OBJECT_PARAM_RE.fullmatch(name):
                continue
            id_format = _id_format(value)
            if id_format == "opaque":
                continue
            references.append(ObjectReference(item, "query", name, value, id_format))
        for match in PATH_ID_RE.finditer(split.path):
            references.append(ObjectReference(item, "path", "(path segment)", match.group(1), "numeric"))
    return references


def _swap(reference: ObjectReference, new_value: str) -> str:
    split = urlsplit(reference.item.url)
    if reference.location == "path":
        path = split.path.replace(f"/{reference.value}", f"/{new_value}", 1)
        return urlunsplit((split.scheme, split.netloc, path, split.query, split.fragment))
    pairs = [
        (name, new_value if name == reference.parameter else value)
        for name, value in parse_qsl(split.query, keep_blank_values=True)
    ]
    return urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs), split.fragment))


def _metadata(probe: ProbeResult) -> dict:
    """Response metadata only. The body is fingerprinted and discarded."""
    return {
        "status": probe.status,
        "bytes": probe.size,
        "fingerprint": fingerprint(probe.response.content) if probe.response else "",
    }


def _differs(baseline: dict, candidate: dict, *, baseline_stable: bool) -> bool:
    """Decide whether an adjacent identifier returned a genuinely different object.

    Two records for different owners are often the same length, so a size delta
    alone is not enough. When the baseline is stable across repeat requests the
    content fingerprint is authoritative; when the page is dynamic (timestamps,
    CSRF tokens) fingerprints always differ, so it falls back to a size delta.
    """
    if candidate["status"] != 200:
        return False
    if baseline["status"] != 200:
        return True
    if candidate["fingerprint"] == baseline["fingerprint"]:
        return False
    if baseline_stable:
        return True
    base_size = max(1, baseline["bytes"])
    return abs(candidate["bytes"] - base_size) / base_size > 0.02


def run_idor_tests(target: str, budget: DangerBudget, items: list[AttackSurfaceItem]) -> list[dict]:
    """Enumerate bounded adjacent identifiers and report differential access."""
    references = find_object_references(items)[: settings.DANGER_MAX_ENDPOINTS]
    if not references:
        return [danger_finding(
            tool=MODULE,
            category="danger_idor",
            severity="info",
            title="IDOR Testing - no enumerable object references discovered",
            description=(
                "No endpoint in the attack-surface inventory exposed a numeric, UUID, or base64-encoded object "
                "reference, so no identifier enumeration was performed."
            ),
            evidence=evidence_block([
                ("Target", target),
                ("Input points inspected", len(items)),
                ("Object references", 0),
            ]),
            owasp=A01,
            asset=target,
        )]

    findings: list[dict] = []
    max_ids = settings.DANGER_IDOR_MAX_IDS
    summary_rows: list[str] = []

    for reference in references:
        if not budget.can_spend(MODULE):
            break
        baseline_probe = budget.probe(MODULE, "GET", reference.item.url, counts_as_payload=False)
        if not baseline_probe.ok:
            continue
        baseline = _metadata(baseline_probe)
        # A second identical request tells us whether the page is stable enough
        # for fingerprint comparison to mean anything.
        repeat = budget.probe(MODULE, "GET", reference.item.url, counts_as_payload=False)
        baseline_stable = repeat.ok and _metadata(repeat)["fingerprint"] == baseline["fingerprint"]
        candidates = _adjacent_ids(reference.value, reference.id_format, max_ids)
        differing: list[dict] = []
        distinct_fingerprints: set[str] = {baseline["fingerprint"]}

        for candidate_id in candidates:
            if not budget.can_spend(MODULE):
                break
            probe = budget.probe(MODULE, "GET", _swap(reference, candidate_id))
            if not probe.ok:
                continue
            metadata = _metadata(probe)
            if _differs(baseline, metadata, baseline_stable=baseline_stable):
                differing.append({"id": candidate_id, **metadata})
                distinct_fingerprints.add(metadata["fingerprint"])

        summary_rows.append(
            f"{reference.parameter}={reference.value} [{reference.id_format}] "
            f"tested={len(candidates)} differing={len(differing)} "
            f"baseline={'stable' if baseline_stable else 'dynamic'}"
        )

        if differing:
            severity = "high" if reference.id_format in {"numeric", "base64_numeric"} else "medium"
            findings.append(danger_finding(
                tool=MODULE,
                category="danger_idor",
                severity=severity,
                title=f"IDOR Candidate - {reference.parameter} returns distinct objects for adjacent IDs",
                description=(
                    f"Requesting {len(differing)} adjacent identifier(s) for '{reference.parameter}' returned HTTP "
                    "200 with content that differs from the baseline, so the endpoint appears to serve different "
                    "objects without an authorization check tied to the requester. Only response metadata and "
                    "content fingerprints were recorded; no object content was read into evidence or stored."
                ),
                evidence=evidence_block([
                    ("Method", reference.item.method),
                    ("Endpoint", truncated(reference.item.url, 300)),
                    ("Reference location", reference.location),
                    ("Parameter", reference.parameter),
                    ("Identifier format", reference.id_format),
                    ("Identifiers tested", len(candidates)),
                    ("Baseline", f"status={baseline['status']} bytes={baseline['bytes']} body={baseline['fingerprint']}"),
                    ("Baseline stability", "stable across repeat requests" if baseline_stable else "dynamic content"),
                    ("Distinct object fingerprints", len(distinct_fingerprints)),
                    ("Differing responses", "\n" + "\n".join(
                        f"  id={entry['id']} status={entry['status']} bytes={entry['bytes']} body={entry['fingerprint']}"
                        for entry in differing[:20]
                    )),
                    ("Object content stored", "no - fingerprint and size only"),
                ]),
                remediation=(
                    "Enforce an authorization check on every object access that binds the identifier to the "
                    "authenticated principal. Use unguessable identifiers as defence in depth, never as the control."
                ),
                owasp=A01,
                attack_vector=f"Insecure direct object reference ({reference.id_format} enumeration)",
                asset=reference.item.url,
            ))

        findings.extend(_method_variation(budget, reference, baseline))

    findings.append(danger_finding(
        tool=MODULE,
        category="danger_idor_summary",
        severity="info",
        title=f"IDOR Enumeration Summary - {len(references)} object reference(s)",
        description=(
            f"Danger Mode enumerated up to {max_ids} adjacent identifiers per object reference and compared "
            "response status, size, and content fingerprint against a baseline request."
        ),
        evidence=evidence_block([
            ("Target", target),
            ("Object references tested", len(references)),
            ("Max identifiers per reference", max_ids),
            ("Results", "\n" + "\n".join(f"  {row}" for row in summary_rows) if summary_rows else "  none"),
        ]),
        owasp=A01,
        asset=target,
    ))

    logger.info("[danger:idor] %s: %d references, %d candidates", target, len(references), len(findings) - 1)
    return findings


def _method_variation(budget: DangerBudget, reference: ObjectReference, baseline: dict) -> list[dict]:
    """Check whether an unauthenticated POST is treated differently from GET.

    Only an empty body is sent. Nothing is created, modified, or deleted.
    """
    if not budget.can_spend(MODULE):
        return []
    probe = budget.probe(
        MODULE, "POST", reference.item.url,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=b"",
    )
    if not probe.ok or probe.status is None:
        return []
    if probe.status not in {200, 201, 202, 204}:
        return []
    if baseline["status"] in {401, 403} or probe.status == baseline["status"]:
        return []
    return [danger_finding(
        tool=MODULE,
        category="danger_missing_auth",
        severity="medium",
        title="Method-Variation Access Difference - unauthenticated POST accepted",
        description=(
            "The same object endpoint answered an unauthenticated POST with a success status while the GET "
            "baseline responded differently. Inconsistent authorization between methods on one resource often "
            "means the check is applied per-route rather than per-object. An empty body was sent; no data was "
            "created, modified, or deleted."
        ),
        evidence=evidence_block([
            ("Endpoint", truncated(reference.item.url, 300)),
            ("GET baseline status", baseline["status"]),
            ("POST status", probe.status),
            ("POST response bytes", probe.size),
            ("Request body sent", "empty"),
        ]),
        remediation=(
            "Apply the same authorization check to every method on a resource, and deny by default for methods the "
            "endpoint does not implement."
        ),
        owasp=A01,
        attack_vector="Method-based authorization bypass",
        asset=reference.item.url,
    )]
