"""Triage state: recording that a finding was reviewed, and what was decided.

Without this, every finding is permanently equal. Somebody reviews a report,
determines that three CVE candidates do not apply to their build, and has
nowhere to put that. The next scan shows the same three with the same weight,
the report never gets quieter, and people stop reading it. A scanner nobody
reads finds nothing.

Four states, and only two of them quieten anything:

    open            not yet reviewed. The default; never stored.
    confirmed       reviewed and real. Does NOT suppress -- it raises
                    confidence, and a confirmed finding sorts first.
    false_positive  reviewed and not real here. Suppressed.
    accepted_risk   real, and the owner has decided to live with it.
                    Suppressed from the counts, never from the report.

Two rules keep this from becoming a way to hide problems, which is the obvious
failure mode of any suppression feature:

* Suppressing requires a written reason. A decision with no rationale is not
  a decision, it is deletion with extra steps.
* Nothing is ever removed. Suppressed findings stay in the report carrying
  their triage block, and the report gains a triage summary stating how many
  were suppressed and why. The counts get quieter; the evidence does not move.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any

from app.config import settings

logger = logging.getLogger("recontitan.triage")

OPEN = "open"
CONFIRMED = "confirmed"
FALSE_POSITIVE = "false_positive"
ACCEPTED_RISK = "accepted_risk"

STATES = (OPEN, CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK)
#: States that remove a finding from the severity counts and the attack paths.
SUPPRESSING = (FALSE_POSITIVE, ACCEPTED_RISK)
#: States a person must justify in writing before they take effect.
NEEDS_REASON = (FALSE_POSITIVE, ACCEPTED_RISK)

MAX_REASON = 500
MAX_AUTHOR = 100
_MAX_DECISIONS_PER_TARGET = 2_000

_lock = threading.Lock()


# ── Fingerprinting ────────────────────────────────────────────────────────────
#
# A decision has to outlive the scan that produced it, and finding ids are a
# fresh uuid every run. So triage is keyed on a fingerprint derived from what
# the finding *is*.
#
# The whole design turns on one asymmetry. Under-normalising means the
# fingerprint changes, the finding reappears, and somebody re-triages it --
# annoying. Over-normalising means two different findings collapse to one key,
# and suppressing one silently suppresses the other -- a real vulnerability
# hidden by a tool the user trusts. So this normalises conservatively and,
# where it is unsure, prefers to let the finding come back.
#
# Concretely: digits are never stripped wholesale. "Internet-Exposed Port:
# 3306/mysql" and "...: 22/ssh" must stay distinct, and a blanket digit rule
# would merge them. Only patterns that are provably volatile *and* carry no
# identity are collapsed.

_VOLATILE = (
    # "Certificate valid for 53 more days" -- changes daily, identifies nothing.
    (re.compile(r"\b\d+\s+more\s+days?\b", re.I), "N more days"),
    (re.compile(r"\bexpires?\s+in\s+\d+\s+days?\b", re.I), "expires in N days"),
    # "Port Scan - 2 Open Port(s) Found" -- the count is not the identity.
    (re.compile(r"\b\d+\s+(open\s+port|subdomain|name|finding|url|file|endpoint)s?\b", re.I),
     r"N \1s"),
    # Absolute dates and timestamps.
    (re.compile(r"\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?\b"), "DATE"),
    (re.compile(r"\b\d{1,2}\s+\w{3}\s+\d{4}\b"), "DATE"),
)


def _normalise_title(title: str) -> str:
    text = str(title or "")
    for pattern, replacement in _VOLATILE:
        text = pattern.sub(replacement, text)
    return " ".join(text.split()).casefold()


def _normalise_asset(asset: str) -> str:
    """Keep the endpoint and its parameter names, drop the values.

    ``/item?id=7`` and ``/item?id=9`` are the same finding about the same
    parameter. ``/item?id=`` and ``/search?q=`` are not.
    """
    text = str(asset or "").strip()
    if not text:
        return ""
    base, separator, query = text.partition("?")
    if not separator:
        return base.casefold()
    names = sorted(part.split("=", 1)[0] for part in query.split("&") if part)
    return (base + "?" + "&".join(names)).casefold()


def fingerprint(finding: dict[str, Any]) -> str:
    """A stable key for one finding, unchanged across re-scans.

    Identity comes from the most specific stable field available, because a
    structured field beats a prose title that a wording change would alter.
    """
    tool = str(finding.get("tool") or "").casefold()
    category = str(finding.get("category") or "").casefold()

    cve = str(finding.get("cve_id") or "").strip().upper()
    asset = _normalise_asset(finding.get("affected_asset") or "")
    title = _normalise_title(finding.get("title") or "")

    if cve:
        # A CVE on an asset is a different decision from the same CVE
        # elsewhere, so the asset stays in the key when it is known.
        identity = f"cve:{cve}|{asset}"
    elif asset:
        # Danger findings all carry an asset. The title is still included:
        # two different flaws on one endpoint must not share a decision.
        identity = f"asset:{asset}|{title}"
    else:
        identity = f"title:{title}"

    digest = hashlib.sha256(f"{tool}|{category}|{identity}".encode()).hexdigest()
    return digest[:32]


# ── Storage ───────────────────────────────────────────────────────────────────
#
# A JSON file, because this has to work in the mode the project actually runs
# in: no MongoDB, no Celery, one process on somebody's laptop. It is small
# (one short record per reviewed finding) and it is human-readable, which
# matters for something that records human decisions.

def _store_path() -> str:
    configured = settings.TRIAGE_STORE_PATH
    if configured:
        return configured
    return str(settings.BASE_DIR.parent / "triage.json")


def _read_store() -> dict[str, Any]:
    path = _store_path()
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        # A corrupt store must not take the scanner down with it. Triage is an
        # aid; losing it is worse than nothing but far better than a 500 on
        # every scan.
        logger.warning("[triage] cannot read %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def _write_store(data: dict[str, Any]) -> None:
    path = _store_path()
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    # Written through a temporary file and replaced, so an interrupted write
    # cannot leave a half-written file where the decisions used to be.
    handle = tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=directory, delete=False, suffix=".tmp",
    )
    try:
        with handle:
            json.dump(data, handle, indent=2, sort_keys=True)
        os.replace(handle.name, path)
    except OSError:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def _target_key(target: str) -> str:
    return str(target or "").strip().casefold()


def decisions_for(target: str) -> dict[str, dict[str, Any]]:
    """Every recorded decision for one target, keyed by fingerprint."""
    key = _target_key(target)
    if not key:
        return {}
    with _lock:
        entry = _read_store().get(key)
    return entry if isinstance(entry, dict) else {}


def record(
    target: str,
    finding_fingerprint: str,
    state: str,
    reason: str = "",
    author: str = "",
) -> dict[str, Any]:
    """Record one decision. Returns the stored record.

    Raises ValueError for an unknown state, a malformed fingerprint, or a
    suppressing state with no written reason.
    """
    key = _target_key(target)
    if not key:
        raise ValueError("A target is required.")
    if state not in STATES:
        raise ValueError(f"Unknown triage state: {state}")
    if not re.fullmatch(r"[0-9a-f]{32}", str(finding_fingerprint or "")):
        raise ValueError("Malformed finding fingerprint.")

    reason = " ".join(str(reason or "").split())[:MAX_REASON]
    author = " ".join(str(author or "").split())[:MAX_AUTHOR]
    if state in NEEDS_REASON and not reason:
        raise ValueError(
            f"A written reason is required to mark a finding {state.replace('_', ' ')}."
        )

    with _lock:
        store = _read_store()
        target_entry = store.setdefault(key, {})
        if not isinstance(target_entry, dict):
            target_entry = store[key] = {}

        if state == OPEN:
            # Returning to open is forgetting the decision, not recording one.
            target_entry.pop(finding_fingerprint, None)
            record_value: dict[str, Any] = {"state": OPEN}
        else:
            if (
                finding_fingerprint not in target_entry
                and len(target_entry) >= _MAX_DECISIONS_PER_TARGET
            ):
                raise ValueError(
                    f"This target already has {_MAX_DECISIONS_PER_TARGET} triage decisions."
                )
            record_value = {
                "state": state,
                "reason": reason,
                "author": author,
                "decided_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            }
            target_entry[finding_fingerprint] = record_value

        if not target_entry:
            store.pop(key, None)
        _write_store(store)
    return record_value


# ── Applying decisions to a report ────────────────────────────────────────────

def annotate(findings: list[dict], decisions: dict[str, dict]) -> None:
    """Stamp each finding with its fingerprint and any recorded decision.

    Every finding gets a fingerprint whether or not it has been reviewed, so
    the UI has a key to submit a decision against.
    """
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        key = fingerprint(finding)
        finding["triage_fingerprint"] = key
        decision = decisions.get(key)
        if isinstance(decision, dict) and decision.get("state") in STATES:
            finding["triage"] = {
                "state": decision.get("state", OPEN),
                "reason": decision.get("reason", ""),
                "author": decision.get("author", ""),
                "decided_at": decision.get("decided_at", ""),
            }
        else:
            finding["triage"] = {"state": OPEN, "reason": "", "author": "", "decided_at": ""}


def is_suppressed(finding: dict) -> bool:
    return str((finding.get("triage") or {}).get("state")) in SUPPRESSING


def summarise(findings: list[dict]) -> dict[str, Any]:
    """What triage is currently hiding, and what it has confirmed.

    This exists so suppression is never silent. A reader must be able to see
    that the quiet report is quiet because somebody made a decision, and to
    see which decisions those were.
    """
    counts = {state: 0 for state in STATES}
    suppressed: list[dict[str, Any]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        triage = finding.get("triage") or {}
        state = str(triage.get("state") or OPEN)
        counts[state] = counts.get(state, 0) + 1
        if state in SUPPRESSING:
            suppressed.append({
                "title": str(finding.get("title") or "")[:300],
                "severity": str(finding.get("severity") or "info"),
                "state": state,
                "reason": str(triage.get("reason") or "")[:MAX_REASON],
                "decided_at": str(triage.get("decided_at") or ""),
                "fingerprint": str(finding.get("triage_fingerprint") or ""),
            })
    return {
        "counts": counts,
        "suppressed_total": len(suppressed),
        "suppressed": suppressed[:200],
    }


def apply_to_report(report: dict[str, Any]) -> dict[str, Any]:
    """Annotate findings, requantify the counts, and add the triage summary.

    Counts and attack paths reflect the findings that are still open; the
    findings list keeps everything. Mutates and returns the report.
    """
    findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)]
    decisions = decisions_for(report.get("target") or "")
    annotate(findings, decisions)

    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in findings:
        if is_suppressed(finding):
            continue
        severity = str(finding.get("severity") or "info").casefold()
        counts[severity if severity in counts else "info"] += 1

    report["severity_counts"] = counts
    report["total_findings"] = sum(counts.values())
    report["triage_summary"] = summarise(findings)
    return report


def active_findings(findings: list[dict]) -> list[dict]:
    """The findings that still count: everything not suppressed."""
    return [
        finding for finding in findings
        if isinstance(finding, dict) and not is_suppressed(finding)
    ]
