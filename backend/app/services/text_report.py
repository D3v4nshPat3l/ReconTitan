"""Plain-text report rendering.

PDF is for handing to a person and JSON is for handing to a program. Neither
is much use at a terminal, in a pipeline, or in a diff between two scans of
the same target a week apart -- and those are the places a report most often
needs to be read quickly.

So this renders the same report structure as fixed-width text: greppable,
diffable, and readable over SSH on a host with no PDF viewer. It carries the
same content as the other exports, including the triage state and the reasons
behind any suppression. A quiet report still says why it is quiet.
"""

from __future__ import annotations

from datetime import datetime, timezone

WIDTH = 78

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

#: Triage states that remove a finding from the counts. Suppressed findings
#: are still printed -- hiding them is the failure mode this whole feature
#: exists to avoid -- but they are printed in their own section, labelled.
SUPPRESSING_STATES = {"false_positive", "accepted_risk"}


def _rule(char: str = "=") -> str:
    return char * WIDTH


def _heading(text: str, char: str = "=") -> list[str]:
    return [_rule(char), text.upper(), _rule(char), ""]


def _wrap(text: str, indent: str = "  ", width: int = WIDTH) -> list[str]:
    """Wrap prose, preserving the paragraph breaks the source already has."""
    import textwrap

    out: list[str] = []
    for paragraph in str(text or "").split("\n"):
        paragraph = paragraph.rstrip()
        if not paragraph:
            out.append("")
            continue
        out.extend(
            textwrap.wrap(
                paragraph, width=width, initial_indent=indent,
                subsequent_indent=indent, break_long_words=False,
                break_on_hyphens=False,
            )
            or [indent]
        )
    return out


def _block(text: str, indent: str = "    ") -> list[str]:
    """Emit evidence verbatim. Evidence is aligned output; wrapping destroys it."""
    lines = []
    for line in str(text or "").split("\n"):
        lines.append(f"{indent}{line}".rstrip())
    return lines


def _severity_key(finding: dict) -> tuple[int, str]:
    severity = str(finding.get("severity", "info")).lower()
    rank = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return rank, str(finding.get("title", ""))


def render_text_report(report: dict) -> str:
    """Render a scan report as plain text."""
    lines: list[str] = []
    target = report.get("target", "unknown")
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines += [
        _rule(),
        "  ReconTitan — External Attack Surface Assessment".ljust(WIDTH),
        _rule(),
        "",
        f"  Target            : {target}",
        f"  Scan ID           : {report.get('scan_id', 'unknown')}",
        f"  Profile           : {report.get('scan_type', 'unknown')}"
        + (" (overridden by an explicit module list)" if report.get("module_selection") else ""),
        f"  Version           : {report.get('version', '')}".rstrip(),
        f"  Generated         : {generated}",
        f"  Duration          : {report.get('total_time_seconds', '?')}s",
        f"  Modules run       : {report.get('tools_run', '?')}",
        f"  Findings          : {report.get('total_findings', 0)}",
        "",
    ]

    selection = report.get("module_selection")
    if selection:
        lines += [
            "  Modules selected  : " + ", ".join(selection),
            "  A scan restricted to named modules covers only what those modules",
            "  look at. Read the findings as that scope, not as a full profile.",
            "",
        ]

    counts = report.get("severity_counts") or {}
    if counts:
        lines.append("  Severity breakdown:")
        for severity in SEVERITY_ORDER:
            count = counts.get(severity, 0)
            if count:
                bar = "#" * min(40, count)
                lines.append(f"    {severity.upper():<9} {count:>4}  {bar}")
        lines.append("")

    if report.get("time_limited"):
        skipped = report.get("stages_skipped_for_time") or []
        lines += [
            "  ! This scan hit its time limit. These stages did not run:",
            *(f"      - {stage}" for stage in skipped),
            "    A stage that did not run found nothing because it was never asked.",
            "",
        ]

    triage = report.get("triage_summary") or {}
    suppressed_count = int(triage.get("suppressed", 0) or 0)
    if suppressed_count:
        lines += [
            f"  ! {suppressed_count} finding(s) are suppressed by a recorded triage",
            "    decision and are excluded from the counts above. None have been",
            "    deleted — each appears in the SUPPRESSED FINDINGS section below",
            "    with its state and the reason given.",
            "",
        ]

    # ── Executive summary ──
    ai_summary = report.get("ai_summary") or {}
    summary_text = (
        ai_summary.get("summary")
        or ai_summary.get("text")
        or report.get("summary")
        or ""
    )
    if summary_text:
        lines += _heading("Summary")
        lines += _wrap(summary_text)
        backend = report.get("ai_backend")
        if backend:
            lines += ["", f"  (summary generated by: {backend})"]
        lines.append("")

    # ── Findings ──
    findings = list(report.get("findings") or [])
    active = [f for f in findings if str(f.get("triage_state", "")) not in SUPPRESSING_STATES]
    suppressed = [f for f in findings if str(f.get("triage_state", "")) in SUPPRESSING_STATES]

    lines += _heading(f"Findings ({len(active)})")
    if not active:
        lines += _wrap(
            "No active findings. Check the module coverage section below before "
            "reading that as a clean result — a module that could not run "
            "reports nothing, which looks identical to a module that found nothing."
        )
        lines.append("")
    else:
        for index, finding in enumerate(sorted(active, key=_severity_key), start=1):
            lines += _render_finding(index, finding)

    if suppressed:
        lines += _heading(f"Suppressed findings ({len(suppressed)})", "-")
        lines += _wrap(
            "These were reviewed and marked. They are excluded from the counts "
            "and the attack paths, and are reproduced here in full so the "
            "decision stays auditable."
        )
        lines.append("")
        for index, finding in enumerate(sorted(suppressed, key=_severity_key), start=1):
            lines += _render_finding(index, finding, show_triage=True)

    # ── Attack paths ──
    paths = report.get("attack_paths") or []
    if paths:
        lines += _heading(f"Attack paths ({len(paths)})")
        lines += _wrap(
            "Chains correlated from findings the scan already collected. No "
            "traffic was sent to build these. Every step carries how it is "
            "known: confirmed (observed on this target), supported (several "
            "observations or an authoritative source agree), or possible (a "
            "plausible next step that was never executed)."
        )
        lines.append("")
        for index, path in enumerate(paths, start=1):
            lines += _render_path(index, path)

    # ── Module coverage ──
    tool_results = report.get("tool_results") or {}
    if tool_results:
        lines += _heading("Module coverage")
        lines += _wrap(
            "What each module contributed. A module reporting zero findings is "
            "not the same as a module that could not run."
        )
        lines.append("")
        for name in sorted(tool_results):
            result = tool_results[name]
            if isinstance(result, dict):
                count = result.get("findings", result.get("count", "?"))
                status = result.get("status", "")
            elif isinstance(result, list):
                count, status = len(result), ""
            else:
                count, status = result, ""
            suffix = f"  [{status}]" if status else ""
            lines.append(f"  {name:<24} {count} finding(s){suffix}")
        lines.append("")

    lines += [
        _rule(),
        "  Every finding above is candidate-graded. This report states what was",
        "  observed and what would confirm it. It does not claim any weakness was",
        "  exploited.",
        _rule(),
        "",
    ]
    return "\n".join(lines)


def _render_finding(index: int, finding: dict, *, show_triage: bool = False) -> list[str]:
    severity = str(finding.get("severity", "info")).upper()
    title = finding.get("title", "(untitled finding)")
    lines = [
        f"[{index:>3}] [{severity}] {title}",
        f"      module: {finding.get('tool', 'unknown')}"
        f"   category: {finding.get('category', 'uncategorised')}",
        "",
    ]

    for label, key in (("Description", "description"), ("Remediation", "remediation")):
        value = finding.get(key)
        if value:
            lines.append(f"  {label}:")
            lines += _wrap(value, indent="    ")
            lines.append("")

    evidence = finding.get("evidence")
    if evidence:
        lines.append("  Evidence:")
        lines += _block(evidence)
        lines.append("")

    exploit = finding.get("exploit_priority") or finding.get("kev_status")
    if exploit:
        lines.append(f"  Exploit intelligence: {exploit}")
        for key, label in (("epss_score", "EPSS probability"), ("epss_percentile", "EPSS percentile")):
            if finding.get(key) is not None:
                lines.append(f"    {label}: {finding[key]}")
        lines.append("")

    if finding.get("requires_manual_validation"):
        lines += [
            "  ! Candidate — requires manual validation. Nothing here was exploited.",
            "",
        ]

    state = finding.get("triage_state")
    if show_triage or state:
        if state:
            lines.append(f"  Triage: {state}")
            if finding.get("triage_reason"):
                lines += _wrap(f"Reason: {finding['triage_reason']}", indent="    ")
            if finding.get("triage_updated_at"):
                lines.append(f"    Recorded: {finding['triage_updated_at']}")
            lines.append("")

    lines.append(_rule("-"))
    lines.append("")
    return lines


def _render_path(index: int, path: dict) -> list[str]:
    title = path.get("title") or path.get("name") or f"Path {index}"
    kind = path.get("kind") or path.get("type") or ""
    lines = [f"[{index:>3}] {title}" + (f"   ({kind})" if kind else ""), ""]

    if path.get("summary"):
        lines += _wrap(path["summary"], indent="    ")
        lines.append("")

    for step_index, step in enumerate(path.get("steps") or [], start=1):
        confidence = str(step.get("confidence", step.get("label", "unknown"))).lower()
        label = step.get("title") or step.get("label") or step.get("name", "")
        lines.append(f"    {step_index}. [{confidence:^9}] {label}")
        if step.get("detail"):
            lines += _wrap(step["detail"], indent="        ")
    lines.append("")

    weakest = path.get("weakest_link") or path.get("caveat")
    if weakest:
        lines += _wrap(f"Weakest link: {weakest}", indent="    ")
        lines.append("")

    lines.append(_rule("-"))
    lines.append("")
    return lines
