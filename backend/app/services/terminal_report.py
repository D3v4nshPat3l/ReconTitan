"""Render a scan report for a terminal someone is actually looking at.

``text_report`` renders for a file, a pipe or an API response: fixed width,
no colour, stable enough to diff between two scans. This renders for a human
reading it live, and the difference is not decoration.

A report's job is to be *acted on*, and the obstacle is volume: a full scan
produces dozens of findings and most readers give it one pass. So the shape
here is built around how that pass actually goes:

* **The verdict first.** A masthead and severity chart, so the question "is
  anything on fire" is answered before any scrolling.
* **A contents list.** Every finding as one line, ranked worst first, so the
  reader chooses what to open instead of reading in emission order.
* **Then the detail**, each finding in a consistent four-part shape --
  what was found, the evidence, what to do, and how far the evidence goes.

Severity is carried by a coloured badge *and* the word, never by colour
alone. Colour-blind readers and piped output both need the word, and a report
that only works in one terminal is not a report.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.services.terminal import SEVERITY_ORDER, Theme

#: Triage states that remove a finding from the counts. Suppressed findings
#: are still printed, in their own section -- hiding them is the failure the
#: triage rules exist to prevent.
SUPPRESSING_STATES = {"false_positive", "accepted_risk"}

BANNER = r"""
    ____                      _______ __
   / __ \___  _________  ____/_  __(_) /_____ _____
  / /_/ / _ \/ ___/ __ \/ __ \/ / / / __/ __ `/ __ \
 / _, _/  __/ /__/ /_/ / / / / / / / /_/ /_/ / / / /
/_/ |_|\___/\___/\____/_/ /_/_/ /_/\__/\__,_/_/ /_/
"""


def render_banner(theme: Theme, version: str = "") -> str:
    """The launch banner. Matches the one the setup scripts already print."""
    lines = [theme.s(line, "cyan") for line in BANNER.strip("\n").split("\n")]
    subtitle = "  External attack surface assessment"
    if version:
        subtitle += theme.s(f"   v{version}", "grey")
    return "\n".join(["", *lines, "", subtitle, ""])


def _severity_key(finding: dict) -> tuple[int, str]:
    severity = str(finding.get("severity", "info")).lower()
    rank = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    return rank, str(finding.get("title", ""))


def _shorten(text: str, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def render_terminal_report(report: dict, theme: Theme | None = None) -> str:
    """Render a scan report with colour, structure and a contents list."""
    t = theme or Theme()
    out: list[str] = []

    findings = list(report.get("findings") or [])
    active = [f for f in findings if str(f.get("triage_state", "")) not in SUPPRESSING_STATES]
    suppressed = [f for f in findings if str(f.get("triage_state", "")) in SUPPRESSING_STATES]
    active.sort(key=_severity_key)
    suppressed.sort(key=_severity_key)

    out += _masthead(t, report)
    out += _severity_chart(t, report, active)
    out += _caveats(t, report)
    out += _summary(t, report)
    out += _contents(t, active)
    out += _findings_section(t, active)
    if suppressed:
        out += _suppressed_section(t, suppressed)
    out += _attack_paths(t, report)
    out += _coverage(t, report)
    out += _footer(t)
    return "\n".join(out)


# ── masthead ────────────────────────────────────────────────────────────────

def _masthead(t: Theme, report: dict) -> list[str]:
    target = str(report.get("target", "unknown"))
    profile = str(report.get("scan_type", "unknown"))
    if report.get("module_selection"):
        profile += " (overridden by an explicit module list)"

    rows = [
        ("Target", t.s(target, "bold", "white")),
        ("Profile", profile),
        ("Modules", f"{report.get('tools_run', '?')} run"),
        ("Duration", f"{report.get('total_time_seconds', '?')}s"),
        ("Scan ID", t.s(str(report.get("scan_id", "unknown")), "grey")),
        ("Generated", t.s(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"), "grey")),
    ]
    if report.get("version"):
        rows.append(("Version", t.s(str(report["version"]), "grey")))

    selection = report.get("module_selection")
    if selection:
        rows.append(("Selected", ", ".join(selection)))

    return t.panel("SCAN", rows, style="cyan")


def _severity_chart(t: Theme, report: dict, active: list[dict]) -> list[str]:
    counts = report.get("severity_counts") or {}
    if not counts:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for finding in active:
            key = str(finding.get("severity", "info")).lower()
            counts[key if key in counts else "info"] += 1

    total = sum(counts.get(s, 0) for s in SEVERITY_ORDER) or 1
    worst = next((s for s in SEVERITY_ORDER if counts.get(s, 0)), None)

    out = ["  " + t.s("FINDINGS BY SEVERITY", "bold", "white"), ""]
    for severity in SEVERITY_ORDER:
        count = counts.get(severity, 0)
        colour = t.severity_color(severity)
        label = t.s(f"{severity.upper():<9}", colour if count else "grey")
        number = t.s(f"{count:>4}", "bold", colour) if count else t.s("   0", "grey")
        out.append(f"  {label} {number}  {t.bar(count, total, style=colour)}")
    out.append("")

    if worst in ("critical", "high"):
        out += [
            "  " + t.s(
                f"{t.g('warn')} {counts[worst]} {worst} finding(s) — read the contents list first.",
                "bold", t.severity_color(worst),
            ),
            "",
        ]
    elif worst is None:
        out += t.wrap(
            "No findings at any severity. Check module coverage at the end before "
            "reading that as a clean result: a module that could not run reports "
            "nothing, which looks identical to a module that found nothing.",
            indent="  ",
        ) + [""]
    return out


def _caveats(t: Theme, report: dict) -> list[str]:
    """Everything that changes how the numbers above should be read."""
    out: list[str] = []

    if report.get("time_limited"):
        skipped = report.get("stages_skipped_for_time") or []
        out += [
            "  " + t.s(f"{t.g('warn')} SCAN HIT ITS TIME LIMIT", "bold", "orange"),
            *t.wrap(
                "These stages did not run, and a stage that did not run found "
                "nothing because it was never asked: " + ", ".join(skipped),
                indent="    ",
            ),
            "",
        ]

    triage = report.get("triage_summary") or {}
    count = int(triage.get("suppressed", 0) or 0)
    if count:
        out += [
            "  " + t.s(f"{t.g('warn')} {count} FINDING(S) SUPPRESSED BY TRIAGE", "bold", "yellow"),
            *t.wrap(
                "Excluded from the counts above by a recorded decision. None are "
                "deleted — each appears below with its state and the reason given.",
                indent="    ",
            ),
            "",
        ]
    return out


def _summary(t: Theme, report: dict) -> list[str]:
    ai = report.get("ai_summary") or {}
    text = (
        ai.get("executive_summary") or ai.get("summary") or ai.get("text")
        or report.get("summary") or ""
    )
    if not text:
        return []
    out = t.heading("Summary")
    out += t.wrap(text, indent="  ")
    backend = report.get("ai_backend")
    if backend:
        out += ["", "  " + t.s(f"generated by: {backend}", "dim", "grey")]
    out.append("")
    return out


# ── contents ────────────────────────────────────────────────────────────────

def _contents(t: Theme, active: list[dict]) -> list[str]:
    """One line per finding, worst first.

    The reason this exists: a full scan produces dozens of findings and most
    readers give the report one pass. Without an index that pass is in
    emission order, which is the order the modules happened to finish in.
    """
    if not active:
        return []
    out = t.heading(f"Contents — {len(active)} findings")
    number_w = len(str(len(active)))
    for index, finding in enumerate(active, start=1):
        severity = str(finding.get("severity", "info")).lower()
        colour = t.severity_color(severity)
        marker = t.s(f"{severity.upper():<8}", colour)
        module = t.s(_shorten(finding.get("tool", "?"), 18).ljust(18), "grey")
        budget = t.width - number_w - 34
        title = _shorten(finding.get("title", "(untitled)"), max(20, budget))
        out.append(f"  {t.s(str(index).rjust(number_w), 'dim')}  {marker} {module} {title}")
    out.append("")
    return out


# ── findings ────────────────────────────────────────────────────────────────

def _findings_section(t: Theme, active: list[dict]) -> list[str]:
    if not active:
        return []
    out = t.heading(f"Findings — {len(active)}")
    current = None
    for index, finding in enumerate(active, start=1):
        severity = str(finding.get("severity", "info")).lower()
        if severity != current:
            current = severity
            same = sum(1 for f in active if str(f.get("severity", "info")).lower() == severity)
            out += t.subheading(
                f"{severity.upper()}  {t.g('dot')}  {same} finding(s)",
                "bold", t.severity_color(severity),
            )
        out += _render_finding(t, index, finding)
    return out


def _render_finding(t: Theme, index: int, finding: dict, *, show_triage: bool = False) -> list[str]:
    severity = str(finding.get("severity", "info")).lower()
    colour = t.severity_color(severity)
    bar = t.s(t.g("v"), colour)

    title = finding.get("title", "(untitled finding)")
    out = [
        f"{t.s(t.g('tl') + t.g('h'), colour)} {t.s(f'[{index}]', 'dim')} "
        f"{t.severity_badge(severity)}  {t.s(title, 'bold', 'white')}",
        f"{bar}",
        f"{bar}  {t.s('module', 'grey')}    {finding.get('tool', 'unknown')}"
        f"    {t.s('category', 'grey')}  {finding.get('category', 'uncategorised')}",
        f"{bar}",
    ]

    def block(label: str, text: str, *, verbatim: bool = False, style: str = "white") -> None:
        if not text:
            return
        out.append(f"{bar}  {t.s(label, 'bold', style)}")
        if verbatim:
            # Evidence is aligned output. Wrapping it destroys the alignment
            # that makes it readable in the first place.
            for line in str(text).split("\n"):
                out.append(f"{bar}    {t.s(line.rstrip(), 'grey')}")
        else:
            for line in t.wrap(text, indent="    ", width_override=t.width - 2):
                out.append(f"{bar}{line}")
        out.append(f"{bar}")

    block("WHAT WAS FOUND", finding.get("description", ""))
    block("EVIDENCE", finding.get("evidence", ""), verbatim=True)
    block("REMEDIATION", finding.get("remediation", ""), style="green")

    exploit = finding.get("exploit_priority") or finding.get("kev_status")
    if exploit:
        detail = [f"priority: {exploit}"]
        for key, label in (("epss_score", "EPSS probability"), ("epss_percentile", "EPSS percentile")):
            if finding.get(key) is not None:
                detail.append(f"{label}: {finding[key]}")
        out += [
            f"{bar}  {t.s('EXPLOIT INTELLIGENCE', 'bold', 'magenta')}",
            f"{bar}    {t.s('  ' .join(detail), 'magenta')}",
            f"{bar}",
        ]

    if finding.get("requires_manual_validation"):
        caveat = f"{t.g('warn')} CANDIDATE — nothing here was exploited; confirm by hand."
        out += [f"{bar}  {t.s(caveat, 'italic', 'yellow')}", f"{bar}"]

    state = finding.get("triage_state")
    if state and (show_triage or state not in ("", "open")):
        out.append(f"{bar}  {t.s('TRIAGE', 'bold', 'cyan')}  {t.s(str(state), 'cyan')}")
        if finding.get("triage_reason"):
            for line in t.wrap(str(finding["triage_reason"]), indent="    ", width_override=t.width - 2):
                out.append(f"{bar}{line}")
        if finding.get("triage_updated_at"):
            out.append(f"{bar}    {t.s('recorded ' + str(finding['triage_updated_at']), 'dim', 'grey')}")
        out.append(f"{bar}")

    out.append(t.s(t.g("bl") + t.g("h") * 3, colour))
    out.append("")
    return out


def _suppressed_section(t: Theme, suppressed: list[dict]) -> list[str]:
    out = t.heading(f"Suppressed findings — {len(suppressed)}", style="yellow")
    out += t.wrap(
        "Reviewed and marked. Excluded from the counts and the attack paths, and "
        "reproduced here in full so the decision stays auditable. Nothing is "
        "ever deleted.",
        indent="  ",
    )
    out.append("")
    for index, finding in enumerate(suppressed, start=1):
        out += _render_finding(t, index, finding, show_triage=True)
    return out


# ── attack paths ────────────────────────────────────────────────────────────

CONFIDENCE_STYLE = {"confirmed": "green", "supported": "yellow", "possible": "grey"}


def _attack_paths(t: Theme, report: dict) -> list[str]:
    paths = report.get("attack_paths") or []
    if not paths:
        return []
    out = t.heading(f"Attack paths — {len(paths)}", style="magenta")
    out += t.wrap(
        "Chains correlated from findings the scan already collected. No traffic "
        "was sent to build these. Every step carries how it is known: confirmed "
        "(observed on this target), supported (several observations or an "
        "authoritative source agree), or possible (a plausible next step that "
        "was never executed).",
        indent="  ",
    )
    out.append("")

    for index, path in enumerate(paths, start=1):
        title = path.get("title") or path.get("name") or f"Path {index}"
        kind = path.get("kind") or path.get("type") or ""
        out.append(
            f"  {t.s(f'[{index}]', 'dim')} {t.s(str(title), 'bold', 'white')}"
            + (f"   {t.s(str(kind), 'magenta')}" if kind else "")
        )
        if path.get("summary"):
            out += t.wrap(str(path["summary"]), indent="      ")
        out.append("")

        steps = path.get("steps") or []
        for position, step in enumerate(steps, start=1):
            confidence = str(step.get("confidence", step.get("label", "unknown"))).lower()
            colour = CONFIDENCE_STYLE.get(confidence, "grey")
            label = step.get("title") or step.get("label") or step.get("name", "")
            connector = t.g("corner") if position == len(steps) else t.g("tee")
            out.append(
                f"      {t.s(connector + t.g('h'), 'grey')} "
                f"{t.s(f'{confidence:^9}', colour)} {label}"
            )
            if step.get("detail"):
                out += t.wrap(str(step["detail"]), indent="           ")
        out.append("")

        weakest = path.get("weakest_link") or path.get("caveat")
        if weakest:
            out += t.wrap(f"{t.g('warn')} Weakest link: {weakest}", indent="      ")
            out.append("")
    return out


# ── coverage ────────────────────────────────────────────────────────────────

def _coverage(t: Theme, report: dict) -> list[str]:
    results = report.get("tool_results") or {}
    if not results:
        return []
    out = t.heading("Module coverage")
    out += t.wrap(
        "What each module contributed. A module reporting zero findings is not "
        "the same as a module that could not run, which is why this table "
        "exists at all.",
        indent="  ",
    )
    out.append("")

    name_w = max((len(name) for name in results), default=10)
    ok, failed, empty = [], [], []
    for name in sorted(results):
        result = results[name]
        if isinstance(result, dict):
            count = result.get("findings", result.get("count", 0))
            status = str(result.get("status", ""))
        elif isinstance(result, list):
            count, status = len(result), "ok"
        else:
            count, status = result or 0, ""
        row = (name, count, status)
        if status.startswith("error"):
            failed.append(row)
        elif count:
            ok.append(row)
        else:
            empty.append(row)

    for rows, glyph, colour, note in (
        (ok, "ok", "green", ""),
        (empty, "skip", "grey", "no findings"),
        (failed, "fail", "red", ""),
    ):
        for name, count, status in rows:
            detail = status if status.startswith("error") else (note or f"{count} finding(s)")
            out.append(
                f"  {t.s(t.g(glyph), colour)} {name.ljust(name_w)}   "
                f"{t.s(detail, colour if colour != 'green' else 'white')}"
            )
    out.append("")

    if failed:
        out += t.wrap(
            f"{t.g('warn')} {len(failed)} module(s) failed. A module that errored found "
            "nothing because it never finished, so treat the counts above as a floor.",
            indent="  ",
        )
        out.append("")
    return out


def _footer(t: Theme) -> list[str]:
    return [
        t.rule("double"),
        *t.wrap(
            "Every finding above is candidate-graded: this report states what was "
            "observed and what would confirm it. It does not claim that any "
            "weakness was exploited.",
            indent="  ",
        ),
        t.rule("double"),
        "",
    ]
