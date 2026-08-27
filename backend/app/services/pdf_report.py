"""Generate a detailed, portable ReconTitan PDF security report.

The renderer intentionally uses only ReportLab's built-in fonts so reports are
portable, fast to generate, and do not depend on external assets or font files.
"""

from __future__ import annotations

import json
import re
import unicodedata
from datetime import date, datetime, timezone
from html import escape
from io import BytesIO
from typing import Any, Iterable

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    CondPageBreak,
    LongTable,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_ORDER = {name: index for index, name in enumerate(SEVERITIES)}
PROFILE_LABELS = {
    "full": "Full Safe Scan",
    "recon_only": "Recon Only",
    "osint_only": "OSINT and Web Analysis",
    "vuln_only": "Vulnerability Focus",
    "danger": "Danger Mode - Full Intermediate Penetration Test Simulation",
}

DANGER_BANNER = (
    "DANGER MODE RESULTS REQUIRE MANUAL VALIDATION. Every observation in this section is a detection "
    "candidate produced by bounded, non-destructive simulation traffic. Nothing was exploited, no data was "
    "modified or deleted, no credentials were used against live accounts, and no shell was connected. Treat "
    "each item as a lead to reproduce under your rules of engagement, not as a confirmed vulnerability."
)

SEVERITY_COLORS = {
    "critical": colors.HexColor("#991B1B"),
    "high": colors.HexColor("#C2410C"),
    "medium": colors.HexColor("#A16207"),
    "low": colors.HexColor("#0E7490"),
    "info": colors.HexColor("#475569"),
}
SEVERITY_TINTS = {
    "critical": colors.HexColor("#FEF2F2"),
    "high": colors.HexColor("#FFF7ED"),
    "medium": colors.HexColor("#FEFCE8"),
    "low": colors.HexColor("#ECFEFF"),
    "info": colors.HexColor("#F8FAFC"),
}
SEVERITY_GUIDANCE = {
    "critical": "Immediate action. A confirmed issue may permit severe compromise or broad unauthorized access.",
    "high": "Prioritize remediation. A confirmed issue may materially affect confidentiality, integrity, or availability.",
    "medium": "Schedule remediation after higher-risk items and validate exploitability in the target environment.",
    "low": "Address through normal hardening work and verify that the condition is not part of a larger attack chain.",
    "info": "Context or inventory data. Review for accuracy and use it to support manual assessment decisions.",
}

BRAND = colors.HexColor("#65A30D")
BRAND_DARK = colors.HexColor("#3F6212")
INK = colors.HexColor("#0F172A")
MUTED = colors.HexColor("#475569")
SOFT = colors.HexColor("#64748B")
PANEL = colors.HexColor("#F8FAFC")
PANEL_ALT = colors.HexColor("#F1F5F9")
BORDER = colors.HexColor("#CBD5E1")
LINK = colors.HexColor("#1D4ED8")
WHITE = colors.white

_URL_RE = re.compile(r"https?://[^\s<>{}\[\]\"']+", re.IGNORECASE)
_KV_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 _./()\-]{1,55}):\s*(.*)$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _ascii_safe(value: Any, limit: int = 50_000) -> str:
    """Return bounded, printable text compatible with ReportLab core fonts."""
    text = str(value if value is not None else "")[:limit]
    text = _CONTROL_RE.sub("", text)
    text = (
        text.replace("\u2013", "-")
        .replace("\u2014", "-")
        .replace("\u2018", "'")
        .replace("\u2019", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u2022", "-")
        .replace("\u2192", "->")
        .replace("\u26a0\ufe0f", "Warning:")
        .replace("\u26a0", "Warning:")
    )
    # Built-in Helvetica/Courier do not cover all Unicode. Transliteration
    # avoids black boxes and broken glyphs in exported reports.
    return unicodedata.normalize("NFKD", text).encode("ascii", "replace").decode("ascii")


def _text(value: Any, limit: int = 20_000) -> str:
    return escape(_ascii_safe(value, limit)).replace("\n", "<br/>")


def _rich_text(value: Any, limit: int = 20_000) -> str:
    """Escape untrusted text and make only HTTP(S) references clickable."""
    raw = _ascii_safe(value, limit)
    result: list[str] = []
    cursor = 0
    for match in _URL_RE.finditer(raw):
        url = match.group(0)
        trailing = ""
        while url and url[-1] in ".,;:)]}":
            trailing = url[-1] + trailing
            url = url[:-1]
        result.append(escape(raw[cursor:match.start()]))
        safe_url = escape(url, quote=True)
        result.append(f'<link href="{safe_url}" color="#1D4ED8"><u>{escape(url)}</u></link>')
        result.append(escape(trailing))
        cursor = match.end()
    result.append(escape(raw[cursor:]))
    return "".join(result).replace("\n", "<br/>")


def _format_scalar(value: Any) -> str:
    if isinstance(value, datetime):
        if value.year <= 1:
            return "Unknown"
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if isinstance(value, date):
        if value.year <= 1:
            return "Unknown"
        return value.isoformat()
    return _ascii_safe(value)


def _json_default(value: Any) -> str:
    return _format_scalar(value)


def _normalise_datetime_repr(text: str) -> str:
    """Clean common python-whois datetime reprs in older stored findings."""
    patterns = [
        re.compile(
            r"datetime\.datetime\((\d{1,4}),\s*(\d{1,2}),\s*(\d{1,2}),\s*"
            r"(\d{1,2}),\s*(\d{1,2}),\s*(\d{1,2})(?:,\s*\d+)?\s*,\s*"
            r"tzinfo=tzoffset\(['\"]UTC['\"],\s*0\)\)"
        ),
        re.compile(
            r"datetime\.datetime\((\d{1,4}),\s*(\d{1,2}),\s*(\d{1,2}),\s*"
            r"(\d{1,2}),\s*(\d{1,2}),\s*(\d{1,2})(?:,\s*\d+)?\s*,\s*"
            r"tzinfo=tzutc\(\)\)"
        ),
        re.compile(
            r"datetime\.datetime\((\d{1,4}),\s*(\d{1,2}),\s*(\d{1,2}),\s*"
            r"(\d{1,2}),\s*(\d{1,2}),\s*(\d{1,2})(?:,\s*\d+)?\)"
        ),
    ]

    def replace(match: re.Match[str]) -> str:
        parts = [int(item) for item in match.groups()]
        if parts[0] <= 1:
            return "Unknown"
        try:
            return datetime(*parts, tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except ValueError:
            return "Unknown"

    for pattern in patterns:
        text = pattern.sub(replace, text)
    return text


def _evidence_text(value: Any, limit: int = 30_000) -> tuple[str, bool]:
    if isinstance(value, (dict, list, tuple, set)):
        if isinstance(value, set):
            value = sorted(value, key=str)
        raw = json.dumps(value, indent=2, ensure_ascii=True, default=_json_default)
    else:
        raw = _ascii_safe(value, limit + 1)
    raw = _normalise_datetime_repr(raw)
    truncated = len(raw) > limit
    if truncated:
        raw = raw[:limit].rstrip() + "\n[Evidence truncated at report limit]"
    return raw or "No evidence was supplied.", truncated


def _format_timestamp(value: Any) -> str:
    if value in (None, ""):
        return "Not recorded"
    if isinstance(value, datetime):
        parsed = value
    else:
        raw = _ascii_safe(value, 100).strip()
        if not raw:
            return "Not recorded"
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return raw
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _human_duration(value: Any) -> str:
    if value is None:
        return "Not recorded"
    try:
        seconds = max(0.0, float(value))
    except (TypeError, ValueError):
        return _ascii_safe(value, 100) or "Not recorded"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    minutes, remaining = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes}m {remaining:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes:02d}m {remaining:02d}s"


def _severity_counts(findings: list[dict[str, Any]], supplied: Any) -> dict[str, int]:
    calculated = {level: 0 for level in SEVERITIES}
    for finding in findings:
        level = str(finding.get("severity", "info")).lower()
        calculated[level if level in calculated else "info"] += 1
    if sum(calculated.values()):
        return calculated
    if isinstance(supplied, dict):
        for level in SEVERITIES:
            try:
                calculated[level] = max(0, int(supplied.get(level, 0) or 0))
            except (TypeError, ValueError):
                calculated[level] = 0
    return calculated


def _risk_level(counts: dict[str, int], ai: Any) -> str:
    if isinstance(ai, dict) and ai.get("risk_level"):
        supplied = _ascii_safe(ai["risk_level"], 30).upper()
        if supplied:
            return supplied
    for level in SEVERITIES:
        if counts.get(level, 0):
            return level.upper()
    return "INFORMATIONAL"


def _page_chrome(canvas, doc) -> None:
    canvas.saveState()
    width, height = A4
    target = _ascii_safe(getattr(doc, "report_target", "target"), 90)
    generated = _ascii_safe(getattr(doc, "report_generated", ""), 60)

    canvas.setStrokeColor(BRAND)
    canvas.setLineWidth(1.1)
    canvas.line(18 * mm, height - 13 * mm, width - 18 * mm, height - 13 * mm)
    canvas.setFont("Helvetica-Bold", 7.7)
    canvas.setFillColor(INK)
    canvas.drawString(18 * mm, height - 10.2 * mm, "RECONTITAN SECURITY ASSESSMENT")
    canvas.setFont("Helvetica", 7.2)
    canvas.setFillColor(MUTED)
    canvas.drawRightString(width - 18 * mm, height - 10.2 * mm, target[:72])

    canvas.setStrokeColor(BORDER)
    canvas.setLineWidth(0.5)
    canvas.line(18 * mm, 13 * mm, width - 18 * mm, 13 * mm)
    canvas.setFont("Helvetica-Bold", 7.2)
    canvas.setFillColor(INK)
    canvas.drawString(18 * mm, 9 * mm, "RECONTITAN")
    canvas.setFont("Helvetica", 7)
    canvas.setFillColor(MUTED)
    canvas.drawCentredString(width / 2, 9 * mm, generated)
    canvas.drawRightString(width - 18 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def _severity_summary(counts: dict[str, int], styles) -> Table:
    cards: list[Any] = []
    for level in SEVERITIES:
        cards.append(Table(
            [
                [Paragraph(level.upper(), styles["MetricLabel"])],
                [Paragraph(str(counts.get(level, 0)), styles["MetricValue"])],
            ],
            colWidths=[31.5 * mm],
            rowHeights=[8 * mm, 13 * mm],
            style=TableStyle([
                ("BACKGROUND", (0, 0), (0, 0), SEVERITY_COLORS[level]),
                ("BACKGROUND", (0, 1), (0, 1), SEVERITY_TINTS[level]),
                ("BOX", (0, 0), (-1, -1), 0.6, SEVERITY_COLORS[level]),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("LEFTPADDING", (0, 0), (-1, -1), 2),
                ("RIGHTPADDING", (0, 0), (-1, -1), 2),
                ("TOPPADDING", (0, 0), (-1, -1), 1),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
            ]),
        ))
    table = Table([cards], colWidths=[33.2 * mm] * 5)
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return table


def _tool_coverage_table(tool_results: dict[str, Any], styles) -> LongTable | None:
    if not isinstance(tool_results, dict) or not tool_results:
        return None
    rows: list[list[Any]] = [["Module", "Status", "Findings", "Duration"]]
    for tool, raw_result in list(tool_results.items())[:100]:
        result = raw_result if isinstance(raw_result, dict) else {}
        duration = result.get("time_seconds")
        rows.append([
            Paragraph(_text(tool, 100), styles["TableCell"]),
            Paragraph(_text(result.get("status", "unknown"), 40), styles["TableCell"]),
            str(result.get("findings", "-")),
            _human_duration(duration) if duration is not None else "-",
        ])
    table = LongTable(rows, colWidths=[73 * mm, 34 * mm, 25 * mm, 34 * mm], repeatRows=1)
    table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6D2")),
        ("TEXTCOLOR", (0, 0), (-1, 0), INK),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (2, 1), (-1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PANEL]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    return table


def _finding_index(findings: list[dict[str, Any]], styles) -> LongTable:
    rows: list[list[Any]] = [["#", "Severity", "Finding", "Tool", "Reference"]]
    row_severities: list[str] = []
    for index, finding in enumerate(findings, 1):
        severity = str(finding.get("severity", "info")).lower()
        if severity not in SEVERITY_ORDER:
            severity = "info"
        row_severities.append(severity)
        reference_parts = []
        if finding.get("cve_id"):
            reference_parts.append(_ascii_safe(finding["cve_id"], 50))
        if finding.get("cvss_score") is not None:
            reference_parts.append(f"CVSS {_ascii_safe(finding['cvss_score'], 20)}")
        rows.append([
            str(index),
            Paragraph(severity.upper(), styles[f"Badge{severity.title()}"]),
            Paragraph(_text(finding.get("title") or "Untitled finding", 350), styles["TableCell"]),
            Paragraph(_text(finding.get("tool") or "unknown", 80), styles["TableCell"]),
            Paragraph(_text(" | ".join(reference_parts) or "-", 120), styles["TableCell"]),
        ])
    table = LongTable(rows, colWidths=[9 * mm, 25 * mm, 78 * mm, 27 * mm, 27 * mm], repeatRows=1)
    style_commands = [
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6D2")),
        ("TEXTCOLOR", (0, 0), (-1, 0), INK),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 1), (1, -1), "CENTER"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PANEL]),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for row_number, severity in enumerate(row_severities, 1):
        style_commands.append(("BACKGROUND", (1, row_number), (1, row_number), SEVERITY_COLORS[severity]))
    table.setStyle(TableStyle(style_commands))
    return table


def _paragraph_list(items: Iterable[Any], styles, limit: int = 10) -> list[Any]:
    output: list[Any] = []
    for item in list(items)[:limit]:
        output.append(Paragraph(f"- {_rich_text(item, 2000)}", styles["BodyText"] ))
        output.append(Spacer(1, 0.8 * mm))
    return output


def _evidence_flowables(value: Any, styles) -> list[Any]:
    raw, truncated = _evidence_text(value)
    lines = [line.rstrip() for line in raw.splitlines()]
    meaningful = [line for line in lines if line.strip()]
    parsed: list[tuple[str, str]] = []
    for line in meaningful:
        match = _KV_RE.match(line.strip())
        if not match or len(line) > 1_500:
            parsed = []
            break
        parsed.append((match.group(1), match.group(2)))

    if len(parsed) >= 2:
        rows: list[list[Any]] = []
        for key, val in parsed:
            rows.append([
                Paragraph(_text(key, 80), styles["EvidenceKey"]),
                Paragraph(_rich_text(val, 4_000), styles["EvidenceValue"]),
            ])
        table = Table(rows, colWidths=[39 * mm, 127 * mm], hAlign="LEFT")
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), PANEL_ALT),
            ("BACKGROUND", (1, 0), (1, -1), PANEL),
            ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        output: list[Any] = [table]
    else:
        output = [Preformatted(
            raw,
            styles["EvidenceCode"],
            maxLineLength=112,
            splitChars=" /?&=._:-,;|",
        )]
    if truncated:
        output.extend([
            Spacer(1, 1 * mm),
            Paragraph(
                "The evidence exceeded the per-finding PDF safety limit. Use the JSON export for the complete raw value.",
                styles["TinyMuted"],
            ),
        ])
    return output


def _remediation_flowables(value: Any, styles) -> list[Any]:
    """Render remediation, preserving code blocks in a monospace face.

    The code-level fixes are indentation-significant, so the renderer splits
    prose from code rather than collapsing everything into one paragraph.
    """
    raw = _ascii_safe(
        value
        or "No module-specific remediation was supplied. Validate the observation, identify the owning "
           "team, apply the least disruptive corrective control, and retest the affected asset.",
        24_000,
    )
    if "\n" not in raw:
        return [Paragraph(_rich_text(raw, 24_000), styles["BodyText"])]

    output: list[Any] = []
    buffer: list[str] = []
    buffer_is_code = False

    def flush() -> None:
        if not buffer:
            return
        block = "\n".join(buffer).strip("\n")
        if not block.strip():
            buffer.clear()
            return
        if buffer_is_code:
            output.append(Preformatted(block, styles["RemediationCode"], maxLineLength=104,
                                       splitChars=" /?&=._:-,;|()"))
        else:
            output.append(Paragraph(_rich_text(block, 8_000), styles["BodyText"]))
        output.append(Spacer(1, 1.6 * mm))
        buffer.clear()

    for line in raw.splitlines():
        # Indented lines and anything containing code punctuation render as code.
        is_code = bool(line[:1].isspace() and line.strip()) or bool(
            re.match(r"^\s*(?:#|//|<|\$|>>>|[A-Za-z_.]+\s*[:=]\s*[\"'{\[])", line)
        )
        if is_code != buffer_is_code:
            flush()
            buffer_is_code = is_code
        buffer.append(line)
    flush()
    return output or [Paragraph(_rich_text(raw, 24_000), styles["BodyText"])]


def _finding_references(finding: dict[str, Any]) -> list[str]:
    references: list[str] = []
    cve = _ascii_safe(finding.get("cve_id"), 50).upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
        references.append(f"https://nvd.nist.gov/vuln/detail/{cve}")
    for field in ("description", "evidence", "remediation", "reference", "references"):
        value = finding.get(field)
        if isinstance(value, (list, tuple, set)):
            value = "\n".join(str(item) for item in value)
        for match in _URL_RE.findall(_ascii_safe(value, 25_000)):
            url = match.rstrip(".,;:)]}")
            if url and url not in references:
                references.append(url)
            if len(references) >= 10:
                return references
    return references


def _validation_guidance(finding: dict[str, Any]) -> str:
    combined = " ".join(
        _ascii_safe(finding.get(field), 300).lower()
        for field in ("tool", "category", "title")
    )
    if "reverse_shell" in combined:
        return (
            "This entry documents a possible execution vector; ReconTitan never connected a shell or generated a "
            "connecting payload. Confirm the underlying command injection first, then validate impact only with "
            "the asset owner's written approval and within the agreed rules of engagement."
        )
    if "danger_" in combined or bool(finding.get("requires_manual_validation")):
        return (
            "Reproduce the exact request recorded in the evidence from an authorized test system, confirm the "
            "response signal is caused by the payload rather than by caching, load balancing, or dynamic content, "
            "and capture request and response evidence before treating this candidate as a real vulnerability."
        )
    if "takeover" in combined:
        return (
            "Resolve the complete CNAME chain, confirm the provider fingerprint from a clean network path, and verify "
            "provider-side ownership state. Do not register or claim third-party resources without explicit authorization."
        )
    if "javascript" in combined or "js_" in combined or "source map" in combined:
        return (
            "Inspect the referenced script and source map manually, determine whether the value is a real credential or "
            "test placeholder, and rotate any confirmed secret before retesting."
        )
    if "cve" in combined or "nvd" in combined or "technology" in combined or "tech_stack" in combined:
        return (
            "Confirm the exact product and version from an authoritative source before mapping this observation to a CVE. "
            "Version banners and passive fingerprints can be incomplete or intentionally misleading."
        )
    if "whois" in combined:
        return (
            "Confirm dates and registrar state in the authoritative registry or registrar portal. WHOIS privacy services "
            "and registry synchronization delays can obscure ownership details."
        )
    return (
        "Reproduce the observation manually from an authorized test system, preserve request and response evidence, and "
        "confirm practical impact before changing the finding status to verified."
    )


def _finding_block(index: int, finding: dict[str, Any], target: str, styles) -> list[Any]:
    severity = str(finding.get("severity", "info")).lower()
    if severity not in SEVERITY_ORDER:
        severity = "info"
    title = finding.get("title") or "Untitled finding"
    finding_id = finding.get("id") or f"finding-{index}"
    verified = bool(finding.get("verified"))
    manual = bool(finding.get("requires_manual_validation"))
    exploited = bool(finding.get("exploited"))
    if exploited:
        status = "EXPLOITED - confirmed by the scanner"
    elif verified:
        status = "Verified"
    elif manual:
        status = "Simulation candidate - manual validation required"
    else:
        status = "Automated candidate"
    affected_asset = finding.get("affected_asset") or finding.get("asset") or target

    severity_paragraph = Paragraph(severity.upper(), styles[f"Badge{severity.title()}"])
    title_paragraph = Paragraph(f"{index}. {_text(title, 700)}", styles["FindingTitle"])
    heading = Table([[severity_paragraph, title_paragraph]], colWidths=[27 * mm, 139 * mm])
    heading.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), SEVERITY_COLORS[severity]),
        ("BACKGROUND", (1, 0), (1, 0), SEVERITY_TINTS[severity]),
        ("BOX", (0, 0), (-1, -1), 0.65, SEVERITY_COLORS[severity]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (0, 0), "CENTER"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))

    metadata_rows = [
        ["Finding ID", _ascii_safe(finding_id, 100), "Status", status],
        ["Tool", _ascii_safe(finding.get("tool") or "unknown", 100), "Category", _ascii_safe(finding.get("category") or "general", 100)],
        ["Affected asset", _ascii_safe(affected_asset, 300), "Confidence", _ascii_safe(finding.get("confidence") or "Requires validation", 100)],
    ]
    if finding.get("cve_id") or finding.get("cvss_score") is not None:
        metadata_rows.append([
            "CVE", _ascii_safe(finding.get("cve_id") or "Not supplied", 80),
            "CVSS", _ascii_safe(finding.get("cvss_score") if finding.get("cvss_score") is not None else "Not supplied", 40),
        ])
    if finding.get("owasp_category") or finding.get("attack_vector"):
        metadata_rows.append([
            "OWASP", _ascii_safe(finding.get("owasp_category") or "Not mapped", 120),
            "Attack vector", _ascii_safe(finding.get("attack_vector") or "Not supplied", 200),
        ])
    metadata_data: list[list[Any]] = []
    for left_key, left_value, right_key, right_value in metadata_rows:
        metadata_data.append([
            Paragraph(_text(left_key, 60), styles["MetaLabel"]),
            Paragraph(_rich_text(left_value, 600), styles["MetaValue"]),
            Paragraph(_text(right_key, 60), styles["MetaLabel"]),
            Paragraph(_rich_text(right_value, 600), styles["MetaValue"]),
        ])
    metadata = Table(metadata_data, colWidths=[25 * mm, 58 * mm, 25 * mm, 58 * mm])
    metadata.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), PANEL_ALT),
        ("BACKGROUND", (2, 0), (2, -1), PANEL_ALT),
        ("GRID", (0, 0), (-1, -1), 0.35, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))

    output: list[Any] = [
        CondPageBreak(54 * mm),
        heading,
        Spacer(1, 2.5 * mm),
        metadata,
        Spacer(1, 3 * mm),
        Paragraph("Observation", styles["FindingSubhead"]),
        Paragraph(_rich_text(finding.get("description") or "No description was supplied."), styles["BodyText"]),
        Spacer(1, 2.5 * mm),
        Paragraph("Risk context", styles["FindingSubhead"]),
        Paragraph(SEVERITY_GUIDANCE[severity], styles["BodyText"]),
    ]

    if exploited:
        output.extend([
            Spacer(1, 2.5 * mm),
            Paragraph("Exploitation - what was proven", styles["FindingSubhead"]),
            Paragraph(
                "<b>Technique:</b> " + _text(finding.get("exploit_technique") or "not recorded", 400)
                + "<br/><b>Proof captured:</b> " + _text(finding.get("exploit_proof") or "not recorded", 1_000)
                + "<br/><b>Impact:</b> " + _text(finding.get("exploit_impact") or "not recorded", 2_000),
                styles["ExploitCallout"],
            ),
        ])

    ai_explanation = finding.get("ai_explanation") or finding.get("explanation")
    if ai_explanation:
        output.extend([
            Spacer(1, 2.5 * mm),
            Paragraph("Analyst context", styles["FindingSubhead"]),
            Paragraph(_rich_text(ai_explanation, 8_000), styles["CalloutNeutral"]),
        ])

    output.extend([
        Spacer(1, 2.5 * mm),
        Paragraph("Evidence", styles["FindingSubhead"]),
        *_evidence_flowables(finding.get("evidence"), styles),
        Spacer(1, 2.5 * mm),
        Paragraph("Recommended remediation", styles["FindingSubhead"]),
        *_remediation_flowables(finding.get("remediation"), styles),
        Spacer(1, 2.5 * mm),
        Paragraph("Manual validation steps", styles["FindingSubhead"]),
        Paragraph(_validation_guidance(finding), styles["BodyText"]),
    ])

    references = _finding_references(finding)
    if references:
        output.extend([Spacer(1, 2.5 * mm), Paragraph("References", styles["FindingSubhead"])])
        for reference in references:
            safe = escape(reference, quote=True)
            output.append(Paragraph(f'- <link href="{safe}" color="#1D4ED8"><u>{escape(reference)}</u></link>', styles["Reference"] ))

    output.extend([Spacer(1, 4 * mm), Table([[""]], colWidths=[166 * mm], rowHeights=[0.3 * mm], style=[("BACKGROUND", (0, 0), (-1, -1), BORDER)]) , Spacer(1, 3 * mm)])
    return output


def _simple_table(rows: list[list[Any]], widths: list[float], styles, *, header: bool = True) -> LongTable:
    table = LongTable(rows, colWidths=widths, repeatRows=1 if header else 0)
    commands = [
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, PANEL]),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    if header:
        commands.extend([
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6D2")),
            ("TEXTCOLOR", (0, 0), (-1, 0), INK),
        ])
    table.setStyle(TableStyle(commands))
    return table


def _danger_section(danger: dict[str, Any], findings: list[dict[str, Any]], styles) -> list[Any]:
    """Render the Danger Mode section: banner, coverage, inventory, and matrices."""
    story: list[Any] = [
        PageBreak(),
        Paragraph("Danger Mode - penetration test simulation", styles["Section"]),
    ]

    banner = Table(
        [[Paragraph(DANGER_BANNER, styles["DangerBannerText"])]],
        colWidths=[166 * mm],
    )
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_TINTS["critical"]),
        ("BOX", (0, 0), (-1, -1), 1.1, SEVERITY_COLORS["critical"]),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.extend([banner, Spacer(1, 5 * mm)])

    stages_done = [str(item) for item in danger.get("stages_completed") or []]
    stages_failed = [str(item) for item in danger.get("stages_failed") or []]
    stages_skipped = [str(item) for item in danger.get("stages_skipped") or []]
    techniques = danger.get("exploit_techniques") or {}
    confirmed = int(danger.get("exploits_confirmed") or 0)
    story.extend([
        Paragraph("Execution summary", styles["FindingSubhead"]),
        _simple_table(
            [
                ["Metric", "Value"],
                ["Target", Paragraph(_text(danger.get("target", "unknown"), 253), styles["TableCell"])],
                ["Stages completed", Paragraph(_text(", ".join(stages_done) or "none", 2_000), styles["TableCell"])],
                ["Stages failed", Paragraph(_text(", ".join(stages_failed) or "none", 2_000), styles["TableCell"])],
                ["Stages skipped", Paragraph(_text(", ".join(stages_skipped) or "none", 2_000), styles["TableCell"])],
                ["Requests sent", str(danger.get("requests_sent", 0))],
                ["Payloads sent", str(danger.get("payloads_sent", 0))],
                ["Elapsed (danger phase)", f"{danger.get('elapsed_seconds', 0)} s"],
                ["Time limit reached", "Yes" if danger.get("timed_out") else "No"],
                ["Request budget exhausted", "Yes" if danger.get("budget_exhausted") else "No"],
            ],
            [45 * mm, 121 * mm],
            styles,
        ),
        Spacer(1, 4 * mm),
    ])

    exploited = [item for item in findings if item.get("exploited")]
    if exploited or confirmed:
        rows: list[list[Any]] = [["Vulnerability", "Technique", "Proof captured"]]
        for item in exploited[:40]:
            rows.append([
                Paragraph(_text(item.get("title", ""), 200), styles["TableCell"]),
                Paragraph(_text(item.get("exploit_technique") or "-", 160), styles["TableCell"]),
                Paragraph(_text(item.get("exploit_proof") or "-", 400), styles["TableCell"]),
            ])
        story.extend([
            Paragraph(f"Confirmed exploitation - {len(exploited) or confirmed} finding(s)", styles["FindingSubhead"]),
            Paragraph(
                "These were not merely detected. The scanner reproduced the condition and captured the proof "
                "shown below. Proof is deliberately limited to a version banner, an arithmetic result, an "
                "identified platform, or a reflection context - no records, credentials, or personal data were "
                "extracted.",
                styles["SectionLead"],
            ),
            _simple_table(rows, [58 * mm, 44 * mm, 64 * mm], styles) if exploited else Paragraph(
                f"{confirmed} exploit(s) confirmed.", styles["BodyText"]),
            Spacer(1, 3 * mm),
        ])
        if techniques:
            story.extend([
                Paragraph(
                    "Techniques proven: "
                    + ", ".join(f"{name} x{count}" for name, count in sorted(techniques.items())),
                    styles["BodyText"],
                ),
                Spacer(1, 4 * mm),
            ])

    coverage = [item for item in (danger.get("owasp_coverage") or []) if isinstance(item, dict)]
    if coverage:
        rows: list[list[Any]] = [["OWASP Top 10 (2021) category", "Coverage", "Findings"]]
        for entry in coverage:
            rows.append([
                Paragraph(_text(entry.get("category", "unknown"), 120), styles["TableCell"]),
                Paragraph(
                    "TESTED" if entry.get("tested") else "NOT TESTED",
                    styles["CoverageTested"] if entry.get("tested") else styles["CoverageUntested"],
                ),
                str(entry.get("findings", 0)),
            ])
        story.extend([
            Paragraph("OWASP Top 10 coverage matrix", styles["FindingSubhead"]),
            Paragraph(
                "TESTED means at least one bounded module ran against the category. It does not mean the "
                "application is free of that weakness class, and NOT TESTED must be read as unassessed.",
                styles["SectionLead"],
            ),
            _simple_table(rows, [116 * mm, 30 * mm, 20 * mm], styles),
            Spacer(1, 4 * mm),
        ])

    surface = [item for item in (danger.get("attack_surface") or []) if isinstance(item, dict)]
    if surface:
        counts: dict[str, int] = {}
        for item in surface:
            key = str(item.get("input_type", "unknown"))
            counts[key] = counts.get(key, 0) + 1
        summary_rows: list[list[Any]] = [["Input point type", "Count"]]
        for key, value in sorted(counts.items()):
            summary_rows.append([Paragraph(_text(key, 80), styles["TableCell"]), str(value)])
        summary_rows.append([Paragraph("<b>Total</b>", styles["TableCell"]), str(len(surface))])

        detail_rows: list[list[Any]] = [["Method", "Endpoint", "Type", "Parameters"]]
        for item in surface[:60]:
            parameters = ", ".join(str(value) for value in (item.get("parameters") or [])[:10]) or "-"
            detail_rows.append([
                Paragraph(_text(item.get("method", "GET"), 10), styles["TableCell"]),
                Paragraph(_text(item.get("url", ""), 300), styles["TableCell"]),
                Paragraph(_text(item.get("input_type", ""), 40), styles["TableCell"]),
                Paragraph(_text(parameters, 300), styles["TableCell"]),
            ])
        story.extend([
            CondPageBreak(50 * mm),
            Paragraph("Attack surface inventory", styles["FindingSubhead"]),
            _simple_table(summary_rows, [126 * mm, 40 * mm], styles),
            Spacer(1, 2.5 * mm),
            _simple_table(detail_rows, [16 * mm, 82 * mm, 28 * mm, 40 * mm], styles),
            Spacer(1, 4 * mm),
        ])

    matrix = [item for item in (danger.get("injection_matrix") or []) if isinstance(item, dict)]
    if matrix:
        grouped: dict[tuple[str, str], dict[str, int]] = {}
        for entry in matrix:
            key = (str(entry.get("endpoint", "")), str(entry.get("injection_type", "")))
            bucket = grouped.setdefault(key, {"probes": 0, "signals": 0})
            bucket["probes"] += 1
            if str(entry.get("signal", "none")) != "none":
                bucket["signals"] += 1
        rows = [["Endpoint", "Injection type", "Probes", "Result"]]
        for (endpoint, injection_type), counts in list(grouped.items())[:80]:
            result = f"{counts['signals']} signal(s)" if counts["signals"] else "no signal"
            rows.append([
                Paragraph(_text(endpoint, 300), styles["TableCell"]),
                Paragraph(_text(injection_type, 40), styles["TableCell"]),
                str(counts["probes"]),
                Paragraph(_text(result, 40), styles["TableCell"]),
            ])
        story.extend([
            CondPageBreak(50 * mm),
            Paragraph("Injection test matrix", styles["FindingSubhead"]),
            Paragraph(
                "Endpoint by injection type. Probes with no signal are listed so coverage gaps are visible; "
                "absence of a signal is not evidence the endpoint is safe.",
                styles["SectionLead"],
            ),
            _simple_table(rows, [84 * mm, 30 * mm, 18 * mm, 34 * mm], styles),
            Spacer(1, 4 * mm),
        ])

    highlights = [
        ("Zone transfer (AXFR)", "danger_zone_transfer"),
        ("IDOR candidates", "danger_idor"),
        ("Reverse shell possibility", "danger_reverse_shell"),
        ("Path traversal candidates", "danger_path_traversal"),
    ]
    rows = [["Danger check", "Findings", "Highest severity"]]
    for label, category in highlights:
        matched = [item for item in findings if str(item.get("category", "")) == category]
        if matched:
            highest = min(matched, key=lambda item: SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 99))
            severity = str(highest.get("severity", "info")).lower()
        else:
            severity = "-"
        rows.append([
            Paragraph(_text(label, 80), styles["TableCell"]),
            str(len(matched)),
            Paragraph(_text(severity.upper(), 20), styles["TableCell"]),
        ])
    story.extend([
        CondPageBreak(40 * mm),
        Paragraph("Danger check results", styles["FindingSubhead"]),
        _simple_table(rows, [96 * mm, 30 * mm, 40 * mm], styles),
        Spacer(1, 3 * mm),
        Paragraph(
            "Authorization reminder: Danger Mode may only be run against systems you own or hold written "
            "permission to assess. Retain that authorization alongside this report.",
            styles["CalloutNeutral"],
        ),
    ])
    return story


def _build_styles():
    styles = getSampleStyleSheet()
    styles["BodyText"].fontName = "Helvetica"
    styles["BodyText"].fontSize = 9.2
    styles["BodyText"].leading = 13
    styles["BodyText"].textColor = INK
    styles["BodyText"].spaceAfter = 0
    styles["BodyText"].splitLongWords = True

    styles.add(ParagraphStyle(
        name="BrandTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=28,
        leading=31, alignment=TA_CENTER, textColor=INK, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="Subtitle", parent=styles["BodyText"], fontName="Helvetica", fontSize=11,
        leading=15, alignment=TA_CENTER, textColor=MUTED, spaceAfter=9,
    ))
    styles.add(ParagraphStyle(
        name="Section", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=14,
        leading=18, textColor=INK, spaceBefore=10, spaceAfter=7, keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        name="SectionLead", parent=styles["BodyText"], fontSize=9, leading=13, textColor=MUTED,
        spaceAfter=5,
    ))
    styles.add(ParagraphStyle(
        name="FindingTitle", parent=styles["Heading3"], fontName="Helvetica-Bold", fontSize=11,
        leading=14, textColor=INK, spaceAfter=0, splitLongWords=True,
    ))
    styles.add(ParagraphStyle(
        name="FindingSubhead", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=8.5,
        leading=11, textColor=BRAND_DARK, spaceAfter=2, keepWithNext=True,
    ))
    styles.add(ParagraphStyle(name="TinyMuted", parent=styles["BodyText"], fontSize=7, leading=9, textColor=SOFT))
    styles.add(ParagraphStyle(name="TableCell", parent=styles["BodyText"], fontSize=7.8, leading=10, textColor=INK, splitLongWords=True))
    styles.add(ParagraphStyle(name="MetaLabel", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7.4, leading=9, textColor=MUTED))
    styles.add(ParagraphStyle(name="MetaValue", parent=styles["BodyText"], fontSize=7.7, leading=9.5, textColor=INK, splitLongWords=True))
    styles.add(ParagraphStyle(name="EvidenceKey", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7.4, leading=9.5, textColor=MUTED, splitLongWords=True))
    styles.add(ParagraphStyle(name="EvidenceValue", parent=styles["BodyText"], fontSize=7.5, leading=9.6, textColor=INK, wordWrap="CJK", splitLongWords=True))
    styles.add(ParagraphStyle(
        name="EvidenceCode", parent=styles["Code"], fontName="Courier", fontSize=7, leading=8.8,
        leftIndent=5, rightIndent=5, borderPadding=6, borderColor=BORDER, borderWidth=0.5,
        backColor=PANEL, textColor=INK, allowWidows=1, allowOrphans=1,
    ))
    styles.add(ParagraphStyle(
        name="Callout", parent=styles["BodyText"], fontSize=8.7, leading=12.5, leftIndent=8, rightIndent=8,
        borderPadding=8, borderColor=colors.HexColor("#A3E635"), borderWidth=0.8,
        backColor=colors.HexColor("#F7FEE7"), textColor=INK,
    ))
    styles.add(ParagraphStyle(
        name="CalloutNeutral", parent=styles["BodyText"], fontSize=8.5, leading=12, leftIndent=7, rightIndent=7,
        borderPadding=7, borderColor=BORDER, borderWidth=0.6, backColor=PANEL, textColor=INK,
    ))
    styles.add(ParagraphStyle(name="MetricLabel", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=6.8, leading=8, alignment=TA_CENTER, textColor=WHITE))
    styles.add(ParagraphStyle(name="MetricValue", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=16, leading=18, alignment=TA_CENTER, textColor=INK))
    styles.add(ParagraphStyle(name="Reference", parent=styles["BodyText"], fontSize=7.8, leading=10.5, textColor=LINK, leftIndent=4, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="RiskBanner", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=12, leading=15, alignment=TA_CENTER, textColor=WHITE))
    styles.add(ParagraphStyle(
        name="DangerBannerText", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=8.8,
        leading=12.5, textColor=SEVERITY_COLORS["critical"],
    ))
    styles.add(ParagraphStyle(
        name="ExploitCallout", parent=styles["BodyText"], fontSize=8.5, leading=12.5, leftIndent=7,
        rightIndent=7, borderPadding=7, borderColor=SEVERITY_COLORS["critical"], borderWidth=0.9,
        backColor=SEVERITY_TINTS["critical"], textColor=INK,
    ))
    styles.add(ParagraphStyle(
        name="RemediationCode", parent=styles["Code"], fontName="Courier", fontSize=6.6, leading=8.2,
        leftIndent=5, rightIndent=5, borderPadding=6, borderColor=BORDER, borderWidth=0.5,
        backColor=colors.HexColor("#F7FEE7"), textColor=INK, allowWidows=1, allowOrphans=1,
    ))
    styles.add(ParagraphStyle(
        name="CoverageTested", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7.6,
        leading=10, alignment=TA_CENTER, textColor=BRAND_DARK,
    ))
    styles.add(ParagraphStyle(
        name="CoverageUntested", parent=styles["BodyText"], fontName="Helvetica-Bold", fontSize=7.6,
        leading=10, alignment=TA_CENTER, textColor=SEVERITY_COLORS["medium"],
    ))

    for level in SEVERITIES:
        styles.add(ParagraphStyle(
            name=f"Badge{level.title()}", parent=styles["BodyText"], fontName="Helvetica-Bold",
            fontSize=7.2, leading=9, alignment=TA_CENTER, textColor=WHITE,
        ))
    return styles


def build_pdf_report(data: dict[str, Any]) -> bytes:
    """Build a complete PDF report from a validated report-export payload."""
    buffer = BytesIO()
    styles = _build_styles()

    target = _ascii_safe(data.get("target") or "unknown", 253)
    scan_id = _ascii_safe(data.get("scan_id") or "manual", 100)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scan_type = str(data.get("scan_type", "full"))
    assessment_label = PROFILE_LABELS.get(scan_type, _ascii_safe(scan_type.replace("_", " ").title(), 100))
    duration = data.get("total_time_seconds", data.get("duration_seconds"))

    findings = [item for item in list(data.get("findings") or []) if isinstance(item, dict)][:1000]
    findings.sort(key=lambda item: (
        SEVERITY_ORDER.get(str(item.get("severity", "info")).lower(), 99),
        _ascii_safe(item.get("title"), 500).lower(),
    ))
    counts = _severity_counts(findings, data.get("severity_counts"))
    total = len(findings) if findings else sum(counts.values())
    ai = data.get("ai_summary") if isinstance(data.get("ai_summary"), dict) else {}
    risk = _risk_level(counts, ai)
    risk_key = risk.lower() if risk.lower() in SEVERITY_COLORS else next((level for level in SEVERITIES if counts.get(level)), "info")

    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=21 * mm,
        bottomMargin=18 * mm,
        title=f"ReconTitan report - {target}",
        author="ReconTitan",
        subject="Authorized external attack surface and web security assessment",
        creator="ReconTitan PDF Report Engine",
        pageCompression=1,
    )
    document.report_target = target
    document.report_generated = generated

    story: list[Any] = [
        Spacer(1, 8 * mm),
        Paragraph("RECONTITAN", styles["BrandTitle"]),
        Paragraph("External Attack Surface and Web Security Report", styles["Subtitle"]),
        Spacer(1, 2 * mm),
    ]

    risk_banner = Table(
        [[Paragraph(f"OVERALL RISK: {escape(risk)}", styles["RiskBanner"]) ]],
        colWidths=[166 * mm],
        rowHeights=[12 * mm],
    )
    risk_banner.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), SEVERITY_COLORS.get(risk_key, SEVERITY_COLORS["info"])),
        ("BOX", (0, 0), (-1, -1), 0.8, SEVERITY_COLORS.get(risk_key, SEVERITY_COLORS["info"])),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ]))
    story.extend([risk_banner, Spacer(1, 5 * mm)])

    meta_rows = [
        ["Target", Paragraph(_rich_text(target, 500), styles["BodyText"])],
        ["Scan ID", Paragraph(_text(scan_id, 200), styles["BodyText"])],
        ["Scan status", Paragraph(_text(data.get("status", "completed"), 60), styles["BodyText"])],
        ["Started", _format_timestamp(data.get("started_at"))],
        ["Completed", _format_timestamp(data.get("completed_at"))],
        ["Generated", generated],
        ["Duration", _human_duration(duration)],
        ["Assessment profile", Paragraph(_text(assessment_label, 100), styles["BodyText"])],
        ["Report version", Paragraph(_text(data.get("version", "0.5.0"), 40), styles["BodyText"])],
    ]
    meta = Table(meta_rows, colWidths=[42 * mm, 124 * mm])
    meta.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), INK),
        ("BACKGROUND", (0, 0), (0, -1), PANEL_ALT),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    danger = data.get("danger_summary") if isinstance(data.get("danger_summary"), dict) else None
    is_danger = scan_type == "danger" or danger is not None

    story.extend([
        meta,
        Spacer(1, 6 * mm),
        Paragraph("Severity overview", styles["Section"]),
        _severity_summary(counts, styles),
        Spacer(1, 5 * mm),
        Paragraph(
            "This report contains automated observations and candidate risks. Technology, CVE, takeover, and risky-JavaScript results require manual validation before they are treated as confirmed vulnerabilities.",
            styles["Callout"],
        ),
    ])
    if is_danger:
        story.extend([Spacer(1, 3 * mm), Paragraph(DANGER_BANNER, styles["DangerBannerText"])])

    story.append(Paragraph("Executive summary", styles["Section"]))
    executive_summary = ai.get("executive_summary") or data.get("summary")
    if executive_summary:
        story.append(Paragraph(_rich_text(executive_summary, 20_000), styles["BodyText"]))
    else:
        story.append(Paragraph(
            f"ReconTitan recorded {total} reportable observation(s) for {escape(target)}. The highest represented severity is {escape(risk)}. Prioritize manual validation of critical and high-severity candidates, then address configuration and informational findings through normal hardening work.",
            styles["BodyText"],
        ))

    recommendations = ai.get("top_recommendations") if isinstance(ai, dict) else None
    if recommendations:
        story.extend([Spacer(1, 2 * mm), Paragraph("Priority actions", styles["FindingSubhead"])])
        story.extend(_paragraph_list(recommendations, styles, 10))
    else:
        priority = [f for f in findings if str(f.get("severity", "info")).lower() in {"critical", "high"}][:5]
        if priority:
            story.extend([Spacer(1, 2 * mm), Paragraph("Priority validation queue", styles["FindingSubhead"])])
            story.extend(_paragraph_list(
                [f"{_ascii_safe(item.get('severity'), 20).upper()}: {_ascii_safe(item.get('title') or 'Untitled finding', 400)}" for item in priority],
                styles,
                5,
            ))

    story.extend([
        PageBreak(),
        Paragraph("Assessment scope and methodology", styles["Section"]),
        Paragraph(
            "ReconTitan performs a bounded external assessment against the supplied public target. It normalizes and validates the target, rejects private or non-routable destinations by default, revalidates redirects, limits response sizes, and executes the modules selected by the assessment profile.",
            styles["BodyText"],
        ),
        Spacer(1, 2 * mm),
        Paragraph(
            "The workflow may include domain and DNS inventory, certificate-transparency discovery, historical URL collection, HTTP probing, security-header review, TLS and cookie checks, CORS review, WAF detection, technology fingerprinting, JavaScript inspection, favicon hashing, conservative subdomain-takeover checks, port discovery, threat-intelligence correlation, and CVE candidates. Intrusive vulnerability tools remain disabled unless the operator explicitly enables them for an authorized target.",
            styles["BodyText"],
        ),
        Spacer(1, 3 * mm),
        Paragraph("Interpretation rules", styles["FindingSubhead"]),
        Paragraph(
            "Passive fingerprints are indicators, not proof. Product-version and CVE mappings must be confirmed. A dangling DNS signature does not by itself prove takeover. Secret-like JavaScript strings may be placeholders. Findings should move to verified status only after an authorized analyst reproduces the condition and confirms impact.",
            styles["CalloutNeutral"],
        ),
    ])

    coverage = _tool_coverage_table(data.get("tool_results") or {}, styles)
    if coverage is not None:
        story.extend([
            Paragraph("Module execution coverage", styles["Section"]),
            Paragraph("The table records the status and output count supplied by each scan module.", styles["SectionLead"]),
            coverage,
        ])

    if is_danger:
        story.extend(_danger_section(danger or {}, findings, styles))

    story.extend([
        Paragraph("Findings index", styles["Section"]),
        Paragraph("Findings are ordered by severity and then by title. Use the finding number to match each index row to the detailed section that follows.", styles["SectionLead"]),
    ])
    if findings:
        story.append(_finding_index(findings, styles))
    else:
        story.append(Paragraph("No findings were included in this report.", styles["BodyText"]))

    story.extend([PageBreak(), Paragraph(f"Detailed findings ({len(findings)})", styles["Section"])])
    if not findings:
        story.append(Paragraph("No detailed findings were supplied.", styles["BodyText"]))
    for index, finding in enumerate(findings, 1):
        story.extend(_finding_block(index, finding, target, styles))

    severity_rows = [["Severity", "Interpretation"]]
    for level in SEVERITIES:
        severity_rows.append([
            Paragraph(level.upper(), styles[f"Badge{level.title()}"]),
            Paragraph(SEVERITY_GUIDANCE[level], styles["TableCell"]),
        ])
    severity_table = Table(severity_rows, colWidths=[30 * mm, 136 * mm], repeatRows=1)
    severity_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#DCE6D2")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 1), (0, 1), SEVERITY_COLORS["critical"]),
        ("BACKGROUND", (0, 2), (0, 2), SEVERITY_COLORS["high"]),
        ("BACKGROUND", (0, 3), (0, 3), SEVERITY_COLORS["medium"]),
        ("BACKGROUND", (0, 4), (0, 4), SEVERITY_COLORS["low"]),
        ("BACKGROUND", (0, 5), (0, 5), SEVERITY_COLORS["info"]),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))

    story.extend([
        CondPageBreak(92 * mm),
        Paragraph("Appendix A - Severity model", styles["Section"]),
        severity_table,
        Paragraph("Appendix B - Limitations and retesting", styles["Section"]),
        Paragraph(
            "Automated reconnaissance can produce false positives and false negatives. Network location, CDN behavior, authentication state, rate limiting, dynamic content, and third-party provider changes can affect results. Absence of a finding does not prove the target is secure.",
            styles["BodyText"],
        ),
        Spacer(1, 2 * mm),
        Paragraph(
            "For closure, confirm asset ownership and authorization, reproduce high-impact findings manually, preserve before-and-after evidence, validate detected product versions, verify provider-side takeover state, rotate confirmed exposed secrets, and retest after remediation from an equivalent network path.",
            styles["BodyText"],
        ),
        Spacer(1, 4 * mm),
        Paragraph(
            f"Generated by ReconTitan {_text(data.get('version', '0.5.0'), 40)}. Authorized security testing only.",
            styles["TinyMuted"],
        ),
    ])

    document.build(story, onFirstPage=_page_chrome, onLaterPages=_page_chrome)
    return buffer.getvalue()
