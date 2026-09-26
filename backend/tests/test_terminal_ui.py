"""Tests for the terminal UI layer.

Most of these pin the one rule that matters beyond looks: escape codes belong
in a terminal and nowhere else. A report piped into grep or written to a file
must be plain text, because a colour code in a file is corruption and every
downstream tool sees the escape sequence where it expected a word.

The rest pin the things that quietly stop being true as a renderer grows: box
geometry that holds when the content is styled, a severity bar that never
rounds a real finding down to nothing, and severity carried by a word rather
than by colour alone.
"""

from __future__ import annotations

import io

import pytest

from app.services.terminal import (
    SEVERITY_ORDER,
    Theme,
    strip_ansi,
    supports_color,
    visible_len,
    width,
)
from app.services.terminal_report import render_banner, render_terminal_report


class _Stream:
    """A stream that can claim to be a terminal, or not.

    Not a StringIO subclass: its ``encoding`` is read-only, and the encoding
    is precisely what the glyph fallback is decided from.
    """

    def __init__(self, tty: bool, encoding: str = "utf-8"):
        self._tty = tty
        self.encoding = encoding
        self._buffer = io.StringIO()

    def isatty(self) -> bool:
        return self._tty

    def write(self, text: str) -> int:
        return self._buffer.write(text)

    def flush(self) -> None:
        self._buffer.flush()


REPORT = {
    "scan_id": "cli-test",
    "target": "example.com",
    "scan_type": "full",
    "version": "0.5.0",
    "total_time_seconds": 12.5,
    "tools_run": 3,
    "total_findings": 3,
    "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 1},
    "tool_results": {
        "dns_lookup": {"findings": 2, "status": "ok"},
        "crt.sh": {"findings": 0, "status": "error: ConnectionError"},
        "whois": {"findings": 0, "status": "ok"},
    },
    "findings": [
        {
            "tool": "dns_lookup", "category": "dnssec", "severity": "high",
            "title": "DNSSEC Signed But Not Delegated",
            "description": "The zone is signed but the parent publishes no DS record.",
            "evidence": "DNSKEY records: 2\nDS records: none",
            "remediation": "Submit the DS record to the registrar.",
        },
        {
            "tool": "dir_enum", "category": "directory_enumeration", "severity": "low",
            "title": "Directory Enumeration - 1 Candidate Path",
            "description": "One path answered distinctly.",
            "evidence": "  /admin   320 bytes",
            "requires_manual_validation": True,
        },
        {
            "tool": "crawler", "category": "crawl", "severity": "info",
            "title": "Site Crawl - 4 pages",
            "description": "A bounded same-scope crawl.",
            "evidence": "Pages crawled: 4",
            "triage_state": "false_positive",
            "triage_reason": "Staging host, decommissioned last quarter.",
        },
    ],
    "triage_summary": {"suppressed": 1},
}


# ── colour is a property of the destination ─────────────────────────────────

def test_a_terminal_gets_colour(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("TERM", raising=False)
    assert supports_color(_Stream(tty=True)) is True


def test_a_pipe_gets_no_colour(monkeypatch):
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    assert supports_color(_Stream(tty=False)) is False


def test_no_color_env_is_honoured(monkeypatch):
    """The cross-tool convention, so it has to win over an attached terminal."""
    monkeypatch.setenv("NO_COLOR", "1")
    assert supports_color(_Stream(tty=True)) is False


def test_force_color_survives_a_pipe(monkeypatch):
    """CI pipes output and still renders it."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")
    assert supports_color(_Stream(tty=False)) is True


def test_dumb_terminals_get_no_colour(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert supports_color(_Stream(tty=True)) is False


def test_a_plain_report_contains_no_escape_codes():
    """The rule the whole module exists to keep: a piped report is plain."""
    rendered = render_terminal_report(REPORT, Theme(_Stream(tty=False), color=False))
    assert "\x1b" not in rendered


def test_a_terminal_report_does_contain_them():
    rendered = render_terminal_report(REPORT, Theme(_Stream(tty=True), color=True))
    assert "\x1b[" in rendered


# ── geometry ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("color", [True, False])
@pytest.mark.parametrize("ascii_only", [True, False])
def test_panel_lines_are_all_the_same_width(color, ascii_only):
    """Padding is computed from visible length, not string length.

    Measuring the styled string instead pushes the right border out by the
    length of the escape codes, which is invisible until someone turns colour
    on and the box falls apart.
    """
    t = Theme(_Stream(tty=True), color=color, ascii_only=ascii_only)
    t.width = 64
    rows = [
        ("Target", t.s("example.com", "bold", "white") + t.s("  -> 1.2.3.4", "grey")),
        ("Profile", "full"),
    ]
    lines = [line for line in t.panel("RUN", rows) if line]

    assert lines, "panel produced nothing"
    assert all(visible_len(line) == t.width for line in lines)


def test_width_is_clamped_both_ways():
    """Eighty columns is a guess that is wrong in both directions."""
    assert 60 <= width() <= 110


def test_visible_length_ignores_escape_codes():
    t = Theme(_Stream(tty=True), color=True)
    assert visible_len(t.s("abc", "red", "bold")) == 3
    assert strip_ansi(t.s("abc", "red")) == "abc"


# ── severity presentation ───────────────────────────────────────────────────

def test_a_nonzero_count_never_renders_an_empty_bar():
    """Rounding a real finding down to nothing makes it look like zero."""
    t = Theme(_Stream(tty=True), color=False)
    assert t.bar(1, 10_000, size=28) != ""


def test_a_zero_count_renders_no_bar():
    t = Theme(_Stream(tty=True), color=False)
    assert t.bar(0, 10) == ""


def test_severity_is_carried_by_the_word_not_only_colour():
    """Colour alone excludes colour-blind readers and every piped consumer."""
    for theme in (Theme(_Stream(tty=True), color=True), Theme(_Stream(tty=False), color=False)):
        for severity in SEVERITY_ORDER:
            badge = strip_ansi(theme.severity_badge(severity))
            assert severity.upper() in badge


def test_every_severity_has_a_distinct_colour():
    t = Theme(_Stream(tty=True), color=True)
    colours = {t.severity_color(s) for s in SEVERITY_ORDER}
    assert len(colours) == len(SEVERITY_ORDER)


# ── glyph degradation ───────────────────────────────────────────────────────

def test_a_legacy_codepage_falls_back_to_ascii():
    """A traceback about encoding is worse than a box drawn with dashes."""
    t = Theme(_Stream(tty=True, encoding="cp1252"))
    rendered = "".join(t.panel("RUN", [("Target", "example.com")]))
    rendered.encode("cp1252")  # raises if a box-drawing glyph slipped through


def test_ascii_mode_still_draws_a_box():
    t = Theme(_Stream(tty=True), color=False, ascii_only=True)
    assert "+" in "".join(t.panel("RUN", [("Target", "example.com")]))


# ── report structure ────────────────────────────────────────────────────────

def _plain(report=REPORT) -> str:
    return strip_ansi(render_terminal_report(report, Theme(_Stream(tty=True), color=True)))


def test_report_leads_with_the_verdict():
    """The question "is anything on fire" is answered before any scrolling."""
    text = _plain()
    assert text.index("FINDINGS BY SEVERITY") < text.index("CONTENTS")


def test_contents_list_is_ranked_worst_first():
    text = _plain()
    contents = text.split("CONTENTS")[1].split("FINDINGS —")[0]
    assert contents.index("HIGH") < contents.index("LOW")


def test_suppressed_findings_are_reproduced_with_their_reason():
    """Nothing is ever deleted -- that rule survives every renderer."""
    text = _plain()
    assert "SUPPRESSED FINDINGS" in text.upper()
    assert "Staging host, decommissioned last quarter." in text


def test_suppressed_findings_are_excluded_from_the_contents_list():
    text = _plain()
    contents = text.split("CONTENTS")[1].split("FINDINGS —")[0]
    assert "Site Crawl" not in contents


def test_candidate_findings_are_labelled():
    assert "CANDIDATE" in _plain()


def test_evidence_is_reproduced_verbatim():
    """Evidence is aligned output; reflowing it destroys the alignment."""
    text = _plain()
    assert "DNSKEY records: 2" in text
    assert "DS records: none" in text


def test_failed_modules_are_named_in_coverage():
    """A module that errored found nothing because it never finished."""
    text = _plain()
    assert "crt.sh" in text
    assert "ConnectionError" in text


def test_report_states_it_claims_no_exploitation():
    assert "does not claim" in _plain().lower()


def test_an_empty_report_does_not_read_as_a_clean_target():
    text = strip_ansi(
        render_terminal_report(
            {"target": "example.com", "findings": [], "severity_counts": {}},
            Theme(_Stream(tty=True), color=False),
        )
    )
    assert "could not run" in text.lower()


def test_renderer_survives_a_minimal_payload():
    assert render_terminal_report({}, Theme(_Stream(tty=False), color=False)).strip()


def test_banner_renders_in_both_modes():
    for color in (True, False):
        banner = render_banner(Theme(_Stream(tty=True), color=color), "0.5.0")
        assert "0.5.0" in strip_ansi(banner)
