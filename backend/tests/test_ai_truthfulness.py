"""The AI summary must never contradict the numbers printed beside it.

This is not a hypothetical. On a real scan of a live host, qwen2.5:1.5b wrote
"5 critical, 5 high, and 5 medium issues" into the executive summary while the
severity bar directly above it read 0 critical, 0 high, 5 medium. A security
report that disagrees with itself is worse than one with no summary, because a
reader has no way to tell which half is wrong.

Prompt instructions reduce this but cannot be relied on, so the claim is
verified against the real counts before it is shown.
"""

from __future__ import annotations

import pytest

from app.tasks import ai_analysis

COUNTS = {"critical": 0, "high": 0, "medium": 5, "low": 5, "info": 24}


# ── Detecting a false claim ─────────────────────────────────────────────────

@pytest.mark.parametrize(
    "text",
    [
        "The target has 5 critical, 5 high, and 5 medium issues.",
        "There are 12 high severity problems.",
        "We found 3 critical weaknesses.",
        "Scan produced 99 info findings.",
    ],
)
def test_wrong_counts_are_detected(text):
    assert ai_analysis._contradicts_counts(text, COUNTS)


@pytest.mark.parametrize(
    "text",
    [
        "The host shows 5 medium and 5 low findings.",
        "There are 24 info items worth reviewing.",
        "Missing security headers leave the browser on permissive defaults.",
        "",
    ],
)
def test_accurate_or_numberless_text_passes(text):
    assert ai_analysis._contradicts_counts(text, COUNTS) == ""


def test_severity_word_without_a_count_is_not_flagged():
    """"highly recommended" must not read as a claim about high severity."""
    assert ai_analysis._contradicts_counts(
        "It is highly recommended to review the 5 medium items.", COUNTS
    ) == ""


def test_informational_is_treated_as_info():
    assert ai_analysis._contradicts_counts("24 informational findings", COUNTS) == ""
    assert ai_analysis._contradicts_counts("2 informational findings", COUNTS)


# ── The guard actually gates the summary ────────────────────────────────────

def _model_says(monkeypatch, payload: str):
    monkeypatch.setattr(ai_analysis.settings, "AI_PROVIDER", "ollama")
    monkeypatch.setattr(ai_analysis, "_call_ollama", lambda *a, **k: payload)
    monkeypatch.setattr(ai_analysis.settings, "OPENAI_API_KEY", "")


def test_a_hallucinated_summary_is_discarded(monkeypatch):
    """The exact failure observed in production, end to end."""
    _model_says(monkeypatch, (
        '{"executive_summary": "packetpulse.live has 5 critical, 5 high, and 5 medium '
        'issues.", "risk_level": "MEDIUM", "top_recommendations": ["Fix headers"]}'
    ))

    result = ai_analysis.generate_scan_summary("packetpulse.live", [], COUNTS)

    assert result["ai_generated"] is False, "a false count must not reach the report"
    assert "5 critical" not in result["executive_summary"]


def test_an_accurate_summary_is_kept(monkeypatch):
    _model_says(monkeypatch, (
        '{"executive_summary": "Missing security headers and no SPF record weaken '
        'this host.", "risk_level": "MEDIUM", "top_recommendations": ["Add HSTS"]}'
    ))

    result = ai_analysis.generate_scan_summary("example.com", [], COUNTS)

    assert result["ai_generated"] is True
    assert "Missing security headers" in result["executive_summary"]


def test_recommendations_about_the_scanner_are_dropped(monkeypatch):
    """"Install subfinder" is operator advice, not the target's security posture."""
    _model_says(monkeypatch, (
        '{"executive_summary": "Headers are missing.", "risk_level": "MEDIUM",'
        ' "top_recommendations": ["Install subfinder and amass for enumeration",'
        ' "Add a Content-Security-Policy header"]}'
    ))

    recs = ai_analysis.generate_scan_summary("example.com", [], COUNTS)["top_recommendations"]

    assert not any("subfinder" in r.lower() or "amass" in r.lower() for r in recs)
    assert any("Content-Security-Policy" in r for r in recs)


# ── Scanner notices must not be fed to the model as findings ────────────────

@pytest.mark.parametrize(
    "title,expected",
    [
        ("subfinder Not Installed — Enumeration Skipped", True),
        ("Port Scan Did Not Run", True),
        ("Missing Security Header: Content-Security-Policy", False),
        ("Subdomain Takeover Candidate", False),
    ],
)
def test_scanner_notices_are_identified(title, expected):
    assert ai_analysis._is_scanner_notice({"title": title}) is expected


def test_scanner_notices_are_excluded_from_the_prompt():
    findings = [
        {"title": "amass Not Installed — Enumeration Skipped", "severity": "info"},
        {"title": "Missing Security Header: CSP", "severity": "medium",
         "description": "No CSP header was returned."},
    ]
    text = ai_analysis._build_findings_text(findings, "example.com")

    assert "amass" not in text
    assert "CSP" in text


def test_a_scan_of_only_notices_reads_as_no_findings():
    """Otherwise the model describes the scanner's gaps as the target's flaws."""
    findings = [{"title": "subfinder Not Installed — Enumeration Skipped", "severity": "info"}]
    assert "No vulnerabilities" in ai_analysis._build_findings_text(findings, "example.com")
