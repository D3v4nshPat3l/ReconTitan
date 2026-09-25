"""Tests for the plain-text export and the command-line interface.

The text report's job is to carry the same content as the PDF and JSON
exports, including the parts a suppression feature makes it tempting to drop.
The CLI's job is to run the same pipeline the API runs, so a finding at a
terminal is the same finding the report shows.
"""

from __future__ import annotations

from app.cli import _exit_code_for, build_parser
from app.services.text_report import render_text_report

REPORT = {
    "scan_id": "cli-test",
    "target": "example.com",
    "scan_type": "full",
    "version": "0.5.0",
    "total_time_seconds": 12.5,
    "tools_run": 3,
    "total_findings": 3,
    "severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 1, "info": 1},
    "tool_results": {"dns_lookup": {"findings": 2, "status": "ok"}},
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
            "title": "Directory Enumeration — 1 Candidate Path",
            "description": "One path answered distinctly.",
            "evidence": "  /admin   320 bytes",
            "requires_manual_validation": True,
        },
        {
            "tool": "crawler", "category": "crawl", "severity": "info",
            "title": "Site Crawl — 4 pages",
            "description": "A bounded same-scope crawl.",
            "evidence": "Pages crawled: 4",
            "triage_state": "false_positive",
            "triage_reason": "Staging host, decommissioned last quarter.",
        },
    ],
    "triage_summary": {"suppressed": 1},
}


def test_text_report_carries_the_header_facts():
    text = render_text_report(REPORT)

    assert "example.com" in text
    assert "cli-test" in text
    assert "HIGH" in text


def test_suppressed_findings_are_reproduced_not_deleted():
    """Nothing is ever deleted -- that rule has to survive every export."""
    text = render_text_report(REPORT)

    assert "SUPPRESSED FINDINGS" in text.upper()
    assert "Site Crawl" in text
    assert "Staging host, decommissioned last quarter." in text


def test_a_quiet_report_says_why_it_is_quiet():
    text = render_text_report(REPORT)
    assert "suppressed" in text.lower()


def test_suppressed_findings_are_not_listed_as_active():
    text = render_text_report(REPORT)
    # Split on the section heading, which carries the count. The summary
    # banner near the top also names the section, so a bare string match
    # would cut the report before the findings rather than after them.
    active_section = text.split("SUPPRESSED FINDINGS (1)")[0]

    assert "FINDINGS (2)" in active_section
    assert "Site Crawl —" not in active_section


def test_candidate_findings_are_labelled():
    text = render_text_report(REPORT)
    assert "requires manual validation" in text.lower()


def test_evidence_is_not_reflowed():
    """Evidence is aligned output; wrapping it destroys the alignment."""
    text = render_text_report(REPORT)
    assert "DNSKEY records: 2" in text
    assert "DS records: none" in text


def test_report_states_it_claims_no_exploitation():
    text = render_text_report(REPORT)
    assert "does not claim" in text.lower()


def test_empty_report_does_not_read_as_a_clean_target():
    text = render_text_report({"target": "example.com", "findings": []})
    assert "could not run" in text.lower()


def test_text_report_survives_a_minimal_payload():
    assert render_text_report({}).strip()


# ── CLI ─────────────────────────────────────────────────────────────────────

def test_profiles_map_to_real_scan_types():
    from app.cli import PROFILES
    from app.models.schemas import ScanType

    for value in PROFILES.values():
        ScanType(value)  # raises if the profile name is not a real scan type


def test_pdf_without_an_output_path_is_rejected():
    from app.cli import main

    assert main(["example.com", "-f", "pdf"]) == 2


def test_a_target_is_required():
    from app.cli import main

    assert main([]) == 2


def test_fail_on_threshold_is_inclusive_and_upward():
    report = {"severity_counts": {"critical": 0, "high": 1, "medium": 0, "low": 0}}

    assert _exit_code_for(report, "high") == 1
    # A critical threshold must still fail on nothing lower than critical.
    assert _exit_code_for(report, "critical") == 0
    # A lower threshold must still catch the higher severity above it.
    assert _exit_code_for(report, "low") == 1
    assert _exit_code_for(report, None) == 0


def test_overrides_reach_the_environment(monkeypatch):
    """Flags must be applied before settings are read, or they do nothing."""
    from app.cli import _apply_overrides

    monkeypatch.delenv("DNS_SERVERS", raising=False)
    monkeypatch.delenv("DIR_ENUM_EXTENSIONS", raising=False)

    args = build_parser().parse_args(
        ["example.com", "-d", "1.1.1.1,8.8.8.8", "-e", "php,bak", "--no-crawl"]
    )
    _apply_overrides(args)

    import os

    assert os.environ["DNS_SERVERS"] == "1.1.1.1,8.8.8.8"
    assert os.environ["DIR_ENUM_EXTENSIONS"] == "php,bak"
    assert os.environ["CRAWLER_ENABLED"] == "false"
    # A terminal scan has no worker to hand the job to.
    assert os.environ["ASYNC_SCANS_ENABLED"] == "false"


def test_danger_profile_is_selectable_but_gated():
    """The CLI must not become a way around the acknowledgement phrase."""
    args = build_parser().parse_args(["example.com", "-p", "danger"])
    assert args.profile == "danger"
    assert args.danger_ack is None
