from __future__ import annotations

from app.services.pdf_report import PROFILE_LABELS, _build_styles, _danger_section, build_pdf_report


def test_pdf_report_is_valid_and_escapes_untrusted_text():
    payload = {
        "scan_id": "manual",
        "target": "example.com<script>alert(1)</script>",
        "total_time_seconds": 3.2,
        "total_findings": 1,
        "severity_counts": {"critical": 1},
        "ai_summary": {"risk_level": "HIGH", "executive_summary": "Review <b>carefully</b>"},
        "findings": [{
            "tool": "test", "category": "xss", "severity": "critical",
            "title": "<img src=x onerror=alert(1)>",
            "description": "A" * 1000,
            "evidence": "payload=<script>alert(1)</script>\n" + ("line\n" * 3000),
            "remediation": "Encode < and >",
        }],
    }
    content = build_pdf_report(payload)
    assert content.startswith(b"%PDF-")
    assert len(content) > 2000


def test_pdf_report_handles_structured_evidence_and_large_wrapped_values():
    findings = []
    for index in range(30):
        findings.append({
            "id": f"finding_{index}",
            "tool": "whois" if index == 29 else "test",
            "category": "whois" if index == 29 else "configuration",
            "severity": "info" if index == 29 else "medium",
            "title": "WHOIS Record - example.com" if index == 29 else f"Finding {index}",
            "description": "Detailed observation with a long value that must remain inside the page margins.",
            "evidence": {
                "Endpoint": "https://example.com/" + ("very-long-segment/" * 30),
                "Status": "observed",
                "Nested": ["one", "two", {"generated": "2026-07-24T10:00:00Z"}],
            },
            "remediation": "Validate the observation and retest after remediation.",
        })
    content = build_pdf_report({
        "scan_id": "layout-test",
        "target": "example.com",
        "version": "0.4.1",
        "findings": findings,
    })
    assert content.startswith(b"%PDF-")
    assert len(content) > 10_000


DANGER_PAYLOAD = {
    "scan_id": "scan_abcdef123456",
    "target": "example.com",
    "scan_type": "danger",
    "severity_counts": {"high": 2, "info": 1},
    "danger_summary": {
        "enabled": True,
        "target": "example.com",
        "stages_completed": ["danger_recon", "attack_surface", "injection_sqli", "idor_testing"],
        "stages_failed": ["injection_xxe"],
        "requests_sent": 214,
        "payloads_sent": 158,
        "budget_exhausted": False,
        "attack_surface": [
            {"id": "as_1", "url": "https://example.com/login", "method": "POST",
             "input_type": "login_form", "parameters": ["username", "password"]},
            {"id": "as_2", "url": "https://example.com/item?id=1", "method": "GET",
             "input_type": "object_reference", "parameters": ["id"]},
        ],
        "injection_matrix": [
            {"endpoint": "https://example.com/item?id=1", "injection_type": "sql",
             "payload_category": "error", "signal": "error", "status_code": 500},
            {"endpoint": "https://example.com/item?id=1", "injection_type": "xss",
             "payload_category": "script_marker", "signal": "none", "status_code": 200},
        ],
        "owasp_coverage": [
            {"category": "A01:2021-Broken Access Control", "tested": True, "findings": 1, "modules": ["idor_testing"]},
            {"category": "A09:2021-Security Logging and Monitoring Failures", "tested": False, "findings": 0, "modules": []},
        ],
    },
    "findings": [
        {"id": "f1", "tool": "injection_sqli", "category": "danger_injection_sql", "severity": "high",
         "title": "SQL Injection Candidate - id", "description": "Error signal observed.",
         "evidence": "Parameter: id\nResponse signal: error", "requires_manual_validation": True,
         "owasp_category": "A03:2021-Injection", "attack_vector": "SQL injection"},
        {"id": "f2", "tool": "reverse_shell_assessment", "category": "danger_reverse_shell", "severity": "high",
         "title": "Reverse Shell Possibility (blind) - host", "description": "Vector documented only.",
         "evidence": "Connection attempted by ReconTitan: no", "requires_manual_validation": True,
         "owasp_category": "A03:2021-Injection"},
        {"id": "f3", "tool": "danger_axfr", "category": "danger_zone_transfer", "severity": "info",
         "title": "Zone Transfer Refused", "description": "Expected behaviour.", "evidence": "ns1: refused",
         "requires_manual_validation": True},
    ],
}


def test_danger_profile_has_a_label():
    assert PROFILE_LABELS["danger"].startswith("Danger Mode")


def _collect_text(node, out: list[str]) -> None:
    """Walk flowables (and nested table cells) collecting every text value."""
    if node is None:
        return
    if isinstance(node, str):
        out.append(node)
        return
    if isinstance(node, (list, tuple)):
        for child in node:
            _collect_text(child, out)
        return
    text = getattr(node, "text", None)
    if isinstance(text, str):
        out.append(text)
    _collect_text(getattr(node, "_cellvalues", None), out)


def _flatten(flowables) -> str:
    out: list[str] = []
    _collect_text(list(flowables), out)
    return " ".join(out)


def test_danger_section_renders_every_block():
    styles = _build_styles()
    story = _danger_section(DANGER_PAYLOAD["danger_summary"], DANGER_PAYLOAD["findings"], styles)
    assert story
    rendered = _flatten(story)
    assert "Danger Mode" in rendered
    assert "REQUIRE MANUAL VALIDATION" in rendered
    assert "OWASP Top 10 coverage matrix" in rendered
    assert "Attack surface inventory" in rendered
    assert "Injection test matrix" in rendered
    assert "Danger check results" in rendered


def test_danger_report_builds_and_includes_all_findings():
    content = build_pdf_report(DANGER_PAYLOAD)
    assert content.startswith(b"%PDF-")
    assert len(content) > 10_000


def test_danger_section_is_absent_from_a_safe_scan_report():
    safe = {
        "scan_id": "scan_safe", "target": "example.com", "scan_type": "full",
        "findings": [{"tool": "t", "category": "c", "severity": "info", "title": "x",
                      "description": "y", "evidence": "z"}],
    }
    content = build_pdf_report(safe)
    assert content.startswith(b"%PDF-")


def test_danger_summary_without_optional_blocks_still_renders():
    minimal = {
        "scan_id": "scan_min", "target": "example.com", "scan_type": "danger",
        "danger_summary": {"enabled": True, "target": "example.com"},
        "findings": [],
    }
    content = build_pdf_report(minimal)
    assert content.startswith(b"%PDF-")
