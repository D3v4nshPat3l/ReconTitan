from __future__ import annotations

from app.models.schemas import ScanType
from app.routers import test_scan
from app.services.capabilities import capabilities_payload, tools_for_profile


def _tool(name):
    def run(_target):
        return [{"tool": name}]
    return run


def test_profile_tool_metadata_is_deduplicated_and_complete():
    full = tools_for_profile("full")
    assert len(full) == len(set(full))
    assert {"tech_stack", "favicon_hash", "js_analysis", "subdomain_takeover", "port_scan", "nvd_cve", "ai_report"}.issubset(full)
    payload = capabilities_payload("0.4.0")
    assert len(payload["profiles"]) == 5
    assert all(profile["tool_count"] == len(profile["tools"]) for profile in payload["profiles"])


def test_danger_profile_supersets_the_safe_profiles():
    danger = tools_for_profile("danger")
    assert len(danger) == len(set(danger))
    # Danger must run everything the safe profiles run, plus its own modules.
    for profile in ("recon_only", "osint_only", "vuln_only"):
        assert set(tools_for_profile(profile)).issubset(danger)
    assert {
        "danger_recon", "danger_axfr", "attack_surface", "injection_sqli", "injection_command",
        "injection_xss", "injection_ssrf", "directory_fuzzing", "path_traversal",
        "idor_testing", "reverse_shell_assessment", "owasp_matrix",
    }.issubset(danger)


def test_synchronous_scan_profile_selection(monkeypatch):
    monkeypatch.setattr(test_scan, "_tool_groups", lambda: {
        "recon": [("recon", _tool("recon"))],
        "osint": [("osint", _tool("osint"))],
        "vuln": [("vuln", _tool("vuln"))],
    })
    assert [name for name, _ in test_scan._selected_tools(ScanType.RECON_ONLY)] == ["recon"]
    assert [name for name, _ in test_scan._selected_tools(ScanType.OSINT_ONLY)] == ["osint"]
    assert [name for name, _ in test_scan._selected_tools(ScanType.VULN_ONLY)] == ["vuln"]
    assert [name for name, _ in test_scan._selected_tools(ScanType.FULL)] == ["recon", "osint", "vuln"]
