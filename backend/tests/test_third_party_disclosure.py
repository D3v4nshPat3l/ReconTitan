"""Tests for third-party disclosure gating and honest module-skip reporting.

Two failure modes are covered here, both of which mislead an operator rather
than crashing:

  1. Sending the target to a service the operator was never told about.
  2. Returning nothing when a module did not run, so "no findings" reads as
     "nothing wrong".
"""

from __future__ import annotations

import pytest

from app.services import capabilities
from app.tasks.recon import ipinfo, port_scan, subfinder_amass


# ── HackerTarget must not be contacted unless explicitly enabled ────────────

def test_port_scan_fallback_is_off_by_default(monkeypatch):
    monkeypatch.setattr(port_scan.settings, "ALLOW_HACKERTARGET", False)

    def _boom(*a, **k):
        raise AssertionError("api.hackertarget.com must not be contacted by default")

    monkeypatch.setattr(port_scan.requests, "get", _boom)
    assert port_scan._hackertarget_portscan("93.184.216.34") == ""


def test_port_scan_fallback_runs_when_opted_in(monkeypatch):
    monkeypatch.setattr(port_scan.settings, "ALLOW_HACKERTARGET", True)
    calls = []

    class _Resp:
        text = "80/tcp open http"

        def raise_for_status(self):
            return None

    def _get(url, **kwargs):
        calls.append(url)
        return _Resp()

    monkeypatch.setattr(port_scan.requests, "get", _get)
    assert "80/tcp open" in port_scan._hackertarget_portscan("93.184.216.34")
    assert calls == ["https://api.hackertarget.com/nmap/"]


def test_reverse_ip_lookup_is_off_by_default(monkeypatch):
    """The reverse-IP lookup must not leak the resolved address by default."""
    monkeypatch.setattr(ipinfo.settings, "ALLOW_HACKERTARGET", False)

    seen = []

    class _Resp:
        status_code = 200
        text = "example.org\nexample.net"

        def raise_for_status(self):
            return None

        def json(self):
            return {"ip": "93.184.216.34", "country": "US", "org": "AS15133 Edgecast"}

    def _get(url, **kwargs):
        seen.append(url)
        return _Resp()

    monkeypatch.setattr(ipinfo.requests, "get", _get)
    monkeypatch.setattr(ipinfo.socket, "gethostbyname", lambda d: "93.184.216.34")

    findings = ipinfo.run_ipinfo("example.com")

    assert all("hackertarget" not in url for url in seen)
    assert all(f.get("category") != "reverse_ip" for f in findings)
    # The module's own ipinfo.io lookup is unaffected — only the extra
    # third-party call is gated.
    assert any(f.get("category") == "ip_geolocation" for f in findings)


# ── A skipped scan must not look like a clean scan ──────────────────────────

def test_port_scan_reports_that_it_did_not_run(monkeypatch):
    """No scanner and no fallback must not read as 'no open ports'."""
    monkeypatch.setattr(port_scan.settings, "ALLOW_HACKERTARGET", False)
    monkeypatch.setattr(port_scan, "validate_scan_target", lambda t, **k: (True, "example.com", ""))
    monkeypatch.setattr(port_scan, "resolve_target_addresses", lambda d: ["93.184.216.34"])
    monkeypatch.setattr(port_scan.shutil, "which", lambda b: None)

    findings = port_scan.run_port_scan("example.com")

    assert len(findings) == 1
    assert findings[0]["title"] == "Port Scan Did Not Run"
    assert "not evidence" in findings[0]["description"].lower()
    assert "ALLOW_HACKERTARGET" in findings[0]["remediation"]


def test_port_scan_skip_notice_names_the_real_cause(monkeypatch):
    """With the fallback enabled the message must not blame the flag."""
    monkeypatch.setattr(port_scan.settings, "ALLOW_HACKERTARGET", True)
    monkeypatch.setattr(port_scan, "validate_scan_target", lambda t, **k: (True, "example.com", ""))
    monkeypatch.setattr(port_scan, "resolve_target_addresses", lambda d: ["93.184.216.34"])
    monkeypatch.setattr(port_scan.shutil, "which", lambda b: None)
    monkeypatch.setattr(port_scan, "_hackertarget_portscan", lambda a: "")

    findings = port_scan.run_port_scan("example.com")
    assert "ALLOW_HACKERTARGET=false" not in findings[0]["description"]


@pytest.mark.parametrize(
    "runner,binary",
    [(subfinder_amass.run_subfinder, "subfinder"), (subfinder_amass.run_amass, "amass")],
)
def test_missing_enumeration_binary_is_reported(monkeypatch, runner, binary):
    """Silence previously made an absent binary look like a target with no subdomains."""
    monkeypatch.setattr(subfinder_amass.shutil, "which", lambda b: None)

    findings = runner("example.com")

    assert len(findings) == 1
    assert findings[0]["tool"] == binary
    assert "Not Installed" in findings[0]["title"]
    assert "not evidence" in findings[0]["description"].lower()
    assert findings[0]["remediation"]


def test_present_binary_does_not_emit_a_skip_notice(monkeypatch):
    monkeypatch.setattr(subfinder_amass.shutil, "which", lambda b: f"/usr/bin/{b}")
    monkeypatch.setattr(subfinder_amass, "_run_binary", lambda cmd, timeout=120: "a.example.com")

    findings = subfinder_amass.run_subfinder("example.com")
    assert all("Not Installed" not in f["title"] for f in findings)


# ── Capability reporting must match reality ────────────────────────────────

def test_waf_detect_is_not_reported_as_needing_a_binary():
    """run_wafw00f matches headers in pure Python; it never shells out.

    Listing it as binary-backed reported a working module as unavailable,
    which inverts the purpose of the runtime report.
    """
    assert "waf_detect" not in capabilities.BINARY_MODULES

    report = capabilities.runtime_report()
    assert "waf_detect" not in report["binary_modules_unavailable"]
    assert "waf_detect" not in report["binary_modules_available"]


def test_active_scanners_are_still_tracked_as_binary_modules():
    """Delisting waf_detect must not quietly drop the opt-in active tools."""
    for module in ("nuclei", "nikto", "sqlmap", "dir_fuzzing", "port_scan"):
        assert module in capabilities.BINARY_MODULES
