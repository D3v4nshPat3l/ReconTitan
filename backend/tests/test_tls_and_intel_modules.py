"""Behavioural tests for TLS analysis and the keyed intelligence integrations.

No socket is opened and no API is called. `_connect_tls` is replaced with a
fake TLS socket so the certificate *analysis* can be exercised independently of
the network, and the threat-intel modules are checked for their most important
property: staying silent and harmless when no credentials are configured.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timedelta, timezone

import pytest

from app.tasks.osint import ssl_check, threat_intel, username_osint


def _fmt(moment: datetime) -> str:
    """OpenSSL's notBefore/notAfter format."""
    return moment.strftime("%b %d %H:%M:%S %Y GMT")


class FakeTLSSocket:
    def __init__(self, cert: dict, protocol: str = "TLSv1.3", cipher=("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)):
        self._cert = cert
        self._protocol = protocol
        self._cipher = cipher

    def getpeercert(self):
        return self._cert

    def version(self):
        return self._protocol

    def cipher(self):
        return self._cipher

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _cert(days_until_expiry: int, sans: list[str] | None = None) -> dict:
    now = datetime.now(timezone.utc)
    return {
        "notBefore": _fmt(now - timedelta(days=30)),
        "notAfter": _fmt(now + timedelta(days=days_until_expiry)),
        "subject": [(("commonName", "example.com"),)],
        "issuer": [(("organizationName", "Example CA"),)],
        "subjectAltName": [("DNS", name) for name in (sans or ["example.com"])],
    }


@pytest.fixture(autouse=True)
def _allow_target(monkeypatch):
    monkeypatch.setattr(ssl_check, "validate_scan_target", lambda t, **k: (True, "example.com", ""))


def _install_socket(monkeypatch, sock):
    monkeypatch.setattr(ssl_check, "_connect_tls", lambda domain: sock)


def _titles(findings: list[dict]) -> str:
    return " | ".join(f.get("title", "") for f in findings)


# ── Certificate expiry banding ──────────────────────────────────────────────

@pytest.mark.parametrize(
    "days,expected",
    [(-1, "critical"), (7, "high"), (20, "medium"), (200, "info")],
)
def test_expiry_severity_bands(monkeypatch, days, expected):
    _install_socket(monkeypatch, FakeTLSSocket(_cert(days)))

    cert_findings = [
        f for f in ssl_check.run_ssl_check("example.com") if f["category"] == "ssl_certificate"
    ]
    assert cert_findings[0]["severity"] == expected


def test_expired_certificate_says_so_explicitly(monkeypatch):
    _install_socket(monkeypatch, FakeTLSSocket(_cert(-5)))
    assert "expired" in _titles(ssl_check.run_ssl_check("example.com")).lower()


def test_unparseable_expiry_does_not_crash(monkeypatch):
    """A malformed date must degrade to informational, not raise."""
    cert = _cert(100)
    cert["notAfter"] = "not-a-date"
    _install_socket(monkeypatch, FakeTLSSocket(cert))

    findings = ssl_check.run_ssl_check("example.com")
    assert findings and findings[0]["severity"] == "info"


# ── Protocol assessment ─────────────────────────────────────────────────────

@pytest.mark.parametrize("protocol", ["TLSv1", "TLSv1.1", "SSLv3"])
def test_obsolete_protocols_are_high_severity(monkeypatch, protocol):
    _install_socket(monkeypatch, FakeTLSSocket(_cert(200), protocol=protocol))

    weak = [f for f in ssl_check.run_ssl_check("example.com") if f["category"] == "weak_tls"]
    assert len(weak) == 1
    assert weak[0]["severity"] == "high"


@pytest.mark.parametrize("protocol", ["TLSv1.2", "TLSv1.3"])
def test_modern_protocols_are_not_flagged(monkeypatch, protocol):
    _install_socket(monkeypatch, FakeTLSSocket(_cert(200), protocol=protocol))

    assert not [f for f in ssl_check.run_ssl_check("example.com") if f["category"] == "weak_tls"]


# ── SAN disclosure ──────────────────────────────────────────────────────────

def test_multiple_sans_are_surfaced_for_review(monkeypatch):
    sans = ["example.com", "admin.example.com", "vpn.example.com"]
    _install_socket(monkeypatch, FakeTLSSocket(_cert(200, sans=sans)))

    san_findings = [
        f for f in ssl_check.run_ssl_check("example.com") if f["category"] == "subdomain_enumeration"
    ]
    assert len(san_findings) == 1
    assert "admin.example.com" in san_findings[0]["evidence"]


def test_single_san_is_not_reported_as_enumeration(monkeypatch):
    """One SAN is the hostname itself and reveals nothing."""
    _install_socket(monkeypatch, FakeTLSSocket(_cert(200, sans=["example.com"])))

    assert not [
        f for f in ssl_check.run_ssl_check("example.com") if f["category"] == "subdomain_enumeration"
    ]


# ── Connection failure modes ────────────────────────────────────────────────

def test_certificate_verification_failure_is_high_and_not_fatal(monkeypatch):
    def _raise(domain):
        raise ssl.SSLCertVerificationError("hostname mismatch")

    monkeypatch.setattr(ssl_check, "_connect_tls", _raise)
    findings = ssl_check.run_ssl_check("example.com")

    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "Verification Failed" in findings[0]["title"]


def test_unreachable_port_443_is_reported_as_medium(monkeypatch):
    def _raise(domain):
        raise socket.timeout("timed out")

    monkeypatch.setattr(ssl_check, "_connect_tls", _raise)
    findings = ssl_check.run_ssl_check("example.com")

    assert findings[0]["severity"] == "medium"
    assert "HTTPS Not Available" in findings[0]["title"]


def test_blocked_target_is_reported_before_any_connection(monkeypatch):
    """Target validation must run first; a private host is never dialled."""
    monkeypatch.setattr(ssl_check, "validate_scan_target", lambda t, **k: (False, t, "private address"))

    def _must_not_run(domain):
        raise AssertionError("a rejected target must never be connected to")

    monkeypatch.setattr(ssl_check, "_connect_tls", _must_not_run)

    findings = ssl_check.run_ssl_check("127.0.0.1")
    assert findings[0]["severity"] == "high"
    assert "Unsafe or Invalid TLS Target" in findings[0]["title"]


# ── Threat intelligence: keyless behaviour ──────────────────────────────────

@pytest.mark.parametrize(
    "runner,key_attr",
    [
        (threat_intel.run_virustotal, "VT_KEY"),
        (threat_intel.run_shodan, "SHODAN_KEY"),
        (threat_intel.run_greynoise, "GN_KEY"),
    ],
)
def test_unkeyed_intel_modules_make_no_request(monkeypatch, runner, key_attr):
    """Without a key these must skip silently -- never call out, never error."""
    monkeypatch.setattr(threat_intel, key_attr, "")

    def _boom(*a, **k):
        raise AssertionError("an unkeyed integration must not contact its API")

    monkeypatch.setattr(threat_intel.requests, "get", _boom)
    assert runner("example.com") == []


def test_intel_api_failure_is_swallowed(monkeypatch):
    """A third-party outage must not fail the scan."""
    monkeypatch.setattr(threat_intel, "VT_KEY", "k" * 32)

    def _boom(*a, **k):
        raise ConnectionError("virustotal down")

    monkeypatch.setattr(threat_intel.requests, "get", _boom)
    assert threat_intel.run_virustotal("example.com") == []


# ── username_osint: missing binaries ────────────────────────────────────────

def test_theharvester_absence_is_reported(monkeypatch):
    """This module already reported its own absence -- keep it that way."""
    monkeypatch.setattr(username_osint.shutil, "which", lambda b: None)

    findings = username_osint.run_theharvester("example.com")
    assert len(findings) == 1
    assert "Not Installed" in findings[0]["title"]


def test_sherlock_absence_does_not_raise(monkeypatch):
    monkeypatch.setattr(username_osint.shutil, "which", lambda b: None)
    assert isinstance(username_osint.run_sherlock("someuser"), list)
