from __future__ import annotations

import socket

import pytest

from app import targeting


def test_normalize_target_strips_scheme_port_path_and_case():
    assert targeting.normalize_target(" HTTPS://Sub.Example.COM:8443/a?q=1 ") == "sub.example.com"


@pytest.mark.parametrize(
    "target",
    ["localhost", "127.0.0.1", "::1", "169.254.169.254", "10.0.0.1", "metadata.google.internal", "printer.local"],
)
def test_internal_targets_are_blocked(target):
    ok, clean, error = targeting.validate_scan_target(target, resolve_dns=False)
    assert not ok
    assert clean
    assert error


def test_public_domain_resolution_is_accepted(monkeypatch):
    monkeypatch.setattr(targeting, "resolve_target_addresses", lambda host: ["93.184.216.34"])
    ok, clean, error = targeting.validate_scan_target("Example.COM", resolve_dns=True)
    assert (ok, clean, error) == (True, "example.com", "")


def test_mixed_public_private_dns_is_rejected(monkeypatch):
    monkeypatch.setattr(targeting, "resolve_target_addresses", lambda host: ["93.184.216.34", "127.0.0.1"])
    ok, _clean, error = targeting.validate_scan_target("example.com", resolve_dns=True)
    assert not ok
    assert "private" in error.lower()


def test_dns_failure_is_sanitized(monkeypatch):
    def fail(_host):
        raise socket.gaierror("internal resolver detail")

    monkeypatch.setattr(targeting, "resolve_target_addresses", fail)
    ok, _clean, error = targeting.validate_scan_target("example.com", resolve_dns=True)
    assert not ok
    assert error == "Target does not resolve"


def test_scope_check_prevents_suffix_confusion():
    assert targeting.is_same_target_scope("cdn.example.com", "example.com")
    assert targeting.is_same_target_scope("example.com", "example.com")
    assert not targeting.is_same_target_scope("example.com.attacker.test", "example.com")
