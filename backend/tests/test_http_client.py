from __future__ import annotations

import pytest

from app.tasks import http_client


def test_destination_validation_rejects_non_http_and_credentials():
    with pytest.raises(http_client.UnsafeURL):
        http_client._validated_destination("file:///etc/passwd")
    with pytest.raises(http_client.UnsafeURL):
        http_client._validated_destination("https://user:pass@example.com/")


def test_destination_pins_public_addresses(monkeypatch):
    monkeypatch.setattr(http_client, "validate_scan_target", lambda host, resolve_dns=True: (True, host, ""))
    monkeypatch.setattr(http_client, "resolve_target_addresses", lambda host: ["93.184.216.34"])
    parsed, hostname, addresses = http_client._validated_destination("https://example.com/a")
    assert parsed.path == "/a"
    assert hostname == "example.com"
    assert addresses == ["93.184.216.34"]


def test_host_header_formats_ports_and_ipv6():
    assert http_client._host_header("example.com", 443, "https") == "example.com"
    assert http_client._host_header("example.com", 8443, "https") == "example.com:8443"
    assert http_client._host_header("2001:db8::1", 8080, "http") == "[2001:db8::1]:8080"
