"""Behavioural tests for the recon scanner modules.

Nothing here reaches the network: DNS resolution, `requests`, and the pinned
HTTP client are all stubbed at the module boundary.

The recurring theme is the difference between *absent evidence* and *evidence
of absence*. A recon module that returns nothing when a lookup fails is telling
the operator the target is clean, which is the one conclusion the data does not
support.
"""

from __future__ import annotations

import pytest

from app.tasks.http_client import SafeResponse
from app.tasks.recon import crtsh, dns_lookup, httpx_probe, wayback


def response(
    url: str = "https://example.com/",
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    status: int = 200,
) -> SafeResponse:
    return SafeResponse(status_code=status, url=url, headers=headers or {}, content=body)


def _titles(findings: list[dict]) -> str:
    return " | ".join(f.get("title", "") for f in findings)


def _categories(findings: list[dict]) -> set[str]:
    return {f.get("category", "") for f in findings}


class FakeJsonResponse:
    """Minimal stand-in for a `requests` response."""

    def __init__(self, payload, text: str = "", status: int = 200):
        self._payload = payload
        self.text = text
        self.status_code = status

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


# ── crtsh ───────────────────────────────────────────────────────────────────

def _certs(*names: str) -> list[dict]:
    return [{"name_value": name} for name in names]


def test_crtsh_deduplicates_and_strips_wildcards(monkeypatch):
    payload = _certs("*.example.com", "www.example.com", "WWW.example.com", "api.example.com")
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: FakeJsonResponse(payload))

    findings = crtsh.run_crtsh("example.com")
    evidence = findings[0]["evidence"]

    assert evidence.count("www.example.com") == 1, "case and wildcard duplicates must collapse"
    assert "api.example.com" in evidence


def test_crtsh_excludes_the_apex_domain_itself(monkeypatch):
    """The apex is the input, not a discovered subdomain."""
    monkeypatch.setattr(
        crtsh.requests, "get", lambda *a, **k: FakeJsonResponse(_certs("example.com", "api.example.com"))
    )
    findings = crtsh.run_crtsh("example.com")
    assert "1 found" in findings[0]["title"]


def test_crtsh_escalates_sensitive_subdomains(monkeypatch):
    payload = _certs("admin.example.com", "vpn.example.com", "www.example.com")
    monkeypatch.setattr(crtsh.requests, "get", lambda *a, **k: FakeJsonResponse(payload))

    findings = crtsh.run_crtsh("example.com")
    sensitive = [f for f in findings if f["category"] == "sensitive_subdomains"]

    assert len(sensitive) == 1
    assert sensitive[0]["severity"] == "medium"
    assert "admin.example.com" in sensitive[0]["evidence"]
    assert "vpn.example.com" in sensitive[0]["evidence"]
    assert "www.example.com" not in sensitive[0]["evidence"]


def test_crtsh_multiline_name_values_are_split(monkeypatch):
    """crt.sh packs SANs into one newline-delimited field."""
    monkeypatch.setattr(
        crtsh.requests,
        "get",
        lambda *a, **k: FakeJsonResponse([{"name_value": "a.example.com\nb.example.com"}]),
    )
    evidence = crtsh.run_crtsh("example.com")[0]["evidence"]
    assert "a.example.com" in evidence and "b.example.com" in evidence


def test_crtsh_unrelated_names_are_not_claimed(monkeypatch):
    """A certificate can carry names for other domains entirely."""
    monkeypatch.setattr(
        crtsh.requests,
        "get",
        lambda *a, **k: FakeJsonResponse(_certs("api.example.com", "www.other-site.net")),
    )
    evidence = crtsh.run_crtsh("example.com")[0]["evidence"]
    assert "other-site.net" not in evidence


def test_crtsh_api_failure_does_not_raise(monkeypatch):
    def _boom(*a, **k):
        raise ConnectionError("crt.sh unreachable")

    monkeypatch.setattr(crtsh.requests, "get", _boom)
    assert isinstance(crtsh.run_crtsh("example.com"), list)


# ── dns_lookup ──────────────────────────────────────────────────────────────

class _Answer:
    def __init__(self, value: str):
        self._value = value

    def __str__(self):
        return self._value


def _resolver(records: dict[str, list[str]]):
    """Return a dns.resolver.resolve stub backed by a name->records mapping."""
    import dns.resolver

    def _resolve(name, rtype, **kwargs):
        values = records.get(f"{name}:{rtype}")
        if not values:
            raise dns.resolver.NoAnswer()
        return [_Answer(v) for v in values]

    return _resolve


def test_missing_spf_is_reported(monkeypatch):
    monkeypatch.setattr(
        dns_lookup.dns.resolver, "resolve", _resolver({"example.com:A": ["93.184.216.34"]})
    )
    findings = dns_lookup.run_dns_lookup("example.com")
    assert "Missing SPF Record" in _titles(findings)


def test_present_spf_is_not_reported_missing(monkeypatch):
    monkeypatch.setattr(
        dns_lookup.dns.resolver,
        "resolve",
        _resolver({"example.com:TXT": ['"v=spf1 include:_spf.google.com ~all"']}),
    )
    findings = dns_lookup.run_dns_lookup("example.com")
    assert "Missing SPF Record" not in _titles(findings)


def test_spf_detection_is_case_insensitive(monkeypatch):
    """TXT records are not normalised by the resolver."""
    monkeypatch.setattr(
        dns_lookup.dns.resolver, "resolve", _resolver({"example.com:TXT": ['"V=SPF1 -all"']})
    )
    assert "Missing SPF Record" not in _titles(dns_lookup.run_dns_lookup("example.com"))


def test_missing_dmarc_is_reported(monkeypatch):
    monkeypatch.setattr(dns_lookup.dns.resolver, "resolve", _resolver({}))
    assert "Missing DMARC Record" in _titles(dns_lookup.run_dns_lookup("example.com"))


def test_present_dmarc_is_not_reported_missing(monkeypatch):
    monkeypatch.setattr(
        dns_lookup.dns.resolver,
        "resolve",
        _resolver({"_dmarc.example.com:TXT": ['"v=DMARC1; p=reject"']}),
    )
    assert "Missing DMARC Record" not in _titles(dns_lookup.run_dns_lookup("example.com"))


def test_nameservers_are_reported_when_present(monkeypatch):
    monkeypatch.setattr(
        dns_lookup.dns.resolver,
        "resolve",
        _resolver({"example.com:NS": ["a.iana-servers.net.", "b.iana-servers.net."]}),
    )
    findings = dns_lookup.run_dns_lookup("example.com")
    ns = [f for f in findings if f["category"] == "dns_nameservers"]
    assert len(ns) == 1
    assert "a.iana-servers.net." in ns[0]["evidence"]


def test_records_are_grouped_by_type_in_evidence(monkeypatch):
    monkeypatch.setattr(
        dns_lookup.dns.resolver,
        "resolve",
        _resolver({"example.com:A": ["93.184.216.34"], "example.com:MX": ["10 mail.example.com."]}),
    )
    evidence = dns_lookup.run_dns_lookup("example.com")[0]["evidence"]
    assert "A" in evidence and "93.184.216.34" in evidence
    assert "MX" in evidence and "mail.example.com." in evidence


def test_resolver_errors_do_not_abort_the_lookup(monkeypatch):
    """One broken record type must not lose the others."""
    import dns.resolver

    def _resolve(name, rtype, **kwargs):
        if rtype == "TXT":
            raise dns.exception.Timeout()
        if rtype == "A":
            return [_Answer("93.184.216.34")]
        raise dns.resolver.NoAnswer()

    monkeypatch.setattr(dns_lookup.dns.resolver, "resolve", _resolve)
    findings = dns_lookup.run_dns_lookup("example.com")
    assert "93.184.216.34" in findings[0]["evidence"]


# ── httpx_probe ─────────────────────────────────────────────────────────────

def test_https_failure_with_http_success_is_high_severity(monkeypatch):
    """Serving only plaintext HTTP is a real finding, not a silent fallback."""
    def _get(url, **kwargs):
        if url.startswith("https://"):
            raise ConnectionError("no tls")
        return response(url=url, body=b"<html><title>Site</title></html>")

    monkeypatch.setattr(httpx_probe, "safe_get", _get)
    findings = httpx_probe.run_httpx_probe("example.com")

    downgrade = [f for f in findings if f["category"] == "ssl_issue"]
    assert len(downgrade) == 1
    assert downgrade[0]["severity"] == "high"


def test_working_https_reports_no_downgrade(monkeypatch):
    monkeypatch.setattr(
        httpx_probe, "safe_get", lambda *a, **k: response(body=b"<html><title>Site</title></html>")
    )
    findings = httpx_probe.run_httpx_probe("example.com")
    assert "ssl_issue" not in _categories(findings)


def test_technology_signatures_are_detected_from_body(monkeypatch):
    body = b'<html><head><script src="/_next/static/chunk.js"></script></head></html>'
    monkeypatch.setattr(httpx_probe, "safe_get", lambda *a, **k: response(body=body))

    evidence = " ".join(f.get("evidence", "") for f in httpx_probe.run_httpx_probe("example.com"))
    assert "Next.js" in evidence


def test_totally_unreachable_host_does_not_raise(monkeypatch):
    def _boom(*a, **k):
        raise ConnectionError("refused")

    monkeypatch.setattr(httpx_probe, "safe_get", _boom)
    assert isinstance(httpx_probe.run_httpx_probe("example.com"), list)


# ── wayback ─────────────────────────────────────────────────────────────────

def _wayback_stub(available: dict | None = None, cdx: list | None = None):
    def _get(url, **kwargs):
        if "available" in url:
            if available is None:
                raise ConnectionError("archive.org down")
            return FakeJsonResponse(available)
        if cdx is None:
            raise ConnectionError("cdx down")
        return FakeJsonResponse(cdx)

    return _get


def test_wayback_reports_nothing_when_no_archive_exists(monkeypatch):
    monkeypatch.setattr(
        wayback.requests,
        "get",
        _wayback_stub(available={"archived_snapshots": {}}, cdx=[["original", "timestamp", "statuscode"]]),
    )
    assert wayback.run_wayback("example.com") == []


def test_wayback_cdx_header_row_is_not_counted_as_a_url(monkeypatch):
    """The first CDX row is a header; counting it inflates every result by one."""
    monkeypatch.setattr(
        wayback.requests,
        "get",
        _wayback_stub(
            available={"archived_snapshots": {"closest": {"url": "http://web.archive.org/x", "timestamp": "20240101"}}},
            cdx=[
                ["original", "timestamp", "statuscode"],
                ["https://example.com/a", "20240101", "200"],
            ],
        ),
    )
    findings = wayback.run_wayback("example.com")
    assert findings
    assert "original" not in findings[0]["evidence"]


def test_wayback_survives_one_endpoint_failing(monkeypatch):
    """A dead availability endpoint must not discard usable CDX results."""
    monkeypatch.setattr(
        wayback.requests,
        "get",
        _wayback_stub(
            available=None,
            cdx=[
                ["original", "timestamp", "statuscode"],
                ["https://example.com/admin", "20240101", "200"],
            ],
        ),
    )
    assert wayback.run_wayback("example.com") != []


def test_wayback_total_failure_does_not_raise(monkeypatch):
    monkeypatch.setattr(wayback.requests, "get", _wayback_stub(available=None, cdx=None))
    assert wayback.run_wayback("example.com") == []
