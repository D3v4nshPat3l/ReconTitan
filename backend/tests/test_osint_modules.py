"""Behavioural tests for the OSINT scanner modules.

These modules produce most of the findings in a normal scan and had no tests.
No test here touches the network: the pinned HTTP client is stubbed at the
module boundary, exactly as the existing feature tests do it.

The emphasis is on the judgements each module makes -- which condition is a
finding, at what severity, and which conditions must *not* be reported -- since
a scanner that invents findings is as harmful as one that misses them.
"""

from __future__ import annotations

import pytest

from app.tasks.http_client import SafeResponse
from app.tasks.osint import cookie_check, cors_check, robots_sitemap, security_headers, waf_detect


def response(
    url: str = "https://example.com/",
    body: bytes = b"",
    headers: dict[str, str] | None = None,
    status: int = 200,
) -> SafeResponse:
    return SafeResponse(status_code=status, url=url, headers=headers or {}, content=body)


def _titles(findings: list[dict]) -> str:
    return " | ".join(f.get("title", "") for f in findings)


# ── security_headers ────────────────────────────────────────────────────────

def test_every_missing_header_is_reported_once(monkeypatch):
    monkeypatch.setattr(security_headers, "safe_get", lambda *a, **k: response())

    findings = security_headers.run_security_headers("example.com")
    missing = [f["title"].split(": ", 1)[1] for f in findings if f["title"].startswith("Missing")]

    assert set(missing) == set(security_headers.HEADERS_TO_CHECK)
    assert len(missing) == len(set(missing)), "a header must not be reported twice"


def test_present_headers_are_not_reported_missing(monkeypatch):
    present = {name: "somevalue" for name in security_headers.HEADERS_TO_CHECK}
    monkeypatch.setattr(security_headers, "safe_get", lambda *a, **k: response(headers=present))

    findings = security_headers.run_security_headers("example.com")
    assert not [f for f in findings if f["title"].startswith("Missing")]


def test_header_matching_is_case_insensitive(monkeypatch):
    """Servers choose their own casing; HTTP header names are case-insensitive."""
    lowercased = {name.lower(): "v" for name in security_headers.HEADERS_TO_CHECK}
    monkeypatch.setattr(security_headers, "safe_get", lambda *a, **k: response(headers=lowercased))

    findings = security_headers.run_security_headers("example.com")
    assert not [f for f in findings if f["title"].startswith("Missing")]


def test_legacy_xss_filter_flagged_only_when_enabled(monkeypatch):
    """`X-XSS-Protection: 0` is the *recommended* value and must not be flagged."""
    monkeypatch.setattr(
        security_headers, "safe_get", lambda *a, **k: response(headers={"X-XSS-Protection": "0"})
    )
    assert "Legacy X-XSS-Protection" not in _titles(security_headers.run_security_headers("example.com"))

    monkeypatch.setattr(
        security_headers, "safe_get", lambda *a, **k: response(headers={"X-XSS-Protection": "1; mode=block"})
    )
    assert "Legacy X-XSS-Protection" in _titles(security_headers.run_security_headers("example.com"))


def test_version_disclosure_is_reported_with_the_offending_headers(monkeypatch):
    monkeypatch.setattr(
        security_headers,
        "safe_get",
        lambda *a, **k: response(headers={"Server": "nginx/1.26.0", "X-Powered-By": "PHP/8.2.1"}),
    )
    disclosure = [
        f for f in security_headers.run_security_headers("example.com")
        if f["category"] == "information_disclosure"
    ]
    assert len(disclosure) == 1
    assert "nginx/1.26.0" in disclosure[0]["evidence"]
    assert "PHP/8.2.1" in disclosure[0]["evidence"]


def test_unreachable_host_yields_no_findings(monkeypatch):
    """An unreachable target must not be reported as missing every header."""
    def _boom(*a, **k):
        raise ConnectionError("refused")

    monkeypatch.setattr(security_headers, "safe_get", _boom)
    assert security_headers.run_security_headers("example.com") == []


def test_https_failure_falls_back_to_http(monkeypatch):
    attempted: list[str] = []

    def _get(url, **kwargs):
        attempted.append(url)
        if url.startswith("https://"):
            raise ConnectionError("no tls")
        return response(url=url, headers={"Server": "nginx"})

    monkeypatch.setattr(security_headers, "safe_get", _get)
    security_headers.run_security_headers("example.com")

    assert attempted == ["https://example.com/", "http://example.com/"]


# ── cookie_check ────────────────────────────────────────────────────────────

def test_missing_cookie_flags_are_reported(monkeypatch):
    monkeypatch.setattr(
        cookie_check,
        "safe_get",
        lambda *a, **k: response(headers={"Set-Cookie": "sessionid=abc123; Path=/"}),
    )
    findings = cookie_check.run_cookie_check("example.com")

    assert findings[0]["severity"] == "medium"
    evidence = findings[0]["evidence"]
    assert "sessionid" in evidence
    for flag in ("Secure", "HttpOnly", "SameSite"):
        assert flag in evidence


def test_fully_flagged_cookie_is_not_reported_as_an_issue(monkeypatch):
    monkeypatch.setattr(
        cookie_check,
        "safe_get",
        lambda *a, **k: response(
            headers={"Set-Cookie": "sid=x; Path=/; Secure; HttpOnly; SameSite=Strict"}
        ),
    )
    findings = cookie_check.run_cookie_check("example.com")
    assert findings[0]["severity"] == "info"
    assert "Include Recommended Flags" in findings[0]["title"]


def test_secure_flag_is_not_demanded_over_plain_http(monkeypatch):
    """`Secure` on an http:// response is unenforceable, so demanding it is noise."""
    monkeypatch.setattr(
        cookie_check,
        "safe_get",
        lambda *a, **k: response(
            url="http://example.com/",
            headers={"Set-Cookie": "sid=x; HttpOnly; SameSite=Lax"},
        ),
    )
    findings = cookie_check.run_cookie_check("example.com")
    assert findings[0]["severity"] == "info"


def test_multiple_cookies_in_one_header_are_split(monkeypatch):
    """A combined Set-Cookie value must not be parsed as a single cookie."""
    combined = "a=1; Path=/, b=2; Path=/, c=3; Secure; HttpOnly; SameSite=Lax"
    monkeypatch.setattr(cookie_check, "safe_get", lambda *a, **k: response(headers={"Set-Cookie": combined}))

    evidence = cookie_check.run_cookie_check("example.com")[0]["evidence"]
    assert "a:" in evidence and "b:" in evidence
    assert "c:" not in evidence, "the fully flagged cookie must not be reported"


def test_expires_comma_does_not_split_a_cookie(monkeypatch):
    """Expires dates contain a comma; splitting there invents phantom cookies."""
    value = "sid=x; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Secure; HttpOnly; SameSite=Lax"
    monkeypatch.setattr(cookie_check, "safe_get", lambda *a, **k: response(headers={"Set-Cookie": value}))

    findings = cookie_check.run_cookie_check("example.com")
    assert findings[0]["severity"] == "info"
    assert "1 Set-Cookie value" in findings[0]["evidence"]


def test_no_cookies_is_reported_as_informational(monkeypatch):
    monkeypatch.setattr(cookie_check, "safe_get", lambda *a, **k: response())
    findings = cookie_check.run_cookie_check("example.com")
    assert findings[0]["severity"] == "info"
    assert "No Cookies Observed" in findings[0]["title"]


def test_unreachable_host_produces_no_cookie_findings(monkeypatch):
    def _boom(*a, **k):
        raise ConnectionError("refused")

    monkeypatch.setattr(cookie_check, "safe_get", _boom)
    assert cookie_check.run_cookie_check("example.com") == []


# ── cors_check ──────────────────────────────────────────────────────────────

def test_reflected_origin_with_credentials_is_high_severity(monkeypatch):
    """Reflection plus credentials is the exploitable combination."""
    def _options(url, **kwargs):
        origin = kwargs["headers"]["Origin"]
        return response(headers={
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
        })

    monkeypatch.setattr(cors_check, "safe_options", _options)
    findings = cors_check.run_cors_check("example.com")

    assert findings, "reflection must be reported"
    assert all(f["severity"] == "high" for f in findings)
    assert "evil.example" in _titles(findings)


def test_wildcard_without_credentials_is_medium(monkeypatch):
    """`*` cannot carry credentials, so it is real but weaker than reflection."""
    monkeypatch.setattr(
        cors_check,
        "safe_options",
        lambda url, **kwargs: response(headers={"Access-Control-Allow-Origin": "*"}),
    )
    findings = cors_check.run_cors_check("example.com")
    assert findings and all(f["severity"] == "medium" for f in findings)


def test_unrelated_allowed_origin_is_not_a_finding(monkeypatch):
    """A server naming some third origin has not accepted ours."""
    monkeypatch.setattr(
        cors_check,
        "safe_options",
        lambda url, **kwargs: response(headers={"Access-Control-Allow-Origin": "https://trusted.example"}),
    )
    findings = cors_check.run_cors_check("example.com")
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"


def test_no_cors_headers_reports_a_clean_result(monkeypatch):
    monkeypatch.setattr(cors_check, "safe_options", lambda url, **kwargs: response())
    findings = cors_check.run_cors_check("example.com")
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"


def test_cors_failures_do_not_abort_remaining_origins(monkeypatch):
    """One dead probe must not suppress the others."""
    def _options(url, **kwargs):
        if kwargs["headers"]["Origin"] == "null":
            raise TimeoutError("slow")
        return response(headers={
            "Access-Control-Allow-Origin": kwargs["headers"]["Origin"],
            "Access-Control-Allow-Credentials": "true",
        })

    monkeypatch.setattr(cors_check, "safe_options", _options)
    findings = cors_check.run_cors_check("example.com")
    assert len(findings) == len(cors_check.TEST_ORIGINS) - 1


# ── robots_sitemap ──────────────────────────────────────────────────────────

def _robots_only(body: bytes, content_type: str = "text/plain", status: int = 200):
    def _get(url, **kwargs):
        if url.endswith("/robots.txt"):
            return response(url=url, body=body, headers={"Content-Type": content_type}, status=status)
        raise FileNotFoundError("no sitemap")

    return _get


def test_sensitive_disallow_entries_are_escalated(monkeypatch):
    body = b"User-agent: *\nDisallow: /admin/\nDisallow: /public/\nDisallow: /.git/\n"
    monkeypatch.setattr(robots_sitemap, "safe_get", _robots_only(body))

    findings = robots_sitemap.run_robots_sitemap("example.com")
    sensitive = [f for f in findings if f["category"] == "sensitive_paths_disclosed"]

    assert len(sensitive) == 1
    assert sensitive[0]["severity"] == "medium"
    assert "/admin/" in sensitive[0]["evidence"]
    assert "/.git/" in sensitive[0]["evidence"]
    assert "/public/" not in sensitive[0]["evidence"]


def test_benign_robots_stays_informational(monkeypatch):
    monkeypatch.setattr(
        robots_sitemap, "safe_get", _robots_only(b"User-agent: *\nDisallow: /images/\n")
    )
    findings = robots_sitemap.run_robots_sitemap("example.com")

    assert [f["severity"] for f in findings] == ["info"]
    assert not [f for f in findings if f["category"] == "sensitive_paths_disclosed"]


def test_sitemap_reference_is_captured(monkeypatch):
    body = b"User-agent: *\nDisallow: /x/\nSitemap: https://example.com/sitemap.xml\n"
    monkeypatch.setattr(robots_sitemap, "safe_get", _robots_only(body))

    evidence = robots_sitemap.run_robots_sitemap("example.com")[0]["evidence"]
    assert "sitemap.xml" in evidence


def test_html_error_page_is_not_parsed_as_robots(monkeypatch):
    """Many hosts answer /robots.txt with a 200 HTML 404 page."""
    monkeypatch.setattr(
        robots_sitemap,
        "safe_get",
        _robots_only(b"<html>Not Found</html>", content_type="text/html"),
    )
    findings = robots_sitemap.run_robots_sitemap("example.com")
    assert not [f for f in findings if f["category"] == "robots_txt"]


def test_missing_robots_and_sitemap_yields_nothing(monkeypatch):
    def _boom(*a, **k):
        raise FileNotFoundError("404")

    monkeypatch.setattr(robots_sitemap, "safe_get", _boom)
    assert robots_sitemap.run_robots_sitemap("example.com") == []


def test_sitemap_urls_are_reported(monkeypatch):
    sitemap = (
        b'<?xml version="1.0"?><urlset><url><loc>https://example.com/</loc></url>'
        b"<url><loc>https://example.com/admin/panel</loc></url></urlset>"
    )

    def _get(url, **kwargs):
        if url.endswith("/sitemap.xml"):
            return response(url=url, body=sitemap, headers={"Content-Type": "application/xml"})
        raise FileNotFoundError("no robots")

    monkeypatch.setattr(robots_sitemap, "safe_get", _get)
    findings = robots_sitemap.run_robots_sitemap("example.com")

    assert any(f["category"] == "sitemap" for f in findings)
    sensitive = [f for f in findings if f["category"] == "sensitive_paths_disclosed"]
    assert sensitive and "/admin/panel" in sensitive[0]["evidence"]


# ── waf_detect ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "headers,expected",
    [
        ({"CF-RAY": "8a1b2c3d4e5f"}, "Cloudflare"),
        ({"X-Akamai-Transformed": "9 0 0"}, "Akamai"),
        ({"X-Sucuri-ID": "abc"}, "Sucuri"),
        ({"X-Amz-Cf-Id": "xyz"}, "CloudFront"),
    ],
)
def test_waf_signatures_match_from_headers_alone(monkeypatch, headers, expected):
    """This module must keep working with no binary installed -- that is the
    whole reason it is not listed in BINARY_MODULES."""
    monkeypatch.setattr(waf_detect, "safe_get", lambda *a, **k: response(headers=headers))

    findings = waf_detect.run_wafw00f("example.com")
    assert expected.lower() in _titles(findings).lower()


def test_waf_header_matching_is_case_insensitive(monkeypatch):
    monkeypatch.setattr(waf_detect, "safe_get", lambda *a, **k: response(headers={"cf-ray": "abc"}))
    assert "Cloudflare" in _titles(waf_detect.run_wafw00f("example.com"))


def test_absent_waf_signature_is_not_claimed_as_proof(monkeypatch):
    """No signature is weak evidence, so the finding must say so rather than
    asserting the target is unprotected."""
    monkeypatch.setattr(waf_detect, "safe_get", lambda *a, **k: response(headers={"Server": "nginx"}))
    findings = waf_detect.run_wafw00f("example.com")

    assert len(findings) == 1
    assert "No Known WAF" in findings[0]["title"]
    assert "not proof" in findings[0]["description"].lower()


def test_unreachable_host_yields_no_waf_finding(monkeypatch):
    def _boom(*a, **k):
        raise ConnectionError("refused")

    monkeypatch.setattr(waf_detect, "safe_get", _boom)
    assert waf_detect.run_wafw00f("example.com") == []
