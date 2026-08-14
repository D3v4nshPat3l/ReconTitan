from __future__ import annotations

from app.tasks.http_client import SafeResponse
from app.tasks.recon import favicon_hash, js_analysis, subdomain_takeover, tech_stack, whois_lookup


def response(url: str, body: bytes, headers: dict[str, str] | None = None, status: int = 200) -> SafeResponse:
    return SafeResponse(status_code=status, url=url, headers=headers or {}, content=body)


def test_murmurhash_is_mmh3_compatible():
    assert favicon_hash.murmurhash3_x86_32(b"") == 0
    assert favicon_hash.murmurhash3_x86_32(b"foo") == -156908512
    assert favicon_hash.murmurhash3_x86_32(b"hello") == 613153351


def test_tech_stack_detects_headers_and_assets(monkeypatch):
    html = b'''<html><head><meta name="generator" content="WordPress 6.8">
        <script src="/_next/static/app.js"></script><script src="/jquery-3.7.1.min.js"></script>
        </head><body><div data-reactroot></div></body></html>'''
    monkeypatch.setattr(
        tech_stack,
        "safe_get",
        lambda *args, **kwargs: response(
            "https://example.com/", html,
            {"Server": "nginx/1.26", "X-Powered-By": "Next.js", "Set-Cookie": "csrftoken=x"},
        ),
    )
    findings = tech_stack.run_tech_stack_detection("example.com")
    evidence = "\n".join(item.get("evidence", "") for item in findings)
    assert "WordPress" in evidence
    assert "Next.js" in evidence
    assert "React" in evidence
    assert "jQuery" in evidence
    assert any(item["category"] == "version_disclosure" for item in findings)


def test_favicon_hash_generates_all_hashes(monkeypatch):
    page = b'<html><head><link rel="icon" href="/assets/icon.png"></head></html>'
    icon = b"\x89PNG\r\n\x1a\nrecontitan-icon"

    def fake_get(url, **kwargs):
        if url.endswith("/"):
            return response("https://example.com/", page, {"Content-Type": "text/html"})
        return response("https://example.com/assets/icon.png", icon, {"Content-Type": "image/png"})

    monkeypatch.setattr(favicon_hash, "safe_get", fake_get)
    monkeypatch.setattr(favicon_hash, "_optional_shodan_lookup", lambda value: None)
    findings = favicon_hash.run_favicon_hash_lookup("example.com")
    evidence = findings[0]["evidence"]
    assert "MD5:" in evidence and "SHA-256:" in evidence and "Shodan MurmurHash3:" in evidence
    assert "/assets/icon.png" in evidence


def test_js_analysis_redacts_secrets_and_detects_sinks(monkeypatch):
    secret = "AKIAABCDEFGHIJKLMNOP"
    page = b'<html><script src="/app.js"></script><script src="https://evil.test/x.js"></script></html>'
    script = f'''const key = "{secret}"; const endpoint = "/api/v1/users";
        element.innerHTML = input; eval(code); //# sourceMappingURL=app.js.map'''.encode()

    def fake_get(url, **kwargs):
        if url.endswith("/"):
            return response("https://example.com/", page, {"Content-Type": "text/html"})
        assert url == "https://example.com/app.js"
        return response(url, script, {"Content-Type": "application/javascript"})

    monkeypatch.setattr(js_analysis, "safe_get", fake_get)
    findings = js_analysis.run_js_file_analysis("example.com")
    rendered = "\n".join(str(item) for item in findings)
    assert secret not in rendered
    assert "value redacted" in rendered
    assert "innerHTML assignment" in rendered
    assert "/api/v1/users" in rendered
    assert "app.js.map" in rendered
    assert "evil.test" not in rendered


def test_takeover_requires_provider_and_positive_evidence(monkeypatch):
    monkeypatch.setattr(subdomain_takeover, "_discover_subdomains", lambda domain: ["docs.example.com", "safe.example.com"])
    monkeypatch.setattr(
        subdomain_takeover,
        "_resolve_cname",
        lambda host: "missing.github.io" if host.startswith("docs") else "cdn.example.net",
    )
    monkeypatch.setattr(subdomain_takeover, "_cname_target_exists", lambda cname: False)
    monkeypatch.setattr(subdomain_takeover, "_unclaimed_http_fingerprint", lambda host, provider: (False, ""))
    findings = subdomain_takeover.run_subdomain_takeover("example.com")
    high = [item for item in findings if item["severity"] == "high"]
    assert len(high) == 1
    assert "docs.example.com" in high[0]["title"]
    assert "NXDOMAIN" in high[0]["evidence"]


def test_whois_values_are_human_readable_and_invalid_dates_are_filtered():
    from datetime import datetime, timezone

    value = [
        datetime(2026, 7, 23, 22, 33, 41, tzinfo=timezone.utc),
        datetime(1, 1, 1, tzinfo=timezone.utc),
        datetime(2026, 7, 23, 22, 33, 41, tzinfo=timezone.utc),
    ]
    rendered = whois_lookup._format_whois_value(value)
    assert rendered == "2026-07-23 22:33:41 UTC"
    assert "datetime.datetime" not in rendered


def test_whois_expiry_chooses_valid_date():
    from datetime import datetime, timedelta, timezone

    future = datetime.now(timezone.utc) + timedelta(days=90)
    selected = whois_lookup._expiry_datetime([datetime(1, 1, 1, tzinfo=timezone.utc), future])
    assert selected == future
