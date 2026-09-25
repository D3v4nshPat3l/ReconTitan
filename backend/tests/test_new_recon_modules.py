"""Tests for the dependency-free recon modules.

Each of these exists because a module that needed an external binary reported
"skipped" on most hosts. The tests below therefore pin two things: that the
module finds what it should, and -- at least as importantly -- that when it
cannot run it says so rather than returning nothing. Silence and "nothing
found" look identical in a report, and only one of them is true.
"""

from __future__ import annotations

import pytest

from app.tasks.recon import crawler, dir_enum, subdomain_sources, wayback


def _titles(findings) -> str:
    return " | ".join(f["title"] for f in findings)


# ── subdomain_sources ───────────────────────────────────────────────────────

def test_out_of_scope_names_are_discarded():
    """A source returning someone else's domain must not put it in the report."""
    cleaned = subdomain_sources._clean(
        ["api.example.com", "evil.com", "example.com.attacker.net", "*.dev.example.com"],
        "example.com",
    )
    assert cleaned == {"api.example.com", "dev.example.com"}


def test_apex_and_malformed_names_are_discarded():
    cleaned = subdomain_sources._clean(
        ["example.com", "", "  ", "a b c.example.com", "MAIL.Example.Com."],
        "example.com",
    )
    assert cleaned == {"mail.example.com"}


def test_urls_and_emails_are_reduced_to_hostnames():
    cleaned = subdomain_sources._clean(
        ["https://api.example.com/v1/users", "user@mail.example.com"], "example.com"
    )
    assert cleaned == {"api.example.com", "mail.example.com"}


def test_keyed_sources_are_skipped_and_reported(monkeypatch):
    """An absent key must be reported as skipped, never counted as a clean result."""
    for source in subdomain_sources.SOURCES:
        if source.key_setting:
            monkeypatch.setattr(subdomain_sources.settings, source.key_setting, "", raising=False)
    monkeypatch.setattr(subdomain_sources.settings, "ALLOW_HACKERTARGET", False)
    monkeypatch.setattr(
        subdomain_sources, "_query",
        lambda source, domain: (source, {f"a.{domain}"}, ""),
    )

    findings = subdomain_sources.run_subdomain_sources("example.com")

    coverage = [f for f in findings if f["category"] == "scanner_coverage"]
    assert len(coverage) == 1
    assert "no API key" in coverage[0]["evidence"]
    assert "floor" in coverage[0]["description"]


def test_source_errors_are_named_rather_than_swallowed(monkeypatch):
    def _fail(source, domain):
        return source, set(), "rate-limited (429)"

    monkeypatch.setattr(subdomain_sources, "_query", _fail)

    findings = subdomain_sources.run_subdomain_sources("example.com")

    coverage = [f for f in findings if f["category"] == "scanner_coverage"]
    assert coverage and "rate-limited (429)" in coverage[0]["evidence"]


def test_a_broken_source_does_not_end_the_sweep():
    """One source raising must not cost the results of every other source."""
    def _boom(domain):
        raise RuntimeError("source exploded")

    source = subdomain_sources.Source("broken", _boom)
    returned, names, error = subdomain_sources._query(source, "example.com")

    assert returned is source
    assert names == set()
    assert "source exploded" in error


def test_disclosing_sources_are_gated(monkeypatch):
    """A source that must be told the target stays off unless opted in."""
    monkeypatch.setattr(subdomain_sources.settings, "ALLOW_HACKERTARGET", False)
    monkeypatch.setattr(
        subdomain_sources, "_query", lambda source, domain: (source, set(), ""),
    )

    findings = subdomain_sources.run_subdomain_sources("example.com")

    coverage = [f for f in findings if f["category"] == "scanner_coverage"]
    assert coverage and "would disclose the target" in coverage[0]["evidence"]


# ── crawler ─────────────────────────────────────────────────────────────────

SAMPLE_HTML = """
<html><head>
<link rel="stylesheet" href="/css/main.css">
<link rel="icon" href="/favicon.ico">
<script src="/js/app.js"></script>
</head><body>
<!-- TODO: remove the debug api_key before launch -->
<a href="/about">About</a>
<a href="https://cdn.third-party.net/lib.js">CDN</a>
<a href="javascript:void(0)">inert</a>
<a href="/admin/login">Admin</a>
<img src="/img/logo.png">
<form action="/login" method="post"><input name="user"><input name="pass"></form>
<form action="/safe" method="post"><input name="csrf_token"><input name="x"></form>
</body></html>
"""


def test_link_graph_extraction():
    found = crawler._extract(SAMPLE_HTML, "https://example.com/")

    assert "https://example.com/about" in found["links"]
    assert "https://cdn.third-party.net/lib.js" in found["links"]
    assert found["scripts"] == {"https://example.com/js/app.js"}
    assert found["images"] == {"https://example.com/img/logo.png"}


def test_only_rel_stylesheet_counts_as_a_stylesheet():
    """<link> also carries icons, preloads and canonicals."""
    found = crawler._extract(SAMPLE_HTML, "https://example.com/")

    assert found["styles"] == {"https://example.com/css/main.css"}
    assert "https://example.com/favicon.ico" not in found["styles"]


def test_inert_hrefs_are_not_treated_as_links():
    found = crawler._extract(SAMPLE_HTML, "https://example.com/")
    assert not any("javascript:" in link for link in found["links"])


def test_forms_record_method_and_field_names():
    forms = crawler._extract(SAMPLE_HTML, "https://example.com/")["forms"]
    login = next(f for f in forms if f["action"].endswith("/login"))

    assert login["method"] == "POST"
    assert login["fields"] == ["pass", "user"]


def test_endpoints_are_extracted_from_scripts():
    paths, urls = crawler._extract_from_js(
        'fetch("/api/v2/users");const t="https://analytics.example.net/collect";',
        "https://example.com/js/app.js",
    )

    assert "https://example.com/api/v2/users" in paths
    assert "https://analytics.example.net/collect" in urls


def test_crawl_of_an_unreachable_host_says_so(monkeypatch):
    def _boom(url, **kwargs):
        raise ConnectionError("unreachable")

    monkeypatch.setattr(crawler, "safe_get", _boom)
    monkeypatch.setattr(crawler, "validate_scan_target", lambda t, **k: (True, "example.com", ""))

    findings = crawler.run_crawler("example.com")

    assert len(findings) == 1
    assert "No Readable Pages" in findings[0]["title"]
    assert "not evidence" in findings[0]["description"].lower()


def test_http_is_tried_when_https_fails(monkeypatch):
    """A plain-HTTP host must not be reported as having no pages."""
    attempted: list[str] = []

    def _get(url, **kwargs):
        attempted.append(url)
        raise ConnectionError("refused")

    monkeypatch.setattr(crawler, "safe_get", _get)
    monkeypatch.setattr(crawler, "validate_scan_target", lambda t, **k: (True, "example.com", ""))

    crawler.run_crawler("example.com")

    assert any(url.startswith("https://") for url in attempted)
    assert any(url.startswith("http://") for url in attempted)


# ── dir_enum ────────────────────────────────────────────────────────────────

class _Resp:
    def __init__(self, status, body=b"", location=""):
        self.status_code = status
        self.content = body
        self.headers = {"Location": location} if location else {}
        self.url = ""

    @property
    def text(self):
        return self.content.decode()


def _server(real: dict[str, bytes], *, soft_404: bool):
    """A fake server: known paths answer, unknown ones 404 -- hard or soft."""
    def _get(url, **kwargs):
        path = "/" + url.split("/", 3)[-1] if url.count("/") > 2 else "/"
        path = path.rstrip("/") or "/"
        if path in real:
            return _Resp(200, real[path])
        if soft_404:
            # Echoes the requested path, so two "not found" bodies differ.
            return _Resp(200, b"<html>Sorry, " + path.encode() + b" was not found.</html>")
        return _Resp(404, b"<html>404 Not Found</html>")
    return _get


REAL_PATHS = {
    "/admin": b"<h1>Admin</h1>" + b"x" * 300,
    "/.env": b"DB_PASSWORD=redacted\n",
}


@pytest.mark.parametrize("soft_404", [False, True])
def test_real_paths_are_found_and_the_rest_suppressed(monkeypatch, soft_404):
    """A soft-404 server must not turn the whole wordlist into findings."""
    monkeypatch.setattr(dir_enum, "safe_get", _server(REAL_PATHS, soft_404=soft_404))
    monkeypatch.setattr(dir_enum, "validate_scan_target", lambda t, **k: (True, "example.com", ""))
    monkeypatch.setattr(dir_enum, "_load_wordlist",
                        lambda: (["admin", ".env", "nothing-here", "also-absent"], "test list"))

    findings = dir_enum.run_dir_enum("example.com")

    evidence = " ".join(f["evidence"] for f in findings)
    assert "/admin" in evidence
    assert "/.env" in evidence
    assert "nothing-here" not in evidence
    assert "also-absent" not in evidence


def test_configuration_paths_are_escalated(monkeypatch):
    monkeypatch.setattr(dir_enum, "safe_get", _server(REAL_PATHS, soft_404=False))
    monkeypatch.setattr(dir_enum, "validate_scan_target", lambda t, **k: (True, "example.com", ""))
    monkeypatch.setattr(dir_enum, "_load_wordlist", lambda: ([".env", "admin"], "test list"))

    findings = dir_enum.run_dir_enum("example.com")

    high = [f for f in findings if f["severity"] == "high"]
    assert high and ".env" in high[0]["evidence"]


def test_nothing_is_tested_without_a_baseline(monkeypatch):
    """Enumerating without knowing this server's 404 produces noise, not findings."""
    def _boom(url, **kwargs):
        raise ConnectionError("unreachable")

    monkeypatch.setattr(dir_enum, "safe_get", _boom)
    monkeypatch.setattr(dir_enum, "validate_scan_target", lambda t, **k: (True, "example.com", ""))

    findings = dir_enum.run_dir_enum("example.com")

    assert len(findings) == 1
    assert "Baseline" in findings[0]["title"]
    assert "not evidence" in findings[0]["description"].lower()


def test_empty_result_is_not_reported_as_a_clean_target(monkeypatch):
    monkeypatch.setattr(dir_enum, "safe_get", _server({}, soft_404=False))
    monkeypatch.setattr(dir_enum, "validate_scan_target", lambda t, **k: (True, "example.com", ""))
    monkeypatch.setattr(dir_enum, "_load_wordlist", lambda: (["absent"], "test list"))

    findings = dir_enum.run_dir_enum("example.com")

    assert "not that the server has no hidden paths" in findings[0]["description"]


def test_bundled_wordlists_are_present_and_usable():
    """The hardcoded Linux wordlist path made this module dead on Windows."""
    for tier in ("small", "common", "big"):
        path = dir_enum.WORDLIST_DIR / f"dirs-{tier}.txt"
        assert path.is_file(), f"missing bundled wordlist: {path}"
        assert len(dir_enum._read_wordlist(path)) > 50


def test_extensions_are_appended_without_losing_the_bare_name(monkeypatch):
    monkeypatch.setattr(dir_enum.settings, "DIR_ENUM_EXTENSIONS", ["php", "bak"])
    expanded = dir_enum._expand(["admin", "index.html"])

    assert "admin" in expanded
    assert "admin.php" in expanded and "admin.bak" in expanded
    # Already carries an extension, so it is left alone.
    assert "index.html.php" not in expanded


# ── wayback triage ──────────────────────────────────────────────────────────

ARCHIVED = [
    "http://example.com/js/app.min.js",
    "http://example.com/api/v2/users?id=5",
    "http://example.com/db/backup.sql",
    "http://example.com/go?url=http://elsewhere.test",
    "http://example.com/static/logo.png",
    "http://example.com/about/company",
]


def test_archived_urls_are_triaged_by_what_they_are():
    buckets = wayback._bucket(ARCHIVED)

    assert buckets["scripts"] == {"http://example.com/js/app.min.js"}
    assert buckets["api"] == {"http://example.com/api/v2/users?id=5"}
    assert ".sql" in buckets["sensitive"]
    assert "redirect / SSRF" in buckets["parameterised"]


def test_hostname_does_not_make_every_url_interesting():
    """Matching the whole URL meant a host containing 'api' flagged all of its URLs."""
    buckets = wayback._bucket(["http://api.example.com/static/logo.png"])
    assert buckets["interesting"] == set()


def test_compound_extensions_are_recognised():
    assert wayback._extension("/releases/site.tar.gz") == ".tar.gz"
    assert wayback._extension("/config/.env") == ".env"
    assert wayback._extension("/no-extension-here") == ""


def test_uninteresting_urls_stay_out_of_every_bucket():
    buckets = wayback._bucket(["http://example.com/static/logo.png"])

    assert not buckets["scripts"]
    assert not buckets["api"]
    assert not buckets["sensitive"]
    assert not buckets["interesting"]
