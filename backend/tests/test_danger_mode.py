"""Danger Mode coverage: opt-in gate, discovery, classification, and bounds.

Every test here runs against local fixtures or monkeypatched transports. No test
sends traffic to a real external host.
"""

from __future__ import annotations

from urllib.parse import unquote_plus

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.main import app
from app.middleware.security import rate_limiter
from app.models.schemas import AttackSurfaceItem, InjectionSignal, InputPointType, ScanType
from app.services import danger_mode
from app.services.capabilities import capabilities_payload, tools_for_profile
from app.tasks.http_client import SafeResponse
from app.tasks.vulnscan.danger import attack_surface, directory, dns_axfr, idor, injection, owasp
from app.tasks.vulnscan.danger.budget import CANARY, DangerBudget, ProbeResult, classify_signal, fingerprint


def client() -> TestClient:
    rate_limiter.requests.clear()
    rate_limiter.blocked.clear()
    return TestClient(app)


def response(url: str, body: bytes, headers: dict[str, str] | None = None, status: int = 200) -> SafeResponse:
    return SafeResponse(status_code=status, url=url, headers=headers or {}, content=body)


def probe(body: bytes = b"", status: int = 200, elapsed: float = 0.1, headers: dict[str, str] | None = None) -> ProbeResult:
    return ProbeResult(ok=True, response=response("https://example.com/", body, headers, status), elapsed=elapsed)


class StubBudget(DangerBudget):
    """Budget that serves scripted responses instead of touching the network."""

    def __init__(self, handler, **kwargs):
        super().__init__(delay_seconds=0.0, **kwargs)
        self.handler = handler
        self.calls: list[tuple[str, str, bytes | None]] = []

    def probe(self, module, method, url, *, headers=None, body=None, timeout=None, counts_as_payload=True):
        if not self.can_spend(module):
            self.exhausted = True
            return ProbeResult(ok=False, error="budget_exhausted")
        self.requests_sent += 1
        self.per_module[module] = self.per_module.get(module, 0) + 1
        if counts_as_payload:
            self.payloads_sent += 1
        self.calls.append((method, url, body))
        return self.handler(method, url, body, headers)


# ── Opt-in gate ───────────────────────────────────────────────────────────────

def test_danger_gate_blocks_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", False)
    result = danger_mode.check_danger_gate("danger", acknowledgement=danger_mode.DANGER_ACKNOWLEDGEMENT)
    assert result.allowed is False
    assert "ALLOW_DANGER_MODE" in result.reason


def test_danger_gate_requires_typed_acknowledgement(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", True)
    assert danger_mode.check_danger_gate("danger", acknowledgement=None).allowed is False
    assert danger_mode.check_danger_gate("danger", acknowledgement="yes").allowed is False
    assert danger_mode.check_danger_gate("danger", acknowledgement="i am authorized").allowed is False
    assert danger_mode.check_danger_gate("danger", acknowledgement="I am authorized").allowed is True
    assert danger_mode.check_danger_gate("danger", acknowledgement="  I am authorized  ").allowed is True


def test_danger_gate_never_blocks_safe_profiles(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", False)
    for profile in ("full", "recon_only", "osint_only", "vuln_only"):
        assert danger_mode.check_danger_gate(profile).allowed is True


def test_require_danger_enabled_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", False)
    with pytest.raises(danger_mode.DangerModeDisabled):
        danger_mode.require_danger_enabled()


def test_test_scan_endpoint_rejects_danger_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", False)
    with client() as test_client:
        result = test_client.get("/api/test-scan", params={"target": "example.com", "scan_type": "danger"})
    assert result.status_code == 403
    assert "ALLOW_DANGER_MODE" in result.json()["detail"]


def test_test_scan_endpoint_rejects_danger_without_acknowledgement(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", True)
    with client() as test_client:
        result = test_client.get("/api/test-scan", params={"target": "example.com", "scan_type": "danger"})
    assert result.status_code == 403
    assert "acknowledgement" in result.json()["detail"].lower()


def test_scan_endpoint_rejects_danger_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", False)
    with client() as test_client:
        result = test_client.post("/api/scan", json={
            "target": "example.com",
            "scan_type": "danger",
            "danger_acknowledgement": danger_mode.DANGER_ACKNOWLEDGEMENT,
        })
    assert result.status_code == 403


def test_capabilities_publishes_danger_profile_and_gate_state(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", False)
    payload = capabilities_payload("0.4.1")
    danger = next(profile for profile in payload["profiles"] if profile["key"] == "danger")
    assert danger["enabled"] is False
    assert danger["requires_opt_in"] is True
    assert "danger_recon" in danger["tools"]
    assert payload["danger_mode"]["enabled"] is False
    assert payload["danger_mode"]["acknowledgement_phrase"] == "I am authorized"
    assert len(payload["danger_mode"]["owasp_coverage"]) == 10
    assert payload["danger_mode"]["bounds"]["idor_max_ids"] >= 2


def test_danger_profile_is_selectable_scan_type():
    assert ScanType("danger") is ScanType.DANGER
    assert "danger_recon" in tools_for_profile("danger")


def test_disabled_pipeline_emits_only_a_notice(monkeypatch):
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", False)
    from app.tasks.vulnscan.danger.pipeline import run_danger_pipeline

    findings, summary = run_danger_pipeline("example.com")
    assert len(findings) == 1
    assert findings[0]["title"] == "Danger Mode Disabled"
    assert summary.enabled is False
    assert summary.requests_sent == 0


# ── Attack-surface discovery ──────────────────────────────────────────────────

FIXTURE_HTML = b"""
<html><body>
  <form action="/login" method="post">
    <input name="username"><input name="password" type="password">
  </form>
  <form action="/search" method="get"><input name="q"></form>
  <form action="/upload" method="post" enctype="multipart/form-data">
    <input name="attachment" type="file">
  </form>
  <a href="/profile?user_id=42">profile</a>
  <a href="/api/v1/orders?order=1001">order</a>
  <a href="/fetch?url=https://example.com/x">fetch</a>
  <a href="/docs/1042">doc</a>
  <a href="https://third-party.test/off-scope?id=1">offsite</a>
</body></html>
"""


def test_attack_surface_classifies_every_input_point():
    def handler(method, url, body, headers):
        if "third-party" in url:
            raise AssertionError("crawler left the target scope")
        return probe(FIXTURE_HTML, headers={"Content-Type": "text/html"})

    budget = StubBudget(handler)
    items, visited = attack_surface.build_attack_surface("example.com", budget)
    by_type = {item.input_type for item in items}

    assert visited
    assert InputPointType.LOGIN_FORM in by_type
    assert InputPointType.SEARCH_FORM in by_type
    assert InputPointType.UPLOAD_FORM in by_type
    assert InputPointType.OBJECT_REFERENCE in by_type
    assert InputPointType.URL_PARAM in by_type
    assert InputPointType.API_ENDPOINT in by_type

    login = next(item for item in items if item.input_type is InputPointType.LOGIN_FORM)
    assert login.method == "POST"
    assert set(login.parameters) == {"username", "password"}
    assert login.url.endswith("/login")
    assert all("third-party.test" not in item.url for item in items)


def test_attack_surface_findings_report_upload_endpoints():
    budget = StubBudget(lambda *args: probe(FIXTURE_HTML, headers={"Content-Type": "text/html"}))
    items, findings = attack_surface.run_attack_surface("example.com", budget)
    assert items
    assert all(finding["requires_manual_validation"] for finding in findings)
    titles = [finding["title"] for finding in findings]
    assert any("Attack Surface Inventory" in title for title in titles)
    assert any("File Upload" in title for title in titles)


def test_crawler_respects_page_ceiling(monkeypatch):
    monkeypatch.setattr(settings, "DANGER_MAX_CRAWL_PAGES", 3)
    html = b'<html><body>' + b"".join(
        f'<a href="/page{index}">p</a>'.encode() for index in range(50)
    ) + b'</body></html>'
    budget = StubBudget(lambda *args: probe(html, headers={"Content-Type": "text/html"}))
    _, visited = attack_surface.build_attack_surface("example.com", budget)
    assert len(visited) <= 3


# ── Injection classification ──────────────────────────────────────────────────

def test_classify_signal_detects_error_reflection_timing_and_differential():
    baseline = probe(b"x" * 1000, status=200, elapsed=0.1)
    error = probe(b"You have an error in your SQL syntax near", status=500)
    assert classify_signal(baseline, error, error_markers=injection.SQL_ERROR_MARKERS) is InjectionSignal.ERROR

    reflected = probe(f"hello {CANARY} world".encode())
    assert classify_signal(baseline, reflected, reflection=CANARY) is InjectionSignal.REFLECTED

    slow = probe(b"x" * 1000, elapsed=3.5)
    assert classify_signal(baseline, slow, timing_threshold=2.0) is InjectionSignal.TIMING

    different = probe(b"x" * 100)
    assert classify_signal(baseline, different) is InjectionSignal.DIFFERENTIAL

    same = probe(b"x" * 1000)
    assert classify_signal(baseline, same) is InjectionSignal.NONE

    assert classify_signal(baseline, ProbeResult(ok=False)) is InjectionSignal.NONE


def _context(handler, items):
    budget = StubBudget(handler)
    return injection.InjectionContext(target="example.com", budget=budget, items=items)


QUERY_ITEM = AttackSurfaceItem(
    id="as_1", url="https://example.com/item?id=1", method="GET",
    input_type=InputPointType.QUERY_PARAM, parameters=["id"],
)


def test_sql_injection_reports_error_based_candidate():
    """An error signal on a value-insensitive endpoint stays a candidate, not a proof."""
    def handler(method, url, body, headers):
        if "%27" in url or "'" in url:
            return probe(b"Warning: mysql_fetch_array(): supplied argument... SQL syntax", status=500)
        return probe(b"normal page body")

    findings = injection.run_sql_injection(_context(handler, [QUERY_ITEM]))
    sqli = [item for item in findings if item["category"] == "danger_injection_sql"]
    assert sqli
    assert sqli[0]["severity"] == "high"
    assert sqli[0]["owasp_category"] == "A03:2021-Injection"
    assert sqli[0]["requires_manual_validation"] is True
    assert "Response signal: error" in sqli[0]["evidence"]
    # Every id renders the same page, so arithmetic proves nothing and the
    # engine must not claim exploitation.
    assert sqli[0].get("exploited") is not True
    assert "[EXPLOITED]" not in sqli[0]["title"]
    assert "Database family: mysql" in sqli[0]["evidence"]


def test_sql_injection_arithmetic_needs_a_value_sensitive_endpoint():
    """Guards the false positive: identical output for every id is not injection."""
    from app.tasks.vulnscan.danger.exploit import confirm_sql_injection

    same_page = probe(b"a static page that ignores the id entirely")
    result = confirm_sql_injection(lambda payload: same_page, same_page, "1", lambda: True)
    assert result.confirmed is False


def test_sql_arithmetic_rejects_apps_that_default_on_a_parse_error():
    """An app that falls back to a default on bad input mimics arithmetic evaluation.

    `limit=2-0` returning the same page as `limit=2` looks like the database
    computed 2-0, but it is far more often int() raising and the handler using
    its default. Obvious garbage must therefore also be rejected.
    """
    from app.tasks.vulnscan.danger.exploit import confirm_sql_injection

    baseline_body = b"x" * 500
    def send(payload):
        if payload.isdigit() and int(payload) > 90000:
            return probe(b"y" * 5000)          # value-sensitive: a big id differs
        return probe(baseline_body)            # everything else falls back to default

    result = confirm_sql_injection(send, probe(baseline_body), "2", lambda: True)
    assert result.confirmed is False, "silent default must not be reported as arithmetic evaluation"


def test_sql_injection_confirmed_by_boolean_differential():
    """TRUE renders the record, FALSE does not - that differential is conclusive."""
    def handler(method, url, body, headers):
        decoded = unquote_plus(url)
        if "'1'='1" in decoded or "'1' LIKE '1" in decoded:
            return probe(b"<html><body>Record 1: Widget, in stock, 40 units</body></html>")
        if "'1'='2" in decoded or "'1' LIKE '2" in decoded:
            return probe(b"<html><body>No record found</body></html>")
        if "@@version" in decoded:
            return probe(b"<html><body>8.0.36-0ubuntu0.22.04.1 MySQL</body></html>")
        return probe(b"<html><body>Record 1: Widget, in stock, 40 units</body></html>")

    context = _context(handler, [QUERY_ITEM])
    findings = injection.run_sql_injection(context)
    exploited = [item for item in findings if item.get("exploited")]
    assert exploited, "boolean differential should confirm injection"
    finding = exploited[0]
    assert finding["severity"] == "critical"
    assert finding["title"].startswith("[EXPLOITED]")
    assert "Boolean-based blind" in finding["exploit_technique"]
    assert "CONFIRMED" in finding["confidence"]
    assert "Exploitation status: CONFIRMED" in finding["evidence"]
    assert "Reproduction steps" in finding["evidence"]
    assert "MySQL" in finding["exploit_proof"] or "8.0.36" in finding["exploit_proof"]
    # Proof only - the engine must never claim to have read table data.
    assert "Data extracted beyond proof: none" in finding["evidence"]
    assert context.exploits and context.exploits[0].confirmed


def test_sql_injection_stays_quiet_on_a_clean_endpoint():
    findings = injection.run_sql_injection(_context(lambda *args: probe(b"stable body"), [QUERY_ITEM]))
    assert [item for item in findings if item["category"] == "danger_injection_sql"] == []


def test_command_injection_classifies_direct_versus_blind():
    def direct(method, url, body, headers):
        return probe(f"output: {CANARY}".encode()) if "echo" in url or "printf" in url else probe(b"x")

    context = _context(direct, [QUERY_ITEM])
    findings = injection.run_command_injection(context)
    assert findings
    assert findings[0]["severity"] == "critical"
    assert "direct output" in findings[0]["title"]
    assert context.command_candidates[0]["context"] == "direct output"


def test_html_and_xss_probes_require_reflection():
    def reflecting(method, url, body, headers):
        from urllib.parse import unquote_plus

        return probe(unquote_plus(url).encode())

    html_findings = injection.run_html_injection(_context(reflecting, [QUERY_ITEM]))
    assert any(item["category"] == "danger_injection_html" for item in html_findings)

    xss_findings = injection.run_xss(_context(reflecting, [QUERY_ITEM]))
    assert any(item["category"] == "danger_injection_xss" for item in xss_findings)

    quiet = injection.run_xss(_context(lambda *args: probe(b"escaped &lt;script&gt;"), [QUERY_ITEM]))
    assert [item for item in quiet if item["category"] == "danger_injection_xss"] == []


def test_ssti_requires_evaluated_arithmetic():
    """The engine must see its own product computed, not a coincidental number."""
    from app.tasks.vulnscan.danger.payloads import MATH_PRODUCT

    evaluated = injection.run_ssti(
        _context(lambda *args: probe(f"result is {MATH_PRODUCT} here".encode()), [QUERY_ITEM])
    )
    ssti = [item for item in evaluated if item["category"] == "danger_injection_ssti"]
    assert ssti
    assert ssti[0]["exploited"] is True
    assert ssti[0]["severity"] == "critical"
    assert ssti[0]["title"].startswith("[EXPLOITED]")
    assert MATH_PRODUCT in ssti[0]["exploit_proof"]

    # The literal expression echoed back is not evaluation.
    literal = injection.run_ssti(
        _context(lambda *args: probe(b"you typed {{8675*3099}}"), [QUERY_ITEM])
    )
    assert [item for item in literal if item["category"] == "danger_injection_ssti"] == []

    # A page that merely contains the number without the payload being sent
    # must not confirm either - the literal must be absent AND the product present.
    quiet = injection.run_ssti(_context(lambda *args: probe(b"nothing to see"), [QUERY_ITEM]))
    assert [item for item in quiet if item["category"] == "danger_injection_ssti"] == []


def test_ssrf_only_fires_on_a_differential_against_the_control():
    url_item = AttackSurfaceItem(
        id="as_2", url="https://example.com/fetch?url=https://a.test/", method="GET",
        input_type=InputPointType.URL_PARAM, parameters=["url"],
    )

    def differential(method, url, body, headers):
        if "127.0.0.1" in url or "169.254" in url:
            return probe(b"connection refused to internal host", status=500)
        return probe(b"x" * 500)

    findings = injection.run_ssrf(_context(differential, [url_item]))
    assert any(item["owasp_category"] == "A10:2021-Server-Side Request Forgery" for item in findings)

    quiet = injection.run_ssrf(_context(lambda *args: probe(b"x" * 500), [url_item]))
    assert quiet == []


def test_injection_matrix_records_probes_that_found_nothing():
    context = _context(lambda *args: probe(b"stable body"), [QUERY_ITEM])
    injection.run_sql_injection(context)
    matrix = injection.injection_matrix_finding(context)
    assert context.matrix
    assert all(entry.requires_manual_validation for entry in context.matrix)
    assert "Injection Test Matrix" in matrix["title"]
    assert "probes=" in matrix["evidence"]


def test_injection_evidence_never_contains_response_bodies():
    secret_body = b"SESSION=super-secret-token-value; user=alice@example.com"

    def leaky(method, url, body, headers):
        return probe(b"SQL syntax error near " + secret_body, status=500)

    context = _context(leaky, [QUERY_ITEM])
    findings = injection.run_sql_injection(context)
    rendered = "\n".join(str(item) for item in findings)
    assert "super-secret-token-value" not in rendered
    assert "alice@example.com" not in rendered


# ── AXFR ──────────────────────────────────────────────────────────────────────

class FakeZone:
    def __init__(self, names):
        self.nodes = {name: object() for name in names}


def test_axfr_success_is_high_severity_with_summarized_zone(monkeypatch):
    monkeypatch.setattr(dns_axfr, "enumerate_records", lambda domain: {"NS": ["ns1.example.com."], "A": ["1.2.3.4"]})
    monkeypatch.setattr(dns_axfr, "_nameserver_addresses", lambda ns: ["203.0.113.10"])
    monkeypatch.setattr(dns_axfr.dns.query, "xfr", lambda *args, **kwargs: object())
    monkeypatch.setattr(dns_axfr.dns.zone, "from_xfr", lambda source: FakeZone(["@", "www", "vpn", "internal"]))

    findings = dns_axfr.run_dns_axfr("example.com")
    transfers = [item for item in findings if item["category"] == "danger_zone_transfer"]
    assert transfers
    assert transfers[0]["severity"] == "high"
    assert "ns1.example.com" in transfers[0]["title"]
    assert "Record nodes transferred: 4" in transfers[0]["evidence"]
    assert "vpn.example.com" in transfers[0]["evidence"]


def test_axfr_refusal_is_informational(monkeypatch):
    monkeypatch.setattr(dns_axfr, "enumerate_records", lambda domain: {"NS": ["ns1.example.com."]})
    monkeypatch.setattr(dns_axfr, "_nameserver_addresses", lambda ns: ["203.0.113.10"])

    def refuse(*args, **kwargs):
        raise ConnectionRefusedError("refused")

    monkeypatch.setattr(dns_axfr.dns.query, "xfr", refuse)
    findings = dns_axfr.run_dns_axfr("example.com")
    transfers = [item for item in findings if item["category"] == "danger_zone_transfer"]
    assert transfers
    assert all(item["severity"] == "info" for item in transfers)
    assert "Refused" in transfers[0]["title"]


def test_axfr_without_nameservers_is_informational(monkeypatch):
    monkeypatch.setattr(dns_axfr, "enumerate_records", lambda domain: {"NS": []})
    findings = dns_axfr.run_dns_axfr("example.com")
    assert any("No Name Servers" in item["title"] for item in findings)


# ── IDOR ──────────────────────────────────────────────────────────────────────

def test_idor_identifier_format_detection():
    assert idor._id_format("42") == "numeric"
    assert idor._id_format("6ba7b810-9dad-11d1-80b4-00c04fd430c8") == "uuidv1"
    assert idor._id_format("f47ac10b-58cc-4372-a567-0e02b2c3d479") == "uuidv4"
    assert idor._id_format("MTAwMQ==") == "base64_numeric"
    assert idor._id_format("shopping-cart") == "opaque"


def test_idor_detects_differential_access():
    item = AttackSurfaceItem(
        id="as_3", url="https://example.com/invoice?id=1000", method="GET",
        input_type=InputPointType.OBJECT_REFERENCE, parameters=["id"],
    )

    def handler(method, url, body, headers):
        if method == "POST":
            return probe(b"", status=405)
        marker = url.rsplit("id=", 1)[-1]
        return probe(f"invoice for customer {marker} with distinct content padding".encode())

    findings = idor.run_idor_tests("example.com", StubBudget(handler), [item])
    candidates = [entry for entry in findings if entry["category"] == "danger_idor"]
    assert candidates
    assert candidates[0]["severity"] == "high"
    assert candidates[0]["owasp_category"] == "A01:2021-Broken Access Control"
    assert "Object content stored: no - fingerprint and size only" in candidates[0]["evidence"]


def test_idor_stays_quiet_when_every_id_returns_the_same_object():
    item = AttackSurfaceItem(
        id="as_4", url="https://example.com/invoice?id=1000", method="GET",
        input_type=InputPointType.OBJECT_REFERENCE, parameters=["id"],
    )
    handler = lambda method, url, body, headers: probe(b"access denied", status=403)
    findings = idor.run_idor_tests("example.com", StubBudget(handler), [item])
    assert [entry for entry in findings if entry["category"] == "danger_idor"] == []
    assert any(entry["category"] == "danger_idor_summary" for entry in findings)


def test_idor_never_stores_object_contents():
    item = AttackSurfaceItem(
        id="as_5", url="https://example.com/doc?doc_id=7", method="GET",
        input_type=InputPointType.OBJECT_REFERENCE, parameters=["doc_id"],
    )
    secret = b"PATIENT RECORD: Jane Doe, SSN 123-45-6789, diagnosis confidential"
    handler = lambda method, url, body, headers: probe(secret + url.encode())
    findings = idor.run_idor_tests("example.com", StubBudget(handler), [item])
    rendered = "\n".join(str(entry) for entry in findings)
    assert "Jane Doe" not in rendered
    assert "123-45-6789" not in rendered
    assert "sha256:" in rendered


def test_idor_respects_the_identifier_ceiling(monkeypatch):
    monkeypatch.setattr(settings, "DANGER_IDOR_MAX_IDS", 4)
    item = AttackSurfaceItem(
        id="as_6", url="https://example.com/x?id=10", method="GET",
        input_type=InputPointType.OBJECT_REFERENCE, parameters=["id"],
    )
    budget = StubBudget(lambda *args: probe(b"body"))
    idor.run_idor_tests("example.com", budget, [item])
    enumerated = {
        url.rsplit("id=", 1)[-1]
        for method, url, _ in budget.calls
        if method == "GET" and "id=" in url
    }
    # The original identifier plus at most DANGER_IDOR_MAX_IDS adjacent ones.
    assert len(enumerated) <= 5
    assert "10" in enumerated


# ── Directory fuzzing and traversal ───────────────────────────────────────────

def test_directory_fuzzing_filters_soft_404s(monkeypatch):
    monkeypatch.setattr(settings, "DANGER_DIR_BUST_WORDLIST", 10)

    def handler(method, url, body, headers):
        if url.endswith("/admin"):
            return probe(b"<html>admin login</html>" * 10, status=200)
        return probe(b"not found page", status=200)

    findings = directory.run_directory_fuzzing("example.com", StubBudget(handler), ["https://example.com/"])
    summary = next(item for item in findings if item["category"] == "danger_directory_fuzzing")
    assert "/admin" in summary["evidence"]
    assert summary["evidence"].count("\n  ") <= 3


def test_directory_fuzzing_flags_sensitive_paths(monkeypatch):
    monkeypatch.setattr(settings, "DANGER_DIR_BUST_WORDLIST", 60)

    def handler(method, url, body, headers):
        if url.endswith("/.git/HEAD"):
            return probe(b"ref: refs/heads/main\n", status=200)
        return probe(b"", status=404)

    findings = directory.run_directory_fuzzing("example.com", StubBudget(handler), ["https://example.com/"])
    sensitive = [item for item in findings if item["category"] == "danger_sensitive_path"]
    assert sensitive
    assert sensitive[0]["severity"] == "high"
    assert ".git/HEAD" in sensitive[0]["evidence"]


def test_directory_listing_detection(monkeypatch):
    monkeypatch.setattr(settings, "DANGER_DIR_BUST_WORDLIST", 80)

    def handler(method, url, body, headers):
        if url.endswith("/uploads"):
            return probe(b"<html><title>Index of /uploads</title><a href='a.txt'>a</a></html>", status=200)
        return probe(b"", status=404)

    findings = directory.run_directory_fuzzing("example.com", StubBudget(handler), ["https://example.com/"])
    assert any(item["category"] == "danger_directory_listing" for item in findings)


def test_path_traversal_reports_signature_match_without_body():
    item = AttackSurfaceItem(
        id="as_7", url="https://example.com/read?file=notes.txt", method="GET",
        input_type=InputPointType.QUERY_PARAM, parameters=["file"],
    )
    passwd = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    handler = lambda method, url, body, headers: probe(passwd) if "etc" in url else probe(b"notes")

    findings = directory.run_path_traversal("example.com", StubBudget(handler), [item])
    hits = [entry for entry in findings if entry["severity"] == "critical"]
    assert hits
    assert "unix_passwd" in hits[0]["evidence"]
    assert "daemon:x:1:1" not in hits[0]["evidence"]
    assert "Response body stored: no - fingerprint only" in hits[0]["evidence"]


def test_path_traversal_without_file_parameters_is_informational():
    item = AttackSurfaceItem(
        id="as_8", url="https://example.com/search?q=x", method="GET",
        input_type=InputPointType.SEARCH_FORM, parameters=["q"],
    )
    findings = directory.run_path_traversal("example.com", StubBudget(lambda *args: probe(b"")), [item])
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert "no file-serving parameters" in findings[0]["title"]


# ── Reverse shell assessment ──────────────────────────────────────────────────

def test_reverse_shell_documents_vectors_without_payloads():
    from app.tasks.vulnscan.danger import reverse_shell

    candidates = [{
        "url": "https://example.com/ping?host=1.1.1.1", "method": "GET", "parameter": "host",
        "context": "direct output", "payload_category": "separator_echo",
        "signal": "reflected", "input_type": "query_param",
    }]
    findings = reverse_shell.assess_reverse_shell_vectors("example.com", candidates)
    assert len(findings) == 1
    finding = findings[0]
    assert finding["severity"] == "high"
    assert finding["requires_manual_validation"] is True
    assert "Connection attempted by ReconTitan: no" in finding["evidence"]
    assert "Payload generated by ReconTitan: no" in finding["evidence"]
    # The module names interpreter families but must never emit a usable payload.
    rendered = finding["evidence"] + finding["description"]
    for forbidden in ("/dev/tcp/", "nc -e", "bash -i", "socket.connect", "sh -i", "0>&1"):
        assert forbidden not in rendered


def test_reverse_shell_without_candidates_is_informational():
    from app.tasks.vulnscan.danger import reverse_shell

    findings = reverse_shell.assess_reverse_shell_vectors("example.com", [])
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"


# ── OWASP matrix ──────────────────────────────────────────────────────────────

def test_owasp_matrix_marks_tested_and_untested_categories():
    findings = [
        {"owasp_category": "A03:2021-Injection"},
        {"owasp_category": "A03:2021-Injection"},
        {"owasp_category": "A01:2021-Broken Access Control"},
    ]
    entries = owasp.build_owasp_matrix(findings, ["injection_sqli", "idor_testing"])
    assert len(entries) == 10
    by_key = {entry.category.value: entry for entry in entries}
    assert by_key["A03:2021-Injection"].tested is True
    assert by_key["A03:2021-Injection"].findings == 2
    assert by_key["A01:2021-Broken Access Control"].tested is True
    assert by_key["A09:2021-Security Logging and Monitoring Failures"].tested is False

    rendered = owasp.owasp_matrix_finding("example.com", entries)
    assert "NOT TESTED" in rendered["evidence"]
    assert "TESTED" in rendered["evidence"]


def test_known_vulnerable_version_fingerprints(monkeypatch):
    monkeypatch.setattr(
        owasp, "run_tech_stack_detection", lambda target: [], raising=False
    )
    monkeypatch.setattr(
        "app.tasks.recon.tech_stack.run_tech_stack_detection",
        lambda target: [{"evidence": "• jQuery 3.4.1 [JavaScript] — matched jquery\n• nginx 1.14.0 [Web server] — matched server"}],
    )
    findings = owasp.check_outdated_components("example.com")
    assert findings[0]["severity"] == "high"
    assert "jquery 3.4.1" in findings[0]["evidence"].lower()


# ── Budget and safety bounds ──────────────────────────────────────────────────

def test_budget_enforces_total_module_and_payload_ceilings():
    budget = DangerBudget(max_requests_total=5, max_requests_per_module=2, max_payloads=100, delay_seconds=0)
    assert budget.remaining("a") == 2
    budget.requests_sent, budget.per_module["a"] = 2, 2
    assert budget.can_spend("a") is False
    assert budget.can_spend("b") == True

    payload_bound = DangerBudget(max_requests_total=100, max_requests_per_module=100, max_payloads=3, delay_seconds=0)
    payload_bound.payloads_sent = 3
    assert payload_bound.can_spend("a") is False


def test_budget_enforces_a_wall_clock_deadline():
    """Request counting alone cannot bound a scan; elapsed time must too."""
    budget = DangerBudget(max_requests_total=10_000, max_payloads=10_000, delay_seconds=0, max_seconds=60)
    assert budget.can_spend("m") is True
    assert budget.expired is False
    # Pretend the scan started 61 seconds ago.
    budget.started_at -= 61
    assert budget.time_left == 0
    assert budget.expired is True
    assert budget.timed_out is True
    assert budget.remaining("m") == 0
    assert budget.can_spend("m") is False

    result = budget.probe("m", "GET", "https://example.com/")
    assert result.ok is False
    assert result.error == "deadline_reached"
    assert budget.snapshot()["timed_out"] is True


def test_danger_clock_starts_at_the_first_stage_not_at_construction(monkeypatch):
    """The recon/OSINT/vuln groups run first and must not eat the danger budget."""
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", True)
    from app.tasks.vulnscan.danger.pipeline import DangerSession

    session = DangerSession(target="example.com", budget=DangerBudget(delay_seconds=0, max_seconds=60))
    assert session.budget.clock_started is False

    # Simulate 300s of safe-profile work before any danger stage runs.
    session.budget.started_at -= 300
    assert session.budget.expired is True, "clock is running from construction"

    # The first guarded stage must restart the clock, giving danger its full budget.
    name, stage = session.stages()[0]
    session.budget.begin()
    assert session.budget.clock_started is True
    assert session.budget.time_left > 55
    assert session.budget.expired is False


def test_deadline_skips_remaining_stages_but_still_produces_a_report(monkeypatch):
    """A slow target must never leave the caller with no report at all."""
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", True)
    from app.tasks.vulnscan.danger.pipeline import DangerSession

    session = DangerSession(target="example.com", budget=DangerBudget(delay_seconds=0, max_seconds=60))
    # Mark the clock as already started, then age it, so begin() does not reset
    # it and no stage performs real network work.
    session.budget.clock_started = True
    session.budget.started_at -= 120

    ran: list[str] = []
    for name, stage in session.stages():
        if name == "owasp_matrix":
            continue  # exercised separately; it performs real network work
        stage("example.com")
        ran.append(name)

    # Every guarded stage returned immediately and recorded itself as skipped.
    assert session.stages_skipped == ran
    assert session.budget.requests_sent == 0

    notice = session.deadline_finding()
    assert "Stopped at Time Limit" in notice["title"]
    assert notice["requires_manual_validation"] is True
    assert "Stages skipped" in notice["evidence"]

    summary = session.summary()
    assert summary.timed_out is True
    assert summary.stages_skipped == ran
    assert summary.stages_completed == []
    assert summary.elapsed_seconds >= 120


def test_owasp_matrix_still_runs_after_the_deadline():
    """The coverage report itself must not be skipped, or there is no output."""
    from app.tasks.vulnscan.danger.pipeline import DangerSession

    session = DangerSession(target="example.com", budget=DangerBudget(delay_seconds=0, max_seconds=60))
    session.budget.clock_started = True
    session.budget.started_at -= 120
    names = [name for name, _ in session.stages()]
    guarded = dict(session.stages())
    assert "owasp_matrix" in names
    # Calling every other stage marks it skipped; owasp_matrix is not guarded out.
    for name in names:
        if name != "owasp_matrix":
            guarded[name]("example.com")
    assert "owasp_matrix" not in session.stages_skipped


def test_probe_timeout_is_clamped_to_remaining_time():
    """One slow probe must not overrun the deadline by its full timeout."""
    budget = DangerBudget(delay_seconds=0, timeout=30, max_seconds=60)
    budget.started_at -= 58  # only ~2s left
    captured = {}

    def fake_request(method, url, *, timeout, max_bytes, headers, body, **kwargs):
        captured["timeout"] = timeout
        raise RuntimeError("stop here")

    import app.tasks.vulnscan.danger.budget as budget_module

    original = budget_module.safe_request
    budget_module.safe_request = fake_request
    try:
        budget.probe("m", "GET", "https://example.com/")
    finally:
        budget_module.safe_request = original

    assert captured["timeout"] <= 2.5, "timeout should be clamped to the remaining budget, not 30s"
    assert captured["timeout"] >= 1.0


def test_pacing_never_sleeps_past_the_deadline():
    budget = DangerBudget(delay_seconds=5.0, max_seconds=60)
    budget.started_at -= 59.5  # 0.5s left, but pacing wants 5s
    started = __import__("time").monotonic()
    budget._pace()
    assert __import__("time").monotonic() - started < 1.5


def test_budget_probe_returns_failure_instead_of_raising_when_exhausted():
    budget = DangerBudget(max_requests_total=0, delay_seconds=0)
    result = budget.probe("m", "GET", "https://example.com/")
    assert result.ok is False
    assert result.error == "budget_exhausted"
    assert budget.exhausted is True


def test_budget_backs_off_when_the_target_signals_throttling():
    budget = DangerBudget(delay_seconds=0)
    budget._observe(429)
    first = budget._backoff
    assert first > 0
    budget._observe(503)
    escalated = budget._backoff
    assert escalated > first
    budget._observe(200)
    assert budget._backoff < escalated
    assert budget._backoff >= 0


def test_fingerprint_is_stable_and_non_reversible():
    secret = "session=abcdef123456"
    first = fingerprint(secret)
    assert first == fingerprint(secret)
    assert first != fingerprint("session=other")
    assert secret not in first
    assert first.startswith("sha256:")


def test_danger_bounds_are_published_and_positive():
    bounds = danger_mode.danger_bounds()
    for key in (
        "max_requests_total", "max_requests_per_module", "max_payloads_per_scan",
        "max_endpoints", "idor_max_ids", "dir_bust_wordlist",
    ):
        assert bounds[key] > 0
    assert bounds["xxe_oob_enabled"] is False


def test_every_danger_module_marks_findings_for_manual_validation():
    from app.tasks.vulnscan.danger.budget import danger_finding

    finding = danger_finding(
        tool="t", category="c", severity="high", title="x",
        description="Something was observed.", evidence="Key: value",
    )
    assert finding["requires_manual_validation"] is True
    assert "requires manual validation" in finding["confidence"].lower()
    assert danger_mode.MANUAL_VALIDATION_NOTE in finding["description"]
