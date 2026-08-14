"""End-to-end Danger Mode tests against a local, deliberately weak fixture server.

The fixture binds to 127.0.0.1 on an ephemeral port and is torn down with the
module. No traffic leaves the machine and no external target is ever contacted.
These tests exercise the real pinned HTTP client, so they also prove the danger
modules work through the production transport rather than a stub.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from app.config import settings
from app.models.schemas import InputPointType
from app.tasks.vulnscan.danger import attack_surface, directory, idor, injection
from app.tasks.vulnscan.danger.budget import DangerBudget

INDEX_HTML = b"""<html><body>
<h1>Fixture app</h1>
<form action="/login" method="post"><input name="username"><input name="password" type="password"></form>
<form action="/search" method="get"><input name="q"></form>
<form action="/upload" method="post" enctype="multipart/form-data"><input name="attachment" type="file"></form>
<a href="/item?id=1">item</a>
<a href="/invoice?id=1000">invoice</a>
<a href="/read?file=notes.txt">notes</a>
<a href="/fetch?url=https://example.com/logo.png">fetch</a>
<a href="/api/v1/orders?order=7">orders</a>
</body></html>"""

PASSWD = b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
SQL_ERROR = b"<html><body>Warning: You have an error in your SQL syntax near '''' at line 1</body></html>"


class FixtureHandler(BaseHTTPRequestHandler):
    """A deliberately weak application used only as a local test target."""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # keep pytest output clean
        return

    def _send(self, body: bytes, status: int = 200, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length)
        self._send(b"<html><body>submitted</body></html>")

    def do_GET(self):
        split = urlsplit(self.path)
        params = parse_qs(split.query, keep_blank_values=True)
        path = split.path

        if path == "/":
            return self._send(INDEX_HTML)

        if path == "/item":
            value = (params.get("id") or [""])[0]
            if "'" in value or '"' in value:
                return self._send(SQL_ERROR, status=500)
            return self._send(f"<html><body>Item {value} in stock</body></html>".encode())

        if path == "/search":
            # Reflects input unescaped: HTML injection and reflected XSS.
            value = (params.get("q") or [""])[0]
            return self._send(f"<html><body>Results for {value}</body></html>".encode())

        if path == "/read":
            value = unquote(unquote((params.get("file") or [""])[0]))
            if "etc" in value and ".." in value.replace("%2e", ".").replace("\\", "/"):
                return self._send(PASSWD, content_type="text/plain")
            return self._send(b"<html><body>notes.txt contents</body></html>")

        if path == "/invoice":
            # Every identifier returns a distinct object with no access control.
            value = (params.get("id") or [""])[0]
            body = f"<html><body>Invoice {value} for customer {value} total {int(value or 0) * 7}</body></html>"
            return self._send(body.encode())

        if path == "/uploads":
            return self._send(b"<html><head><title>Index of /uploads</title></head><body>"
                              b"<a href='a.txt'>a.txt</a><a href='b.txt'>b.txt</a></body></html>")

        if path == "/.git/HEAD":
            return self._send(b"ref: refs/heads/main\n", content_type="text/plain")

        if path == "/admin":
            return self._send(b"<html><body>admin console login required</body></html>", status=403)

        return self._send(b"<html><body>not found</body></html>", status=404)


@pytest.fixture(scope="module")
def fixture_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.fixture()
def local_target(monkeypatch):
    """Allow the pinned client to reach loopback, and remove pacing delay."""
    monkeypatch.setattr(settings, "ALLOW_PRIVATE_TARGETS", True)
    monkeypatch.setattr(settings, "ALLOW_DANGER_MODE", True)
    monkeypatch.setattr(settings, "DANGER_REQUEST_DELAY_MS", 0)
    return "127.0.0.1"


def _budget(**kwargs) -> DangerBudget:
    return DangerBudget(delay_seconds=0.0, timeout=5.0, **kwargs)


def test_attack_surface_discovery_against_live_fixture(fixture_server, local_target):
    budget = _budget()
    items, visited = attack_surface.build_attack_surface(local_target, budget, seeds=[fixture_server + "/"])

    assert visited
    types = {item.input_type for item in items}
    assert InputPointType.LOGIN_FORM in types
    assert InputPointType.SEARCH_FORM in types
    assert InputPointType.UPLOAD_FORM in types
    assert InputPointType.OBJECT_REFERENCE in types
    assert InputPointType.URL_PARAM in types

    login = next(item for item in items if item.input_type is InputPointType.LOGIN_FORM)
    assert login.method == "POST"
    assert set(login.parameters) == {"username", "password"}


def test_sql_and_reflection_probes_against_live_fixture(fixture_server, local_target):
    budget = _budget()
    items, _ = attack_surface.build_attack_surface(local_target, budget, seeds=[fixture_server + "/"])
    context = injection.InjectionContext(target=local_target, budget=budget, items=items)

    sql_findings = injection.run_sql_injection(context)
    sql = [item for item in sql_findings if item["category"] == "danger_injection_sql"]
    assert sql, "the fixture returns a SQL error for a quote and must be detected"
    assert sql[0]["requires_manual_validation"] is True
    assert sql[0]["owasp_category"] == "A03:2021-Injection"

    html_findings = injection.run_html_injection(context)
    assert any(item["category"] == "danger_injection_html" for item in html_findings)

    xss_findings = injection.run_xss(context)
    assert any(item["category"] == "danger_injection_xss" for item in xss_findings)

    assert context.matrix, "every probe must be recorded in the test matrix"
    assert budget.requests_sent > 0


def test_traversal_and_directory_fuzzing_against_live_fixture(fixture_server, local_target, monkeypatch):
    monkeypatch.setattr(settings, "DANGER_DIR_BUST_WORDLIST", 80)
    budget = _budget(max_requests_per_module=200, max_requests_total=2000, max_payloads=2000)
    items, _ = attack_surface.build_attack_surface(local_target, budget, seeds=[fixture_server + "/"])

    traversal = directory.run_path_traversal(local_target, budget, items)
    hits = [item for item in traversal if item["severity"] == "critical"]
    assert hits, "the fixture serves a passwd-style file for traversal input"
    assert "unix_passwd" in hits[0]["evidence"]
    # The signature is reported; the file contents never are.
    assert "daemon:x:1:1" not in hits[0]["evidence"]

    fuzz = directory.run_directory_fuzzing(local_target, budget, [fixture_server + "/"])
    categories = {item["category"] for item in fuzz}
    assert "danger_directory_fuzzing" in categories
    assert "danger_sensitive_path" in categories
    assert "danger_directory_listing" in categories
    sensitive = next(item for item in fuzz if item["category"] == "danger_sensitive_path")
    assert ".git/HEAD" in sensitive["evidence"]


def test_idor_differential_against_live_fixture(fixture_server, local_target):
    budget = _budget(max_requests_per_module=200, max_requests_total=2000, max_payloads=2000)
    items, _ = attack_surface.build_attack_surface(local_target, budget, seeds=[fixture_server + "/"])

    findings = idor.run_idor_tests(local_target, budget, items)
    candidates = [item for item in findings if item["category"] == "danger_idor"]
    assert candidates, "the fixture serves a different invoice for every id"
    assert candidates[0]["owasp_category"] == "A01:2021-Broken Access Control"
    assert "Object content stored: no - fingerprint and size only" in candidates[0]["evidence"]
    # Invoice bodies contain a computed total; none of it may reach the report.
    assert "total 7007" not in candidates[0]["evidence"]


def test_budget_ceiling_stops_the_scan_early(fixture_server, local_target):
    budget = _budget(max_requests_total=6)
    items, _ = attack_surface.build_attack_surface(local_target, budget, seeds=[fixture_server + "/"])
    context = injection.InjectionContext(target=local_target, budget=budget, items=items)
    injection.run_sql_injection(context)
    injection.run_xss(context)
    assert budget.requests_sent <= 6
    assert budget.exhausted is True


def test_full_pipeline_runs_fail_soft_and_summarizes(fixture_server, local_target, monkeypatch):
    """The whole staged pipeline must complete even when DNS-bound stages fail."""
    monkeypatch.setattr(settings, "DANGER_DIR_BUST_WORDLIST", 30)
    monkeypatch.setattr(settings, "DANGER_MAX_ENDPOINTS", 6)
    from app.tasks.vulnscan.danger.pipeline import DangerSession

    session = DangerSession(target=local_target, budget=_budget(max_requests_total=400, max_payloads=400))
    # Seed directly: recon and AXFR need a real hostname, not a loopback fixture.
    session.seeds = [fixture_server + "/"]

    for name, stage in session.stages():
        if name in {"danger_recon", "danger_axfr"}:
            session.stages_failed.append(name)
            continue
        try:
            stage(local_target)
            session.stages_completed.append(name)
        except Exception:
            session.stages_failed.append(name)

    summary = session.summary()
    assert summary.enabled is True
    assert "attack_surface" in summary.stages_completed
    assert "owasp_matrix" in summary.stages_completed
    assert summary.attack_surface, "the inventory must survive into the summary"
    assert summary.injection_matrix, "probes must be recorded in the matrix"
    assert len(summary.owasp_coverage) == 10
    assert summary.requests_sent > 0

    # Fail-soft: skipping two stages must not prevent the rest from producing findings.
    assert session.findings
    assert all(finding.get("requires_manual_validation") for finding in session.findings)
    categories = {finding["category"] for finding in session.findings}
    assert "danger_attack_surface" in categories
    assert "danger_owasp_matrix" in categories
    assert "danger_reverse_shell" in categories
