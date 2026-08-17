"""Admin surface: authentication, lockout, and structural isolation.

The requirement is that there is no way to reach admin from the internet. That
is not achieved by the token check alone — a token is a lock, and locks get
picked, phished, or leaked. It is achieved by there being no route:

* nginx never proxies admin, so the public origin has no path to it;
* the port is published to host loopback only, so it is unreachable from the
  network whatever the cloud firewall says;
* admin runs on a Docker network the scanner containers are not attached to,
  so a target-validation bypass in the request-forging services cannot reach
  it either.

The token tests below cover the residual case: someone already on the host.
The isolation tests are the ones that carry the actual guarantee, so they
assert the deployment topology, not just the Python.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.admin import auth
from app.config import settings

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
NGINX = (REPO_ROOT / "nginx" / "nginx.conf").read_text(encoding="utf-8")

TOKEN = "T" * 64


def _service_block(name: str) -> str:
    """Return one Compose service's block.

    Service keys sit at exactly two spaces of indent, so a block runs until the
    next such key. Splitting on any indented line (the obvious shortcut) yields
    only the first line and silently passes every assertion made against it.
    """
    lines = COMPOSE.splitlines()
    start = next(
        (i for i, line in enumerate(lines) if re.fullmatch(rf"  {name}:\s*", line)), None
    )
    assert start is not None, f"service {name} not found in docker-compose.yml"
    collected = []
    for line in lines[start + 1:]:
        if re.fullmatch(r"  [A-Za-z0-9_-]+:\s*", line) or re.match(r"^[A-Za-z]", line):
            break
        collected.append(line)
    return "\n".join(collected)


def test_service_block_helper_is_not_vacuous():
    """Guards the guard: a broken extractor makes the isolation tests useless."""
    worker = _service_block("worker")
    assert "celery" in worker, "extractor returned too little to assert against"
    assert "  admin:" not in worker, "extractor bled into the next service"
    assert len(worker.splitlines()) > 10


@pytest.fixture
def admin_client(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_ENABLED", True)
    monkeypatch.setattr(settings, "ADMIN_TOKEN", TOKEN)
    auth.clear_all()
    from app.admin.main import create_admin_app

    with TestClient(create_admin_app()) as client:
        yield client
    auth.clear_all()


# ── Layer 1: no public route ─────────────────────────────────────────────────

def test_nginx_never_proxies_the_admin_surface():
    """The single most important assertion in this file."""
    assert "9000" not in NGINX, "nginx must not reference the admin port"
    assert not re.search(r"location\s+[^{]*admin[^{]*\{[^}]*proxy_pass", NGINX), \
        "nginx must never proxy an admin location"


def test_admin_port_is_published_to_host_loopback_only():
    """Without the 127.0.0.1 prefix Docker would expose this to the world.

    Docker publishes past the host firewall by writing its own iptables rules,
    so a bare "9000:9000" would be internet-reachable even with UFW denying it.
    """
    assert re.search(r'"127\.0\.0\.1:\$\{ADMIN_PORT:-9000\}:9000"', COMPOSE), \
        "admin port must be bound to host loopback"
    assert not re.search(r'^\s+-\s+"9000:9000"', COMPOSE, re.M), \
        "admin port must never be published on all interfaces"


def test_no_other_service_exposes_a_host_port_beyond_the_web_ports():
    """Only nginx should reach the network, and only on 80/443."""
    published = re.findall(r'^\s+-\s+"([^"]+:)?(\d+):(\d+)"', COMPOSE, re.M)
    public = {host_port for prefix, host_port, _ in published if not prefix}
    assert public <= {"80", "443"}, f"unexpected public ports: {public}"


# ── Layer 2: the scanner cannot route to admin ───────────────────────────────

def test_admin_is_isolated_from_the_request_forging_services():
    """api and worker fetch attacker-supplied URLs; they must have no route here.

    Relying only on target validation would mean one bypass equals full admin
    compromise. Isolation makes the route non-existent instead.
    """
    assert "adminnet" in _service_block("admin")

    for service in ("api", "worker"):
        block = _service_block(service)
        assert "adminnet" not in block, f"{service} must not be attached to adminnet"


def test_adminnet_is_declared():
    assert re.search(r"^networks:", COMPOSE, re.M)
    assert "adminnet:" in COMPOSE


# ── Layer 3: fail closed on misconfiguration ─────────────────────────────────

def test_admin_refuses_to_start_when_disabled(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_ENABLED", False)
    from app.admin.main import create_admin_app

    with pytest.raises(auth.AdminDisabled):
        create_admin_app()


@pytest.mark.parametrize("token", ["", "short", "x" * 31])
def test_admin_refuses_to_start_with_a_weak_token(monkeypatch, token):
    """A weak token must stop the process, never degrade to open access."""
    monkeypatch.setattr(settings, "ADMIN_ENABLED", True)
    monkeypatch.setattr(settings, "ADMIN_TOKEN", token)
    from app.admin.main import create_admin_app

    with pytest.raises(auth.AdminDisabled):
        create_admin_app()


def test_token_never_matches_when_unconfigured(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_TOKEN", "")
    assert auth.token_matches("") is False
    assert auth.token_matches("anything") is False


# ── Layer 4: authentication ──────────────────────────────────────────────────

def test_protected_route_requires_a_token(admin_client):
    assert admin_client.get("/admin/api/session").status_code == 401


def test_protected_route_accepts_the_correct_token(admin_client):
    response = admin_client.get("/admin/api/session", headers={auth.ADMIN_HEADER: TOKEN})
    assert response.status_code == 200
    assert response.json()["authenticated"] is True


@pytest.mark.parametrize("bad", ["", "wrong", TOKEN[:-1], TOKEN + "x", TOKEN.lower()])
def test_wrong_tokens_are_rejected(admin_client, bad):
    assert admin_client.get(
        "/admin/api/session", headers={auth.ADMIN_HEADER: bad}
    ).status_code == 401


def test_failures_are_indistinguishable(admin_client):
    """No response should reveal whether a token was absent, malformed, or close."""
    bodies = {
        admin_client.get("/admin/api/session", headers=h).text
        for h in ({}, {auth.ADMIN_HEADER: "wrong"}, {auth.ADMIN_HEADER: TOKEN[:-1]})
    }
    assert len(bodies) == 1, f"denial responses differ and leak information: {bodies}"


def test_admin_has_no_interactive_docs(admin_client):
    """Docs would describe the whole admin surface to anyone who reaches it."""
    for path in ("/docs", "/redoc", "/openapi.json", "/admin/docs"):
        assert admin_client.get(path).status_code == 404


# ── Lockout ──────────────────────────────────────────────────────────────────

def test_repeated_failures_trigger_lockout(admin_client, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_MAX_FAILURES", 3)
    for _ in range(3):
        admin_client.get("/admin/api/session", headers={auth.ADMIN_HEADER: "wrong"})
    response = admin_client.get("/admin/api/session", headers={auth.ADMIN_HEADER: "wrong"})
    assert response.status_code == 429
    assert "Retry-After" in response.headers


def test_lockout_blocks_even_the_correct_token(admin_client, monkeypatch):
    """Guessing must not be rescued by getting it right on the next attempt."""
    monkeypatch.setattr(settings, "ADMIN_MAX_FAILURES", 3)
    for _ in range(3):
        admin_client.get("/admin/api/session", headers={auth.ADMIN_HEADER: "wrong"})
    assert admin_client.get(
        "/admin/api/session", headers={auth.ADMIN_HEADER: TOKEN}
    ).status_code == 429


def test_lockout_escalates_with_repeated_rounds(monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_MAX_FAILURES", 2)
    monkeypatch.setattr(settings, "ADMIN_LOCKOUT_SECONDS", 60)
    auth.clear_all()
    first = [auth.register_failure("10.0.0.1") for _ in range(2)][-1]
    later = [auth.register_failure("10.0.0.1") for _ in range(4)][-1]
    assert later > first
    auth.clear_all()


def test_success_clears_the_failure_record(admin_client, monkeypatch):
    monkeypatch.setattr(settings, "ADMIN_MAX_FAILURES", 5)
    for _ in range(3):
        admin_client.get("/admin/api/session", headers={auth.ADMIN_HEADER: "wrong"})
    assert admin_client.get(
        "/admin/api/session", headers={auth.ADMIN_HEADER: TOKEN}
    ).status_code == 200
    assert auth.lockout_remaining("testclient") == 0


def test_lockout_table_is_bounded():
    auth.clear_all()
    for i in range(11_000):
        auth.register_failure(f"10.1.{i // 256}.{i % 256}")
    assert len(auth._failures) <= 10_001
    auth.clear_all()


# ── CSRF is structurally absent ──────────────────────────────────────────────

def test_auth_is_header_based_not_cookie_based(admin_client):
    """A request carrying no ambient credential cannot be driven cross-site."""
    response = admin_client.get("/admin/api/session", headers={auth.ADMIN_HEADER: TOKEN})
    assert response.status_code == 200
    assert "set-cookie" not in {k.lower() for k in response.headers}


def test_a_cookie_cannot_authenticate(admin_client):
    admin_client.cookies.set("x-recontitan-admin", TOKEN)
    assert admin_client.get("/admin/api/session").status_code == 401
    admin_client.cookies.clear()


# ── Response hardening ───────────────────────────────────────────────────────

@pytest.mark.parametrize("header,expected", [
    ("X-Frame-Options", "DENY"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
])
def test_admin_responses_are_hardened(admin_client, header, expected):
    assert admin_client.get("/admin/health").headers[header] == expected


def test_admin_csp_forbids_framing_and_third_party_content(admin_client):
    csp = admin_client.get("/admin/health").headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in csp
    assert "default-src 'self'" in csp
    assert "object-src 'none'" in csp


def test_admin_responses_are_never_cached(admin_client):
    """Admin data must not linger in a proxy or browser cache."""
    assert "no-store" in admin_client.get("/admin/health").headers["Cache-Control"]


# ── Audit integration ────────────────────────────────────────────────────────

def test_failed_admin_logins_reach_the_audit_trail(admin_client, monkeypatch):
    """An attack on admin should be the loudest thing in the trail."""
    from app.services import audit

    captured: list[dict] = []
    monkeypatch.setattr(audit, "_write", lambda docs: captured.extend(docs))
    monkeypatch.setattr(audit.settings, "AUDIT_ENABLED", True)
    monkeypatch.setattr(audit.settings, "AUDIT_FLUSH_SECONDS", 0)

    admin_client.get("/admin/api/session", headers={auth.ADMIN_HEADER: "wrong"})
    audit.flush()
    assert any(event["kind"] == "admin.login_failed" for event in captured)
