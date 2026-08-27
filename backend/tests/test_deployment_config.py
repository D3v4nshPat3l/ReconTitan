"""Configuration that only fails once it is already deployed.

Every gap covered here is silent by design. A missing database makes audit
writes no-ops because they are deliberately fail-soft; a localhost URI in a
serverless function resolves to nothing; a missing Redis leaves rate limiting
working per-instance with nothing logged. None of them raise, so none of them
are noticed until someone wonders why the console is empty.

The preflight command exists to turn that silence into an exit code.
"""

from __future__ import annotations

import pytest

from app.config import Settings


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for key in (
        "MONGO_URI", "MONGO_HOST", "MONGO_USER", "MONGO_PASS", "REDIS_URL",
        "REDIS_PASSWORD", "VERCEL", "SERVERLESS", "TRUST_PROXY_HEADERS",
        "SHARED_STATE_ENABLED", "ADMIN_IP_ALLOWLIST",
    ):
        monkeypatch.delenv(key, raising=False)


# ── Managed database connection strings ─────────────────────────────────────

def test_a_full_mongo_uri_wins_over_the_parts(monkeypatch):
    """Atlas uses mongodb+srv://, whose host is an SRV record, not host:port.

    Nothing assembled from MONGO_HOST and MONGO_PORT can express that, so the
    full string has to take precedence or a serverless deploy silently falls
    back to localhost.
    """
    monkeypatch.setenv("MONGO_URI", "mongodb+srv://u:p@cluster0.abcd.mongodb.net/recontitan")
    monkeypatch.setenv("MONGO_HOST", "localhost")
    assert Settings().MONGO_URI == "mongodb+srv://u:p@cluster0.abcd.mongodb.net/recontitan"


def test_the_srv_scheme_survives_intact(monkeypatch):
    monkeypatch.setenv("MONGO_URI", "mongodb+srv://user:pw@c0.x.mongodb.net/db?retryWrites=true&w=majority")
    uri = Settings().MONGO_URI
    assert uri.startswith("mongodb+srv://")
    assert "retryWrites=true" in uri, "query options must not be dropped"


def test_local_parts_still_build_a_uri(monkeypatch):
    monkeypatch.setenv("MONGO_HOST", "mongo")
    monkeypatch.setenv("MONGO_PORT", "27017")
    monkeypatch.setenv("MONGO_DB", "recontitan")
    assert Settings().MONGO_URI == "mongodb://mongo:27017/recontitan"


def test_credentials_are_url_encoded(monkeypatch):
    """A password with a slash or an @ would otherwise corrupt the URI."""
    monkeypatch.setenv("MONGO_HOST", "mongo")
    monkeypatch.setenv("MONGO_USER", "app")
    monkeypatch.setenv("MONGO_PASS", "p@ss/word")
    uri = Settings().MONGO_URI
    assert "p%40ss%2Fword" in uri
    assert "p@ss/word" not in uri


def test_a_managed_redis_url_wins_too(monkeypatch):
    monkeypatch.setenv("REDIS_URL", "rediss://default:tok@eu1.upstash.io:6379")
    assert Settings().REDIS_URL == "rediss://default:tok@eu1.upstash.io:6379"


def test_redis_presence_enables_shared_state(monkeypatch):
    """Without it, a limit of 5 becomes 5 x instance count and nothing says so."""
    monkeypatch.setenv("REDIS_URL", "rediss://default:tok@eu1.upstash.io:6379")
    assert Settings().SHARED_STATE_ENABLED is True


# ── Preflight verdicts ──────────────────────────────────────────────────────

def _preflight(monkeypatch, **env):
    monkeypatch.setenv("RECONTITAN_DEBUG", "false")
    monkeypatch.setenv("SECRET_KEY", "s" * 48)
    monkeypatch.setenv("API_ACCESS_KEY", "k" * 48)
    monkeypatch.setenv("DOMAIN", "scanner.example.com")
    monkeypatch.setenv("CORS_ORIGINS", "https://scanner.example.com")
    for key, value in env.items():
        monkeypatch.setenv(key, value)

    import importlib

    from app import config as config_module
    importlib.reload(config_module)
    from app import preflight as preflight_module
    importlib.reload(preflight_module)
    return preflight_module


def test_serverless_with_a_localhost_database_is_blocking(monkeypatch, capsys):
    module = _preflight(monkeypatch, VERCEL="1", MONGO_HOST="localhost")
    code = module.run()
    output = capsys.readouterr().out
    assert code == 1, "a serverless deploy pointing at localhost must not pass"
    assert "BLOCK" in output
    assert "Atlas" in output, "the message must say what to do about it"


def test_serverless_with_a_real_database_passes(monkeypatch, capsys):
    module = _preflight(
        monkeypatch, VERCEL="1",
        MONGO_URI="mongodb+srv://u:p@c0.abcd.mongodb.net/recontitan",
    )
    assert module.run() == 0
    assert "Not ready to deploy" not in capsys.readouterr().out


def test_a_server_deployment_with_localhost_is_fine(monkeypatch):
    """Localhost is only wrong where there is no localhost."""
    module = _preflight(monkeypatch, MONGO_HOST="localhost")
    assert module.run() == 0


def test_missing_redis_on_serverless_warns_but_does_not_block(monkeypatch, capsys):
    module = _preflight(
        monkeypatch, VERCEL="1",
        MONGO_URI="mongodb+srv://u:p@c0.abcd.mongodb.net/recontitan",
    )
    module.run()
    output = capsys.readouterr().out
    assert "warn" in output and "Redis" in output
    assert "instance count" in output


def test_an_unprotected_public_admin_warns(monkeypatch, capsys):
    module = _preflight(
        monkeypatch, VERCEL="1", ADMIN_ENABLED="true", ADMIN_TOKEN="t" * 48,
        MONGO_URI="mongodb+srv://u:p@c0.abcd.mongodb.net/recontitan",
    )
    module.run()
    assert "ADMIN_IP_ALLOWLIST" in capsys.readouterr().out


def test_an_allowlisted_public_admin_does_not_warn(monkeypatch, capsys):
    module = _preflight(
        monkeypatch, VERCEL="1", ADMIN_ENABLED="true", ADMIN_TOKEN="t" * 48,
        ADMIN_IP_ALLOWLIST="203.0.113.0/24",
        MONGO_URI="mongodb+srv://u:p@c0.abcd.mongodb.net/recontitan",
    )
    module.run()
    assert "restricted to 1 network" in capsys.readouterr().out


def test_weak_secrets_block(monkeypatch, capsys):
    monkeypatch.setenv("RECONTITAN_DEBUG", "false")
    monkeypatch.setenv("SECRET_KEY", "short")
    monkeypatch.setenv("API_ACCESS_KEY", "k" * 48)
    monkeypatch.setenv("DOMAIN", "scanner.example.com")
    monkeypatch.setenv("CORS_ORIGINS", "https://scanner.example.com")

    import importlib

    from app import config as config_module
    importlib.reload(config_module)
    from app import preflight as preflight_module
    importlib.reload(preflight_module)

    assert preflight_module.run() == 1
    assert "SECRET_KEY" in capsys.readouterr().out
