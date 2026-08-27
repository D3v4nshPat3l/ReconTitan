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


# ── Blank environment variables ─────────────────────────────────────────────

def test_a_blank_integer_var_falls_back_to_the_default(monkeypatch):
    """Hosting dashboards let a variable exist with an empty value.

    ``os.getenv(name, default)`` only falls back when the name is absent, so a
    blank one returned "" and int("") raised at import — every request to the
    deployed function returned 500 before a single line of app code ran.
    """
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "")
    assert Settings().MAX_REQUEST_BODY_BYTES == 2 * 1024 * 1024


def test_a_whitespace_only_integer_var_also_falls_back(monkeypatch):
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "   ")
    assert Settings().MAX_REQUEST_BODY_BYTES == 2 * 1024 * 1024


def test_a_genuinely_invalid_integer_still_raises(monkeypatch):
    """Blank means "unset". A typo must still fail loudly rather than silently."""
    monkeypatch.setenv("MAX_REQUEST_BODY_BYTES", "2mb")
    with pytest.raises(RuntimeError, match="must be an integer"):
        Settings()


def test_a_blank_database_name_falls_back(monkeypatch):
    """An empty MONGO_DB reached pymongo as client[""], which raises
    "database name cannot be the empty string" on every request. Storage then
    failed for the whole deployment: scans could not be persisted and the SOC
    console had nothing to show, with only a warning in the logs.
    """
    monkeypatch.setenv("MONGO_DB", "")
    assert Settings().MONGO_DB == "recontitan"


def test_blank_string_settings_keep_their_defaults(monkeypatch):
    """Same failure mode as the integer case, across every setting whose
    default is meaningful. Settings that default to "" are excluded on
    purpose: there, blank and unset genuinely mean the same thing.
    """
    for name, expected in (
        ("MONGO_HOST", "localhost"),
        ("REDIS_HOST", "localhost"),
        ("DOMAIN", "localhost"),
        ("AI_PROVIDER", "auto"),
        ("API_HOST", "0.0.0.0"),
    ):
        monkeypatch.setenv(name, "")
        assert getattr(Settings(), name) == expected, f"{name} did not fall back"


def test_a_blank_boolean_var_keeps_its_default(monkeypatch):
    """A blank value used to read as False regardless of the declared default,
    which turns a deliberately-enabled flag off with no error anywhere.
    """
    from app.config import _env_bool

    monkeypatch.setenv("SOME_FLAG", "")
    assert _env_bool("SOME_FLAG", True) is True
    monkeypatch.setenv("SOME_FLAG", "false")
    assert _env_bool("SOME_FLAG", True) is False


# ── Proxy-set headers ───────────────────────────────────────────────────────
#
# These assert against the live settings object rather than reloading the
# config module: a reload swaps `settings` while every module that already
# imported it keeps the old one, and the mismatch leaks into later tests.

VERCEL_HOSTS = ["*.vercel.app", "localhost", "recon-titan.vercel.app"]


@pytest.fixture()
def security(monkeypatch):
    from app.middleware import security as module

    # Patch the settings object this module actually holds. An earlier reload
    # of app.config leaves it bound to the previous instance, so patching
    # app.config.settings here would patch something nothing reads.
    monkeypatch.setattr(module.settings, "TRUSTED_HOSTS", VERCEL_HOSTS, raising=False)
    return module


def test_the_platform_host_is_accepted_behind_a_proxy(security):
    """Vercel's edge attaches x-forwarded-host to every request it forwards.

    Blanket-rejecting the header returned 400 for the entire deployment, so
    behind a trusted proxy the value is validated rather than the header
    refused.
    """
    assert security._host_is_trusted("recon-titan.vercel.app")
    assert security._host_is_trusted("recon-titan-abc123-team.vercel.app"),         "preview deployments get generated subdomains and must still work"
    assert security._host_is_trusted("recon-titan.vercel.app:443"), "a port must not break the match"


def test_an_untrusted_forwarded_host_is_still_rejected(security):
    assert not security._host_is_trusted("evil.com")
    assert not security._host_is_trusted(""), "an empty forwarded host is not a trusted one"


def test_a_wildcard_does_not_match_a_lookalike_suffix(security):
    """*.vercel.app must not match attacker.vercel.app.evil.com."""
    assert not security._host_is_trusted("attacker.vercel.app.evil.com")


def test_headers_that_override_routing_are_blocked_everywhere(security):
    """These are forgery regardless of what sits in front."""
    for header in ("x-original-url", "x-rewrite-url", "x-host", "x-custom-ip-authorization"):
        assert header in security.DANGEROUS_HEADERS
    assert "x-forwarded-host" not in security.DANGEROUS_HEADERS,         "it is proxy-set, and must be validated rather than blanket-refused"


# ── Synchronous scan deadline ───────────────────────────────────────────────

def test_serverless_gets_a_scan_deadline_by_default(monkeypatch):
    """Without one the loop runs every tool and the platform kills the request
    part-way, so the caller gets a 500 and every finding already gathered is
    thrown away with the unwritten response.
    """
    monkeypatch.setenv("VERCEL", "1")
    settings = Settings()
    assert settings.MAX_SYNC_SCAN_SECONDS > 0
    assert settings.MAX_SYNC_SCAN_SECONDS < 60, \
        "the ceiling must leave room to summarise and serialise inside a 60s function"


def test_a_server_deployment_has_no_deadline(monkeypatch):
    """Celery workers have no wall clock to fit inside, so nothing is skipped."""
    assert Settings().MAX_SYNC_SCAN_SECONDS == 0


def test_the_deadline_is_overridable(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("MAX_SYNC_SCAN_SECONDS", "20")
    assert Settings().MAX_SYNC_SCAN_SECONDS == 20
