from __future__ import annotations

import pytest

from app.config import Settings


def _safe_settings(monkeypatch) -> Settings:
    monkeypatch.setenv("RECONTITAN_DEBUG", "false")
    monkeypatch.setenv("DOMAIN", "scanner.example.com")
    monkeypatch.setenv("SECRET_KEY", "s" * 40)
    monkeypatch.setenv("API_ACCESS_KEY", "a" * 40)
    monkeypatch.setenv("CORS_ORIGINS", "https://scanner.example.com")
    return Settings()


def test_secure_production_configuration_is_accepted(monkeypatch):
    settings = _safe_settings(monkeypatch)
    settings.validate_production()


def test_production_rejects_missing_access_key(monkeypatch):
    settings = _safe_settings(monkeypatch)
    settings.API_ACCESS_KEY = ""
    with pytest.raises(RuntimeError, match="API_ACCESS_KEY"):
        settings.validate_production()


def test_production_rejects_wildcard_cors(monkeypatch):
    _safe_settings(monkeypatch)
    monkeypatch.setenv("CORS_ORIGINS", "*")
    settings = Settings()
    with pytest.raises(RuntimeError, match="CORS_ORIGINS"):
        settings.validate_production()


def test_production_rejects_default_domain_and_secret(monkeypatch):
    settings = _safe_settings(monkeypatch)
    settings.DOMAIN = "localhost"
    settings.SECRET_KEY = "dev-secret-change-in-production"
    with pytest.raises(RuntimeError) as exc:
        settings.validate_production()
    message = str(exc.value)
    assert "DOMAIN" in message
    assert "SECRET_KEY" in message


def test_database_urls_escape_credentials(monkeypatch):
    monkeypatch.setenv("REDIS_PASSWORD", "p@ss/word")
    monkeypatch.setenv("MONGO_USER", "app@user")
    monkeypatch.setenv("MONGO_PASS", "p@ss/word")
    monkeypatch.setenv("MONGO_DB", "recon titan")
    monkeypatch.setenv("MONGO_AUTH_SOURCE", "recon titan")
    settings = Settings()
    assert "p%40ss%2Fword" in settings.REDIS_URL
    assert "app%40user:p%40ss%2Fword" in settings.MONGO_URI
    assert "authSource=recon+titan" in settings.MONGO_URI
