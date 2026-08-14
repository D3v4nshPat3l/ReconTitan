"""ReconTitan configuration with secure production validation."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote_plus


def _env_bool(name: str, default: bool = False) -> bool:
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    return value


def _origins_from_env() -> list[str]:
    raw = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:8000,http://127.0.0.1:8000",
    ).strip()
    if raw == "*":
        return ["*"]
    return [origin.strip().rstrip("/") for origin in raw.split(",") if origin.strip()]


class Settings:
    """Central configuration loaded from the current process environment."""

    def __init__(self) -> None:
        # Paths
        self.BASE_DIR = Path(__file__).resolve().parent.parent
        self.FRONTEND_DIR = Path(os.getenv("FRONTEND_PATH", str(self.BASE_DIR.parent / "frontend")))

        # Application
        self.APP_NAME = "ReconTitan"
        self.APP_VERSION = "0.4.1"
        self.DEBUG = _env_bool("RECONTITAN_DEBUG", True)

        # Domain / security
        self.DOMAIN = os.getenv("DOMAIN", "localhost").strip().lower()
        self.SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-in-production")
        self.API_ACCESS_KEY = os.getenv("API_ACCESS_KEY", "").strip()
        self.ALLOW_PRIVATE_TARGETS = _env_bool("ALLOW_PRIVATE_TARGETS", False)
        self.ENABLE_ACTIVE_VULN_TOOLS = _env_bool("ENABLE_ACTIVE_VULN_TOOLS", False)
        self.MAX_REQUEST_BODY_BYTES = _env_int("MAX_REQUEST_BODY_BYTES", 2 * 1024 * 1024, minimum=1024)
        self.RATE_LIMIT_BURST = _env_int("RATE_LIMIT_BURST", 30, minimum=1)
        self.RATE_LIMIT_SCAN = _env_int("RATE_LIMIT_SCAN", 5, minimum=1)
        self.RATE_LIMIT_DANGER = _env_int("RATE_LIMIT_DANGER", 2, minimum=1)
        self.RATE_LIMIT_API = _env_int("RATE_LIMIT_API", 120, minimum=1)
        self.RATE_LIMIT_EXPORT = _env_int("RATE_LIMIT_EXPORT", 10, minimum=1)
        self.RATE_LIMIT_BLOCK_SECONDS = _env_int("RATE_LIMIT_BLOCK_SECONDS", 300, minimum=1)

        # API server / browser access
        self.API_HOST = os.getenv("API_HOST", "0.0.0.0")
        self.API_PORT = _env_int("API_PORT", 8000, minimum=1)
        self.CORS_ORIGINS = _origins_from_env()
        self.CORS_ALLOW_CREDENTIALS = (
            _env_bool("CORS_ALLOW_CREDENTIALS", False) and self.CORS_ORIGINS != ["*"]
        )
        trusted_hosts = ["localhost", "127.0.0.1", "testserver"]
        if self.DOMAIN and self.DOMAIN != "localhost":
            trusted_hosts.extend([self.DOMAIN, f"www.{self.DOMAIN}"])
        extra_hosts = os.getenv("TRUSTED_HOSTS", "")
        trusted_hosts.extend(
            host.strip().lower() for host in extra_hosts.split(",") if host.strip()
        )
        self.TRUSTED_HOSTS = sorted(set(trusted_hosts))

        # Redis
        self.REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
        self.REDIS_PORT = _env_int("REDIS_PORT", 6379, minimum=1)
        self.REDIS_DB = _env_int("REDIS_DB", 0, minimum=0)
        self.REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")

        # MongoDB
        self.MONGO_HOST = os.getenv("MONGO_HOST", "localhost")
        self.MONGO_PORT = _env_int("MONGO_PORT", 27017, minimum=1)
        self.MONGO_DB = os.getenv("MONGO_DB", "recontitan")
        self.MONGO_USER = os.getenv("MONGO_USER", "")
        self.MONGO_PASS = os.getenv("MONGO_PASS", "")
        self.MONGO_AUTH_SOURCE = os.getenv("MONGO_AUTH_SOURCE", self.MONGO_DB)

        # OpenAI
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
        self.OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

        # Threat intelligence API keys
        self.VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
        self.CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
        self.CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")
        self.GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
        self.SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
        self.URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
        self.INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")

        # Tool timeouts / bounded workload
        self.SCAN_TIMEOUT_NMAP = _env_int("SCAN_TIMEOUT_NMAP", 300, minimum=1)
        self.SCAN_TIMEOUT_NUCLEI = _env_int("SCAN_TIMEOUT_NUCLEI", 600, minimum=1)
        self.SCAN_TIMEOUT_DEFAULT = _env_int("SCAN_TIMEOUT_DEFAULT", 120, minimum=1)
        self.JS_ANALYSIS_MAX_FILES = _env_int("JS_ANALYSIS_MAX_FILES", 20, minimum=1)
        self.JS_ANALYSIS_MAX_BYTES = _env_int("JS_ANALYSIS_MAX_BYTES", 1024 * 1024, minimum=1024)
        self.TAKEOVER_MAX_SUBDOMAINS = _env_int("TAKEOVER_MAX_SUBDOMAINS", 150, minimum=1)

        # Danger Mode — full intermediate penetration-test simulation.
        # Disabled by default; every bound below is a hard ceiling, never a target.
        self.ALLOW_DANGER_MODE = _env_bool("ALLOW_DANGER_MODE", False)
        self.DANGER_MODE_MAX_TARGETS = _env_int("DANGER_MODE_MAX_TARGETS", 1, minimum=1)
        self.DANGER_MAX_HOSTS = _env_int("DANGER_MAX_HOSTS", 5, minimum=1)
        self.DANGER_MAX_REQUESTS_TOTAL = _env_int("DANGER_MAX_REQUESTS_TOTAL", 500, minimum=1)
        self.DANGER_MAX_REQUESTS_PER_MODULE = _env_int("DANGER_MAX_REQUESTS_PER_MODULE", 80, minimum=1)
        self.DANGER_MAX_PAYLOADS_PER_SCAN = _env_int("DANGER_MAX_PAYLOADS_PER_SCAN", 400, minimum=1)
        self.DANGER_MAX_ENDPOINTS = _env_int("DANGER_MAX_ENDPOINTS", 15, minimum=1)
        self.DANGER_MAX_CRAWL_PAGES = _env_int("DANGER_MAX_CRAWL_PAGES", 10, minimum=1)
        self.DANGER_REQUEST_DELAY_MS = _env_int("DANGER_REQUEST_DELAY_MS", 150, minimum=0)
        # Hard wall-clock ceiling for the danger phase. Without this the scan is
        # only bounded by request count, so a slow target can keep the caller
        # waiting indefinitely and no report is ever produced.
        self.DANGER_MAX_SCAN_SECONDS = _env_int("DANGER_MAX_SCAN_SECONDS", 240, minimum=30)
        self.DANGER_REQUEST_TIMEOUT = _env_int("DANGER_REQUEST_TIMEOUT", 12, minimum=1)
        self.DANGER_TIME_DELAY_SECONDS = _env_int("DANGER_TIME_DELAY_SECONDS", 2, minimum=1)
        self.DANGER_SUBDOMAIN_BRUTE_LIMIT = _env_int("DANGER_SUBDOMAIN_BRUTE_LIMIT", 100, minimum=1)
        self.DANGER_DIR_BUST_WORDLIST = _env_int("DANGER_DIR_BUST_WORDLIST", 120, minimum=1)
        self.DANGER_IDOR_MAX_IDS = _env_int("DANGER_IDOR_MAX_IDS", 10, minimum=2)
        self.DANGER_ENABLE_XXE_OOB = _env_bool("DANGER_ENABLE_XXE_OOB", False)

    @property
    def REDIS_URL(self) -> str:
        if self.REDIS_PASSWORD:
            return f"redis://:{quote_plus(self.REDIS_PASSWORD)}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def MONGO_URI(self) -> str:
        if self.MONGO_USER and self.MONGO_PASS:
            return (
                f"mongodb://{quote_plus(self.MONGO_USER)}:{quote_plus(self.MONGO_PASS)}"
                f"@{self.MONGO_HOST}:{self.MONGO_PORT}/{quote_plus(self.MONGO_DB)}"
                f"?authSource={quote_plus(self.MONGO_AUTH_SOURCE)}"
            )
        return f"mongodb://{self.MONGO_HOST}:{self.MONGO_PORT}/{self.MONGO_DB}"

    def validate_production(self) -> None:
        """Fail closed when production settings would expose the service."""
        if self.DEBUG:
            return
        errors: list[str] = []
        if self.SECRET_KEY == "dev-secret-change-in-production" or len(self.SECRET_KEY) < 32:
            errors.append("SECRET_KEY must be a random value of at least 32 characters")
        if self.CORS_ORIGINS == ["*"]:
            errors.append("CORS_ORIGINS cannot be '*' in production")
        if len(self.API_ACCESS_KEY) < 32:
            errors.append("API_ACCESS_KEY must be a random value of at least 32 characters")
        if self.DOMAIN == "localhost":
            errors.append("DOMAIN must be set in production")
        if errors:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(errors))


settings = Settings()
