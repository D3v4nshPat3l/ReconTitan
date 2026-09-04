"""ReconTitan configuration with secure production validation."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import quote_plus

try:  # pragma: no cover - exercised implicitly by every settings read
    from dotenv import load_dotenv
except ImportError:  # python-dotenv is declared, but never hard-fail on it
    load_dotenv = None


def _load_env_file() -> None:
    """Load the repository ``.env`` into the process environment.

    Docker Compose interpolates ``.env`` itself, so the containers were always
    configured correctly. Nothing loaded it for a bare ``uvicorn``/``celery``
    run, so a local operator who set ``ALLOW_DANGER_MODE=true`` in ``.env`` was
    silently ignored and every danger scan was rejected by the gate. Existing
    environment variables still win, so Compose and systemd keep precedence.
    """
    if load_dotenv is None:
        return
    # The test suite must not inherit whatever the developer has in .env, or
    # results depend on the machine: a local API_ACCESS_KEY makes every API
    # test 401, and a local ALLOW_DANGER_MODE=true inverts the gate tests.
    if os.getenv("RECONTITAN_SKIP_DOTENV", "").strip().lower() in {"1", "true", "yes", "on"}:
        return
    env_path = Path(__file__).resolve().parent.parent.parent / ".env"
    if env_path.is_file():
        load_dotenv(env_path, override=False)


_load_env_file()


def _env_str(name: str, default: str) -> str:
    """Read an env var, treating a blank value as absent.

    Hosting dashboards let a variable exist with an empty value, and
    ``os.getenv(name, default)`` only falls back when the name is missing --
    a blank one returns "" and the default is skipped. That turned an empty
    MAX_REQUEST_BODY_BYTES into an import-time crash on every request.
    """
    raw = os.getenv(name)
    raw = "" if raw is None else raw.strip()
    return raw if raw else default


def _env_bool(name: str, default: bool = False) -> bool:
    return _env_str(name, str(default)).lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, *, minimum: int = 0) -> int:
    raw = _env_str(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if value < minimum:
        raise RuntimeError(f"{name} must be at least {minimum}")
    return value


def _named_keys(name: str) -> dict[str, str]:
    """Parse ``label:secret`` pairs into a {secret: label} lookup.

    Keyed by secret because the hot path is "is this supplied value valid", and
    a dict keyed the other way would need a linear scan. Entries without a
    colon are accepted as an unlabelled secret so a bare comma-separated list
    still works.
    """
    raw = os.getenv(name, "").strip()
    if not raw:
        return {}
    keys: dict[str, str] = {}
    for index, entry in enumerate(raw.split(","), 1):
        entry = entry.strip()
        if not entry:
            continue
        label, separator, secret = entry.partition(":")
        if not separator:
            label, secret = f"key-{index}", entry
        label, secret = label.strip(), secret.strip()
        if secret:
            keys[secret] = label or f"key-{index}"
    return keys


#: Tool counts per phase, used only to size the orchestrator's time budget.
#: Kept here rather than imported from app.tasks so config stays dependency-free.
RECON_TOOL_COUNT = 8
OSINT_TOOL_COUNT = 15


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
        self.FRONTEND_DIR = Path(_env_str("FRONTEND_PATH", str(self.BASE_DIR.parent / "frontend")))

        # Application
        self.APP_NAME = "ReconTitan"
        self.APP_VERSION = "0.5.0"
        self.DEBUG = _env_bool("RECONTITAN_DEBUG", True)

        # Domain / security
        self.DOMAIN = _env_str("DOMAIN", "localhost").strip().lower()
        self.SECRET_KEY = _env_str("SECRET_KEY", "dev-secret-change-in-production")
        self.API_ACCESS_KEY = os.getenv("API_ACCESS_KEY", "").strip()

        # Named API keys, so a deployment is not limited to one shared secret
        # with no way to tell callers apart and no way to revoke one of them
        # without cutting off everybody. Format:
        #
        #   API_ACCESS_KEYS=ci:<key>,scanner-ui:<key>,alice:<key>
        #
        # The name is an audit label only -- it carries no privileges, because
        # these are still all-or-nothing credentials. What it buys is
        # attribution ("which caller made this request") and independent
        # revocation (delete one entry, restart, the rest keep working).
        # API_ACCESS_KEY continues to work unchanged and is recorded as
        # "default", so no existing deployment has to change anything.
        self._NAMED_API_KEYS = _named_keys("API_ACCESS_KEYS")
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
        # Every interface, because in a container the only route in is the
        # port the runtime publishes. Override to 127.0.0.1 when running the
        # process directly on a host that should not expose it.
        self.API_HOST = _env_str("API_HOST", "0.0.0.0")  # nosec B104
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
        self.REDIS_HOST = _env_str("REDIS_HOST", "localhost")
        self.REDIS_PORT = _env_int("REDIS_PORT", 6379, minimum=1)
        self.REDIS_DB = _env_int("REDIS_DB", 0, minimum=0)
        self.REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")

        # MongoDB
        self.MONGO_HOST = _env_str("MONGO_HOST", "localhost")
        self.MONGO_PORT = _env_int("MONGO_PORT", 27017, minimum=1)
        self.MONGO_DB = _env_str("MONGO_DB", "recontitan")
        self.MONGO_USER = os.getenv("MONGO_USER", "")
        self.MONGO_PASS = os.getenv("MONGO_PASS", "")
        self.MONGO_AUTH_SOURCE = _env_str("MONGO_AUTH_SOURCE", self.MONGO_DB)

        # AI narration layer.
        # The scanners themselves stay pure Python — the model never decides
        # what is a finding, it only explains findings that were already
        # produced. AI_PROVIDER selects the backend:
        #   auto   — Ollama if reachable, else OpenAI if keyed, else static text
        #   ollama — local Ollama only
        #   openai — hosted OpenAI only
        #   none   — disable AI entirely, always use the built-in fallbacks
        self.AI_PROVIDER = _env_str("AI_PROVIDER", "auto").strip().lower()
        if self.AI_PROVIDER not in {"auto", "ollama", "openai", "none"}:
            raise RuntimeError("AI_PROVIDER must be one of: auto, ollama, openai, none")

        # Ollama (local, no API key, no data leaves the host)
        self.OLLAMA_BASE_URL = _env_str("OLLAMA_BASE_URL", "http://localhost:11434").strip().rstrip("/")
        # Blank means "use whatever is installed" — the module resolves the
        # first model from /api/tags, so a fresh clone works against any pull.
        self.OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "").strip()
        # A cold model load can take tens of seconds; a scan-summary generation
        # on CPU is slower still. Kept separate from the HTTP scanner timeouts.
        self.OLLAMA_TIMEOUT = _env_int("OLLAMA_TIMEOUT", 120, minimum=5)
        self.OLLAMA_NUM_CTX = _env_int("OLLAMA_NUM_CTX", 4096, minimum=512)
        self.OLLAMA_KEEP_ALIVE = _env_str("OLLAMA_KEEP_ALIVE", "5m").strip()

        # Inline narration budget. Each explanation is one model round-trip, and
        # a local CPU model can take several seconds each, so the synchronous
        # scan endpoint caps both the count and the total wall-clock spend
        # rather than letting a slow model hold the request open.
        self.AI_MAX_FINDING_EXPLANATIONS = _env_int("AI_MAX_FINDING_EXPLANATIONS", 8, minimum=0)
        self.AI_EXPLANATION_BUDGET_SECONDS = _env_int("AI_EXPLANATION_BUDGET_SECONDS", 90, minimum=5)
        self.AI_EXPLANATION_CONCURRENCY = _env_int("AI_EXPLANATION_CONCURRENCY", 2, minimum=1)

        # OpenAI (optional hosted fallback)
        self.OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
        self.OPENAI_MODEL = _env_str("OPENAI_MODEL", "gpt-4o-mini")

        # Scan alerts are deliberately opt-in. Recipient addresses live only in
        # server configuration, never in a browser request, so the scan API
        # cannot be used as an open email relay.
        self.EMAIL_ALERTS_ENABLED = _env_bool("EMAIL_ALERTS_ENABLED", False)
        self.ALERT_EMAIL_RECIPIENTS = [
            address.strip() for address in os.getenv("ALERT_EMAIL_RECIPIENTS", "").split(",")
            if address.strip()
        ]
        self.SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
        self.SMTP_PORT = _env_int("SMTP_PORT", 587, minimum=1)
        self.SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
        self.SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
        self.SMTP_FROM = os.getenv("SMTP_FROM", "").strip()
        self.SMTP_USE_TLS = _env_bool("SMTP_USE_TLS", True)
        self.SMTP_TIMEOUT_SECONDS = _env_int("SMTP_TIMEOUT_SECONDS", 15, minimum=1)
        self.ALERT_MIN_SEVERITY = _env_str("ALERT_MIN_SEVERITY", "high").lower()
        if self.ALERT_MIN_SEVERITY not in {"critical", "high"}:
            raise RuntimeError("ALERT_MIN_SEVERITY must be 'high' or 'critical'")

        # Keyless third-party lookups that receive the target address.
        #
        # api.hackertarget.com was called unconditionally by the port scan
        # fallback and the reverse-IP lookup: no key, no flag, and no mention
        # in the docs, so an operator scanning a client's host silently shipped
        # that host to a third party. The project already removed an automatic
        # web-check.xyz submission for exactly this reason. Off by default;
        # skipped lookups are reported rather than hidden.
        self.ALLOW_HACKERTARGET = _env_bool("ALLOW_HACKERTARGET", False)

        # Threat intelligence API keys
        self.VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
        self.SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
        self.CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
        self.CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")
        self.GREYNOISE_API_KEY = os.getenv("GREYNOISE_API_KEY", "")
        self.SECURITYTRAILS_API_KEY = os.getenv("SECURITYTRAILS_API_KEY", "")
        self.URLSCAN_API_KEY = os.getenv("URLSCAN_API_KEY", "")
        self.INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
        # NVD allows 5 requests per 30s unkeyed and 50 with a free key. Without
        # one, exceeding the limit returns 403s that look identical to "no
        # vulnerabilities found", so a key materially improves CVE accuracy.
        self.NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
        self.NVD_MAX_PRODUCTS = _env_int("NVD_MAX_PRODUCTS", 5, minimum=1)

        # Tool timeouts / bounded workload
        self.SCAN_TIMEOUT_NMAP = _env_int("SCAN_TIMEOUT_NMAP", 300, minimum=1)

        # Deep port scanning: every one of the 65535 TCP ports, full version
        # probing, and the NSE vuln script category.
        #
        # Off by default, and deliberately so. The default profiles promise
        # bounded, non-intrusive traffic; this is neither. It is loud, it takes
        # minutes rather than seconds, and NSE vuln scripts actively probe for
        # weaknesses rather than merely observing. Turn it on only where you
        # would be comfortable running nmap by hand against the same target.
        self.NMAP_DEEP_SCAN = _env_bool("NMAP_DEEP_SCAN", False)
        self.SCAN_TIMEOUT_NMAP_DEEP = _env_int("SCAN_TIMEOUT_NMAP_DEEP", 900, minimum=60)

        # nmap's --version-intensity, 0-9. Higher sends more probes per open
        # port and identifies more services; 7 is thorough without the long
        # tail of rare probes that 9 adds.
        self.NMAP_VERSION_INTENSITY = min(9, _env_int("NMAP_VERSION_INTENSITY", 7, minimum=0))

        # Which TCP ports a deep scan covers. All 65535 is the thorough
        # answer and the impractical one: with -sV and NSE on every open
        # port it does not finish inside any sane timeout, and a scan that
        # times out reports nothing at all. 1-10000 covers the ports that
        # actually carry internet-facing services, and finishes.
        #
        # Worth knowing what falls outside it: MongoDB's 27017 and
        # Elasticsearch's 9300 both sit above 10000. Name them explicitly
        # if you care -- "1-10000,9300,27017" is a valid value.
        self.NMAP_DEEP_PORTS = _env_str("NMAP_DEEP_PORTS", "1-10000")

        # Which NSE scripts a deep scan runs.
        #
        # A named list of 50, not a category expression. Categories are the
        # wrong unit here on both counts: too broad (`default` alone is
        # 100+ scripts, several of which walk hundreds of URL paths per HTTP
        # port) and not curated for what this tool actually looks at, which
        # is an internet-facing host. This list is TLS posture, HTTP
        # configuration and headers, service and version disclosure, and
        # the few vuln checks whose signal justifies their cost.
        #
        # Every entry is detection-only. Nothing here brute-forces
        # credentials, floods, or carries an exploit payload -- notably
        # absent is http-shellshock, which nmap classes as `exploit`
        # because it sends a live payload rather than fingerprinting.
        #
        # Any nmap --script expression is accepted, so a category selector
        # or "all" can be set here instead. Check one before trusting it:
        #     nmap --script-help "<expression>"
        self.NMAP_DEEP_SCRIPTS = _env_str(
            "NMAP_DEEP_SCRIPTS",
            "ssl-cert,ssl-enum-ciphers,ssl-date,ssl-dh-params,"
            "ssl-heartbleed,ssl-poodle,ssl-ccs-injection,sslv2-drown,"
            "tls-alpn,http-title,http-headers,http-server-header,"
            "http-methods,http-security-headers,http-robots.txt,http-git,"
            "http-open-proxy,http-cors,http-cookie-flags,"
            "http-webdav-scan,http-auth,http-internal-ip-disclosure,"
            "http-trace,http-generator,http-vuln-cve2017-5638,"
            "ssh-hostkey,ssh2-enum-algos,ssh-auth-methods,dns-recursion,"
            "dns-nsid,dns-zone-transfer,smb-os-discovery,"
            "smb-security-mode,smb2-security-mode,smb-protocols,"
            "smb-vuln-ms17-010,mysql-info,mysql-empty-password,"
            "ms-sql-info,mongodb-info,redis-info,smtp-commands,"
            "smtp-open-relay,imap-capabilities,ftp-anon,ftp-syst,"
            "rdp-ntlm-info,rdp-enum-encryption,vnc-info,banner"
        )

        # Where -oA writes its .nmap/.gnmap/.xml artifacts during a deep scan.
        # Empty means do not write them at all, which is the default: raw scan
        # output of someone else's infrastructure is not something to leave on
        # disk by accident.
        self.NMAP_OUTPUT_DIR = _env_str("NMAP_OUTPUT_DIR", "")
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

        # Parallelism for independent, network-bound tools. Recon and OSINT
        # tools do not depend on each other, so running them one at a time made
        # a scan as slow as the sum of every tool's timeout.
        self.SCAN_TOOL_CONCURRENCY = _env_int("SCAN_TOOL_CONCURRENCY", 8, minimum=1)
        # Reusing a pinned connection avoids a fresh TCP+TLS handshake per probe.
        self.HTTP_POOL_MAX_IDLE = _env_int("HTTP_POOL_MAX_IDLE", 16, minimum=0)
        # Short by design: a long TTL would widen the DNS-rebinding window that
        # the per-request pinning exists to close.
        self.DNS_CACHE_TTL_SECONDS = _env_int("DNS_CACHE_TTL_SECONDS", 30, minimum=0)

        # ── Admin surface ────────────────────────────────────────────────────
        # The admin app is a separate ASGI application that is never proxied by
        # nginx and never published beyond host loopback. Reaching it requires
        # an SSH tunnel, so there is no public listener to attack. The token
        # below is defence in depth for the cases that survive that: a shell on
        # the host, or a target-validation bypass in the scanner (this service
        # forges HTTP requests for a living, so that risk is real).
        self.ADMIN_ENABLED = _env_bool("ADMIN_ENABLED", False)
        self.ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "").strip()
        # Accepted alongside ADMIN_TOKEN during a rotation. Without this,
        # changing the token is a flag day: every existing session and script
        # breaks the instant the process restarts, which is why in practice
        # tokens never get rotated at all. Set the old value here, deploy the
        # new one, confirm nothing is still using the old, then clear it.
        self.ADMIN_TOKEN_PREVIOUS = os.getenv("ADMIN_TOKEN_PREVIOUS", "").strip()
        self.ADMIN_PORT = _env_int("ADMIN_PORT", 9000, minimum=1)
        # Network allowlist for the admin surface, as addresses or CIDR ranges.
        # Empty means unrestricted, matching the previous behaviour so an
        # upgrade cannot lock an operator out of their own console. When set, a
        # caller outside the list never reaches the token check at all, so the
        # token stops being the only thing between the internet and the console.
        self.ADMIN_IP_ALLOWLIST = [
            entry.strip()
            for entry in os.getenv("ADMIN_IP_ALLOWLIST", "").split(",")
            if entry.strip()
        ]
        self.ADMIN_MIN_TOKEN_LENGTH = _env_int("ADMIN_MIN_TOKEN_LENGTH", 32, minimum=32)
        self.ADMIN_MAX_FAILURES = _env_int("ADMIN_MAX_FAILURES", 5, minimum=1)
        self.ADMIN_LOCKOUT_SECONDS = _env_int("ADMIN_LOCKOUT_SECONDS", 900, minimum=30)

        # Deployment shape. On a serverless platform every instance is a
        # separate process, so per-process counters stop being a limitation and
        # become a hole: rate limits multiply by instance count and admin
        # lockout can be sidestepped by landing on a fresh instance.
        self.SERVERLESS = _env_bool("SERVERLESS", bool(os.getenv("VERCEL")))
        # Local launchers run one API process, not a Celery worker stack.
        self.ASYNC_SCANS_ENABLED = _env_bool("ASYNC_SCANS_ENABLED", True) and not self.SERVERLESS

        # Trusting X-Forwarded-For is safe only when something in front of the
        # app is guaranteed to overwrite it. Behind the Compose nginx, uvicorn
        # already rewrites request.client, so this stays off. On a serverless
        # platform there is no such rewrite and every visitor would otherwise be
        # recorded as the platform's own proxy address, making the audit trail
        # useless for attribution -- so it defaults on there, and only there.
        self.TRUST_PROXY_HEADERS = _env_bool("TRUST_PROXY_HEADERS", self.SERVERLESS)

        # Wall-clock ceiling for a synchronous scan, in seconds. 0 means none.
        #
        # A serverless platform kills the function at its own limit and the
        # caller gets a 500 with nothing in it -- every tool that already ran is
        # thrown away because the response was never written. Stopping first and
        # returning a partial report is strictly better: the findings gathered so
        # far survive, and the skipped stages are named in the report.
        #
        # The default leaves room under a 60s function limit for the AI summary
        # and for serialising the response after the last tool returns.
        self.MAX_SYNC_SCAN_SECONDS = _env_int(
            "MAX_SYNC_SCAN_SECONDS", 45 if self.SERVERLESS else 0, minimum=0
        )
        # Share rate-limit and lockout counters through Redis. Required for any
        # multi-instance deployment; harmless on a single node.
        self.SHARED_STATE_ENABLED = _env_bool("SHARED_STATE_ENABLED", bool(self.REDIS_PASSWORD or os.getenv("REDIS_URL")))

        # Audit trail. Attribution for the admin and SOC dashboards.
        self.AUDIT_ENABLED = _env_bool("AUDIT_ENABLED", True)
        # This collection stores client IP addresses, so retention is a ceiling
        # enforced by a TTL index rather than unbounded history.
        self.AUDIT_RETENTION_DAYS = _env_int("AUDIT_RETENTION_DAYS", 90, minimum=1)
        # Attacker-facing events are coalesced for at most this long so a
        # request flood cannot become a database write flood.
        self.AUDIT_FLUSH_SECONDS = _env_int("AUDIT_FLUSH_SECONDS", 5, minimum=1)
        self.AUDIT_MAX_PENDING = _env_int("AUDIT_MAX_PENDING", 2000, minimum=10)

        # Celery ceilings. The default pair applies to a single phase task; the
        # orchestrator runs every phase inline and needs a whole-pipeline budget.
        self.CELERY_TASK_TIME_LIMIT = _env_int("CELERY_TASK_TIME_LIMIT", 900, minimum=60)
        self.CELERY_TASK_SOFT_TIME_LIMIT = _env_int(
            "CELERY_TASK_SOFT_TIME_LIMIT", max(60, self.CELERY_TASK_TIME_LIMIT - 60), minimum=30
        )

    @property
    def SCAN_SOFT_TIME_LIMIT(self) -> int:
        """Whole-pipeline soft ceiling for ``orchestrate_scan``.

        Derived from the phase budgets rather than hard-coded so raising
        DANGER_MAX_SCAN_SECONDS or a tool timeout can never leave the
        orchestrator with a ceiling below the work it is being asked to do.
        """
        override = os.getenv("SCAN_SOFT_TIME_LIMIT", "").strip()
        if override:
            return _env_int("SCAN_SOFT_TIME_LIMIT", 0, minimum=60)
        lanes = max(1, self.SCAN_TOOL_CONCURRENCY)
        # A phase of N independent tools takes ceil(N / lanes) waves, and a wave
        # is at worst one tool timeout.
        waves = -(-RECON_TOOL_COUNT // lanes) + -(-OSINT_TOOL_COUNT // lanes)
        recon_and_osint = waves * self.SCAN_TIMEOUT_DEFAULT
        active = self.SCAN_TIMEOUT_NMAP + (
            self.SCAN_TIMEOUT_NUCLEI if self.ENABLE_ACTIVE_VULN_TOOLS else self.SCAN_TIMEOUT_DEFAULT
        )
        return recon_and_osint + active + self.DANGER_MAX_SCAN_SECONDS + 300

    @property
    def SCAN_HARD_TIME_LIMIT(self) -> int:
        """Hard ceiling, one minute past the soft one so cleanup can run first."""
        return self.SCAN_SOFT_TIME_LIMIT + 60

    @property
    def API_ACCESS_KEYS(self) -> dict[str, str]:
        """{secret: label} for every accepted key.

        Derived rather than snapshotted in __init__ so that assigning
        ``settings.API_ACCESS_KEY`` at runtime still changes what the gate
        accepts -- the tests rely on that, and so would any operator poking at
        a live process.
        """
        keys = dict(self._NAMED_API_KEYS)
        if self.API_ACCESS_KEY:
            keys.setdefault(self.API_ACCESS_KEY, "default")
        return keys

    @property
    def REDIS_URL(self) -> str:
        # Managed Redis providers hand out a single connection string; prefer it
        # over the host/port/password triple when present.
        direct = os.getenv("REDIS_URL", "").strip()
        if direct:
            return direct
        if self.REDIS_PASSWORD:
            return f"redis://:{quote_plus(self.REDIS_PASSWORD)}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    @property
    def MONGO_URI(self) -> str:
        # A managed provider hands out one connection string, and Atlas uses the
        # mongodb+srv:// scheme whose host is a DNS SRV record rather than a
        # host:port pair. Nothing built from MONGO_HOST/PORT can express that,
        # so a full URI has to win outright — without this, a serverless deploy
        # silently falls back to localhost and every panel reads "MongoDB
        # unavailable" with nothing explaining why.
        direct = os.getenv("MONGO_URI", "").strip()
        if direct:
            return direct

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
        if self.EMAIL_ALERTS_ENABLED:
            missing = [name for name, value in (
                ("SMTP_HOST", self.SMTP_HOST), ("SMTP_FROM", self.SMTP_FROM),
                ("ALERT_EMAIL_RECIPIENTS", self.ALERT_EMAIL_RECIPIENTS),
            ) if not value]
            if missing:
                errors.append("EMAIL_ALERTS_ENABLED requires " + ", ".join(missing))
            if bool(self.SMTP_USERNAME) != bool(self.SMTP_PASSWORD):
                errors.append("set both SMTP_USERNAME and SMTP_PASSWORD, or neither")
        # Production must be authenticated, but it no longer matters *which*
        # variable supplies the credential -- a deployment using only named keys
        # is fully configured and must not be told to set API_ACCESS_KEY.
        if not self.API_ACCESS_KEYS:
            errors.append(
                "API_ACCESS_KEY (or API_ACCESS_KEYS) must be set to a random value "
                "of at least 32 characters"
            )
        else:
            weak = sorted(
                label for secret, label in self.API_ACCESS_KEYS.items() if len(secret) < 32
            )
            if weak:
                errors.append(
                    "API access keys must be random values of at least 32 characters; "
                    f"too short: {', '.join(weak)}"
                )
        if self.DOMAIN == "localhost":
            errors.append("DOMAIN must be set in production")
        if errors:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(errors))


settings = Settings()
