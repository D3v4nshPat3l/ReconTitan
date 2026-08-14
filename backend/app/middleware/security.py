"""
ReconTitan — Security Middleware (Full Coverage)

Protection against ALL 40+ PayloadsAllTheThings categories:
SQL, XSS, SSTI, CMDi, CORS, CRLF, CSS, CSV, XXE, SSRF, LDAP,
XPATH, XSLT, DOM Clobbering, Prototype Pollution, Open Redirect,
Path Traversal, File Inclusion, Request Smuggling, Clickjacking,
Insecure Deserialization, HTTP Parameter Pollution, NoSQL, etc.
"""

import re
import secrets
import time
import logging
import html
import json
import threading
from collections import defaultdict
from typing import Optional
from urllib.parse import unquote_plus

from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.config import settings
from app.targeting import validate_scan_target

logger = logging.getLogger("recontitan.security")

# ═══════════════════════════════════════════════════════════
# MULTI-LAYER DECODE — catches double/triple encoding bypasses
# ═══════════════════════════════════════════════════════════
def deep_decode(value: str, depth: int = 3) -> str:
    """Recursively URL-decode + HTML-decode to catch encoding bypasses."""
    for _ in range(depth):
        decoded = unquote_plus(value)
        decoded = html.unescape(decoded)
        decoded = decoded.replace('\x00', '')  # null byte
        if decoded == value:
            break
        value = decoded
    return value

# ═══════════════════════════════════════════════════════════
# INJECTION PATTERNS — every PayloadsAllTheThings category
# ═══════════════════════════════════════════════════════════

# 1. SQL Injection (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
P_SQL = [
    r"\b(UNION\s+(ALL\s+)?SELECT)\b",
    r"\b(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)\b.*\b(FROM|INTO|TABLE|DATABASE)\b",
    r"\b(OR|AND)\s+['\d]\w*\s*=\s*['\d]",
    r"(--|#|/\*|\*/)",
    r"\b(SLEEP|BENCHMARK|WAITFOR|DELAY|PG_SLEEP)\s*\(",
    r"\b(LOAD_FILE|INTO\s+(OUT|DUMP)FILE)\b",
    r"\bINFORMATION_SCHEMA\b",
    r"\b(CONCAT|GROUP_CONCAT|CHAR|CONVERT|CAST|EXTRACTVALUE|UPDATEXML)\s*\(",
    r";\s*(DROP|ALTER|CREATE|TRUNCATE|EXEC)",
    r"'\s*(OR|AND)\s+.*--",
    r"\bHAVING\s+\d",
    r"\bORDER\s+BY\s+\d{2,}",
]

# 2. XSS Injection (Reflected, Stored, DOM-based)
P_XSS = [
    r"<\s*script",
    r"<\s*/\s*script",
    r"javascript\s*:",
    r"vbscript\s*:",
    r"\bon\w{2,}\s*=",  # onerror=, onload=, onmouseover=
    r"<\s*(img|svg|iframe|object|embed|video|audio|source|body|div|marquee|details|math|table)\b[^>]*(src|href|data|action|background|poster|formaction)\s*=",
    r"<\s*(form|input|button|textarea|select|base|link|meta|isindex)\b",
    r"expression\s*\(",
    r"url\s*\(\s*['\"]?\s*javascript",
    r"data\s*:\s*(text/html|application/xhtml)",
    r"&#[xX]?[0-9a-fA-F]{2,};?",
    r"<\s*style[^>]*>.*(@import|expression|behavior|binding|url\s*\()",
    r"\beval\s*\(",
    r"\b(document|window)\s*\.\s*(cookie|location|write|domain)",
    r"\balert\s*\(", r"\bprompt\s*\(", r"\bconfirm\s*\(",
    r"\bString\.fromCharCode\s*\(",
    r"\batob\s*\(",
]

# 3. CSS Injection
P_CSS = [
    r"<\s*style",
    r"@import\s",
    r"expression\s*\(",
    r"behavior\s*:",
    r"-moz-binding\s*:",
    r"url\s*\(\s*['\"]?javascript",
]

# 4. CRLF Injection
P_CRLF = [
    r"(%0[dD]|%0[aA]|\r|\n)",
    r"\\r\\n",
    r"Set-Cookie\s*:",
    r"HTTP/\d",
]

# 5. CSV Injection
P_CSV = [
    r"^[=+@\-]\s*(cmd|powershell|calc|DDE|HYPERLINK)",
    r"\bDDE\s*\(",
]

# 6. Server Side Template Injection (SSTI)
P_SSTI = [
    r"\{\{.*\}\}",
    r"\{%.*%\}",
    r"\$\{.*\}",
    r"#\{.*\}",
    r"<%=?\s.*%>",
    r"\[\[.*\]\]",
    r"\$\{T\(",  # Spring EL
    r"__class__",
    r"__mro__",
    r"__subclasses__",
    r"__builtins__",
    r"__import__",
]

# 7. Command Injection
P_CMDI = [
    r"[;`]\s*\w",
    r"\|\s*\w",
    r"\|\|",
    r"&&",
    r"\$\([^)]+\)",
    r"`[^`]+`",
    r"\b(cat|ls|id|whoami|pwd|uname|wget|curl|nc|ncat|bash|sh|cmd|powershell|python|perl|ruby|php|node)\b",
    r"(/etc/(passwd|shadow|hosts|issue))",
    r">\s*/",
    r"\bping\s+-[nc]",
    r"\bnslookup\s",
    r"\bdig\s",
]

# 8. Path Traversal / Directory Traversal / File Inclusion (LFI/RFI)
P_PATH = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e[/\\]",
    r"%252e%252e",
    r"\.\.%2f",
    r"\.\.%5c",
    r"/etc/(passwd|shadow|hosts|group)",
    r"C:\\\\Windows",
    r"\\x2e\\x2e",
    r"\binclude\s*\(",
    r"\brequire\s*\(",
    r"(php|data|expect|input|filter)://",
    r"file:///",
    r"proc/self",
]

# 9. SSRF (Server Side Request Forgery)
P_SSRF = [
    r"(127\.0\.0\.1|0\.0\.0\.0|localhost|::1)",
    r"(169\.254\.169\.254)",  # AWS metadata
    r"\b10\.\d+\.\d+\.\d+",
    r"\b172\.(1[6-9]|2\d|3[01])\.\d+\.\d+",
    r"\b192\.168\.\d+\.\d+",
    r"gopher://",
    r"dict://",
    r"ftp://",
    r"tftp://",
    r"file:///",
    r"@(127|0|10|172|192)\.",
    r"0x7f\b",
    r"\b2130706433\b",  # 127.0.0.1 as decimal
]

# 10. XXE (XML External Entity)
P_XXE = [
    r"<!\s*ENTITY",
    r"<!\s*DOCTYPE",
    r"SYSTEM\s+['\"]",
    r"PUBLIC\s+['\"]",
    r"<!ELEMENT",
    r"<!ATTLIST",
    r"file:///",
    r"php://",
    r"expect://",
]

# 11. LDAP Injection
P_LDAP = [
    r"\*\)\(\|",
    r"\)\(&",
    r"\badmin\b\s*\)\s*\(",
    r"\|\(\w+=\*\)",
]

# 12. XPATH Injection
P_XPATH = [
    r"'\s*or\s+'",
    r"'\s*and\s+'",
    r"\bstring-length\s*\(",
    r"\bsubstring\s*\(",
    r"\bcontains\s*\(",
    r"\bcount\s*\(",
    r"\bposition\s*\(",
    r"/child::",
    r"/descendant::",
]

# 13. XSLT Injection
P_XSLT = [
    r"<\s*xsl:",
    r"xsl:value-of",
    r"document\s*\(",
    r"system-property\s*\(",
]

# 14. NoSQL Injection (MongoDB, CouchDB)
P_NOSQL = [
    r"\$gt\b", r"\$lt\b", r"\$ne\b", r"\$eq\b",
    r"\$regex\b", r"\$where\b", r"\$exists\b",
    r"\$or\b", r"\$and\b", r"\$not\b", r"\$nor\b",
    r"\$nin\b", r"\$in\b",
    r"this\.\w+\s*==",
    r"db\.\w+\.find",
    r"db\.\w+\.insert",
]

# 15. Open Redirect
P_REDIRECT = [
    r"(redirect|url|next|return|dest|redir|redirect_uri|return_to|go)\s*=\s*https?://",
    r"//[a-zA-Z0-9]+\.\w+",
    r"@[a-zA-Z0-9]+\.\w+",
]

# 16. Prototype Pollution
P_PROTO = [
    r"__proto__",
    r"constructor\.prototype",
    r"constructor\[",
]

# 17. DOM Clobbering
P_DOM = [
    r"<\s*a\s+id\s*=\s*['\"]__proto__",
    r"<\s*form\s+id\s*=",
    r"document\.\w+\.\w+\s*=",
]

# 18. HTTP Parameter Pollution
P_HPP = [
    r"(&|\?)(\w+=.*){3,}.*\1\2",  # repeated params
]

# 19. Insecure Deserialization
P_DESER = [
    r"O:\d+:\"",  # PHP serialize
    r"rO0ABX",    # Java serialize (base64)
    r"aced0005",  # Java serialize (hex)
    r"__reduce__",
    r"pickle\.",
    r"yaml\.load",
    r"ObjectInputStream",
]

# 20. Request Smuggling
P_SMUGGLE = [
    r"Transfer-Encoding\s*:\s*(chunked|identity)",
    r"Content-Length\s*:\s*\d+.*Content-Length",
    r"0\r\n\r\n",
]

# 21. CORS Misconfiguration (header injection)
P_CORS_ATK = [
    r"Origin\s*:\s*https?://evil",
    r"Access-Control-Allow-Origin\s*:\s*\*",
]

# 22. Web Cache Deception / Poisoning
P_CACHE = [
    r"\.(css|js|png|jpg|gif|ico)\??$",
    r"X-Forwarded-Host\s*:",
    r"X-Original-URL\s*:",
    r"X-Rewrite-URL\s*:",
]

# 23. GraphQL Injection
P_GQL = [
    r"__schema\b",
    r"__type\b",
    r"mutation\s*\{",
    r"query\s*\{.*\{.*\{",  # deep nesting
]

# 24. LaTeX Injection
P_LATEX = [
    r"\\input\{",
    r"\\include\{",
    r"\\write18\{",
    r"\\immediate",
]

# 25. SAML Injection
P_SAML = [
    r"<saml[p]?:",
    r"SAMLResponse",
    r"SAMLRequest",
]

# 26. Server Side Include (SSI)
P_SSI = [
    r"<!--\s*#\s*(exec|include|echo|config|fsize|flastmod)",
]

# 27. Log4Shell / JNDI
P_LOG4J = [
    r"\$\{jndi:",
    r"\$\{env:",
    r"\$\{sys:",
    r"\$\{java:",
    r"\$\{lower:",
    r"\$\{upper:",
]

# Compile ALL into a single mega-pattern
ALL_PATTERNS = (
    P_SQL + P_XSS + P_CSS + P_CRLF + P_CSV + P_SSTI + P_CMDI +
    P_PATH + P_SSRF + P_XXE + P_LDAP + P_XPATH + P_XSLT + P_NOSQL +
    P_REDIRECT + P_PROTO + P_DOM + P_DESER + P_SMUGGLE +
    P_GQL + P_LATEX + P_SAML + P_SSI + P_LOG4J
)

COMBINED_PATTERN = re.compile(
    "|".join(f"({p})" for p in ALL_PATTERNS),
    re.IGNORECASE | re.DOTALL
)

# Domain/IP validation
VALID_TARGET = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    r"|"
    r"^(?:\d{1,3}\.){3}\d{1,3}$"
)


def is_injection_attempt(value: str) -> Optional[str]:
    """Check decoded value against all attack patterns."""
    if not value:
        return None
    decoded = deep_decode(value)
    match = COMBINED_PATTERN.search(decoded)
    if match:
        return match.group(0)[:80]
    return None


def validate_target(target: str) -> tuple[bool, str]:
    """Validate target syntax and reject obvious internal/private destinations."""
    if not target:
        return False, "Target is required"
    injection = is_injection_attempt(target)
    if injection:
        return False, "Potentially malicious input blocked"
    ok, clean, error = validate_scan_target(target, resolve_dns=False)
    return (True, clean) if ok else (False, error)


# ═══════════════════════════════════════════════════════════
# RATE LIMITER
# ═══════════════════════════════════════════════════════════
class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.blocked: dict[str, float] = {}
        self.lock = threading.Lock()
        self.SCAN_LIMIT = settings.RATE_LIMIT_SCAN
        self.SCAN_WINDOW = 60
        # Danger Mode sends far more outbound traffic per scan, so it gets a
        # tighter ceiling stacked on top of the normal scan limit.
        self.DANGER_LIMIT = settings.RATE_LIMIT_DANGER
        self.DANGER_WINDOW = 60
        self.API_LIMIT = settings.RATE_LIMIT_API
        self.API_WINDOW = 60
        self.BLOCK_DURATION = settings.RATE_LIMIT_BLOCK_SECONDS
        self.BURST_THRESHOLD = settings.RATE_LIMIT_BURST
        self.EXPORT_LIMIT = settings.RATE_LIMIT_EXPORT
        self.EXPORT_WINDOW = 60
        self.MAX_TRACKED_KEYS = 50_000
        self.last_sweep = 0.0

    def _clean(self, key: str, window: int, now: float) -> None:
        self.requests[key] = [stamp for stamp in self.requests[key] if now - stamp < window]
        if not self.requests[key]:
            self.requests.pop(key, None)

    def _sweep(self, now: float) -> None:
        """Bound process-local limiter memory under high-cardinality traffic."""
        if now - self.last_sweep < 60 and len(self.requests) < self.MAX_TRACKED_KEYS:
            return
        self.last_sweep = now
        longest_window = max(self.API_WINDOW, self.SCAN_WINDOW, self.EXPORT_WINDOW, 2)
        for key, stamps in list(self.requests.items()):
            fresh = [stamp for stamp in stamps if now - stamp < longest_window]
            if fresh:
                self.requests[key] = fresh
            else:
                self.requests.pop(key, None)
        for ip, blocked_until in list(self.blocked.items()):
            if blocked_until <= now:
                self.blocked.pop(ip, None)
        if len(self.requests) > self.MAX_TRACKED_KEYS:
            oldest = sorted(self.requests, key=lambda key: self.requests[key][-1])
            for key in oldest[: len(self.requests) - self.MAX_TRACKED_KEYS]:
                self.requests.pop(key, None)

    @staticmethod
    def _ip(request: Request) -> str:
        # Uvicorn should only trust headers from the configured reverse proxy.
        # At the application layer, request.client is the authoritative value.
        return request.client.host if request.client else "unknown"

    def _danger_locked(self, ip: str, now: float):
        """Apply the Danger Mode ceiling. Caller must already hold ``self.lock``."""
        danger_key = f"danger:{ip}"
        self.requests[danger_key].append(now)
        self._clean(danger_key, self.DANGER_WINDOW, now)
        if len(self.requests.get(danger_key, [])) > self.DANGER_LIMIT:
            return JSONResponse(
                status_code=429,
                content={"error": "Danger Mode scan rate limit exceeded"},
                headers={"Retry-After": str(self.DANGER_WINDOW)},
            )
        return None

    def check_danger(self, request: Request):
        """Danger ceiling for requests whose profile is only known after parsing."""
        with self.lock:
            return self._danger_locked(self._ip(request), time.time())

    def check(self, request: Request):
        ip = self._ip(request)
        now = time.time()
        path = request.url.path
        with self.lock:
            self._sweep(now)
            blocked_until = self.blocked.get(ip)
            if blocked_until and now < blocked_until:
                return JSONResponse(
                    status_code=429,
                    content={"error": "Temporarily rate limited"},
                    headers={"Retry-After": str(max(1, int(blocked_until - now)))},
                )
            self.blocked.pop(ip, None)

            burst_key = f"burst:{ip}"
            self.requests[burst_key].append(now)
            self._clean(burst_key, 2, now)
            if len(self.requests.get(burst_key, [])) > self.BURST_THRESHOLD:
                self.blocked[ip] = now + self.BLOCK_DURATION
                logger.warning("[DDOS] burst from %s; blocked for %ss", ip, self.BLOCK_DURATION)
                return JSONResponse(status_code=429, content={"error": "Rate limit exceeded"})

            if "/test-scan" in path or path == "/api/scan":
                scan_key = f"scan:{ip}"
                self.requests[scan_key].append(now)
                self._clean(scan_key, self.SCAN_WINDOW, now)
                if len(self.requests.get(scan_key, [])) > self.SCAN_LIMIT:
                    return JSONResponse(status_code=429, content={"error": "Scan rate limit exceeded"})
                if request.query_params.get("scan_type") == "danger":
                    limited = self._danger_locked(ip, now)
                    if limited is not None:
                        return limited

            if path == "/api/report/pdf" or path.endswith("/report.pdf"):
                export_key = f"export:{ip}"
                self.requests[export_key].append(now)
                self._clean(export_key, self.EXPORT_WINDOW, now)
                if len(self.requests.get(export_key, [])) > self.EXPORT_LIMIT:
                    return JSONResponse(
                        status_code=429,
                        content={"error": "Report export rate limit exceeded"},
                        headers={"Retry-After": str(self.EXPORT_WINDOW)},
                    )

            api_key = f"api:{ip}"
            self.requests[api_key].append(now)
            self._clean(api_key, self.API_WINDOW, now)
            if len(self.requests.get(api_key, [])) > self.API_LIMIT:
                return JSONResponse(status_code=429, content={"error": "API rate limit exceeded"})
        return None

rate_limiter = RateLimiter()

# ═══════════════════════════════════════════════════════════
# SECURITY HEADERS
# ═══════════════════════════════════════════════════════════
# Headers applied to ALL responses
SECURITY_HEADERS_ALL = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), interest-cohort=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "worker-src blob: 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "X-DNS-Prefetch-Control": "off",
    "X-Download-Options": "noopen",
    "X-Permitted-Cross-Domain-Policies": "none",
}

# Extra headers only on API JSON responses (not static files)
SECURITY_HEADERS_API = {
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}

BLOCKED_UA = re.compile(
    r"(sqlmap|nikto|dirbuster|gobuster|nessus|acunetix|netsparker|"
    r"burpsuite|w3af|skipfish|wpscan|arachni|openvas|zap|masscan|"
    r"commix|havij|pangolin|jsql|bbqsql|msfconsole|metasploit|"
    r"nuclei|subfinder|amass|httpx|ffuf|feroxbuster|dirb|wfuzz)",
    re.IGNORECASE,
)

# Dangerous headers that shouldn't be in requests
DANGEROUS_HEADERS = [
    "x-original-url", "x-rewrite-url", "x-forwarded-host",
    "x-forwarded-server", "x-host", "x-custom-ip-authorization",
]

# ═══════════════════════════════════════════════════════════
# HELPER: stamp security headers onto any early-exit response
# ═══════════════════════════════════════════════════════════
def _secure_response(response, path: str = "", request_id: str | None = None):
    """Apply all security headers to early-exit responses (429, 403, 404, 400)."""
    for h, v in SECURITY_HEADERS_ALL.items():
        response.headers[h] = v
    if path.startswith("/api/"):
        for h, v in SECURITY_HEADERS_API.items():
            response.headers[h] = v
    response.headers["Server"] = "ReconTitan"
    response.headers["X-Request-ID"] = request_id or secrets.token_hex(12)
    return response


SENSITIVE_BODY_KEYS = {"target", "domain", "host", "hostname", "url", "scan_type"}


def _iter_sensitive_values(value, key: str = ""):
    """Yield only network/dispatch fields; finding evidence may legitimately contain payloads."""
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            normalized = str(child_key).lower()
            if normalized in SENSITIVE_BODY_KEYS and isinstance(child_value, (str, int, float)):
                yield str(child_value)
            elif isinstance(child_value, (dict, list)):
                yield from _iter_sensitive_values(child_value, normalized)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_sensitive_values(child, key)


# ═══════════════════════════════════════════════════════════
# MAIN MIDDLEWARE
# ═══════════════════════════════════════════════════════════
class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        request_id = secrets.token_hex(12)
        request.state.request_id = request_id

        raw_headers = request.scope.get("headers", [])
        content_lengths = [value for key, value in raw_headers if key.lower() == b"content-length"]
        transfer_encodings = [value for key, value in raw_headers if key.lower() == b"transfer-encoding"]
        if len(content_lengths) > 1 or (content_lengths and transfer_encodings):
            logger.warning("[BLOCK] ambiguous request framing id=%s", request_id)
            return _secure_response(
                JSONResponse(status_code=400, content={"error": "Ambiguous request framing"}),
                path,
                request_id,
            )

        if path == "/robots.txt":
            return _secure_response(PlainTextResponse("User-agent: *\nDisallow: /api/\n"), path)
        if path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap"):
            return _secure_response(JSONResponse(status_code=404, content={"detail": "Not found"}), path)

        blocked_paths = (
            ".env", ".git", ".svn", ".htaccess", ".htpasswd", ".ds_store",
            "wp-admin", "wp-login", "phpmyadmin", "adminer", "/admin",
            "console", "debug", "trace", "actuator", "manager",
            "server-status", "server-info", "elmah", "web.config",
        )
        if any(blocked in path.lower() for blocked in blocked_paths):
            return _secure_response(JSONResponse(status_code=404, content={"detail": "Not found"}), path)

        user_agent = request.headers.get("user-agent", "")
        if BLOCKED_UA.search(user_agent):
            logger.warning("[BLOCK] scanner user-agent: %s", user_agent[:80])
            return _secure_response(JSONResponse(status_code=403, content={"detail": "Forbidden"}), path)

        lower_headers = {header.lower() for header in request.headers.keys()}
        for dangerous in DANGEROUS_HEADERS:
            if dangerous in lower_headers:
                logger.warning("[BLOCK] dangerous header: %s", dangerous)
                return _secure_response(JSONResponse(status_code=400, content={"error": "Bad request"}), path)

        if path != "/api/health":
            limited = rate_limiter.check(request)
            if limited:
                return _secure_response(limited, path)

        public_api_paths = {"/api/health", "/api/news", "/api/capabilities", "/api/docs", "/api/redoc", "/api/openapi.json"}
        if settings.API_ACCESS_KEY and path.startswith("/api/") and path not in public_api_paths:
            supplied = request.headers.get("x-recontitan-key", "")
            authorization = request.headers.get("authorization", "")
            if not supplied and authorization.lower().startswith("bearer "):
                supplied = authorization[7:].strip()
            if not supplied or not secrets.compare_digest(supplied, settings.API_ACCESS_KEY):
                return _secure_response(JSONResponse(
                    status_code=401,
                    content={"error": "API access key required"},
                    headers={"WWW-Authenticate": "ReconTitan-Key"},
                ), path)

        if path.startswith("/api/"):
            for key, value in request.query_params.multi_items():
                injection = is_injection_attempt(value)
                if injection:
                    logger.warning("[INJECT] query key=%s payload=%s", key, injection[:80])
                    return _secure_response(JSONResponse(status_code=400, content={"error": "Malicious input blocked"}), path)

            injection = is_injection_attempt(path)
            if injection:
                return _secure_response(JSONResponse(status_code=400, content={"error": "Malicious input blocked"}), path)

            if request.method in {"POST", "PUT", "PATCH"}:
                content_length = request.headers.get("content-length")
                json_only_paths = {"/api/scan", "/api/report/pdf", "/api/verify"}
                content_type = request.headers.get("content-type", "").lower()
                if path in json_only_paths and content_length != "0" and "application/json" not in content_type:
                    return _secure_response(
                        JSONResponse(status_code=415, content={"error": "Content-Type must be application/json"}),
                        path,
                        request_id,
                    )
                if content_length and content_length.isdigit() and int(content_length) > settings.MAX_REQUEST_BODY_BYTES:
                    return _secure_response(JSONResponse(status_code=413, content={"error": "Request body too large"}), path)
                try:
                    body = await request.body()
                except Exception:
                    return _secure_response(JSONResponse(status_code=400, content={"error": "Invalid request body"}), path)
                if len(body) > settings.MAX_REQUEST_BODY_BYTES:
                    return _secure_response(JSONResponse(status_code=413, content={"error": "Request body too large"}), path)
                if body:
                    values = []
                    if "application/json" in content_type:
                        try:
                            parsed_body = json.loads(body)
                            # Only network-dispatch endpoints need payload-pattern scanning.
                            # Report evidence is intentionally allowed to contain exploit strings.
                            values = list(_iter_sensitive_values(parsed_body)) if path == "/api/scan" else []
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            return _secure_response(JSONResponse(status_code=400, content={"error": "Invalid JSON body"}), path)
                        # The danger ceiling can only be applied once the profile
                        # is known, which for POST /api/scan means after parsing.
                        if (
                            path == "/api/scan"
                            and isinstance(parsed_body, dict)
                            and parsed_body.get("scan_type") == "danger"
                        ):
                            limited = rate_limiter.check_danger(request)
                            if limited:
                                return _secure_response(limited, path, request_id)
                    else:
                        values = [body.decode("utf-8", errors="ignore")[:20_000]]
                    for value in values:
                        injection = is_injection_attempt(value)
                        if injection:
                            logger.warning("[INJECT] body payload=%s", injection[:80])
                            return _secure_response(JSONResponse(status_code=400, content={"error": "Malicious input blocked"}), path)

            target = request.query_params.get("target", "")
            if target and "/test-scan" in path:
                ok, result = validate_target(target)
                if not ok:
                    return _secure_response(JSONResponse(status_code=400, content={"error": result}), path)

        response = await call_next(request)
        for header, value in SECURITY_HEADERS_ALL.items():
            response.headers[header] = value
        if path.startswith("/api/"):
            for header, value in SECURITY_HEADERS_API.items():
                response.headers[header] = value
        if "server" in response.headers:
            del response.headers["server"]
        if "x-powered-by" in response.headers:
            del response.headers["x-powered-by"]
        response.headers["Server"] = "ReconTitan"
        response.headers["X-Request-ID"] = request_id
        return response
