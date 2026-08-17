"""Pinned, bounded HTTP client for active scan modules.

The hostname is resolved and validated before a connection is opened. The
connection is then made to that validated IP while preserving the original
Host header and TLS SNI/hostname checks. Redirects are revalidated one hop at a
time, preventing DNS rebinding and redirects into private networks.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import ipaddress
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit, urlunsplit

import certifi
import urllib3

from app.config import settings
from app.targeting import resolve_target_addresses, validate_scan_target

DEFAULT_UA = "Mozilla/5.0 (compatible; ReconTitan/0.3; +authorized-security-scan)"

# Recon, OSINT and danger modules all share this client, and recon/OSINT now run
# in a thread pool, so both caches below are guarded by a lock.
_lock = threading.Lock()
_pools: "OrderedDict[tuple, urllib3.HTTPConnectionPool]" = OrderedDict()
_dns_cache: dict[str, tuple[float, str, tuple[str, ...]]] = {}


class UnsafeURL(ValueError):
    pass


class ResponseTooLarge(ValueError):
    pass


@dataclass
class SafeResponse:
    status_code: int
    url: str
    headers: dict[str, str]
    content: bytes
    history: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        encoding = "utf-8"
        content_type = self.headers.get("Content-Type", "")
        if "charset=" in content_type:
            encoding = content_type.rsplit("charset=", 1)[-1].split(";", 1)[0].strip() or "utf-8"
        return self.content.decode(encoding, errors="replace")

    def json(self):
        import json
        return json.loads(self.text)


def _resolve_validated(host: str) -> tuple[str, tuple[str, ...]]:
    """Validate and resolve ``host``, caching the result for a short TTL.

    A danger scan sends hundreds of probes to one host, and re-running target
    validation plus a fresh DNS lookup on every single one dominated the scan's
    wall clock — especially under Docker, where lookups leave the container.

    The TTL is deliberately short. Caching a resolution widens the DNS-rebinding
    window that the pinning below exists to close, so the cache trades a bounded
    amount of that protection for throughput. Every cached address is still
    re-checked against the private/reserved rules before a socket is opened, and
    setting ``DNS_CACHE_TTL_SECONDS=0`` restores per-request resolution.
    """
    ttl = settings.DNS_CACHE_TTL_SECONDS
    if ttl:
        with _lock:
            entry = _dns_cache.get(host)
            if entry and entry[0] > time.monotonic():
                return entry[1], entry[2]

    ok, hostname, error = validate_scan_target(host, resolve_dns=True)
    if not ok:
        raise UnsafeURL(error)
    addresses = tuple(resolve_target_addresses(hostname))

    if ttl:
        with _lock:
            if len(_dns_cache) > 512:
                _dns_cache.clear()
            _dns_cache[host] = (time.monotonic() + ttl, hostname, addresses)
    return hostname, addresses


def _validated_destination(url: str) -> tuple[object, str, list[str]]:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeURL("Only absolute HTTP(S) URLs are allowed")
    if parsed.username or parsed.password:
        raise UnsafeURL("Credentials in target URLs are not allowed")
    hostname, addresses = _resolve_validated(parsed.hostname)
    return parsed, hostname, list(addresses)


def _get_pool(scheme: str, address: str, port: int, hostname: str, timeout: float):
    """Return a keep-alive pool pinned to one validated address.

    The key includes the resolved address and the hostname used for SNI and
    certificate verification, so a reused connection is always the same pinned
    destination that was validated — reuse cannot cross hosts.
    """
    key = (scheme, address, port, hostname)
    if settings.HTTP_POOL_MAX_IDLE:
        with _lock:
            pool = _pools.get(key)
            if pool is not None:
                _pools.move_to_end(key)
                return pool, True

    common = {
        "host": address,
        "port": port,
        "timeout": urllib3.Timeout(connect=timeout, read=timeout),
        "maxsize": 4,
        "block": False,
        "retries": False,
    }
    if scheme == "https":
        pool = urllib3.HTTPSConnectionPool(
            **common,
            cert_reqs=ssl.CERT_REQUIRED,
            ca_certs=certifi.where(),
            assert_hostname=hostname,
            server_hostname=hostname,
        )
    else:
        pool = urllib3.HTTPConnectionPool(**common)

    if not settings.HTTP_POOL_MAX_IDLE:
        return pool, False
    with _lock:
        _pools[key] = pool
        while len(_pools) > settings.HTTP_POOL_MAX_IDLE:
            _, evicted = _pools.popitem(last=False)
            evicted.close()
    return pool, True


def reset_http_client() -> None:
    """Drop every cached pool and resolution. Used by tests and at worker exit."""
    with _lock:
        for pool in _pools.values():
            pool.close()
        _pools.clear()
        _dns_cache.clear()


def _host_header(hostname: str, port: int | None, scheme: str) -> str:
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    return f"{host}:{port}" if port and port != default_port else host


def _read_bounded(response, max_bytes: int) -> bytes:
    length = response.headers.get("Content-Length")
    if length and str(length).isdigit() and int(length) > max_bytes:
        raise ResponseTooLarge(f"Response exceeds {max_bytes} bytes")
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = response.read(65536)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise ResponseTooLarge(f"Response exceeds {max_bytes} bytes")
        chunks.append(chunk)
    return b"".join(chunks)


def _request_pinned(
    method: str,
    url: str,
    *,
    timeout: float,
    max_bytes: int,
    headers: dict[str, str],
    body: bytes | None = None,
):
    parsed, hostname, addresses = _validated_destination(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    request_target = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
    last_error: Exception | None = None

    for address in addresses:
        # Defense in depth in case resolution helpers are changed later.
        if not settings.ALLOW_PRIVATE_TARGETS and not ipaddress.ip_address(address).is_global:
            raise UnsafeURL("Destination is private, reserved, or non-routable")
        pool, cached = _get_pool(parsed.scheme, address, port, hostname, timeout)
        response = None
        try:
            request_headers = dict(headers)
            request_headers["Host"] = _host_header(hostname, parsed.port, parsed.scheme)
            response = pool.urlopen(
                method,
                request_target,
                body=body,
                headers=request_headers,
                redirect=False,
                preload_content=False,
                decode_content=True,
                # Per-request, never the pool default: a pool is shared across
                # callers and Danger Mode clamps each probe's timeout to the
                # time left on its deadline.
                timeout=urllib3.Timeout(connect=timeout, read=timeout),
            )
            content = _read_bounded(response, max_bytes)
            return response.status, {str(k): str(v) for k, v in response.headers.items()}, content
        except (UnsafeURL, ResponseTooLarge):
            raise
        except Exception as exc:
            last_error = exc
        finally:
            if response is not None:
                # Returns the socket to the pool so the next probe to this
                # pinned destination skips the TCP and TLS handshake.
                response.release_conn()
            if not cached:
                pool.close()
    if last_error:
        raise last_error
    raise UnsafeURL("Target did not resolve to a usable public address")


ALLOWED_METHODS = {"GET", "HEAD", "OPTIONS", "POST"}


def safe_request(
    method: str,
    url: str,
    *,
    timeout: float = 12,
    max_bytes: int = 1024 * 1024,
    headers: dict[str, str] | None = None,
    max_redirects: int = 5,
    body: bytes | None = None,
    follow_redirects: bool = True,
) -> SafeResponse:
    """Perform a bounded GET/HEAD/OPTIONS/POST request against public destinations.

    POST is accepted so authorized active modules can exercise forms and JSON
    APIs. It carries the same destination pinning, redirect revalidation, and
    response-size ceiling as every other method.
    """
    method = method.upper()
    if method not in ALLOWED_METHODS:
        raise ValueError("safe_request supports only GET, HEAD, OPTIONS, and POST")
    if body is not None and method != "POST":
        raise ValueError("Only POST requests may carry a body")
    current = url
    history: list[str] = []
    request_headers = {"User-Agent": DEFAULT_UA, "Accept": "*/*"}
    if headers:
        request_headers.update(headers)

    for _ in range(max_redirects + 1):
        status, response_headers, content = _request_pinned(
            method, current, timeout=timeout, max_bytes=max_bytes, headers=request_headers, body=body
        )
        if status in {301, 302, 303, 307, 308}:
            location = response_headers.get("Location")
            # Callers that need to inspect where a target *would* send them
            # (open-redirect testing) take the response as-is. The Location is
            # only read, never fetched, so no destination validation is needed.
            if not location or not follow_redirects:
                return SafeResponse(status, current, response_headers, content, history)
            next_url = urljoin(current, location)
            # Validate before the next loop and before recording attacker text.
            _validated_destination(next_url)
            history.append(f"{status} {current} -> {next_url}")
            current = next_url
            if status in {301, 302, 303}:
                # Follow the browser convention: the body does not survive these hops.
                method = "GET"
                body = None
                request_headers.pop("Content-Type", None)
                request_headers.pop("Content-Length", None)
            continue
        return SafeResponse(status, current, response_headers, content, history)
    raise UnsafeURL(f"Too many redirects (>{max_redirects})")


def safe_get(url: str, **kwargs) -> SafeResponse:
    return safe_request("GET", url, **kwargs)


def safe_options(url: str, **kwargs) -> SafeResponse:
    return safe_request("OPTIONS", url, **kwargs)


def safe_post(url: str, *, body: bytes = b"", **kwargs) -> SafeResponse:
    return safe_request("POST", url, body=body, **kwargs)
