"""Favicon discovery and Shodan-compatible hash calculation."""

from __future__ import annotations

import base64
import hashlib
import logging
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from app.config import settings
from app.tasks.http_client import safe_get
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.recon.favicon")


def _rotl32(value: int, bits: int) -> int:
    return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF


def murmurhash3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python mmh3 implementation compatible with Shodan favicon hashes."""
    c1, c2 = 0xCC9E2D51, 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded = length & ~0x3

    for i in range(0, rounded, 4):
        k1 = int.from_bytes(data[i : i + 4], "little")
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = _rotl32(h1, 13)
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[rounded:]
    k1 = 0
    if len(tail) == 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if tail:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = _rotl32(k1, 15)
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16
    return h1 if h1 < 0x80000000 else h1 - 0x100000000


def _find_favicon_url(page_url: str, html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")
    for link in soup.find_all("link"):
        rel = " ".join(link.get("rel") or []).lower()
        href = link.get("href")
        if href and "icon" in rel:
            return urljoin(page_url, href)
    return urljoin(page_url, "/favicon.ico")


def _optional_shodan_lookup(favicon_hash: int) -> int | None:
    if not settings.SHODAN_API_KEY:
        return None
    try:
        # Fixed public API endpoint; the secret is sent only as a query parameter
        # and is never included in findings or logs.
        import requests

        response = requests.get(
            "https://api.shodan.io/shodan/host/count",
            params={"key": settings.SHODAN_API_KEY, "query": f"http.favicon.hash:{favicon_hash}"},
            timeout=12,
        )
        response.raise_for_status()
        return int(response.json().get("total", 0))
    except Exception as exc:
        logger.warning("[favicon] Shodan lookup failed: %s", str(exc)[:120])
        return None


def run_favicon_hash_lookup(target: str) -> list[dict]:
    domain = normalize_target(target)
    page = None
    for scheme in ("https", "http"):
        try:
            page = safe_get(f"{scheme}://{domain}/", timeout=12, max_bytes=512 * 1024)
            break
        except Exception:
            continue
    if page is None:
        return []

    favicon_url = _find_favicon_url(page.url, page.text)
    try:
        icon = safe_get(
            favicon_url,
            timeout=12,
            max_bytes=1024 * 1024,
            headers={"Accept": "image/avif,image/webp,image/*,*/*;q=0.8"},
        )
    except Exception as exc:
        logger.info("[favicon] no favicon for %s: %s", domain, str(exc)[:100])
        return []

    content_type = icon.headers.get("Content-Type", "").lower()
    if not icon.content or ("text/html" in content_type and len(icon.content) > 4096):
        return []

    encoded = base64.encodebytes(icon.content)
    shodan_hash = murmurhash3_x86_32(encoded)
    md5_hash = hashlib.md5(icon.content, usedforsecurity=False).hexdigest()
    sha256_hash = hashlib.sha256(icon.content).hexdigest()
    matches = _optional_shodan_lookup(shodan_hash)

    evidence = [
        f"Favicon URL: {icon.url}",
        f"Content-Type: {content_type or 'unknown'}",
        f"Size: {len(icon.content)} bytes",
        f"MD5: {md5_hash}",
        f"SHA-256: {sha256_hash}",
        f"Shodan MurmurHash3: {shodan_hash}",
        f"Shodan query: http.favicon.hash:{shodan_hash}",
    ]
    if matches is not None:
        evidence.append(f"Shodan indexed matches: {matches}")

    return [{
        "tool": "favicon_hash",
        "category": "favicon_hash",
        "severity": "info",
        "title": f"Favicon Fingerprint Generated — {shodan_hash}",
        "description": (
            "The site's favicon was hashed for asset correlation. Matching favicon hashes can reveal related "
            "internet-facing hosts that reuse the same application branding."
        ),
        "evidence": "\n".join(evidence),
        "remediation": "Treat favicon correlation as reconnaissance data and verify ownership before acting on matches.",
    }]
