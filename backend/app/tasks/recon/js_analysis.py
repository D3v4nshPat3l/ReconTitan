"""Bounded JavaScript asset analysis for secrets, endpoints, and risky sinks."""

from __future__ import annotations

import hashlib
import logging
import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup

from app.config import settings
from app.tasks.http_client import safe_get
from app.targeting import is_same_target_scope, normalize_target

logger = logging.getLogger("recontitan.recon.js_analysis")

SECRET_PATTERNS = {
    "AWS access key": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "Google API key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "Slack token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "JWT": re.compile(r"\beyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\b"),
    "Private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "Generic secret assignment": re.compile(
        r"(?i)\b(?:api[_-]?key|secret|access[_-]?token|auth[_-]?token)\b\s*[:=]\s*['\"]([^'\"]{12,})['\"]"
    ),
}
RISKY_PATTERNS = {
    "eval()": re.compile(r"\beval\s*\("),
    "new Function()": re.compile(r"\bnew\s+Function\s*\("),
    "document.write()": re.compile(r"\bdocument\.write(?:ln)?\s*\("),
    "innerHTML assignment": re.compile(r"\.innerHTML\s*="),
    "outerHTML assignment": re.compile(r"\.outerHTML\s*="),
    "insertAdjacentHTML()": re.compile(r"\.insertAdjacentHTML\s*\("),
    "postMessage wildcard": re.compile(r"\.postMessage\s*\([^,]+,\s*['\"]\*['\"]\s*\)"),
}
ENDPOINT_RE = re.compile(
    r"(?P<quote>['\"])(?P<url>(?:https?://[^'\"\s]{4,}|/(?:api|v[0-9]+|graphql|auth|admin|internal)/[^'\"\s]*))(?P=quote)",
    re.I,
)
SOURCE_MAP_RE = re.compile(r"//#\s*sourceMappingURL\s*=\s*([^\s]+)")


def _redacted_secret(kind: str, value: str, source: str) -> str:
    fingerprint = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:12]
    return f"{kind} in {source} (fingerprint sha256:{fingerprint}; value redacted)"


def _extract_scripts(page_url: str, html: str, target: str) -> tuple[list[str], list[str]]:
    soup = BeautifulSoup(html, "html.parser")
    external: list[str] = []
    inline: list[str] = []
    for script in soup.find_all("script"):
        src = script.get("src")
        if src:
            url = urljoin(page_url, src)
            host = urlsplit(url).hostname or ""
            if is_same_target_scope(host, target) and url not in external:
                external.append(url)
        else:
            text = script.string or script.get_text(" ", strip=False)
            if text.strip():
                inline.append(text[: settings.JS_ANALYSIS_MAX_BYTES])
    return external[: settings.JS_ANALYSIS_MAX_FILES], inline[:10]


def run_js_file_analysis(target: str) -> list[dict]:
    domain = normalize_target(target)
    page = None
    for scheme in ("https", "http"):
        try:
            page = safe_get(f"{scheme}://{domain}/", timeout=12, max_bytes=1024 * 1024)
            break
        except Exception:
            continue
    if page is None:
        return []

    script_urls, inline_scripts = _extract_scripts(page.url, page.text, domain)
    sources: list[tuple[str, str]] = [("inline-script", text) for text in inline_scripts]
    failed = 0
    for url in script_urls:
        try:
            response = safe_get(
                url,
                timeout=12,
                max_bytes=settings.JS_ANALYSIS_MAX_BYTES,
                headers={"Accept": "application/javascript,text/javascript,*/*;q=0.1"},
            )
            sources.append((response.url, response.text))
        except Exception as exc:
            failed += 1
            logger.debug("[js] skipped %s: %s", url, str(exc)[:100])

    findings: list[dict] = []
    inventory = [f"• {url}" for url in script_urls]
    if inline_scripts:
        inventory.append(f"• {len(inline_scripts)} inline script block(s)")
    inventory.append(f"Downloaded: {max(0, len(sources) - len(inline_scripts))}; failed/skipped: {failed}")
    findings.append({
        "tool": "js_analysis",
        "category": "javascript_inventory",
        "severity": "info",
        "title": f"JavaScript Inventory — {len(script_urls)} external files",
        "description": "Same-origin JavaScript assets were enumerated and analyzed with strict file-count and size limits.",
        "evidence": "\n".join(inventory[:100]),
    })

    secret_hits: list[str] = []
    risky_hits: dict[str, list[str]] = {}
    endpoint_hits: set[str] = set()
    source_maps: set[str] = set()

    for source_name, text in sources:
        for kind, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                value = match.group(1) if match.groups() else match.group(0)
                secret_hits.append(_redacted_secret(kind, value, source_name))
                if len(secret_hits) >= 30:
                    break
        for sink, pattern in RISKY_PATTERNS.items():
            if pattern.search(text):
                risky_hits.setdefault(sink, []).append(source_name)
        for match in ENDPOINT_RE.finditer(text):
            endpoint = match.group("url")
            if len(endpoint) <= 300:
                endpoint_hits.add(endpoint)
            if len(endpoint_hits) >= 100:
                break
        for match in SOURCE_MAP_RE.finditer(text):
            source_maps.add(urljoin(source_name if source_name.startswith("http") else page.url, match.group(1)))

    if secret_hits:
        findings.append({
            "tool": "js_analysis",
            "category": "javascript_secret",
            "severity": "high",
            "title": f"Potential Secrets in JavaScript — {len(secret_hits)} match(es)",
            "description": "Client-side JavaScript contains values matching secret or credential patterns. Values are redacted in this report.",
            "evidence": "\n".join(f"• {hit}" for hit in secret_hits[:30]),
            "remediation": "Rotate confirmed credentials, remove them from client bundles and history, and retrieve secrets from a server-side secret manager.",
        })

    if risky_hits:
        evidence = []
        for sink, urls in risky_hits.items():
            evidence.append(f"• {sink}: {len(set(urls))} file(s)")
        findings.append({
            "tool": "js_analysis",
            "category": "javascript_risky_sink",
            "severity": "medium",
            "title": f"Risky JavaScript Sinks Detected — {len(risky_hits)} type(s)",
            "description": "Potentially dangerous DOM or code-execution APIs were found. Presence alone is not proof of exploitability.",
            "evidence": "\n".join(evidence),
            "remediation": "Trace untrusted data into each sink, prefer safe DOM APIs, and enforce a strict Content Security Policy.",
        })

    if source_maps:
        findings.append({
            "tool": "js_analysis",
            "category": "javascript_source_map",
            "severity": "low",
            "title": f"JavaScript Source Maps Referenced — {len(source_maps)}",
            "description": "Production bundles reference source maps that may expose original source code or internal paths if publicly accessible.",
            "evidence": "\n".join(f"• {url}" for url in sorted(source_maps)[:30]),
            "remediation": "Do not deploy source maps publicly unless they are intentionally access-controlled and scrubbed of secrets.",
        })

    if endpoint_hits:
        findings.append({
            "tool": "js_analysis",
            "category": "javascript_endpoints",
            "severity": "info",
            "title": f"Client-Side Endpoints Discovered — {len(endpoint_hits)}",
            "description": "API and application routes referenced by JavaScript were collected for authorized attack-surface review.",
            "evidence": "\n".join(f"• {url}" for url in sorted(endpoint_hits)[:100]),
        })

    return findings
