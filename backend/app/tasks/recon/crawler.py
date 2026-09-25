"""Bounded same-scope site crawl: the link graph a target publishes about itself.

``js_analysis`` reads bundled JavaScript and ``robots_sitemap`` reads what the
site advertises. Neither walks the pages. That left a gap: the stylesheets,
images, forms and outbound links a site renders are part of its attack surface
and its supply chain, and nothing in a safe-profile scan was looking at them.

This is a *safe-profile* crawler, which constrains it in three ways worth
stating because they are the reasons it is allowed to run without the Danger
Mode gate:

* **It only follows same-scope links.** Off-scope hosts are recorded as
  third-party dependencies and never fetched. Crawling them would be scanning
  somebody the operator has no authorization for.
* **It is bounded by page count**, not depth. Depth reads as a ceiling and is
  not one -- a single page with three hundred links costs more than ten pages
  with three.
* **It reads, it does not submit.** Forms are inventoried, including the
  method and the field names, because an unprotected state-changing form is
  worth knowing about. Nothing is ever posted to one.

Every request goes through the pinned HTTP client, so a redirect into a
private network is refused rather than followed.
"""

from __future__ import annotations

import logging
import re
from collections import deque
from urllib.parse import urljoin, urlsplit, urlunsplit

from app.config import settings
from app.targeting import is_same_target_scope, validate_scan_target
from app.tasks.http_client import UnsafeURL, safe_get

logger = logging.getLogger("recontitan.recon.crawler")

#: Extensions that are not worth fetching as pages: they are assets, and the
#: crawler already records them from the markup that referenced them.
NON_PAGE_SUFFIXES = (
    ".css", ".js", ".mjs", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".pdf", ".zip", ".gz", ".tar",
    ".mp4", ".webm", ".mp3", ".wav", ".avi", ".dmg", ".exe", ".msi",
)

#: Paths that are interesting enough to call out when the crawl reaches them.
SENSITIVE_PATH_HINTS = (
    "admin", "login", "signin", "register", "upload", "debug", "config",
    "backup", "console", "phpmyadmin", "wp-admin", "graphql", "actuator",
    "swagger", "api-docs", ".git", ".env", "phpinfo",
)

_TAG_RE = {
    "a": re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'>]+)["']""", re.I),
    "script": re.compile(r"""<script\b[^>]*?\bsrc\s*=\s*["']([^"'>]+)["']""", re.I),
    "css": re.compile(r"""<link\b[^>]*?\bhref\s*=\s*["']([^"'>]+)["'][^>]*>""", re.I),
    "img": re.compile(r"""<img\b[^>]*?\bsrc\s*=\s*["']([^"'>]+)["']""", re.I),
    "form": re.compile(r"""<form\b([^>]*)>(.*?)</form>""", re.I | re.S),
    "input": re.compile(r"""<(?:input|select|textarea)\b[^>]*?\bname\s*=\s*["']([^"'>]+)["']""", re.I),
    "comment": re.compile(r"<!--(.*?)-->", re.S),
}
_ATTR_RE = re.compile(r"""(\w+)\s*=\s*["']([^"']*)["']""")

#: URLs found inside JavaScript. Deliberately conservative: a pattern loose
#: enough to catch every string that might be a path also catches every regex,
#: date format and CSS selector in the bundle.
_JS_PATH_RE = re.compile(r"""["'`](/[A-Za-z0-9_\-./]{3,120})["'`]""")
_JS_URL_RE = re.compile(r"""["'`](https?://[A-Za-z0-9_\-./:%?=&]{6,200})["'`]""")


def _normalise(url: str) -> str:
    """Drop the fragment and any trailing '?' so one page is not crawled twice."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def _is_page(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return not path.endswith(NON_PAGE_SUFFIXES)


def _extract(html: str, base: str) -> dict:
    """Pull the link graph out of one page's markup."""
    out: dict[str, set] = {
        "links": set(), "scripts": set(), "styles": set(),
        "images": set(), "comments": set(),
    }
    forms: list[dict] = []

    for key, pattern in (("links", _TAG_RE["a"]), ("scripts", _TAG_RE["script"]),
                         ("images", _TAG_RE["img"])):
        for raw in pattern.findall(html):
            raw = raw.strip()
            if not raw or raw.startswith(("javascript:", "data:", "#", "mailto:", "tel:")):
                continue
            out[key].add(_normalise(urljoin(base, raw)))

    # Stylesheets come from <link>, which is also used for icons, preloads and
    # canonical URLs. Only rel=stylesheet is a stylesheet.
    for tag in _TAG_RE["css"].finditer(html):
        attrs = dict(_ATTR_RE.findall(tag.group(0)))
        if "stylesheet" in attrs.get("rel", "").lower() and attrs.get("href"):
            out["styles"].add(_normalise(urljoin(base, attrs["href"])))

    for attrs_raw, body in _TAG_RE["form"].findall(html):
        attrs = dict(_ATTR_RE.findall(attrs_raw))
        forms.append({
            "action": _normalise(urljoin(base, attrs.get("action", "") or base)),
            "method": (attrs.get("method") or "GET").upper(),
            "fields": sorted(set(_TAG_RE["input"].findall(body)))[:25],
            "page": base,
        })

    for comment in _TAG_RE["comment"].findall(html):
        text = " ".join(comment.split())
        if 12 <= len(text) <= 300:
            out["comments"].add(text)

    return {**out, "forms": forms}


def _extract_from_js(body: str, base: str) -> tuple[set[str], set[str]]:
    """Paths and absolute URLs referenced inside a script body."""
    paths = {urljoin(base, m) for m in _JS_PATH_RE.findall(body)}
    urls = set(_JS_URL_RE.findall(body))
    return paths, urls


def _summarise(label: str, items, limit: int) -> list[str]:
    items = sorted(items)
    lines = [f"{label} ({len(items)}):"]
    lines += [f"  • {item}" for item in items[:limit]]
    if len(items) > limit:
        lines.append(f"  ... and {len(items) - limit} more")
    return lines + [""]


def run_crawler(target: str) -> list[dict]:
    """Walk the target's own pages and inventory what they reference."""
    if not settings.CRAWLER_ENABLED:
        return [{
            "tool": "crawler", "category": "scanner_coverage", "severity": "info",
            "title": "Site Crawl Disabled",
            "description": "CRAWLER_ENABLED=false, so the site's link graph was not walked.",
            "evidence": "CRAWLER_ENABLED=false",
        }]

    ok, domain, error = validate_scan_target(target, resolve_dns=False)
    if not ok:
        return [{
            "tool": "crawler", "category": "crawl", "severity": "high",
            "title": "Unsafe or Invalid Crawl Target",
            "description": "Crawling was blocked by target validation.",
            "evidence": error,
        }]

    # HTTPS first, but not only. A host that serves plain HTTP is exactly the
    # kind of host this scan should be reading, and defaulting to https alone
    # reported those as "no readable pages" -- a connection failure dressed up
    # as a finding about the site.
    if target.startswith("http"):
        roots = [target]
    else:
        roots = [f"https://{domain}", f"http://{domain}"]
    root = roots[0]
    queue: deque[str] = deque([_normalise(root)])
    seen: set[str] = set()
    visited: list[tuple[str, int, int]] = []
    failed: list[tuple[str, str]] = []

    links_internal: set[str] = set()
    links_external: set[str] = set()
    scripts: set[str] = set()
    styles: set[str] = set()
    images: set[str] = set()
    comments: set[str] = set()
    forms: list[dict] = []
    js_endpoints: set[str] = set()

    while queue and len(visited) < settings.CRAWLER_MAX_PAGES:
        url = queue.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            response = safe_get(
                url, timeout=settings.CRAWLER_TIMEOUT, max_bytes=2 * 1024 * 1024,
            )
        except (UnsafeURL, Exception) as exc:  # noqa: BLE001 — one bad page must not end the crawl
            failed.append((url, f"{type(exc).__name__}: {exc}"[:140]))
            # If the HTTPS root itself was unreachable, try the plain-HTTP one
            # before concluding the site has no pages.
            if url == _normalise(root) and len(roots) > 1:
                queue.append(_normalise(roots[1]))
            continue

        content_type = response.headers.get("Content-Type", "")
        if "html" not in content_type.lower():
            continue
        body = response.text
        visited.append((url, response.status_code, len(response.content)))

        found = _extract(body, response.url)
        scripts |= found["scripts"]
        styles |= found["styles"]
        images |= found["images"]
        comments |= found["comments"]
        forms.extend(found["forms"])

        for link in found["links"]:
            host = urlsplit(link).hostname or ""
            if host and is_same_target_scope(host, domain):
                links_internal.add(link)
                if _is_page(link) and link not in seen:
                    queue.append(link)
            else:
                links_external.add(link)

    # Scripts are read for the endpoints they reference. js_analysis inspects
    # them for secrets and sinks; this only wants the link graph, so a small
    # bounded sample is enough and keeps the crawl inside its budget.
    for script_url in sorted(scripts)[:10]:
        host = urlsplit(script_url).hostname or ""
        if not host or not is_same_target_scope(host, domain):
            continue
        try:
            response = safe_get(
                script_url, timeout=settings.CRAWLER_TIMEOUT, max_bytes=1024 * 1024,
            )
        except Exception as exc:  # noqa: BLE001
            failed.append((script_url, f"{type(exc).__name__}: {exc}"[:140]))
            continue
        paths, urls = _extract_from_js(response.text, script_url)
        js_endpoints |= paths
        for url in urls:
            host = urlsplit(url).hostname or ""
            if host and not is_same_target_scope(host, domain):
                links_external.add(_normalise(url))
            elif host:
                js_endpoints.add(_normalise(url))

    if not visited:
        return [{
            "tool": "crawler", "category": "crawl", "severity": "info",
            "title": "Site Crawl Found No Readable Pages",
            "description": (
                f"No HTML page under {domain} could be read. The host may serve a "
                "non-HTML root, require authentication, or have refused the "
                "scanner. This is not evidence that the site has no pages."
            ),
            "evidence": "\n".join(f"• {url}: {why}" for url, why in failed[:20]) or f"Start URL: {root}",
        }]

    limit = settings.CRAWLER_MAX_LINKS_REPORTED
    third_party_hosts = sorted({urlsplit(u).hostname or "" for u in links_external} - {""})

    evidence = [
        f"Pages crawled   : {len(visited)} (ceiling {settings.CRAWLER_MAX_PAGES})",
        f"Internal links  : {len(links_internal)}",
        f"External links  : {len(links_external)} across {len(third_party_hosts)} hosts",
        f"Scripts         : {len(scripts)}",
        f"Stylesheets     : {len(styles)}",
        f"Images          : {len(images)}",
        f"Forms           : {len(forms)}",
        "",
        "Pages read:",
        *(f"  [{status}] {url}  ({size} bytes)" for url, status, size in visited),
        "",
        *_summarise("Internal links", links_internal, limit),
        *_summarise("Scripts", scripts, 50),
        *_summarise("Stylesheets", styles, 50),
        *_summarise("Images", images, 50),
    ]
    if failed:
        evidence += _summarise(
            "Not retrieved", [f"{url} — {why}" for url, why in failed], 20
        )

    findings = [{
        "tool": "crawler",
        "category": "crawl",
        "severity": "info",
        "title": f"Site Crawl — {len(visited)} pages, {len(links_internal)} internal links",
        "description": (
            f"A bounded same-scope crawl of {domain} read {len(visited)} pages and "
            "inventoried the links, scripts, stylesheets, images and forms they "
            "reference. Only same-scope links were followed; off-scope hosts were "
            "recorded and never fetched. The crawl stopped at the page ceiling, so "
            "a site larger than that ceiling is not fully represented here."
        ),
        "evidence": "\n".join(evidence),
    }]

    if third_party_hosts:
        findings.append({
            "tool": "crawler",
            "category": "third_party_dependencies",
            "severity": "info",
            "title": f"Third-Party Hosts Referenced — {len(third_party_hosts)} found",
            "description": (
                "These hosts are referenced by the target's own pages or scripts. "
                "Each is a supply-chain dependency: content loaded from them "
                "executes in the target's origin. None of them were contacted by "
                "this scan — they are outside the authorized scope."
            ),
            "evidence": "\n".join(f"• {host}" for host in third_party_hosts[:100]),
            "remediation": (
                "Confirm each host is intended. Pin third-party scripts with "
                "Subresource Integrity, and constrain them with a Content-Security-Policy."
            ),
        })

    if forms:
        unprotected = [
            form for form in forms
            if form["method"] == "POST"
            and not any(
                hint in field.lower()
                for field in form["fields"]
                for hint in ("csrf", "token", "authenticity", "nonce", "_token")
            )
        ]
        findings.append({
            "tool": "crawler",
            "category": "web_input_points",
            "severity": "info",
            "title": f"Input Forms Discovered — {len(forms)} found",
            "description": (
                f"{len(forms)} forms were inventoried across the crawled pages. "
                "These are the target's accepted inputs. Nothing was submitted to "
                "any of them."
            ),
            "evidence": "\n".join(
                f"• [{form['method']}] {form['action']}\n"
                f"    fields: {', '.join(form['fields']) or '(none named)'}"
                for form in forms[:40]
            ),
        })
        if unprotected:
            findings.append({
                "tool": "crawler",
                "category": "web_input_points",
                "severity": "low",
                "title": f"POST Forms With No Visible Anti-CSRF Field — {len(unprotected)} found",
                "description": (
                    "These state-changing forms carry no field whose name suggests a "
                    "CSRF token. That is a candidate observation drawn from field "
                    "names in the markup, not a confirmed vulnerability: the "
                    "protection may be a SameSite cookie, a custom header, or a "
                    "token name this check does not recognise."
                ),
                "evidence": "\n".join(
                    f"• [{form['method']}] {form['action']}\n"
                    f"    fields: {', '.join(form['fields']) or '(none named)'}"
                    for form in unprotected[:25]
                ),
                "remediation": (
                    "Confirm each of these is protected by a synchroniser token, a "
                    "SameSite=Lax/Strict session cookie, or an origin check."
                ),
                "requires_manual_validation": True,
            })

    if js_endpoints:
        findings.append({
            "tool": "crawler",
            "category": "web_input_points",
            "severity": "info",
            "title": f"Endpoints Referenced in JavaScript — {len(js_endpoints)} found",
            "description": (
                "Paths and URLs extracted from the target's own script bundles. "
                "These are endpoints the application knows about, including ones no "
                "page links to. Each was read out of source — none were requested."
            ),
            "evidence": "\n".join(f"• {url}" for url in sorted(js_endpoints)[:100]),
        })

    interesting = sorted(
        url for url in links_internal | js_endpoints
        if any(hint in urlsplit(url).path.lower() for hint in SENSITIVE_PATH_HINTS)
    )
    if interesting:
        findings.append({
            "tool": "crawler",
            "category": "sensitive_paths",
            "severity": "medium",
            "title": f"Sensitive Paths Referenced — {len(interesting)} found",
            "description": (
                "The application's own markup or scripts reference these paths, "
                "which carry names usually belonging to administrative, debugging "
                "or authentication surfaces. The reference is the evidence; the "
                "crawler did not check what any of them return."
            ),
            "evidence": "\n".join(f"• {url}" for url in interesting[:60]),
            "remediation": (
                "Confirm each requires authentication, and that debugging and "
                "configuration endpoints are not reachable from the internet."
            ),
        })

    if comments:
        flagged = sorted(
            comment for comment in comments
            if re.search(r"\b(todo|fixme|hack|password|passwd|api[_-]?key|secret|token|xxx|bug|temporary)\b",
                         comment, re.I)
        )
        if flagged:
            findings.append({
                "tool": "crawler",
                "category": "information_disclosure",
                "severity": "low",
                "title": f"Revealing HTML Comments — {len(flagged)} found",
                "description": (
                    "HTML comments containing developer notes were served to the "
                    "browser. Comments are shipped verbatim to every visitor and "
                    "routinely name internal systems, unfinished controls or "
                    "credentials."
                ),
                "evidence": "\n".join(f"• {comment[:200]}" for comment in flagged[:25]),
                "remediation": "Strip comments from production markup at build time.",
            })

    logger.info(
        "[crawler] %s: %d pages, %d internal, %d external, %d scripts, %d forms",
        domain, len(visited), len(links_internal), len(links_external), len(scripts), len(forms),
    )
    return findings
