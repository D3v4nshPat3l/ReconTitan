"""Technology stack detection from HTTP headers, HTML, cookies, and assets."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from bs4 import BeautifulSoup

from app.tasks.http_client import safe_get
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.recon.tech_stack")


@dataclass(frozen=True)
class Signature:
    name: str
    category: str
    patterns: tuple[str, ...]
    version_pattern: str | None = None


SIGNATURES = (
    Signature("WordPress", "CMS", (r"/wp-content/", r"/wp-includes/", r"/wp-json/"), r"wordpress[\s/\-]?([0-9.]+)"),
    Signature("Drupal", "CMS", (r"drupal-settings-json", r"/sites/default/files/", r"x-generator:\s*drupal"), r"drupal\s*([0-9.]+)"),
    Signature("Joomla", "CMS", (r"/components/com_", r"content=['\"]joomla!", r"x-content-encoded-by:\s*joomla"), r"joomla!?\s*([0-9.]+)"),
    Signature("Shopify", "E-commerce", (r"cdn\.shopify\.com", r"shopify\.theme", r"x-shopid")),
    Signature("WooCommerce", "E-commerce", (r"woocommerce", r"wc-ajax=", r"/plugins/woocommerce/"), r"woocommerce[\s/\-]?([0-9.]+)"),
    Signature("Magento", "E-commerce", (r"mage/cookies", r"static/version", r"x-magento-"), r"magento[\s/\-]?([0-9.]+)"),
    Signature("React", "JavaScript", (r"data-reactroot", r"__react_devtools_global_hook__", r"react-dom"), r"react(?:\.production\.min)?\.js\?v=([0-9.]+)"),
    Signature("Next.js", "Framework", (r"/_next/static/", r"__next_data__", r"x-powered-by:\s*next\.js"), r"next[./-]([0-9.]+)"),
    Signature("Vue.js", "JavaScript", (r"__vue__", r"data-v-[a-f0-9]{6,}", r"vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js"), r"vue(?:\.min)?\.js\?v=([0-9.]+)"),
    Signature("Angular", "JavaScript", (r"ng-version=", r"<app-root", r"angular(?:\.min)?\.js"), r"ng-version=['\"]([0-9.]+)"),
    Signature("Svelte", "JavaScript", (r"svelte-[a-z0-9]+", r"__svelte")),
    Signature("jQuery", "JavaScript", (r"jquery(?:[-.]|\.min\.)", r"jquery v"), r"jquery(?:-|\.)([0-9]+(?:\.[0-9]+){1,2})"),
    Signature("Bootstrap", "CSS", (r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)",), r"bootstrap(?:-|/)([0-9]+(?:\.[0-9]+){1,2})"),
    Signature("Django", "Framework", (r"csrftoken", r"csrfmiddlewaretoken", r"django")),
    Signature("Laravel", "Framework", (r"laravel_session", r"x-powered-by:\s*php", r"csrf-token")),
    Signature("Ruby on Rails", "Framework", (r"_rails_session", r"x-runtime", r"csrf-param")),
    Signature("ASP.NET", "Framework", (r"__viewstate", r"asp\.net_sessionid", r"x-aspnet-version"), r"x-aspnet-version:\s*([0-9.]+)"),
    Signature("Express", "Framework", (r"x-powered-by:\s*express", r"connect\.sid")),
    Signature("GraphQL", "API", (r"/graphql", r"__apollo_state__", r"apollo-client")),
    Signature("Nginx", "Web server", (r"server:\s*nginx",), r"server:\s*nginx/?([0-9.]+)?"),
    Signature("Apache", "Web server", (r"server:\s*apache",), r"server:\s*apache/?([0-9.]+)?"),
    Signature("Microsoft IIS", "Web server", (r"server:\s*microsoft-iis",), r"microsoft-iis/?([0-9.]+)?"),
    Signature("Cloudflare", "CDN/WAF", (r"server:\s*cloudflare", r"cf-ray:", r"__cf_bm")),
    Signature("Fastly", "CDN", (r"x-served-by:.*cache-", r"fastly-debug-digest")),
    Signature("Vercel", "Hosting", (r"x-vercel-id:", r"server:\s*vercel")),
    Signature("Netlify", "Hosting", (r"server:\s*netlify", r"x-nf-request-id")),
)


def _combined_response_text(headers: dict[str, str], body: str, soup: BeautifulSoup) -> str:
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    assets = "\n".join(
        tag.get("src") or tag.get("href") or ""
        for tag in soup.find_all(["script", "link"])
    )
    cookies = headers.get("Set-Cookie", "")
    return "\n".join([header_text, cookies, body[:500_000], assets]).lower()


def run_tech_stack_detection(target: str) -> list[dict]:
    """Detect application, framework, server, CDN, and library technologies."""
    domain = normalize_target(target)
    findings: list[dict] = []
    response = None
    last_error = None
    for scheme in ("https", "http"):
        try:
            response = safe_get(f"{scheme}://{domain}/", timeout=12, max_bytes=1024 * 1024)
            break
        except Exception as exc:  # scanner modules fail soft by design
            last_error = exc
    if response is None:
        logger.warning("[tech] failed for %s: %s", domain, last_error)
        return findings

    body = response.text
    soup = BeautifulSoup(body, "html.parser")
    combined = _combined_response_text(response.headers, body, soup)
    detected: list[tuple[str, str, str | None, str]] = []

    generator = soup.find("meta", attrs={"name": re.compile(r"^generator$", re.I)})
    if generator and generator.get("content"):
        value = str(generator.get("content"))[:160]
        detected.append((value, "Generator", None, "HTML meta generator"))

    for signature in SIGNATURES:
        matched_pattern = None
        for pattern in signature.patterns:
            if re.search(pattern, combined, re.I):
                matched_pattern = pattern
                break
        if not matched_pattern:
            continue
        version = None
        if signature.version_pattern:
            match = re.search(signature.version_pattern, combined, re.I)
            if match and match.groups():
                version = next((g for g in match.groups() if g), None)
        detected.append((signature.name, signature.category, version, matched_pattern))

    # Preserve order but remove duplicates.
    unique: dict[str, tuple[str, str, str | None, str]] = {}
    for item in detected:
        unique.setdefault(item[0].lower(), item)
    detected = list(unique.values())

    if detected:
        evidence_lines = []
        for name, category, version, source in detected:
            label = f"{name} {version}" if version else name
            evidence_lines.append(f"• {label} [{category}] — matched {source}")
        findings.append({
            "tool": "tech_stack",
            "category": "tech_stack",
            "severity": "info",
            "title": f"Technology Stack Detected — {len(detected)} technologies",
            "description": (
                f"ReconTitan identified technologies used by {domain} from response headers, "
                "HTML metadata, cookies, and referenced assets."
            ),
            "evidence": "\n".join(evidence_lines),
            "remediation": "Remove unnecessary version disclosure and keep every detected component patched.",
        })

    disclosed = []
    for header in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
        value = response.headers.get(header)
        if value:
            disclosed.append(f"{header}: {value[:160]}")
    if disclosed:
        findings.append({
            "tool": "tech_stack",
            "category": "version_disclosure",
            "severity": "low",
            "title": "Technology Version Information Disclosed",
            "description": "Response headers reveal server or framework details that simplify targeted vulnerability research.",
            "evidence": "\n".join(disclosed),
            "remediation": "Suppress detailed Server and X-Powered-By headers at the application and reverse-proxy layers.",
        })

    logger.info("[tech] detected %d technologies for %s", len(detected), domain)
    return findings
