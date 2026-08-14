"""Conservative subdomain takeover detection.

A high-severity finding is emitted only when a known SaaS CNAME is paired with
an unclaimed-service HTTP fingerprint or the delegated CNAME target is NXDOMAIN.
Provider CNAMEs that appear active are counted only in the informational summary.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import dns.exception
import dns.resolver

from app.config import settings
from app.tasks.http_client import safe_get
from app.targeting import normalize_target

logger = logging.getLogger("recontitan.recon.takeover")


@dataclass(frozen=True)
class Provider:
    name: str
    cname_suffixes: tuple[str, ...]
    fingerprints: tuple[str, ...]


PROVIDERS = (
    Provider("GitHub Pages", ("github.io",), ("there isn't a github pages site here", "for root urls (like http://example.com/) you must provide an index.html file")),
    Provider("Heroku", ("herokudns.com", "herokuapp.com"), ("no such app", "there's nothing here, yet")),
    Provider("Amazon S3", ("s3.amazonaws.com", "s3-website"), ("nosuchbucket", "the specified bucket does not exist")),
    Provider("Microsoft Azure", ("azurewebsites.net", "cloudapp.azure.com", "trafficmanager.net"), ("404 web site not found", "this azure web app is not available")),
    Provider("Fastly", ("fastly.net",), ("fastly error: unknown domain",)),
    Provider("Netlify", ("netlify.app", "netlify.com"), ("not found - request id", "page not found")),
    Provider("Vercel", ("vercel.app", "now.sh"), ("the deployment could not be found", "404: not_found")),
    Provider("Shopify", ("myshopify.com",), ("sorry, this shop is currently unavailable", "only one step left")),
    Provider("Tumblr", ("domains.tumblr.com",), ("there's nothing here", "whatever you were looking for doesn't currently exist")),
    Provider("Surge", ("surge.sh",), ("project not found",)),
    Provider("ReadMe", ("readme.io",), ("project doesnt exist", "project doesn't exist")),
    Provider("Pantheon", ("pantheonsite.io",), ("the gods are wise", "404 error unknown site")),
    Provider("Ghost", ("ghost.io",), ("the thing you were looking for is no longer here",)),
)


def _provider_for(cname: str) -> Provider | None:
    cname = cname.rstrip(".").lower()
    for provider in PROVIDERS:
        if any(cname == suffix or cname.endswith("." + suffix) for suffix in provider.cname_suffixes):
            return provider
    return None


def _discover_subdomains(domain: str) -> list[str]:
    try:
        response = safe_get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20,
            max_bytes=5 * 1024 * 1024,
            headers={"Accept": "application/json"},
        )
        rows = response.json()
    except Exception as exc:
        logger.warning("[takeover] crt.sh failed for %s: %s", domain, str(exc)[:120])
        return []

    values: set[str] = set()
    if isinstance(rows, list):
        for row in rows:
            for name in str(row.get("name_value", "")).splitlines():
                candidate = name.strip().lower().lstrip("*.").rstrip(".")
                if candidate != domain and candidate.endswith("." + domain):
                    values.add(candidate)
    return sorted(values)[: settings.TAKEOVER_MAX_SUBDOMAINS]


def _resolve_cname(host: str) -> str | None:
    try:
        answer = dns.resolver.resolve(host, "CNAME", lifetime=5)
        return str(answer[0].target).rstrip(".").lower()
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return None


def _cname_target_exists(cname: str) -> bool:
    for record_type in ("A", "AAAA"):
        try:
            answer = dns.resolver.resolve(cname, record_type, lifetime=5)
            if answer:
                return True
        except dns.resolver.NXDOMAIN:
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
    return True  # inconclusive must not become a vulnerability finding


def _unclaimed_http_fingerprint(host: str, provider: Provider) -> tuple[bool, str]:
    for scheme in ("https", "http"):
        try:
            response = safe_get(f"{scheme}://{host}/", timeout=10, max_bytes=256 * 1024)
        except Exception:
            continue
        text = response.text.lower()
        for fingerprint in provider.fingerprints:
            if fingerprint in text:
                return True, f"HTTP {response.status_code} matched: {fingerprint}"
    return False, ""


def run_subdomain_takeover(target: str) -> list[dict]:
    domain = normalize_target(target)
    subdomains = _discover_subdomains(domain)
    checked = 0
    provider_delegations = 0
    vulnerable: list[dict] = []

    for host in subdomains:
        cname = _resolve_cname(host)
        if not cname:
            continue
        checked += 1
        provider = _provider_for(cname)
        if not provider:
            continue
        provider_delegations += 1

        reason = ""
        vulnerable_state = False
        if not _cname_target_exists(cname):
            vulnerable_state = True
            reason = "Delegated CNAME target returns NXDOMAIN"
        else:
            vulnerable_state, reason = _unclaimed_http_fingerprint(host, provider)

        if vulnerable_state:
            vulnerable.append({
                "tool": "subdomain_takeover",
                "category": "subdomain_takeover",
                "severity": "high",
                "title": f"Potential Subdomain Takeover — {host}",
                "description": (
                    f"{host} delegates to {provider.name} through {cname}, and ReconTitan observed evidence "
                    "consistent with an unclaimed resource. Manual provider-side verification is still required."
                ),
                "evidence": f"Subdomain: {host}\nCNAME: {cname}\nProvider: {provider.name}\nEvidence: {reason}",
                "remediation": "Remove the dangling DNS record or claim and secure the referenced provider resource immediately.",
            })

    summary = {
        "tool": "subdomain_takeover",
        "category": "subdomain_takeover_summary",
        "severity": "info",
        "title": f"Subdomain Takeover Check — {len(vulnerable)} potential issue(s)",
        "description": f"Checked {checked} CNAME records across {len(subdomains)} certificate-derived subdomains.",
        "evidence": (
            f"Subdomains enumerated: {len(subdomains)}\n"
            f"CNAME records checked: {checked}\n"
            f"Known SaaS delegations: {provider_delegations}\n"
            f"Potential dangling delegations: {len(vulnerable)}"
        ),
    }
    return [summary, *vulnerable]
