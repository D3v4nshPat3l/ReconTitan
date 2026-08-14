"""Detailed Danger Mode reconnaissance.

Extends the passive recon profile with a bounded brute-force subdomain sweep and
live-host fingerprinting, producing the seed list the attack-surface crawler
consumes. All discovery here is read-only.
"""

from __future__ import annotations

import logging
import socket

from app.config import settings
from app.targeting import is_same_target_scope, normalize_target
from app.tasks.vulnscan.danger.budget import DangerBudget, danger_finding, evidence_block, truncated

logger = logging.getLogger("recontitan.danger.recon")

MODULE = "danger_recon"

#: Bounded built-in wordlist. Trimmed to DANGER_SUBDOMAIN_BRUTE_LIMIT at runtime.
SUBDOMAIN_WORDLIST = (
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp", "sftp", "ns1", "ns2",
    "api", "api-dev", "api-staging", "dev", "development", "staging", "stage", "test",
    "testing", "qa", "uat", "sandbox", "demo", "beta", "alpha", "preview", "next",
    "admin", "administrator", "portal", "dashboard", "panel", "cpanel", "console",
    "manage", "management", "internal", "intranet", "corp", "vpn", "remote", "gateway",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "cd", "build", "deploy",
    "jira", "confluence", "wiki", "docs", "documentation", "help", "support", "status",
    "blog", "news", "shop", "store", "cart", "checkout", "pay", "payment", "billing",
    "auth", "login", "sso", "oauth", "idp", "accounts", "id", "identity",
    "cdn", "static", "assets", "media", "img", "images", "files", "download", "uploads",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic", "search",
    "backup", "backups", "old", "legacy", "archive", "tmp", "temp",
    "monitor", "monitoring", "grafana", "kibana", "prometheus", "metrics", "logs",
    "mobile", "m", "app", "apps", "web", "www2", "secure", "ssl", "proxy", "lb",
)


def _resolve(host: str) -> list[str]:
    try:
        return sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    except Exception:
        return []


def brute_force_subdomains(domain: str, *, limit: int | None = None) -> dict[str, list[str]]:
    """Resolve a bounded wordlist against ``domain``; return live host -> addresses."""
    cap = limit if limit is not None else settings.DANGER_SUBDOMAIN_BRUTE_LIMIT
    live: dict[str, list[str]] = {}
    for word in SUBDOMAIN_WORDLIST[:cap]:
        host = f"{word}.{domain}"
        addresses = _resolve(host)
        if addresses:
            live[host] = addresses
    return live


def _passive_subdomains(domain: str) -> list[str]:
    """Reuse the existing passive sources; each failure is tolerated."""
    hosts: set[str] = set()
    try:
        from app.tasks.recon.crtsh import run_crtsh

        for finding in run_crtsh(domain) or []:
            for line in str(finding.get("evidence", "")).splitlines():
                candidate = line.strip().lstrip("•").strip().lower()
                if candidate and "." in candidate and is_same_target_scope(candidate, domain):
                    hosts.add(candidate)
    except Exception as exc:
        logger.debug("[danger:recon] crt.sh unavailable: %s", str(exc)[:120])

    try:
        from app.tasks.recon.subfinder_amass import run_subfinder

        for finding in run_subfinder(domain) or []:
            for line in str(finding.get("evidence", "")).splitlines():
                candidate = line.strip().lstrip("•").strip().lower()
                if candidate and "." in candidate and is_same_target_scope(candidate, domain):
                    hosts.add(candidate)
    except Exception as exc:
        logger.debug("[danger:recon] subfinder unavailable: %s", str(exc)[:120])

    return sorted(hosts)


def fingerprint_host(budget: DangerBudget, host: str) -> dict | None:
    """Probe one host over HTTPS then HTTP and record its response fingerprint."""
    for scheme in ("https", "http"):
        result = budget.probe(MODULE, "GET", f"{scheme}://{host}/", counts_as_payload=False)
        if result.ok and result.response is not None:
            headers = result.response.headers
            return {
                "host": host,
                "url": result.response.url,
                "scheme": scheme,
                "status": result.status,
                "server": truncated(headers.get("Server", "not disclosed"), 80),
                "powered_by": truncated(headers.get("X-Powered-By", ""), 80),
                "content_type": truncated(headers.get("Content-Type", ""), 60),
                "bytes": result.size,
            }
    return None


def run_danger_recon(target: str, budget: DangerBudget) -> tuple[list[str], list[dict]]:
    """Discover and fingerprint live in-scope hosts.

    Returns ``(seed_urls, findings)`` where the seeds feed the attack-surface
    crawler.
    """
    domain = normalize_target(target)
    findings: list[dict] = []

    passive = _passive_subdomains(domain)
    brute = brute_force_subdomains(domain)
    candidates: list[str] = [domain]
    for host in list(brute.keys()) + passive:
        if host not in candidates:
            candidates.append(host)

    live: list[dict] = []
    for host in candidates[: settings.DANGER_MAX_HOSTS]:
        fingerprinted = fingerprint_host(budget, host)
        if fingerprinted:
            live.append(fingerprinted)

    findings.append(danger_finding(
        tool=MODULE,
        category="danger_host_discovery",
        severity="info",
        title=f"Danger Recon - {len(live)} live host(s) fingerprinted",
        description=(
            f"Danger Mode combined certificate-transparency and passive sources with a bounded brute-force sweep "
            f"({min(len(SUBDOMAIN_WORDLIST), settings.DANGER_SUBDOMAIN_BRUTE_LIMIT)} candidate names) across "
            f"{domain}, then probed the first {settings.DANGER_MAX_HOSTS} candidates to identify live hosts."
        ),
        evidence=evidence_block([
            ("Passive subdomains", len(passive)),
            ("Brute-force hits", len(brute)),
            ("Candidates considered", len(candidates)),
            ("Live hosts probed", len(live)),
            ("Hosts", "\n" + "\n".join(
                f"  {item['host']} -> {item['status']} {item['server']} ({item['bytes']} bytes)"
                for item in live
            ) if live else "No live hosts responded"),
        ]),
        remediation=(
            "Retire hosts that no longer need to be public, and place development, staging, and administrative "
            "hosts behind network controls rather than relying on obscurity."
        ),
        asset=domain,
    ))

    disclosed = [item for item in live if item["server"] not in {"", "not disclosed"} or item["powered_by"]]
    if disclosed:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_fingerprint",
            severity="low",
            title=f"Server Fingerprints Disclosed - {len(disclosed)} host(s)",
            description=(
                "Discovered hosts disclose server or framework identity in response headers, which narrows the "
                "vulnerability research an attacker needs to perform."
            ),
            evidence=evidence_block([
                (item["host"], f"Server={item['server']} X-Powered-By={item['powered_by'] or 'none'}")
                for item in disclosed[:30]
            ]),
            remediation="Suppress Server and X-Powered-By headers at the application and reverse-proxy layers.",
            owasp="A05:2021-Security Misconfiguration",
            asset=domain,
        ))

    seeds = [item["url"] for item in live] or [f"https://{domain}/"]
    logger.info("[danger:recon] %s: %d live hosts, %d seeds", domain, len(live), len(seeds))
    return seeds, findings
