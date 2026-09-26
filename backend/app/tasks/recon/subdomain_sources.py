"""Passive subdomain aggregation across many independent public sources.

Why this exists alongside ``subfinder_amass``: those two are Go binaries. On a
host that does not have them installed -- which is every host that has only
run the setup script -- passive enumeration collapses to certificate
transparency alone, and the report honestly says two modules were skipped.
That is accurate and still unhelpful, because a domain's subdomains are the
attack surface, and one source finds a fraction of them.

Everything here is pure Python over public HTTP APIs, so it runs anywhere the
scanner runs. Sources fall into three groups:

* **Keyless** -- queried on every scan.
* **Keyed** -- skipped silently when the key is absent, exactly like the
  threat-intel modules. An absent key costs nothing and reports nothing.
* **Disclosing** -- sources that must be told the target to answer. These are
  gated behind the same ``ALLOW_HACKERTARGET`` opt-in the port scanner uses,
  because a scan authorization frequently does not extend to telling an
  unrelated company which host is being assessed.

Every source reports its own outcome. A source that errored, timed out or was
rate-limited says so in the coverage table rather than contributing an empty
set that reads as "nothing here" -- the difference between a source finding
nothing and a source never running is the whole point of the table.
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Callable

import requests

from app.config import settings

logger = logging.getLogger("recontitan.recon.subdomain_sources")

#: Subdomains whose leftmost label suggests a less-hardened environment. Kept
#: deliberately narrow: a keyword list that matches everything flags everything,
#: and a finding that flags everything is read by nobody.
SENSITIVE_KEYWORDS = (
    "admin", "dev", "staging", "stage", "test", "internal", "vpn", "portal",
    "manage", "dashboard", "backup", "old", "beta", "qa", "uat", "corp",
    "intranet", "jenkins", "gitlab", "git", "jira", "confluence", "grafana",
    "kibana", "phpmyadmin", "sso", "auth", "legacy", "demo", "sandbox",
)

_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$")


def _clean(names, domain: str) -> set[str]:
    """Normalise raw source output into in-scope hostnames.

    Sources return wildcards, uppercase, trailing dots, whole URLs and
    occasionally an unrelated domain. Accepting those unchecked would put
    names in the report that are not the target's, which is worse than
    missing them.
    """
    suffix = "." + domain
    out: set[str] = set()
    for raw in names:
        if not raw:
            continue
        name = str(raw).strip().lower().rstrip(".")
        name = name.removeprefix("https://").removeprefix("http://").split("/")[0]
        name = name.split("@")[-1].lstrip("*.").strip()
        if not name or name == domain:
            continue
        if not name.endswith(suffix):
            continue
        if not _HOSTNAME_RE.match(name):
            continue
        out.add(name)
    return out


def _get(url: str, **kwargs) -> requests.Response:
    """GET one source, always under a timeout.

    The timeout is passed as a named argument rather than folded into
    ``kwargs``. Both forms set it, but only this one is visible to a static
    reader -- human or analyser -- and a request without a timeout is the kind
    of defect that shows up as a scan that never returns rather than as an
    error anyone can trace. Naming it here means the guarantee cannot be lost
    by a caller who passes a ``kwargs`` dict of their own.
    """
    timeout = kwargs.pop("timeout", settings.SUBDOMAIN_SOURCE_TIMEOUT)
    kwargs.setdefault("headers", {}).setdefault(
        "User-Agent", "Mozilla/5.0 (compatible; ReconTitan; +authorized-security-scan)"
    )
    response = requests.get(url, timeout=timeout, **kwargs)
    response.raise_for_status()
    return response


# ---------------------------------------------------------------------------
# Keyless sources
# ---------------------------------------------------------------------------

def _src_crtsh(domain: str) -> set[str]:
    rows = _get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}).json()
    names: list[str] = []
    for row in rows:
        names.extend(str(row.get("name_value", "")).splitlines())
        names.append(row.get("common_name", ""))
    return _clean(names, domain)


def _src_certspotter(domain: str) -> set[str]:
    rows = _get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
    ).json()
    names: list[str] = []
    for row in rows:
        names.extend(row.get("dns_names", []))
    return _clean(names, domain)


def _src_alienvault(domain: str) -> set[str]:
    data = _get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    ).json()
    return _clean([row.get("hostname", "") for row in data.get("passive_dns", [])], domain)


def _src_anubis(domain: str) -> set[str]:
    return _clean(_get(f"https://jldc.me/anubis/subdomains/{domain}").json(), domain)


def _src_threatminer(domain: str) -> set[str]:
    data = _get("https://api.threatminer.org/v2/domain.php", params={"q": domain, "rt": 5}).json()
    return _clean(data.get("results", []), domain)


def _src_rapiddns(domain: str) -> set[str]:
    html = _get(f"https://rapiddns.io/subdomain/{domain}", params={"full": 1}).text
    return _clean(re.findall(r"<td>([^<]+)</td>", html), domain)


def _src_wayback(domain: str) -> set[str]:
    rows = _get(
        "https://web.archive.org/cdx/search/cdx",
        params={
            "url": f"*.{domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            # Only the hostname is wanted here, and the archive is the slowest
            # source in the set. A lower ceiling than the wayback module's own
            # keeps one slow source from deciding how long the sweep takes.
            "limit": 2000,
        },
    ).json()
    return _clean([row[0] for row in rows[1:] if row], domain)


def _src_urlscan(domain: str) -> set[str]:
    headers = {"API-Key": settings.URLSCAN_API_KEY} if settings.URLSCAN_API_KEY else {}
    data = _get(
        "https://urlscan.io/api/v1/search/",
        params={"q": f"domain:{domain}", "size": 10000},
        headers=headers,
    ).json()
    names: list[str] = []
    for row in data.get("results", []):
        page = row.get("page", {})
        names.append(page.get("domain", ""))
        names.append(page.get("url", ""))
    return _clean(names, domain)


def _src_subdomaincenter(domain: str) -> set[str]:
    return _clean(_get("https://api.subdomain.center/", params={"domain": domain}).json(), domain)


# ---------------------------------------------------------------------------
# Sources that must be told the target
# ---------------------------------------------------------------------------

def _src_hackertarget(domain: str) -> set[str]:
    text = _get("https://api.hackertarget.com/hostsearch/", params={"q": domain}).text
    if "error" in text.lower() or "api count exceeded" in text.lower():
        raise RuntimeError(text.strip()[:120])
    return _clean([line.split(",")[0] for line in text.splitlines()], domain)


# ---------------------------------------------------------------------------
# Keyed sources
# ---------------------------------------------------------------------------

def _src_virustotal(domain: str) -> set[str]:
    data = _get(
        f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
        params={"limit": 1000},
        headers={"x-apikey": settings.VIRUSTOTAL_API_KEY},
    ).json()
    return _clean([row.get("id", "") for row in data.get("data", [])], domain)


def _src_shodan(domain: str) -> set[str]:
    data = _get(
        f"https://api.shodan.io/dns/domain/{domain}",
        params={"key": settings.SHODAN_API_KEY},
    ).json()
    return _clean(
        [f"{entry}.{domain}" for entry in data.get("subdomains", [])], domain
    )


def _src_securitytrails(domain: str) -> set[str]:
    data = _get(
        f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
        params={"children_only": "false"},
        headers={"APIKEY": settings.SECURITYTRAILS_API_KEY},
    ).json()
    return _clean([f"{entry}.{domain}" for entry in data.get("subdomains", [])], domain)


def _src_bevigil(domain: str) -> set[str]:
    data = _get(
        f"https://osint.bevigil.com/api/{domain}/subdomains/",
        headers={"X-Access-Token": settings.BEVIGIL_API_KEY},
    ).json()
    return _clean(data.get("subdomains", []), domain)


def _src_chaos(domain: str) -> set[str]:
    data = _get(
        f"https://dns.projectdiscovery.io/dns/{domain}/subdomains",
        headers={"Authorization": settings.CHAOS_API_KEY},
    ).json()
    return _clean(
        [f"{entry}.{domain}" for entry in data.get("subdomains", []) if entry], domain
    )


def _src_leakix(domain: str) -> set[str]:
    data = _get(
        f"https://leakix.net/api/subdomains/{domain}",
        headers={"api-key": settings.LEAKIX_API_KEY, "Accept": "application/json"},
    ).json()
    return _clean([row.get("subdomain", "") for row in data or []], domain)


def _src_fullhunt(domain: str) -> set[str]:
    data = _get(
        f"https://fullhunt.io/api/v1/domain/{domain}/subdomains",
        headers={"X-API-KEY": settings.FULLHUNT_API_KEY},
    ).json()
    return _clean(data.get("hosts", []), domain)


def _src_binaryedge(domain: str) -> set[str]:
    data = _get(
        f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}",
        headers={"X-Key": settings.BINARYEDGE_API_KEY},
    ).json()
    return _clean(data.get("events", []), domain)


def _src_netlas(domain: str) -> set[str]:
    data = _get(
        "https://app.netlas.io/api/domains/",
        params={"q": f"domain:(domain:*.{domain} AND NOT domain:{domain})", "source_type": "include", "start": 0},
        headers={"X-API-Key": settings.NETLAS_API_KEY},
    ).json()
    return _clean(
        [row.get("data", {}).get("domain", "") for row in data.get("items", [])], domain
    )


def _src_hunter(domain: str) -> set[str]:
    import base64

    query = base64.b64encode(f'domain.suffix="{domain}"'.encode()).decode()
    data = _get(
        "https://api.hunter.how/search",
        params={"api-key": settings.HUNTER_API_KEY, "query": query,
                "page": 1, "page_size": 100, "start_time": "2024-01-01", "end_time": "2030-01-01"},
    ).json()
    rows = (data.get("data") or {}).get("list") or []
    return _clean([row.get("domain", "") for row in rows], domain)


def _src_zoomeye(domain: str) -> set[str]:
    data = _get(
        "https://api.zoomeye.ai/domain/search",
        params={"q": domain, "type": 1, "page": 1},
        headers={"API-KEY": settings.ZOOMEYE_API_KEY},
    ).json()
    return _clean([row.get("name", "") for row in data.get("list", [])], domain)


def _src_github(domain: str) -> set[str]:
    """Subdomains leaked in public source code.

    Distinct from every other source here: it searches what developers
    committed, not what the internet observed. Internal hostnames routinely
    appear in config files long before they appear in DNS or a certificate.
    """
    names: set[str] = set()
    pattern = re.compile(r"[A-Za-z0-9._-]+\." + re.escape(domain))
    data = _get(
        "https://api.github.com/search/code",
        params={"q": domain, "per_page": 50},
        headers={
            "Authorization": f"token {settings.GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3.text-match+json",
        },
    ).json()
    for item in data.get("items", []):
        for match in item.get("text_matches", []):
            names.update(pattern.findall(match.get("fragment", "")))
    return _clean(names, domain)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Source:
    name: str
    fn: Callable[[str], set[str]]
    #: Human-readable requirement, or "" when the source needs nothing.
    key_setting: str = ""
    #: True when answering requires handing the target to a third party.
    discloses_target: bool = False

    def key_present(self) -> bool:
        if not self.key_setting:
            return True
        return bool(getattr(settings, self.key_setting, ""))


SOURCES: tuple[Source, ...] = (
    # Keyless
    Source("crt.sh", _src_crtsh),
    Source("certspotter", _src_certspotter),
    Source("alienvault", _src_alienvault),
    Source("anubis", _src_anubis),
    Source("threatminer", _src_threatminer),
    Source("rapiddns", _src_rapiddns),
    Source("wayback", _src_wayback),
    Source("urlscan", _src_urlscan),
    Source("subdomain.center", _src_subdomaincenter),
    # Discloses the target to a third party
    Source("hackertarget", _src_hackertarget, discloses_target=True),
    # Keyed
    Source("virustotal", _src_virustotal, key_setting="VIRUSTOTAL_API_KEY"),
    Source("shodan", _src_shodan, key_setting="SHODAN_API_KEY"),
    Source("securitytrails", _src_securitytrails, key_setting="SECURITYTRAILS_API_KEY"),
    Source("bevigil", _src_bevigil, key_setting="BEVIGIL_API_KEY"),
    Source("chaos", _src_chaos, key_setting="CHAOS_API_KEY"),
    Source("leakix", _src_leakix, key_setting="LEAKIX_API_KEY"),
    Source("fullhunt", _src_fullhunt, key_setting="FULLHUNT_API_KEY"),
    Source("binaryedge", _src_binaryedge, key_setting="BINARYEDGE_API_KEY"),
    Source("netlas", _src_netlas, key_setting="NETLAS_API_KEY"),
    Source("hunter", _src_hunter, key_setting="HUNTER_API_KEY"),
    Source("zoomeye", _src_zoomeye, key_setting="ZOOMEYE_API_KEY"),
    Source("github", _src_github, key_setting="GITHUB_TOKEN"),
)


def _describe_error(exc: Exception) -> str:
    """Turn an exception into something an operator can act on.

    A bare ``HTTPError`` string names a URL and a code and leaves the reader to
    work out that 429 means they were rate-limited rather than that the domain
    has no subdomains.
    """
    if isinstance(exc, requests.exceptions.Timeout):
        return f"timed out after {settings.SUBDOMAIN_SOURCE_TIMEOUT}s"
    if isinstance(exc, requests.exceptions.HTTPError) and exc.response is not None:
        code = exc.response.status_code
        return {
            401: "rejected the API key (401)",
            403: "refused the request (403) — bot-blocked, or the key is invalid or out of quota",
            429: "rate-limited (429)",
        }.get(code, f"returned HTTP {code}")
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "unreachable"
    return f"{type(exc).__name__}: {exc}"[:160]


def _query(source: Source, domain: str) -> tuple[Source, set[str], str]:
    try:
        return source, source.fn(domain), ""
    except Exception as exc:  # noqa: BLE001 — one bad source must not end the sweep
        detail = _describe_error(exc)
        logger.debug("[subdomain_sources] %s: %s", source.name, detail)
        return source, set(), detail


def run_subdomain_sources(target: str) -> list[dict]:
    """Aggregate subdomains from every source that can run here."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].lower()
    if not domain:
        return []

    runnable: list[Source] = []
    skipped: list[tuple[str, str]] = []
    for source in SOURCES:
        if not source.key_present():
            skipped.append((source.name, f"no API key ({source.key_setting})"))
        elif source.discloses_target and not settings.ALLOW_HACKERTARGET:
            skipped.append((source.name, "disabled — would disclose the target (ALLOW_HACKERTARGET=false)"))
        else:
            runnable.append(source)

    union: set[str] = set()
    attribution: dict[str, set[str]] = {}
    per_source: list[tuple[str, int, str]] = []

    workers = min(settings.SUBDOMAIN_SOURCE_CONCURRENCY, max(1, len(runnable)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_query, source, domain) for source in runnable]
        for future in as_completed(futures):
            source, names, error = future.result()
            per_source.append((source.name, len(names), error))
            union |= names
            for name in names:
                attribution.setdefault(name, set()).add(source.name)

    per_source.sort(key=lambda row: (-row[1], row[0]))
    succeeded = [row for row in per_source if not row[2]]
    failed = [row for row in per_source if row[2]]

    # Ceiling applied after the union so the count reported is the real one
    # even when the listing is truncated.
    subdomains = sorted(union)
    truncated = len(subdomains) > settings.SUBDOMAIN_MAX_RESULTS
    listed = subdomains[: settings.SUBDOMAIN_MAX_RESULTS]

    coverage = ["Source coverage:"]
    for name, count, _ in succeeded:
        coverage.append(f"  {name:<16} {count:>5} names")
    for name, _, error in failed:
        coverage.append(f"  {name:<16}     — {error}")
    for name, reason in sorted(skipped):
        coverage.append(f"  {name:<16}     — skipped: {reason}")

    # Names only one source knew about. This is the argument for querying more
    # than one: a name with a single source would have been missed entirely if
    # that source had been the only one asked.
    unique_to_one = sorted(n for n, srcs in attribution.items() if len(srcs) == 1)

    evidence = [
        f"Unique subdomains: {len(subdomains)}",
        f"Sources queried  : {len(runnable)} of {len(SOURCES)} "
        f"({len(succeeded)} answered, {len(failed)} failed, {len(skipped)} skipped)",
        "",
        *coverage,
        "",
        "Subdomains:",
        *(f"  • {name}" for name in listed),
    ]
    if truncated:
        evidence.append(
            f"  ... {len(subdomains) - len(listed)} more not listed "
            f"(SUBDOMAIN_MAX_RESULTS={settings.SUBDOMAIN_MAX_RESULTS})"
        )

    findings = [{
        "tool": "subdomain_sources",
        "category": "subdomain_enumeration",
        "severity": "info",
        "title": f"Passive Subdomain Aggregation — {len(subdomains)} unique names",
        "description": (
            f"{len(subdomains)} unique subdomains of {domain} were aggregated from "
            f"{len(succeeded)} public sources. These names were observed by third "
            "parties — in certificates, passive DNS, archives or public code — so "
            "each one is evidence that the name existed, not that it currently "
            "resolves or is reachable. The httpx probe establishes which are live."
        ),
        "evidence": "\n".join(evidence),
    }]

    if failed or skipped:
        findings.append({
            "tool": "subdomain_sources",
            "category": "scanner_coverage",
            "severity": "info",
            "title": f"Subdomain Coverage Reduced — {len(failed) + len(skipped)} source(s) did not contribute",
            "description": (
                "Not every source ran. A source that was skipped or errored found "
                "nothing because it was never asked, which is not the same as the "
                "target having no subdomains there. Treat the count above as a "
                "floor rather than a total."
            ),
            "evidence": "\n".join(
                [f"• {name}: {error}" for name, _, error in failed]
                + [f"• {name}: {reason}" for name, reason in sorted(skipped)]
            ),
            "remediation": (
                "Add API keys for the keyed sources to widen coverage. Every key is "
                "optional and every one is free at the tier this uses."
            ),
        })

    sensitive = [
        name for name in subdomains
        if any(keyword in name.split(".")[0] for keyword in SENSITIVE_KEYWORDS)
    ]
    if sensitive:
        findings.append({
            "tool": "subdomain_sources",
            "category": "sensitive_subdomains",
            "severity": "medium",
            "title": f"Sensitive Subdomain Names — {len(sensitive)} found",
            "description": (
                f"{len(sensitive)} aggregated subdomains carry names that usually "
                "belong to non-production or administrative environments. These are "
                "typically less hardened than production while being equally "
                "reachable. The name is the only evidence here — none of these were "
                "probed to confirm what they serve."
            ),
            "evidence": "\n".join(f"• {name}" for name in sensitive[:100]),
            "remediation": (
                "Restrict these to an IP allowlist or VPN, and confirm non-production "
                "environments hold no production data."
            ),
        })

    if unique_to_one:
        findings.append({
            "tool": "subdomain_sources",
            "category": "subdomain_enumeration",
            "severity": "info",
            "title": f"Single-Source Subdomains — {len(unique_to_one)} found by one source only",
            "description": (
                "These names were reported by exactly one source. They are the names "
                "a single-source enumeration would have missed entirely, and they are "
                "also the ones most worth confirming by hand: one observation is the "
                "weakest form of the evidence this module produces."
            ),
            "evidence": "\n".join(
                f"• {name}  ({', '.join(sorted(attribution[name]))})"
                for name in unique_to_one[:100]
            ),
        })

    logger.info(
        "[subdomain_sources] %s: %d unique from %d/%d sources (%d failed, %d skipped)",
        domain, len(subdomains), len(succeeded), len(SOURCES), len(failed), len(skipped),
    )
    return findings
