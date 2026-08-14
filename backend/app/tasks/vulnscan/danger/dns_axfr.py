"""Full DNS record enumeration and AXFR zone-transfer attempts.

A zone transfer is a read-only DNS query. Danger Mode asks every authoritative
name server for the zone; a server that answers is misconfigured. Successful
transfers are summarized (record counts and host names) — the raw zone is never
stored in full.
"""

from __future__ import annotations

import logging

import dns.exception
import dns.query
import dns.resolver
import dns.zone

from app.tasks.vulnscan.danger.budget import danger_finding, evidence_block

logger = logging.getLogger("recontitan.danger.dns_axfr")

MODULE = "danger_axfr"

#: Full record set enumerated in Danger Mode (recon_only covers a subset).
RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "SRV")

#: Common service records probed alongside the apex. Kept short because each
#: miss costs a full DNS timeout and the stage shares one wall-clock budget.
SRV_PREFIXES = (
    "_sip._tcp", "_ldap._tcp", "_autodiscover._tcp",
)

AXFR_TIMEOUT = 5
RECORD_LIFETIME = 4
SRV_LIFETIME = 3


def enumerate_records(domain: str) -> dict[str, list[str]]:
    """Resolve every Danger Mode record type, failing soft per record type."""
    records: dict[str, list[str]] = {}
    for record_type in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(domain, record_type, lifetime=RECORD_LIFETIME)
            records[record_type] = sorted(str(item) for item in answers)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
            records[record_type] = []
        except Exception as exc:  # fail soft; one record type must not stop the module
            logger.debug("[danger:dns] %s %s: %s", record_type, domain, str(exc)[:120])
            records[record_type] = []

    srv_hits: list[str] = []
    for prefix in SRV_PREFIXES:
        try:
            answers = dns.resolver.resolve(f"{prefix}.{domain}", "SRV", lifetime=SRV_LIFETIME)
            srv_hits.extend(f"{prefix}.{domain} -> {item}" for item in answers)
        except Exception:
            continue
    if srv_hits:
        records["SRV"] = sorted(set(records.get("SRV", []) + srv_hits))
    return records


def _nameserver_addresses(nameserver: str) -> list[str]:
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(nameserver, record_type, lifetime=RECORD_LIFETIME)
            addresses.extend(str(item) for item in answers)
        except Exception:
            continue
    return addresses


def attempt_zone_transfer(domain: str, nameserver: str) -> tuple[bool, dict]:
    """Attempt AXFR against one name server.

    Returns ``(transferred, detail)``. ``detail`` summarizes the zone by counts
    and host names only; record values are never returned.
    """
    detail: dict = {"nameserver": nameserver, "error": "", "records": 0, "hosts": []}
    addresses = _nameserver_addresses(nameserver.rstrip("."))
    if not addresses:
        detail["error"] = "name server did not resolve"
        return False, detail

    for address in addresses:
        try:
            zone = dns.zone.from_xfr(dns.query.xfr(address, domain, lifetime=AXFR_TIMEOUT, timeout=AXFR_TIMEOUT))
        except Exception as exc:
            detail["error"] = type(exc).__name__
            continue
        if zone is None:
            detail["error"] = "empty zone"
            continue
        names = [str(name) for name in zone.nodes.keys()]
        detail.update({
            "address": address,
            "error": "",
            "records": len(names),
            "hosts": sorted(
                f"{name}.{domain}" if name not in {"@"} else domain
                for name in names
            )[:100],
        })
        return True, detail
    return False, detail


def run_dns_axfr(target: str) -> list[dict]:
    """Enumerate DNS records and attempt AXFR against every authoritative server."""
    findings: list[dict] = []
    records = enumerate_records(target)

    record_lines = []
    for record_type, values in records.items():
        if values:
            record_lines.append(f"{record_type}: {len(values)} record(s)")
            for value in values[:15]:
                record_lines.append(f"  {value}")
    findings.append(danger_finding(
        tool=MODULE,
        category="danger_dns_enumeration",
        severity="info",
        title=f"Full DNS Record Enumeration - {target}",
        description=(
            f"Danger Mode enumerated A, AAAA, MX, TXT, NS, SOA, CNAME, and SRV records for {target} to map the "
            "authoritative infrastructure before attempting zone transfers."
        ),
        evidence="\n".join(record_lines) or "No DNS records were returned.",
        asset=target,
    ))

    nameservers = [value.rstrip(".") for value in records.get("NS", [])]
    if not nameservers:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_zone_transfer",
            severity="info",
            title="Zone Transfer Not Attempted - No Name Servers Found",
            description=(
                f"No NS records were returned for {target}, so no authoritative server could be asked for a zone "
                "transfer."
            ),
            evidence=evidence_block([("Domain", target), ("NS records", 0)]),
            owasp="A05:2021-Security Misconfiguration",
            asset=target,
        ))
        return findings

    successes: list[dict] = []
    failures: list[dict] = []
    for nameserver in nameservers[:10]:
        transferred, detail = attempt_zone_transfer(target, nameserver)
        (successes if transferred else failures).append(detail)

    for detail in successes:
        hosts = detail.get("hosts", [])
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_zone_transfer",
            severity="high",
            title=f"DNS Zone Transfer Permitted - {detail['nameserver']}",
            description=(
                f"The authoritative name server {detail['nameserver']} answered an AXFR request for {target} and "
                f"returned the full zone ({detail['records']} record node(s)). An unauthenticated zone transfer hands "
                "an attacker the complete internal host inventory in one query. The zone contents are summarized "
                "here and were not stored."
            ),
            evidence=evidence_block([
                ("Name server", detail["nameserver"]),
                ("Answering address", detail.get("address", "unknown")),
                ("Record nodes transferred", detail["records"]),
                ("Sample hosts", "\n" + "\n".join(f"  {host}" for host in hosts[:50])),
                ("Hosts shown", f"{min(len(hosts), 50)} of {len(hosts)}"),
            ]),
            remediation=(
                "Restrict AXFR to authorized secondary name servers with an allow-list or TSIG keys, and deny zone "
                "transfers from every other source."
            ),
            owasp="A05:2021-Security Misconfiguration",
            attack_vector="Unauthenticated DNS zone transfer (AXFR)",
            asset=detail["nameserver"],
        ))

    if failures:
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_zone_transfer",
            severity="info",
            title=f"Zone Transfer Refused - {len(failures)} name server(s)",
            description=(
                f"{len(failures)} authoritative name server(s) for {target} refused the AXFR request. This is the "
                "expected, correctly configured behaviour and is recorded for coverage only."
            ),
            evidence=evidence_block([
                (detail["nameserver"], detail.get("error") or "refused")
                for detail in failures
            ]),
            owasp="A05:2021-Security Misconfiguration",
            asset=target,
        ))

    logger.info("[danger:axfr] %s: %d permitted, %d refused", target, len(successes), len(failures))
    return findings
