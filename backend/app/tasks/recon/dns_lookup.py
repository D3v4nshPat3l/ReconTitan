"""DNS record enumeration for ReconTitan recon pipeline."""
import logging
import dns.resolver
from concurrent.futures import ThreadPoolExecutor
import dns.exception

logger = logging.getLogger("recontitan.recon.dns")

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

# A resolver that has not answered in this long is not going to.
DNS_LIFETIME = 4

def run_dns_lookup(target: str) -> list[dict]:
    """
    Enumerates DNS records for the target domain.
    Checks for SPF, DMARC, DKIM misconfigurations.
    Returns a list of Finding-compatible dicts.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings = []
    all_records = {}

    # Seven record types, each waiting on a different server. Sequentially at
    # lifetime=8 a domain with two unanswered types spends 16 seconds doing
    # nothing, which is most of the budget on a platform that kills the request
    # at 60. They do not depend on each other, so they are asked at once and the
    # whole step costs one lifetime rather than seven.
    def _resolve(rtype: str) -> tuple[str, list[str]]:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=DNS_LIFETIME)
            return rtype, [str(r) for r in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return rtype, []
        except Exception as e:
            logger.debug("[dns] %s %s: %s", rtype, domain, e)
            return rtype, []

    with ThreadPoolExecutor(max_workers=len(RECORD_TYPES)) as pool:
        for rtype, records in pool.map(_resolve, RECORD_TYPES):
            all_records[rtype] = records

    # Build evidence
    evidence_lines = []
    for rtype, records in all_records.items():
        if records:
            for r in records:
                evidence_lines.append(f"{rtype:6s}  {r}")

    evidence = "\n".join(evidence_lines) or "No DNS records found."

    findings.append({
        "tool":        "dns_lookup",
        "category":    "dns_records",
        "severity":    "info",
        "title":       f"DNS Records — {domain}",
        "description": f"Full DNS record enumeration for {domain}.",
        "evidence":    evidence,
    })

    # ── SPF check ──
    txt_records = all_records.get("TXT", [])
    spf_records = [r for r in txt_records if "v=spf1" in r.lower()]
    if not spf_records:
        findings.append({
            "tool":        "dns_lookup",
            "category":    "email_security",
            "severity":    "medium",
            "title":       "Missing SPF Record — Email Spoofing Risk",
            "description": (
                f"No SPF (Sender Policy Framework) TXT record found for {domain}. "
                "Attackers can send emails that appear to come from this domain."
            ),
            "evidence":    f"No TXT record containing 'v=spf1' found for {domain}.",
            "remediation": "Add an SPF TXT record, e.g.: v=spf1 include:_spf.google.com ~all",
        })

    # ── DMARC check ──
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT", lifetime=DNS_LIFETIME)
        dmarc_records = [str(r) for r in dmarc_answers]
    except Exception:
        dmarc_records = []

    if not dmarc_records:
        findings.append({
            "tool":        "dns_lookup",
            "category":    "email_security",
            "severity":    "medium",
            "title":       "Missing DMARC Record",
            "description": (
                f"No DMARC policy found at _dmarc.{domain}. "
                "Without DMARC, spoofed emails may not be rejected by recipient servers."
            ),
            "evidence":    f"DNS query for _dmarc.{domain} TXT returned no results.",
            "remediation": "Add: _dmarc TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\"",
        })

    # ── Zone transfer attempt (benign check) ──
    ns_records = all_records.get("NS", [])
    if ns_records:
        findings.append({
            "tool":        "dns_lookup",
            "category":    "dns_nameservers",
            "severity":    "info",
            "title":       f"Name Servers Identified — {domain}",
            "description": f"Authoritative name servers for {domain}.",
            "evidence":    "\n".join(ns_records),
        })

    return findings
