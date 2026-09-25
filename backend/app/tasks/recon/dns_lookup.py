"""DNS record enumeration for the ReconTitan recon pipeline.

Seven record types answer "where does this name point". They do not answer
"what has this zone been configured to allow", which is where most of the
findings are: CAA decides which certificate authorities may issue for the
domain, DNSKEY/DS decide whether answers can be forged, TLSA and SSHFP pin
service keys, and SRV/NAPTR/HTTPS advertise services that nothing else in a
scan will surface.

So the sweep is wide, grouped by what each category tells you, and reports the
grouping rather than a flat list -- forty records in one column is data, not
information. The wide sweep is a setting (``DNS_EXTENDED_RECORDS``) because a
scan of a large zone behind a slow resolver pays for every type queried.

Resolvers are configurable for a reason worth stating: a filtering or
split-horizon resolver returns NXDOMAIN for names that resolve perfectly well
in public DNS, and a report built on those answers says a host is gone when it
is merely invisible from here.
"""

import logging
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.rdatatype
import dns.resolver

from app.config import settings

logger = logging.getLogger("recontitan.recon.dns")

#: The types every scan queries. These resolve the name and carry the mail and
#: delegation configuration, so they are worth the time on any profile.
CORE_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")

#: The full sweep, grouped by what the group tells an assessor. Order is the
#: report order.
RECORD_CATEGORIES: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "Addressing",
        "Where the name points, and what it is an alias for.",
        ("A", "AAAA", "CNAME", "DNAME", "PTR"),
    ),
    (
        "Zone authority",
        "Who is authoritative for the zone and how it is served.",
        ("NS", "SOA", "CSYNC", "ZONEMD"),
    ),
    (
        "Mail",
        "Mail routing and the addresses responsible for the zone.",
        ("MX", "SPF", "RP", "MINFO", "MB", "MG", "MR"),
    ),
    (
        "Text and policy",
        "Free-form records. SPF, DMARC, domain verification and site policy all live here.",
        ("TXT", "URI", "AVC"),
    ),
    (
        "Service discovery",
        "Services the zone advertises, including modern HTTPS/SVCB service binding.",
        ("SRV", "NAPTR", "KX", "HTTPS", "SVCB", "WKS"),
    ),
    (
        "DNSSEC",
        "Whether answers for this zone can be cryptographically validated.",
        ("DNSKEY", "DS", "RRSIG", "NSEC", "NSEC3", "NSEC3PARAM",
         "CDS", "CDNSKEY", "TA", "DLV", "KEY", "SIG"),
    ),
    (
        "Certificates and keys",
        "Which authorities may issue certificates, and which service keys are pinned.",
        ("CAA", "TLSA", "SSHFP", "SMIMEA", "OPENPGPKEY", "IPSECKEY", "CERT", "DHCID"),
    ),
    (
        "Infrastructure and legacy",
        "Location, host metadata and historical record types. Rarely set; informative when they are.",
        ("LOC", "HINFO", "AFSDB", "X25", "ISDN", "RT", "NSAP", "PX", "GPOS",
         "APL", "EUI48", "EUI64", "L32", "L64", "LP", "NID"),
    ),
)

#: Records whose *absence* is itself worth reporting.
SECURITY_RECORDS = ("CAA", "DNSKEY", "DS", "TLSA", "SSHFP", "NSEC", "NSEC3")

#: DKIM selectors used by the common mail providers. Probing a fixed list is
#: the only way to find DKIM keys: the selector is not discoverable from DNS,
#: so a key under an unguessed selector is invisible, and this list finding
#: nothing is not evidence that DKIM is unconfigured.
DKIM_SELECTORS = (
    "default", "google", "selector1", "selector2", "k1", "k2", "dkim",
    "mail", "smtp", "s1", "s2", "mandrill", "mailjet", "zoho", "protonmail",
    "amazonses", "sendgrid", "postmark", "fm1", "fm2", "fm3",
)

DNS_LIFETIME = 8
#: Fifty types against one resolver, unthrottled, looks like abuse and gets
#: rate-limited. Sixteen at a time keeps the sweep inside a few seconds without
#: hammering anyone.
MAX_CONCURRENT_QUERIES = 16


def _build_resolver() -> dns.resolver.Resolver | None:
    """A resolver instance, or None to use dnspython's default.

    Returning None in the common case is deliberate. Constructing a fresh
    ``Resolver`` to query the system's own nameservers gains nothing and costs
    something real: a resolver built here must also be given a per-server
    timeout, and setting that equal to the overall lifetime makes one
    unreachable nameserver -- a stale VPN entry, a container's own stub --
    consume the whole budget so the working servers are never tried. Every
    record type then comes back empty, which reads as "this zone publishes
    nothing". dnspython's default already handles the rotation correctly.

    A custom resolver is built only when the operator asked for specific
    nameservers, and that one gets an explicit per-server timeout below the
    lifetime so the same failure mode cannot occur.
    """
    if not settings.DNS_SERVERS:
        return None
    resolver = dns.resolver.Resolver()
    resolver.nameservers = list(settings.DNS_SERVERS)
    lifetime = settings.DNS_RECORD_TIMEOUT or DNS_LIFETIME
    resolver.lifetime = lifetime
    resolver.timeout = max(1.0, lifetime / max(2, len(resolver.nameservers)))
    resolver.rotate = True
    return resolver


def _resolve_records(resolver, name: str, rtype: str) -> list[str]:
    """Resolve one name, through the configured resolver or the default one.

    The single place DNS queries leave this module, so the choice between a
    custom resolver and the default is made once rather than at every call.
    """
    lifetime = settings.DNS_RECORD_TIMEOUT or DNS_LIFETIME
    if resolver is not None:
        answers = resolver.resolve(name, rtype)
    else:
        answers = dns.resolver.resolve(name, rtype, lifetime=lifetime)
    return [str(record) for record in answers]


def _selected_types() -> tuple[tuple[str, str, tuple[str, ...]], ...]:
    """Which categories to query, honouring DNS_EXTENDED_RECORDS.

    Types this build of dnspython does not know are dropped here rather than
    raising mid-sweep: the list is deliberately broad and includes types that
    only newer releases define.
    """
    if settings.DNS_EXTENDED_RECORDS:
        categories = RECORD_CATEGORIES
    else:
        categories = (("Addressing", "Core records only (DNS_EXTENDED_RECORDS=false).", CORE_RECORD_TYPES),)

    out = []
    for name, blurb, types in categories:
        known = tuple(t for t in types if _is_known_type(t))
        if known:
            out.append((name, blurb, known))
    return tuple(out)


def _is_known_type(rtype: str) -> bool:
    try:
        dns.rdatatype.from_text(rtype)
        return True
    except Exception:  # noqa: BLE001 — dnspython raises several types here
        return False


def run_dns_lookup(target: str) -> list[dict]:
    """Enumerate DNS records for the target domain and assess the zone's posture."""
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    findings: list[dict] = []
    resolver = _build_resolver()
    categories = _selected_types()
    all_types = [rtype for _, _, types in categories for rtype in types]

    def _resolve(rtype: str) -> tuple[str, list[str]]:
        try:
            return rtype, _resolve_records(resolver, domain, rtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return rtype, []
        except Exception as exc:  # noqa: BLE001
            logger.debug("[dns] %s %s: %s", rtype, domain, exc)
            return rtype, []

    all_records: dict[str, list[str]] = {}
    workers = min(MAX_CONCURRENT_QUERIES, max(1, len(all_types)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for rtype, records in pool.map(_resolve, all_types):
            all_records[rtype] = records

    present = {rtype: records for rtype, records in all_records.items() if records}

    evidence_lines: list[str] = []
    if settings.DNS_SERVERS:
        evidence_lines.append(f"Resolvers: {', '.join(settings.DNS_SERVERS)}")
    else:
        evidence_lines.append("Resolvers: system default")
    evidence_lines.append(
        f"Record types queried: {len(all_types)}   answered: {len(present)}"
    )
    evidence_lines.append("")

    for name, blurb, types in categories:
        answered = [(rtype, present[rtype]) for rtype in types if rtype in present]
        if not answered:
            continue
        evidence_lines.append(f"── {name} ──")
        evidence_lines.append(f"   {blurb}")
        for rtype, records in answered:
            for record in records:
                evidence_lines.append(f"   {rtype:<12} {record}")
        evidence_lines.append("")

    findings.append({
        "tool": "dns_lookup",
        "category": "dns_records",
        "severity": "info",
        "title": f"DNS Records — {domain} ({len(present)} record types present)",
        "description": (
            f"{len(all_types)} DNS record types were queried for {domain}; "
            f"{len(present)} returned data. Records are grouped by what they "
            "configure rather than listed flat, because the security-relevant "
            "ones — certificate issuance, DNSSEC, service key pinning — are "
            "easy to miss in an alphabetical list."
        ),
        "evidence": "\n".join(evidence_lines) or "No DNS records found.",
    })

    # ── SPF ──
    txt_records = all_records.get("TXT", [])
    spf_records = [r for r in txt_records if "v=spf1" in r.lower()]
    if not spf_records:
        findings.append({
            "tool": "dns_lookup",
            "category": "email_security",
            "severity": "medium",
            "title": "Missing SPF Record — Email Spoofing Risk",
            "description": (
                f"No SPF (Sender Policy Framework) TXT record found for {domain}. "
                "Attackers can send emails that appear to come from this domain."
            ),
            "evidence": f"No TXT record containing 'v=spf1' found for {domain}.",
            "remediation": "Add an SPF TXT record, e.g.: v=spf1 include:_spf.google.com ~all",
        })
    elif any("+all" in record.lower() for record in spf_records):
        findings.append({
            "tool": "dns_lookup",
            "category": "email_security",
            "severity": "high",
            "title": "SPF Record Permits Any Sender (+all)",
            "description": (
                "The SPF record ends in '+all', which authorises every host on the "
                "internet to send mail as this domain. That is strictly worse than "
                "having no SPF record, because receivers treat it as an explicit pass."
            ),
            "evidence": "\n".join(spf_records),
            "remediation": "Replace '+all' with '~all' (softfail) or '-all' (hardfail).",
        })

    # ── DMARC ──
    dmarc_records = _query_name(resolver, f"_dmarc.{domain}", "TXT")
    dmarc_policy = ""
    for record in dmarc_records:
        for part in record.strip('"').split(";"):
            if part.strip().lower().startswith("p="):
                dmarc_policy = part.strip().split("=", 1)[1].strip().lower()

    if not dmarc_records:
        findings.append({
            "tool": "dns_lookup",
            "category": "email_security",
            "severity": "medium",
            "title": "Missing DMARC Record",
            "description": (
                f"No DMARC policy found at _dmarc.{domain}. "
                "Without DMARC, spoofed emails may not be rejected by recipient servers."
            ),
            "evidence": f"DNS query for _dmarc.{domain} TXT returned no results.",
            "remediation": "Add: _dmarc TXT \"v=DMARC1; p=quarantine; rua=mailto:dmarc@yourdomain.com\"",
        })
    elif dmarc_policy == "none":
        findings.append({
            "tool": "dns_lookup",
            "category": "email_security",
            "severity": "low",
            "title": "DMARC Policy Is Monitor-Only (p=none)",
            "description": (
                "A DMARC record exists but its policy is 'none', which asks "
                "receivers to report failures and deliver the mail anyway. It "
                "provides visibility, not enforcement — spoofed mail still arrives."
            ),
            "evidence": "\n".join(dmarc_records),
            "remediation": (
                "Once the reports show legitimate senders are aligned, move to "
                "p=quarantine and then p=reject."
            ),
        })

    # ── DKIM ──
    found_selectors = []
    with ThreadPoolExecutor(max_workers=min(MAX_CONCURRENT_QUERIES, len(DKIM_SELECTORS))) as pool:
        results = pool.map(
            lambda selector: (
                selector, _query_name(resolver, f"{selector}._domainkey.{domain}", "TXT")
            ),
            DKIM_SELECTORS,
        )
        found_selectors = [(selector, records) for selector, records in results if records]

    # A DKIM record with an empty p= is a *null key*: the standard way to say
    # "this selector is revoked, reject anything signed with it". Counting
    # those as keys found inverts their meaning, and a domain publishing a
    # wildcard null record answers for every selector probed -- which is how
    # one such domain reported twenty-one DKIM keys and had none.
    live = [
        (selector, records) for selector, records in found_selectors
        if any(_dkim_has_key(record) for record in records)
    ]
    null_keys = [
        (selector, records) for selector, records in found_selectors
        if (selector, records) not in live
    ]

    if live:
        findings.append({
            "tool": "dns_lookup",
            "category": "email_security",
            "severity": "info",
            "title": f"DKIM Selectors Found — {len(live)}",
            "description": (
                "DKIM public keys were found under these selectors. The selector "
                "names also identify which mail providers the domain uses."
            ),
            "evidence": "\n".join(
                f"{selector}._domainkey.{domain}\n    {records[0][:200]}"
                for selector, records in live
            ),
        })
    if null_keys and not live:
        findings.append({
            "tool": "dns_lookup",
            "category": "email_security",
            "severity": "info",
            "title": f"DKIM Null Keys Published — {len(null_keys)} selector(s) revoked",
            "description": (
                "These selectors publish a DKIM record with an empty public key "
                "(p=), which is the standard way to revoke a selector and tell "
                "receivers to reject anything signed with it. This is a "
                "deliberate configuration, not a missing key — a domain that "
                "sends no mail often publishes one as a wildcard."
            ),
            "evidence": "\n".join(
                f"{selector}._domainkey.{domain}\n    {records[0][:200]}"
                for selector, records in null_keys[:10]
            ),
        })
    elif not found_selectors and (spf_records or all_records.get("MX")):
        findings.append({
            "tool": "dns_lookup",
            "category": "email_security",
            "severity": "info",
            "title": "No DKIM Key Found Under Common Selectors",
            "description": (
                f"{len(DKIM_SELECTORS)} well-known DKIM selectors were probed and none "
                "returned a key. DKIM selectors are not discoverable from DNS, so a key "
                "published under a custom selector is invisible to this check. This is "
                "not evidence that DKIM is unconfigured."
            ),
            "evidence": "Selectors probed: " + ", ".join(DKIM_SELECTORS),
            "remediation": "Confirm the selector your mail provider uses and verify it resolves.",
        })

    # ── CAA ──
    if "CAA" not in present:
        findings.append({
            "tool": "dns_lookup",
            "category": "certificate_authority",
            "severity": "low",
            "title": "No CAA Record — Any CA May Issue For This Domain",
            "description": (
                f"{domain} publishes no CAA record. CAA tells certificate authorities "
                "which of them are permitted to issue for the domain; without one, "
                "every publicly trusted CA is permitted. This does not mean a "
                "certificate has been mis-issued — it means nothing in DNS would "
                "stop one."
            ),
            "evidence": f"DNS query for {domain} CAA returned no records.",
            "remediation": (
                'Publish a CAA record naming your CA, e.g.: '
                '@ CAA 0 issue "letsencrypt.org"'
            ),
        })
    else:
        findings.append({
            "tool": "dns_lookup",
            "category": "certificate_authority",
            "severity": "info",
            "title": f"CAA Policy Published — {len(present['CAA'])} record(s)",
            "description": "Certificate issuance for this domain is restricted to the named authorities.",
            "evidence": "\n".join(present["CAA"]),
        })

    # ── DNSSEC ──
    has_dnskey = "DNSKEY" in present
    has_ds = "DS" in present
    if has_dnskey and has_ds:
        findings.append({
            "tool": "dns_lookup",
            "category": "dnssec",
            "severity": "info",
            "title": "DNSSEC Is Signed and Delegated",
            "description": (
                "The zone publishes DNSKEY records and the parent zone publishes a "
                "matching DS record, so resolvers can validate answers for this "
                "domain. This check confirms the records exist; it does not "
                "validate the chain of trust cryptographically."
            ),
            "evidence": (
                f"DNSKEY records: {len(present['DNSKEY'])}\n"
                f"DS records    : {len(present['DS'])}\n\n"
                + "\n".join(present["DS"])
            ),
        })
    elif has_dnskey and not has_ds:
        findings.append({
            "tool": "dns_lookup",
            "category": "dnssec",
            "severity": "medium",
            "title": "DNSSEC Signed But Not Delegated — No DS Record",
            "description": (
                "The zone is signed (DNSKEY present) but the parent publishes no DS "
                "record, so no resolver will validate it. The signing effort is "
                "currently providing no protection: answers can still be forged and "
                "will still be accepted."
            ),
            "evidence": f"DNSKEY records: {len(present['DNSKEY'])}\nDS records: none",
            "remediation": "Submit the DS record to the registrar to complete the chain of trust.",
        })
    else:
        findings.append({
            "tool": "dns_lookup",
            "category": "dnssec",
            "severity": "low",
            "title": "DNSSEC Not Enabled",
            "description": (
                f"{domain} publishes no DNSKEY record, so its DNS answers cannot be "
                "cryptographically validated. A resolver cannot distinguish a genuine "
                "answer from a forged one, which makes cache poisoning and "
                "on-path DNS tampering materially easier."
            ),
            "evidence": f"DNS query for {domain} DNSKEY returned no records.",
            "remediation": "Enable DNSSEC signing at the DNS provider and publish the DS record at the registrar.",
        })

    # ── Service key pinning ──
    for rtype, label in (("TLSA", "TLS certificates (DANE)"), ("SSHFP", "SSH host keys")):
        if rtype in present:
            findings.append({
                "tool": "dns_lookup",
                "category": "key_pinning",
                "severity": "info",
                "title": f"{rtype} Records Published — {label} pinned in DNS",
                "description": (
                    f"The zone pins {label} via {rtype}. These records are only "
                    "meaningful to clients that validate them, which in turn "
                    "requires DNSSEC."
                ),
                "evidence": "\n".join(present[rtype]),
            })

    # ── Wildcard detection ──
    # Worth knowing before reading any subdomain list: under a wildcard, every
    # name resolves, so "this subdomain resolves" stops being evidence that it
    # was ever configured.
    wildcard = _query_name(resolver, f"recontitan-wildcard-probe-zz99.{domain}", "A")
    if wildcard:
        findings.append({
            "tool": "dns_lookup",
            "category": "dns_records",
            "severity": "info",
            "title": "Wildcard DNS Record In Use",
            "description": (
                "A name that should not exist resolved, so this zone answers for "
                "arbitrary subdomains. Read every subdomain result with that in "
                "mind: under a wildcard, a name resolving is not evidence that "
                "anyone configured it."
            ),
            "evidence": (
                f"Probe: recontitan-wildcard-probe-zz99.{domain}\n"
                f"Resolved to: {', '.join(wildcard)}"
            ),
        })

    # ── Name servers ──
    ns_records = all_records.get("NS", [])
    if ns_records:
        findings.append({
            "tool": "dns_lookup",
            "category": "dns_nameservers",
            "severity": "info",
            "title": f"Name Servers Identified — {domain}",
            "description": f"Authoritative name servers for {domain}.",
            "evidence": "\n".join(ns_records),
        })

    missing_security = [rtype for rtype in SECURITY_RECORDS if rtype not in present]
    logger.info(
        "[dns] %s: %d/%d types answered, %d security records absent",
        domain, len(present), len(all_types), len(missing_security),
    )
    return findings


def _dkim_has_key(record: str) -> bool:
    """True when a DKIM TXT record carries an actual public key.

    ``p=`` with nothing after it is a null key -- a revocation -- so the tag
    being present is not the same as a key being present.
    """
    for part in record.strip('"').replace('" "', "").split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            return bool(part[2:].strip())
    return False


def _query_name(resolver, name: str, rtype: str) -> list[str]:
    """Resolve one fully-qualified name, returning [] for every negative answer."""
    try:
        return _resolve_records(resolver, name, rtype)
    except Exception:  # noqa: BLE001 — every failure mode here means "no record"
        return []
