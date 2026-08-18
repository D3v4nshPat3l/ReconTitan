"""Version-aware CVE matching against NVD.

A CVE applies to specific product *versions*, recorded in NVD as CPE
configurations with explicit ranges. Matching on a keyword search instead
answers the wrong question: it finds CVEs whose description text mentions a
word, which returns unrelated products, wrong versions, and (because NVD
returns oldest-first) mostly decades-old entries.

This module asks the right question. When the fingerprinter gives a product
and a version, the query is a CPE match, so NVD itself decides whether the
detected version falls inside each CVE's affected range.

Three confidence tiers, always stated on the finding rather than implied:

``version_match``
    Product and version both known and mapped to CPE. NVD confirmed this
    version is in the affected range. Actionable.

``product_match``
    Product mapped to CPE but no version was disclosed. The CVE affects the
    product; whether it affects *this install* is unknown. Needs the version.

``keyword_candidate``
    Product is not in the CPE catalogue, so this is the old text search.
    Lowest confidence, and labelled as such rather than dressed up.
"""

from __future__ import annotations

import logging
import time

import requests

from app.config import settings
from app.tasks.recon.tech_stack import run_tech_stack_detection
from app.tasks.vulnscan import cpe as cpe_module
from app.tasks.vulnscan.vuln_tools import extract_cvss, run_nvd_cve_lookup

logger = logging.getLogger("recontitan.nvd")

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: NVD allows 5 requests per 30s without a key and 50 with one. Exceeding it
#: returns 403s that look like "no vulnerabilities found", so pace deliberately.
_UNKEYED_DELAY = 6.5
_KEYED_DELAY = 0.7


def _headers() -> dict[str, str]:
    return {"apiKey": settings.NVD_API_KEY} if settings.NVD_API_KEY else {}


def _pace() -> None:
    time.sleep(_KEYED_DELAY if settings.NVD_API_KEY else _UNKEYED_DELAY)


def _affected_range(configurations: list) -> str:
    """Summarise the version range a CVE applies to, for the evidence block."""
    bounds: list[str] = []
    for node in configurations or []:
        for match in node.get("nodes", []):
            for entry in match.get("cpeMatch", []):
                start = entry.get("versionStartIncluding") or entry.get("versionStartExcluding")
                end = entry.get("versionEndIncluding") or entry.get("versionEndExcluding")
                if start or end:
                    bounds.append(f"{start or '*'} to {end or '*'}")
    unique = list(dict.fromkeys(bounds))[:3]
    return ", ".join(unique)


def _finding(item: dict, product: str, version: str, confidence: str, query: str) -> dict:
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
    score, vector, severity = extract_cvss(cve.get("metrics", {}))
    published = str(cve.get("published", ""))[:10]
    affected = _affected_range(cve.get("configurations", []))

    if confidence == "version_match":
        headline = f"{product} {version} is affected by {cve_id}"
        confidence_note = (
            f"NVD confirms {product} {version} falls inside this CVE's affected version range. "
            "Verify the running build before remediating."
        )
    elif confidence == "product_match":
        headline = f"{cve_id} affects {product} (version not disclosed)"
        confidence_note = (
            f"The target runs {product} but did not disclose a version, so it is unknown whether this "
            "install is in the affected range. Determine the version to resolve this."
        )
    else:
        headline = f"Possible CVE match: {cve_id} — {product}"
        confidence_note = (
            f"{product} is not in the CPE catalogue, so this is a keyword text match, not a version "
            "match. Treat as a lead requiring manual confirmation."
        )

    return {
        "tool": "nvd_cve",
        "category": "cve_finding",
        "severity": severity if confidence == "version_match" else _demote(severity, confidence),
        "title": f"{headline} (CVSS {score})" if score else headline,
        "description": f"{description[:360]} {confidence_note}",
        "evidence": "\n".join(filter(None, [
            f"CVE ID: {cve_id}",
            f"CVSS Score: {score}" if score else "CVSS Score: not published",
            f"CVSS Vector: {vector}" if vector else "",
            f"Published: {published}" if published else "",
            f"Detected product: {product} {version}".strip(),
            f"Affected versions: {affected}" if affected else "",
            f"Match basis: {confidence}",
            f"Query: {query}",
        ])),
        "cve_id": cve_id,
        "cvss_score": score,
        "confidence": confidence,
        "requires_manual_validation": confidence != "version_match",
        "remediation": (
            f"Review https://nvd.nist.gov/vuln/detail/{cve_id} and upgrade {product} beyond the "
            "affected range."
        ),
    }


def _demote(severity: str, confidence: str) -> str:
    """Lower the severity of an unconfirmed match.

    A CVE that may not apply to this install must not sit beside a confirmed
    one at the same severity, or the report trains the reader to ignore both.
    """
    if confidence == "keyword_candidate":
        return "info"
    order = ["info", "low", "medium", "high", "critical"]
    index = order.index(severity) if severity in order else 0
    return order[max(0, index - 1)]


def _query_cpe(cpe_string: str, product: str, version: str, confidence: str) -> list[dict]:
    try:
        _pace()
        response = requests.get(
            NVD_ENDPOINT,
            params={"virtualMatchString": cpe_string, "resultsPerPage": 20},
            headers=_headers(),
            timeout=25,
        )
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:
        logger.warning("[nvd] CPE query failed for %s: %s", cpe_string, str(exc)[:160])
        return []

    findings = [
        _finding(item, product, version, confidence, cpe_string)
        for item in payload.get("vulnerabilities", [])
    ]
    # Most severe first: NVD returns oldest-first, which buried real issues.
    findings.sort(key=lambda f: (-(f.get("cvss_score") or 0.0), f.get("cve_id", "")))
    return findings[:10]


def _detected_technologies(target: str) -> list[tuple[str, str]]:
    """Product/version pairs from the fingerprinter, most specific first."""
    detections: list[tuple[str, str]] = []
    for finding in run_tech_stack_detection(target):
        for item in finding.get("technologies", []) or []:
            name = str(item.get("name", "")).strip()
            if name:
                detections.append((name, str(item.get("version") or "").strip()))
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    # Versioned detections first: they produce the actionable matches.
    for name, version in sorted(detections, key=lambda pair: (pair[1] == "", pair[0].lower())):
        key = (name.lower(), version)
        if key not in seen:
            seen.add(key)
            unique.append((name, version))
    return unique


def run_nvd_for_target(target: str) -> list[dict]:
    """Match detected technologies against NVD by CPE version range."""
    technologies = _detected_technologies(target)
    if not technologies:
        return [{
            "tool": "nvd_cve",
            "category": "cve_lookup",
            "severity": "info",
            "title": "CVE Lookup Skipped — No Technology Identified",
            "description": (
                "CVE matching needs a detected product name. Nothing was fingerprinted on this "
                "target, so there is nothing to match against and no conclusion can be drawn "
                "about whether the target is vulnerable."
            ),
            "evidence": f"Target: {target}",
        }]

    findings: list[dict] = []
    unmapped: list[str] = []
    versionless: list[str] = []

    for name, version in technologies[:settings.NVD_MAX_PRODUCTS]:
        mapped = cpe_module.cpe_for(name, version)
        if mapped is None:
            unmapped.append(name)
            # Not in the catalogue: fall back to the old keyword search, but
            # labelled honestly rather than presented as a version match.
            for raw in run_nvd_cve_lookup(name, version)[:5]:
                raw["confidence"] = "keyword_candidate"
                raw["severity"] = "info"
                raw["requires_manual_validation"] = True
                findings.append(raw)
            continue

        cpe_string, clean_version = mapped
        if clean_version:
            findings.extend(_query_cpe(cpe_string, name, clean_version, "version_match"))
        else:
            versionless.append(name)
            findings.extend(_query_cpe(cpe_string, name, "", "product_match"))

    confirmed = sum(1 for f in findings if f.get("confidence") == "version_match")
    findings.append({
        "tool": "nvd_cve",
        "category": "cve_lookup",
        "severity": "info",
        "title": f"CVE Matching Summary — {confirmed} version-confirmed match(es)",
        "description": (
            "Version-confirmed matches mean NVD places the detected version inside the CVE's "
            "affected range. Product-level and keyword results are leads, not findings: they do "
            "not establish that this install is affected."
        ),
        "evidence": "\n".join(filter(None, [
            f"Target: {target}",
            f"Technologies matched by version: {confirmed}",
            f"Detected without a version: {', '.join(versionless)}" if versionless else "",
            f"Not in the CPE catalogue: {', '.join(unmapped)}" if unmapped else "",
            f"NVD API key in use: {'yes' if settings.NVD_API_KEY else 'no (rate limited to 5 req/30s)'}",
        ])),
        "remediation": (
            "Resolve versionless detections by identifying the running build, and treat keyword "
            "results as leads to confirm manually."
        ),
    })
    return findings
