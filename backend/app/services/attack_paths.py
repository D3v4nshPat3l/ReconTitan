"""Correlate scan evidence into honest, top-to-bottom attack paths.

The correlator never sends traffic. It joins evidence already produced by the
scanner and keeps three claims separate:

* confirmed — directly observed or safely proven on this target;
* supported — multiple observations or an authoritative external source agree;
* possible — a plausible next step or impact that was not executed.

In particular, CISA KEV proves exploitation in the wild, not exploitation of
this target. A CVE path is only version-confirmed when NVD applicability and the
detected product version agree. Only a finding with ``exploited=true`` becomes
a target-confirmed exploitation path.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_STATUS_ORDER = {
    "exploited": 0,
    "version_confirmed": 1,
    "supported": 2,
    "candidate": 3,
    "blocked": 4,
}
_MAX_PATHS = 60


def _clip(value: Any, limit: int = 600) -> str:
    text = " ".join(str(value or "").split())
    return text[:limit] + ("..." if len(text) > limit else "")


def _evidence_value(finding: dict, key: str) -> str:
    wanted = key.casefold()
    for line in str(finding.get("evidence") or "").splitlines():
        left, separator, right = line.partition(":")
        if separator and left.strip().casefold() == wanted:
            return right.strip()
    return ""


def _step(
    kind: str,
    label: str,
    detail: str,
    level: str,
    finding: dict | None = None,
) -> dict[str, Any]:
    return {
        "kind": kind,
        "label": _clip(label, 300),
        "detail": _clip(detail, 1_200),
        "evidence_level": level if level in {"confirmed", "supported", "possible"} else "possible",
        "source_finding_id": _clip((finding or {}).get("id"), 100) or None,
    }


def _services(findings: list[dict]) -> list[dict[str, Any]]:
    found: dict[tuple[int, str], dict[str, Any]] = {}
    for finding in findings:
        if str(finding.get("category")) not in {"port_scan", "dangerous_port"}:
            continue
        text = f"{finding.get('title', '')}\n{finding.get('evidence', '')}"
        for match in re.finditer(
            r"\b(\d{1,5})/(tcp|udp)\s+(?:open\s+)?([a-z0-9_.?/-]+)(?:\s+([^\r\n|]+))?",
            text,
            re.IGNORECASE,
        ):
            port = int(match.group(1))
            protocol = match.group(2).lower()
            if not 1 <= port <= 65535:
                continue
            existing = found.get((port, protocol), {})
            found[(port, protocol)] = {
                "port": port,
                "protocol": protocol,
                "service": existing.get("service") or _clip(match.group(3), 100),
                "banner": existing.get("banner") or _clip(match.group(4), 300),
                "source": existing.get("source") or _clip(finding.get("tool"), 100),
                "finding": existing.get("finding") or finding,
            }
    return sorted(found.values(), key=lambda item: (item["port"], item["protocol"]))


def _endpoint(finding: dict) -> str:
    return _evidence_value(finding, "Endpoint") or _clip(finding.get("affected_asset"), 2_000)


def _endpoint_service(endpoint: str, services: list[dict]) -> dict | None:
    if not endpoint:
        return None
    try:
        parsed = urlsplit(endpoint if "://" in endpoint else f"https://{endpoint}")
        port = parsed.port or (443 if parsed.scheme == "https" else 80 if parsed.scheme == "http" else None)
    except ValueError:
        return None
    return next((service for service in services if service["port"] == port), None)


def _product_version(finding: dict) -> tuple[str, str]:
    detected = _evidence_value(finding, "Detected product")
    if not detected:
        return "", ""
    version_match = re.search(r"\s(\d+(?:\.\d+){0,5}(?:[-+._][\w.-]+)?)$", detected)
    if not version_match:
        return detected.strip(), ""
    return detected[:version_match.start()].strip(), version_match.group(1)


def _product_tokens(product: str) -> set[str]:
    ignored = {"server", "http", "web", "the", "software", "project"}
    return {
        token for token in re.findall(r"[a-z0-9]+", product.lower())
        if len(token) > 2 and token not in ignored
    }


def _service_for_product(product: str, version: str, services: list[dict]) -> tuple[dict | None, str]:
    tokens = _product_tokens(product)
    best: tuple[dict | None, str] = (None, "possible")
    for service in services:
        haystack = f"{service['service']} {service['banner']}".lower()
        product_seen = bool(tokens and any(token in haystack for token in tokens))
        version_seen = bool(version and re.search(rf"(?<![\w.]){re.escape(version.lower())}(?![\w.])", haystack))
        if product_seen and version_seen:
            return service, "confirmed"
        if product_seen:
            best = (service, "supported")
    if best[0] is not None:
        return best
    # A web technology can plausibly sit behind an open HTTP service, but this
    # is never called a port-to-product confirmation without a matching banner.
    web = next((item for item in services if item["port"] in {80, 443, 8080, 8443}), None)
    return (web, "possible") if web and product else (None, "possible")


def _attack_family(finding: dict) -> str:
    text = " ".join(str(finding.get(key) or "") for key in (
        "title", "description", "category", "attack_vector", "exploit_technique",
    )).lower()
    families = (
        (("sql injection", "sqli"), "SQL injection"),
        (("command injection", "remote code execution", " rce"), "Remote command execution"),
        (("cross-site scripting", " xss"), "Cross-site scripting"),
        (("template injection", "ssti"), "Server-side template injection"),
        (("path traversal", "directory traversal", "local file inclusion", " lfi"), "Path traversal / file read"),
        (("server-side request forgery", "ssrf"), "Server-side request forgery"),
        (("xml external entity", " xxe"), "XML external entity injection"),
        (("deserial" ,), "Unsafe deserialization"),
        (("authentication bypass", "auth bypass"), "Authentication bypass"),
        (("idor", "object reference"), "Broken object-level authorization"),
        (("subdomain takeover",), "Subdomain takeover"),
        (("open redirect",), "Open redirect"),
        (("cors", "cross-origin"), "Cross-origin access"),
        (("denial of service", " dos"), "Denial of service"),
        (("information disclosure", "data exposure", "sensitive data"), "Information disclosure"),
    )
    for needles, label in families:
        if any(needle in text for needle in needles):
            return label
    return _clip(finding.get("attack_vector") or finding.get("category") or "Vulnerability exploitation", 160)


def _impact(finding: dict, family: str) -> list[str]:
    demonstrated = _clip(finding.get("exploit_impact"), 1_200)
    if demonstrated:
        return [demonstrated]
    mapping = {
        "SQL injection": ["Read or alter database data", "Potential authentication bypass"],
        "Remote command execution": ["Execute commands with the service account's privileges", "Potential host takeover and lateral movement"],
        "Cross-site scripting": ["Run script in a victim's browser under the target origin", "Potential session or action abuse"],
        "Server-side template injection": ["Evaluate server-side template expressions", "Potential remote code execution"],
        "Path traversal / file read": ["Read files accessible to the web process", "Potential credential or configuration disclosure"],
        "Server-side request forgery": ["Reach services accessible from the server", "Potential cloud metadata or internal-service access"],
        "XML external entity injection": ["Potential server-side file read or internal requests"],
        "Authentication bypass": ["Reach functionality without the expected authentication boundary"],
        "Broken object-level authorization": ["Access another user's object if authorization is missing"],
        "Subdomain takeover": ["Serve attacker-controlled content from a trusted subdomain"],
        "Open redirect": ["Redirect users to attacker-controlled destinations"],
        "Information disclosure": ["Expose information that can enable follow-on attacks"],
    }
    return mapping.get(family, [_clip(finding.get("description"), 700) or "Impact requires manual validation"])


def _encoding_analysis(finding: dict) -> str:
    proof = str(finding.get("exploit_proof") or "")
    text = f"{proof} {finding.get('description', '')} {_evidence_value(finding, 'Payload intent')}".lower()
    context = re.search(r"context=([^;]+);\s*unescaped=([^;]+);\s*escaped=([^;]+)", proof, re.I)
    if context:
        return (
            f"Context {context.group(1)}: unescaped breakout characters {context.group(2)}; "
            f"encoded characters {context.group(3)}."
        )
    if "required to break out are encoded" in text or "not exploitable as written" in text:
        return "Output encoding blocked the required breakout characters; this payload path was not confirmed."
    encodings = [name for name in ("url-encoded", "double-encoded", "base64", "unicode", "hex", "html entity") if name in text]
    if encodings:
        return f"Observed payload encoding: {', '.join(encodings)}."
    return "No special encoding was confirmed; review the recorded payload category and proof."


def _base_path(index: int, finding: dict, title: str, status: str, family: str) -> dict[str, Any]:
    severity = str(finding.get("severity") or "info").lower()
    if severity not in _SEVERITY_ORDER:
        severity = "info"
    return {
        "id": f"attack_path_{index:03d}",
        "title": _clip(title, 400),
        "status": status,
        "severity": severity,
        "attack_confirmed": bool(finding.get("exploited")),
        "attack_type": _clip(family, 160),
        "source_finding_ids": [_clip(finding.get("id"), 100)] if finding.get("id") else [],
        "steps": [],
        "possible_impacts": _impact(finding, family),
        "remediation": _clip(finding.get("remediation"), 2_000),
    }


def _exploit_or_candidate_path(index: int, target: str, finding: dict, services: list[dict]) -> dict:
    family = _attack_family(finding)
    endpoint = _endpoint(finding) or target
    exploited = bool(finding.get("exploited"))
    blocked = not exploited and (
        "not exploitable as written" in str(finding.get("description") or "").lower()
        or "required to break out are encoded" in str(finding.get("description") or "").lower()
    )
    status = "exploited" if exploited else "blocked" if blocked else "candidate"
    prefix = "Confirmed" if exploited else "Blocked" if blocked else "Candidate"
    path = _base_path(index, finding, f"{prefix} {family} at {endpoint}", status, family)
    path["steps"].append(_step("target", target, "Authorized scan target", "confirmed"))
    service = _endpoint_service(endpoint, services)
    if service:
        path["steps"].append(_step(
            "service", f"{service['port']}/{service['protocol']} {service['service']}",
            service["banner"] or f"Open service observed by {service['source']}", "confirmed", service["finding"],
        ))
    method = _evidence_value(finding, "Method") or "HTTP"
    path["steps"].append(_step("endpoint", f"{method} {endpoint}", "The scanner sent a bounded request to this endpoint", "confirmed", finding))
    parameter = _evidence_value(finding, "Parameter")
    if parameter and parameter != "(request body)":
        path["steps"].append(_step("input", f"Input: {parameter}", _evidence_value(finding, "Input point type") or "Request parameter", "confirmed", finding))
    payload_category = _evidence_value(finding, "Payload category")
    payload_intent = _evidence_value(finding, "Payload intent")
    if payload_category or payload_intent:
        path["steps"].append(_step(
            "payload", f"Payload family: {payload_category or family}",
            f"{payload_intent or 'Bounded validation probe'}. {_encoding_analysis(finding)}",
            "confirmed" if exploited or blocked else "supported", finding,
        ))
    path["steps"].append(_step(
        "technique", family,
        _clip(finding.get("exploit_technique") or finding.get("attack_vector") or finding.get("description"), 1_000),
        "confirmed" if exploited else "supported", finding,
    ))
    if exploited:
        path["steps"].append(_step(
            "proof", "Target-side execution proof",
            _clip(finding.get("exploit_proof"), 1_200) or "The scanner recorded a deterministic proof value",
            "confirmed", finding,
        ))
    elif blocked:
        path["steps"].append(_step(
            "control", "Encoding stopped the tested path", _encoding_analysis(finding), "confirmed", finding,
        ))
        path["possible_impacts"] = []
    return path


def _cve_path(index: int, target: str, finding: dict, services: list[dict]) -> dict:
    cve = _clip(finding.get("cve_id"), 50) or "CVE candidate"
    product, version = _product_version(finding)
    family = _attack_family(finding)
    version_confirmed = (
        str(finding.get("confidence")) == "version_match"
        and not bool(finding.get("requires_manual_validation"))
    )
    status = "version_confirmed" if version_confirmed else "candidate"
    title = f"{cve} through {product or 'detected software'} {version}".strip()
    path = _base_path(index, finding, title, status, family)
    path["steps"].append(_step("target", target, "Authorized scan target", "confirmed"))
    service, service_level = _service_for_product(product, version, services)
    if service:
        detail = service["banner"] or f"Service name: {service['service']}"
        if service_level != "confirmed":
            detail += "; the service banner did not prove this exact product/version association"
        path["steps"].append(_step(
            "service", f"{service['port']}/{service['protocol']} {service['service']}", detail,
            service_level, service["finding"],
        ))
    path["steps"].append(_step(
        "software", f"{product or 'Detected software'} {version}".strip(),
        "Product/version fingerprint used for NVD range matching",
        "confirmed" if version_confirmed else "supported", finding,
    ))
    path["steps"].append(_step(
        "cve", cve,
        f"CVSS {finding.get('cvss_score', 'unscored')} · {finding.get('exploit_priority', 'unprioritized')} priority",
        "confirmed" if version_confirmed else "supported", finding,
    ))
    if finding.get("kev_status") == "known_exploited":
        path["steps"].append(_step(
            "threat", "CISA KEV: exploited in the wild",
            "Authoritative threat activity for this CVE; this does not prove exploitation of this target",
            "supported", finding,
        ))
    if finding.get("epss_score") is not None:
        path["steps"].append(_step(
            "threat", f"EPSS {float(finding['epss_score']):.1%}",
            f"Predicted exploitation probability; percentile {float(finding.get('epss_percentile') or 0):.1%}",
            "supported", finding,
        ))
    path["steps"].append(_step(
        "technique", f"Possible technique: {family}",
        "No CVE exploit payload was executed; this branch is inferred from the CVE description and version match",
        "possible", finding,
    ))
    return path


def _port_path(index: int, target: str, finding: dict, service: dict | None) -> dict:
    family = "Exposed network service"
    label = finding.get("title") or "Internet-exposed service"
    path = _base_path(index, finding, label, "supported", family)
    path["steps"].append(_step("target", target, "Authorized scan target", "confirmed"))
    if service:
        path["steps"].append(_step(
            "service", f"{service['port']}/{service['protocol']} {service['service']}",
            service["banner"] or "Open network service", "confirmed", finding,
        ))
    path["steps"].append(_step(
        "technique", "Possible service-specific attack",
        _clip(finding.get("description"), 900), "possible", finding,
    ))
    return path


def build_attack_paths(report: dict[str, Any]) -> list[dict[str, Any]]:
    """Build bounded, deterministic paths from one scan report or record."""
    target = _clip(report.get("target") or "Unknown target", 253)
    findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)][:10_000]
    services = _services(findings)
    paths: list[dict[str, Any]] = []
    consumed: set[int] = set()

    for finding in findings:
        if finding.get("exploited"):
            paths.append(_exploit_or_candidate_path(len(paths) + 1, target, finding, services))
            consumed.add(id(finding))

    for finding in findings:
        if id(finding) in consumed or not finding.get("cve_id"):
            continue
        paths.append(_cve_path(len(paths) + 1, target, finding, services))
        consumed.add(id(finding))

    for finding in findings:
        if id(finding) in consumed:
            continue
        category = str(finding.get("category") or "")
        if category.startswith("danger_") and finding.get("attack_vector") and str(finding.get("severity")) != "info":
            paths.append(_exploit_or_candidate_path(len(paths) + 1, target, finding, services))
            consumed.add(id(finding))

    for finding in findings:
        if id(finding) in consumed or str(finding.get("category")) != "dangerous_port":
            continue
        port_text = f"{finding.get('title', '')} {finding.get('evidence', '')}"
        match = re.search(r"\b(\d{1,5})/(?:tcp|udp|[a-z0-9_.?/-]+)", port_text, re.I)
        service = next((item for item in services if match and item["port"] == int(match.group(1))), None)
        paths.append(_port_path(len(paths) + 1, target, finding, service))

    paths.sort(key=lambda path: (
        _STATUS_ORDER.get(path["status"], 99),
        _SEVERITY_ORDER.get(path["severity"], 99),
        path["title"].lower(),
    ))
    for index, path in enumerate(paths[:_MAX_PATHS], 1):
        path["id"] = f"attack_path_{index:03d}"
    return paths[:_MAX_PATHS]
