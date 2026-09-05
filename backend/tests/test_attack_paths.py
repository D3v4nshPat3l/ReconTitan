"""Guards on attack-path correlation.

The value of this feature is entirely in what it refuses to claim. A correlator
that upgrades "this CVE is exploited in the wild" into "this host was
exploited" is worse than no correlator at all, because it looks authoritative
while being wrong. Most of the tests below exist to hold that line.

Findings are built with the real constructors rather than hand-written dicts,
so a change to the finding shape breaks these tests instead of silently
breaking correlation.
"""

from __future__ import annotations

from app.services.attack_paths import build_attack_paths
from app.tasks.vulnscan.danger.budget import danger_finding, evidence_block
from app.tasks.vulnscan.nvd_lookup import _finding as nvd_finding

PORTS = {
    "id": "f_ports",
    "tool": "nmap",
    "category": "port_scan",
    "severity": "info",
    "title": "Port Scan - 3 Open Port(s) Found",
    "evidence": (
        "Target: shop.example.com\nTool: nmap\n\n"
        "• 443/tcp open ssl/https Apache httpd 2.4.49\n"
        "• 22/tcp open ssh OpenSSH 8.2p1\n"
        "• 3306/tcp open mysql MySQL 5.7.33"
    ),
}


def _confirmed_sqli() -> dict:
    finding = danger_finding(
        tool="sqli_probe", category="danger_sql_injection", severity="high",
        title="SQL injection confirmed on id",
        description="Arithmetic differential confirmed server-side evaluation.",
        evidence=evidence_block([
            ("Method", "GET"),
            ("Endpoint", "https://shop.example.com/item?id=7"),
            ("Parameter", "id"),
            ("Input point type", "query"),
            ("Payload category", "boolean/arithmetic differential"),
            ("Payload intent", "Compare 7 AND 1=1 against 7 AND 1=2"),
        ]),
        remediation="Use parameterised queries.",
        owasp="A03:2021-Injection", attack_vector="SQL injection via query parameter",
        asset="https://shop.example.com/item?id=7",
        confidence="CONFIRMED by exploitation",
    )
    finding.update(
        id="f_sqli", exploited=True,
        exploit_technique="Boolean-based arithmetic differential",
        exploit_proof="arithmetic: 7*3=21 evaluated server-side",
        exploit_impact="Read database rows accessible to the application user",
    )
    return finding


def _kev_cve() -> dict:
    item = {"cve": {
        "id": "CVE-2021-41773",
        "descriptions": [{"lang": "en", "value": "Path traversal in Apache HTTP Server 2.4.49 allows remote code execution."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
    }}
    finding = nvd_finding(item, "Apache httpd", "2.4.49", "version_match", "apache")
    finding.update(
        id="f_cve", kev_status="known_exploited",
        epss_score=0.9741, epss_percentile=0.9998, exploit_priority="urgent",
    )
    return finding


def _levels(path: dict) -> list[str]:
    return [step["evidence_level"] for step in path["steps"]]


def _step(path: dict, kind: str) -> dict | None:
    return next((step for step in path["steps"] if step["kind"] == kind), None)


def _by_status(paths: list[dict], status: str) -> dict:
    match = next((path for path in paths if path["status"] == status), None)
    assert match is not None, f"no path with status {status!r} in {[p['status'] for p in paths]}"
    return match


# ── The line this feature exists to hold ──────────────────────────────────────

def test_kev_never_becomes_a_claim_about_this_target():
    """"Exploited in the wild" describes the CVE, not the scanned host."""
    paths = build_attack_paths({
        "target": "shop.example.com", "findings": [PORTS, _kev_cve()],
    })
    path = _by_status(paths, "version_confirmed")

    assert path["attack_confirmed"] is False
    assert path["status"] != "exploited"

    threat = next(s for s in path["steps"] if "KEV" in s["label"])
    assert threat["evidence_level"] == "supported"
    assert "does not prove exploitation of this target" in threat["detail"]

    # The chain must end somewhere unexecuted, or the reader is entitled to
    # conclude the host was compromised.
    assert path["steps"][-1]["evidence_level"] == "possible"
    assert "No CVE exploit payload was executed" in path["steps"][-1]["detail"]


def test_a_version_match_confirms_the_software_not_the_exploit():
    paths = build_attack_paths({
        "target": "shop.example.com", "findings": [PORTS, _kev_cve()],
    })
    path = _by_status(paths, "version_confirmed")

    # The banner says "Apache httpd 2.4.49", so tying the service to the
    # product is an observation, not a guess.
    assert _step(path, "service")["evidence_level"] == "confirmed"
    assert _step(path, "software")["evidence_level"] == "confirmed"
    assert _step(path, "cve")["evidence_level"] == "confirmed"
    # But the technique never ran.
    assert _step(path, "technique")["evidence_level"] == "possible"


def test_a_product_without_a_matching_banner_is_not_confirmed_to_a_port():
    """A web technology may sit behind 443; that is not proof it does."""
    cve = _kev_cve()
    cve["evidence"] = cve["evidence"].replace(
        "Detected product: Apache httpd 2.4.49",
        "Detected product: WordPress 5.8.1",
    )
    paths = build_attack_paths({"target": "shop.example.com", "findings": [PORTS, cve]})
    service = _step(_by_status(paths, "version_confirmed"), "service")

    assert service is not None
    assert service["evidence_level"] == "possible"
    assert "did not prove this exact product/version association" in service["detail"]


def test_only_an_executed_proof_produces_a_confirmed_path():
    paths = build_attack_paths({
        "target": "shop.example.com", "findings": [PORTS, _confirmed_sqli()],
    })
    path = _by_status(paths, "exploited")

    assert path["attack_confirmed"] is True
    assert set(_levels(path)) == {"confirmed"}
    assert _step(path, "proof")["detail"].startswith("arithmetic:")
    # Demonstrated impact replaces the generic list when the scanner recorded one.
    assert path["possible_impacts"] == ["Read database rows accessible to the application user"]


def test_an_encoding_blocked_route_is_reported_as_blocked_with_no_impact():
    """A control that held is worth showing, but it leads nowhere."""
    xss = danger_finding(
        tool="xss_probe", category="danger_reflected_xss", severity="low",
        title="Reflected input in HTML attribute (not exploitable as written)",
        description="The value reflects into an attribute, but the characters required to break out are encoded.",
        evidence=evidence_block([
            ("Method", "GET"),
            ("Endpoint", "https://shop.example.com/search?q=test"),
            ("Parameter", "q"),
            ("Payload category", "reflection context probe"),
        ]),
        remediation="Keep context-aware output encoding in place.",
        owasp="A03:2021-Injection", attack_vector="Reflected cross-site scripting",
        asset="https://shop.example.com/search?q=test",
        confidence="Candidate - requires manual validation",
    )
    xss["id"] = "f_xss"
    xss["exploit_proof"] = 'context=html_attribute; unescaped=none; escaped=" < > &'

    path = _by_status(build_attack_paths({"target": "shop.example.com", "findings": [xss]}), "blocked")

    assert path["attack_confirmed"] is False
    assert path["possible_impacts"] == [], "a blocked route must not advertise impact"
    control = _step(path, "control")
    assert control is not None and control["evidence_level"] == "confirmed"
    assert "html_attribute" in control["detail"]


# ── Structure ─────────────────────────────────────────────────────────────────

def test_the_chain_starts_at_the_target_and_joins_the_endpoint_to_its_port():
    paths = build_attack_paths({
        "target": "shop.example.com", "findings": [PORTS, _confirmed_sqli()],
    })
    path = _by_status(paths, "exploited")

    assert path["steps"][0]["kind"] == "target"
    # The endpoint is https, so it belongs to the observed 443 service.
    assert _step(path, "service")["label"].startswith("443/tcp")


def test_stronger_claims_sort_above_weaker_ones():
    findings = [PORTS, _kev_cve(), _confirmed_sqli()]
    statuses = [path["status"] for path in build_attack_paths(
        {"target": "shop.example.com", "findings": findings})]
    assert statuses.index("exploited") < statuses.index("version_confirmed")


def test_every_step_carries_a_recognised_evidence_level():
    findings = [PORTS, _kev_cve(), _confirmed_sqli()]
    for path in build_attack_paths({"target": "shop.example.com", "findings": findings}):
        assert path["steps"], f"{path['id']} has no steps"
        for step in path["steps"]:
            assert step["evidence_level"] in {"confirmed", "supported", "possible"}
            assert step["kind"] and step["label"]


def test_a_finding_produces_at_most_one_path():
    """Otherwise one issue is counted several times and the report inflates."""
    findings = [PORTS, _kev_cve(), _confirmed_sqli()]
    paths = build_attack_paths({"target": "shop.example.com", "findings": findings})
    seen: list[str] = []
    for path in paths:
        seen.extend(path["source_finding_ids"])
    assert len(seen) == len(set(seen)), f"finding reused across paths: {seen}"


def test_correlation_is_bounded_and_survives_junk_input():
    """It runs on whatever the scan produced, including nothing useful."""
    assert build_attack_paths({}) == []
    assert build_attack_paths({"target": "x.example.com", "findings": []}) == []
    assert build_attack_paths({"findings": [None, "text", 42, {}]}) == []

    flood = [dict(_confirmed_sqli(), id=f"f_{index}") for index in range(400)]
    paths = build_attack_paths({"target": "shop.example.com", "findings": flood})
    assert len(paths) <= 60, "unbounded path count would let one scan flood the report"
    assert [path["id"] for path in paths] == [f"attack_path_{i:03d}" for i in range(1, len(paths) + 1)]
