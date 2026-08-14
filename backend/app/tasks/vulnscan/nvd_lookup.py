"""Technology-led NVD keyword lookup with conservative candidate labeling."""

from __future__ import annotations

import re

from app.tasks.recon.tech_stack import run_tech_stack_detection
from app.tasks.vulnscan.vuln_tools import run_nvd_cve_lookup


def run_nvd_for_target(target: str) -> list[dict]:
    """Search NVD using detected product names rather than the target domain."""
    technologies: list[tuple[str, str]] = []
    for finding in run_tech_stack_detection(target):
        if finding.get("category") != "tech_stack":
            continue
        for line in str(finding.get("evidence", "")).splitlines():
            match = re.match(r"^•\s+(.+?)(?:\s+\[|\s+—)", line.strip())
            if not match:
                continue
            label = match.group(1).strip()
            version_match = re.match(r"^(.*?)(?:\s+([0-9]+(?:\.[0-9A-Za-z_-]+)+))?$", label)
            if version_match:
                technologies.append((version_match.group(1).strip(), (version_match.group(2) or "").strip()))

    unique: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for technology in technologies:
        key = (technology[0].lower(), technology[1])
        if key not in seen:
            seen.add(key)
            unique.append(technology)

    if not unique:
        return [{
            "tool": "nvd_cve",
            "category": "cve_lookup",
            "severity": "info",
            "title": "NVD Lookup Skipped — No Technology Identified",
            "description": "CVE keyword lookup requires a detected product name to avoid unrelated domain-name matches.",
            "evidence": f"Target: {target}",
        }]

    findings: list[dict] = []
    for name, version in unique[:5]:
        findings.extend(run_nvd_cve_lookup(name, version))
    return findings or [{
        "tool": "nvd_cve",
        "category": "cve_lookup",
        "severity": "info",
        "title": "No NVD Keyword Matches Returned",
        "description": "No CVE keyword matches were returned for the detected technology names.",
        "evidence": "Queries: " + ", ".join(f"{name} {version}".strip() for name, version in unique[:5]),
    }]
