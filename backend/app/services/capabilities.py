"""Canonical capability and scan-profile metadata used by the API and UI."""

from __future__ import annotations

from copy import deepcopy

import shutil

from app.config import settings

#: Modules that shell out to a binary. Each already fails soft when the binary
#: is absent, but silence is not the same as a report: an operator needs to
#: know a module was skipped rather than assume it found nothing.
#: ``waf_detect`` is deliberately absent: despite the ``run_wafw00f`` name it
#: never shells out, it matches WAF/CDN signatures from response headers in
#: pure Python. Listing it here reported a working module as unavailable, which
#: inverts the whole point of this report.
BINARY_MODULES: dict[str, tuple[str, ...]] = {
    "port_scan": ("nmap",),
    "subfinder": ("subfinder",),
    "amass": ("amass",),
    "theharvester": ("theHarvester", "theharvester"),
    "nuclei": ("nuclei",),
    "nikto": ("nikto",),
    "dir_fuzzing": ("ffuf", "gobuster"),
    "sqlmap": ("sqlmap",),
}


def runtime_report() -> dict:
    """Which modules can actually run here, and how scans are dispatched.

    On a platform without system packages most of these binaries are absent.
    The scan still runs; this makes the reduced coverage explicit instead of
    letting empty results read as a clean target.
    """
    available, missing = [], []
    for module, binaries in BINARY_MODULES.items():
        (available if any(shutil.which(b) for b in binaries) else missing).append(module)
    return {
        "deployment": "serverless" if settings.SERVERLESS else "server",
        "async_scans": settings.ASYNC_SCANS_ENABLED and not settings.SERVERLESS,
        "sync_scan_endpoint": "/api/test-scan",
        "shared_rate_limit_state": settings.SHARED_STATE_ENABLED,
        "binary_modules_available": sorted(available),
        "binary_modules_unavailable": sorted(missing),
        "note": (
            "Modules listed as unavailable are skipped because their binary is not installed. "
            "A skipped module is not evidence that the target is unaffected."
        ),
    }

CAPABILITIES: list[dict] = [
    {
        "key": "danger_mode",
        "name": "Danger Mode Simulation",
        "category": "Penetration Test Simulation",
        "status": "available" if settings.ALLOW_DANGER_MODE else "opt-in",
        "description": (
            "Bounded intermediate penetration-test simulation covering the OWASP Top 10 with attack-surface "
            "inventory, injection probes, traversal and IDOR candidates, and AXFR attempts. Disabled unless "
            "ALLOW_DANGER_MODE=true; every finding is a candidate requiring manual validation."
        ),
        "tools": ["attack surface inventory", "injection probes", "AXFR", "IDOR differential", "OWASP matrix"],
    },
    {
        "key": "pdf_report",
        "name": "PDF Report Export",
        "category": "Reporting",
        "status": "available",
        "description": "Generate a portable, severity-ranked PDF with methodology, tool coverage, evidence, and remediation guidance.",
        "tools": ["reportlab", "browser export", "stored scan export"],
    },
    {
        "key": "subdomain_takeover",
        "name": "Subdomain Takeover Detection",
        "category": "Attack Surface",
        "status": "available",
        "description": "Correlate certificate-derived subdomains, CNAME delegations, provider fingerprints, and NXDOMAIN evidence conservatively.",
        "tools": ["crt.sh", "DNS CNAME", "provider fingerprints"],
    },
    {
        "key": "js_analysis",
        "name": "JavaScript File Analysis",
        "category": "Client Security",
        "status": "available",
        "description": "Inspect bounded same-scope JavaScript assets for redacted secrets, risky sinks, source maps, and application endpoints.",
        "tools": ["BeautifulSoup", "secret fingerprints", "DOM sink analysis"],
    },
    {
        "key": "favicon_hash",
        "name": "Favicon Hash Lookup",
        "category": "Asset Correlation",
        "status": "available",
        "description": "Calculate MD5, SHA-256, and Shodan-compatible MurmurHash3 fingerprints with optional Shodan correlation.",
        "tools": ["MurmurHash3", "SHA-256", "Shodan"],
    },
    {
        "key": "tech_stack",
        "name": "Technology Stack Detection",
        "category": "Fingerprinting",
        "status": "available",
        "description": "Detect frameworks, CMS platforms, web servers, CDNs, analytics, and exposed versions from multiple response signals.",
        "tools": ["headers", "HTML", "cookies", "asset signatures"],
    },
]

SCAN_PROFILES: dict[str, dict] = {
    "full": {
        "name": "Full Safe Scan",
        "description": "Runs reconnaissance, OSINT, safe active checks, technology-led CVE lookup, and AI summary generation.",
        "groups": ["recon", "osint", "vuln"],
    },
    "recon_only": {
        "name": "Recon Only",
        "description": "Maps domains, DNS, certificates, historical URLs, infrastructure, and passive subdomains.",
        "groups": ["recon"],
    },
    "osint_only": {
        "name": "OSINT & Web Analysis",
        "description": "Focuses on web configuration, JavaScript, technologies, favicon correlation, takeover checks, and threat intelligence.",
        "groups": ["osint"],
    },
    "vuln_only": {
        "name": "Vulnerability Focus",
        "description": "Runs bounded port exposure and technology-led CVE candidate checks; intrusive tools remain opt-in.",
        "groups": ["vuln"],
    },
    "danger": {
        "name": "Full Intermediate Penetration Test Simulation",
        "description": (
            "Danger Mode. Adds detailed recon with AXFR attempts, an attack-surface inventory, bounded OWASP "
            "Top 10 injection, traversal, directory and IDOR probing, and reverse-shell vector assessment on top "
            "of the recon, OSINT, and vulnerability profiles. Requires explicit opt-in and written authorization; "
            "all output is labeled as candidates requiring manual validation."
        ),
        "groups": ["recon", "osint", "vuln", "danger"],
        "requires_opt_in": True,
    },
}

TOOL_GROUPS: dict[str, list[str]] = {
    "recon": [
        "whois", "dns_lookup", "crt.sh", "wayback", "ipinfo", "httpx_probe", "subfinder", "amass",
    ],
    "osint": [
        "security_headers", "ssl_check", "robots_sitemap", "cors_check", "cookie_check", "waf_detect",
        "tech_stack", "favicon_hash", "js_analysis", "subdomain_takeover",
        "virustotal", "shodan", "greynoise", "censys", "theharvester",
    ],
    "vuln": ["port_scan", "nvd_cve", "nuclei", "nikto", "dir_fuzzing", "sqlmap"],
    "danger": [
        "danger_recon", "danger_axfr", "attack_surface",
        "injection_sqli", "injection_command", "injection_html", "injection_xss",
        "injection_ssti", "injection_xxe", "injection_ssrf", "injection_nosql",
        "reverse_shell_assessment", "dom_injection", "directory_fuzzing", "path_traversal",
        "idor_testing", "business_logic", "data_exposure", "advanced_checks", "owasp_matrix",
    ],
}


def tools_for_profile(profile: str, *, include_ai: bool = True) -> list[str]:
    selected = SCAN_PROFILES.get(profile, SCAN_PROFILES["full"])
    tools: list[str] = []
    for group in selected["groups"]:
        for tool in TOOL_GROUPS[group]:
            if tool not in tools:
                tools.append(tool)
    if include_ai:
        tools.append("ai_report")
    return tools


def capabilities_payload(version: str) -> dict:
    from app.services.danger_mode import danger_mode_metadata

    profiles = deepcopy(SCAN_PROFILES)
    for key, profile in profiles.items():
        profile["key"] = key
        profile["tools"] = tools_for_profile(key)
        profile["tool_count"] = len(profile["tools"])
    profiles["danger"]["enabled"] = settings.ALLOW_DANGER_MODE
    return {
        "version": version,
        "capabilities": deepcopy(CAPABILITIES),
        "profiles": list(profiles.values()),
        "tool_groups": deepcopy(TOOL_GROUPS),
        "danger_mode": danger_mode_metadata(),
        "runtime": runtime_report(),
    }
