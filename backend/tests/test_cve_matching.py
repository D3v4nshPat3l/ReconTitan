"""CVE matching: CPE version ranges rather than keyword text search.

A CVE applies to specific product versions, not to any page whose text
mentions a product name. These tests pin the two failures that made the old
keyword approach actively misleading:

* every CVE without CVSS v3.1 data scored 0.0 and was reported "low", because
  the metric lookup defaulted to ``[{}]`` -- a truthy value that stopped the
  ``or`` chain before it reached v3.0 or v2;
* results were whatever NVD returned first, which is oldest-first, so scans
  surfaced CVEs from 2004-2009 while current ones never appeared.

No test here touches the network. Live NVD behaviour is verified by hand; what
must not regress silently is the parsing, mapping, and ranking around it.
"""

from __future__ import annotations

import pytest

from app.tasks.vulnscan import cpe as cpe_module
from app.tasks.vulnscan.vuln_tools import extract_cvss


# ── CVSS extraction ──────────────────────────────────────────────────────────

def test_v2_only_cve_is_not_scored_zero():
    """The regression: a real 7.5 was reported as 0.0 and classified low."""
    metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 7.5, "vectorString": "AV:N/AC:L"}}]}
    score, vector, severity = extract_cvss(metrics)
    assert score == 7.5
    assert severity == "high"
    assert vector == "AV:N/AC:L"


def test_v30_only_cve_is_scored():
    score, _, severity = extract_cvss({"cvssMetricV30": [{"cvssData": {"baseScore": 5.3}}]})
    assert (score, severity) == (5.3, "medium")


def test_v31_is_preferred_over_older_metrics():
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 4.0}}],
    }
    score, _, severity = extract_cvss(metrics)
    assert (score, severity) == (9.8, "critical")


@pytest.mark.parametrize("metrics", [{}, {"cvssMetricV31": []}, {"cvssMetricV31": [{}]}])
def test_missing_metrics_are_info_not_low(metrics):
    """An unscored CVE must not masquerade as a scored low-severity one."""
    score, _, severity = extract_cvss(metrics)
    assert (score, severity) == (0.0, "info")


@pytest.mark.parametrize("score,expected", [
    (10.0, "critical"), (9.0, "critical"), (8.9, "high"), (7.0, "high"),
    (6.9, "medium"), (4.0, "medium"), (3.9, "low"), (0.1, "low"), (0.0, "info"),
])
def test_severity_boundaries(score, expected):
    assert extract_cvss({"cvssMetricV31": [{"cvssData": {"baseScore": score}}]})[2] == expected


# ── CPE mapping ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,expected_vendor,expected_product", [
    ("nginx", "f5", "nginx"),
    ("Apache", "apache", "http_server"),
    ("WordPress", "wordpress", "wordpress"),
    ("jQuery", "jquery", "jquery"),
    ("PHP", "php", "php"),
])
def test_display_names_map_to_the_vendor_product_nvd_indexes(name, expected_vendor, expected_product):
    """NVD's vendor names rarely match the marketing name; nginx is under f5."""
    assert cpe_module.lookup(name) == (expected_vendor, expected_product)


def test_lookup_is_case_insensitive():
    assert cpe_module.lookup("NGINX") == cpe_module.lookup("nginx")


def test_server_header_style_labels_are_handled():
    """Server headers arrive as "nginx/1.18.0", not a bare product name."""
    assert cpe_module.lookup("nginx/1.18.0") == ("f5", "nginx")


def test_unknown_product_returns_none_rather_than_a_guess():
    """An invented CPE matches nothing and is indistinguishable from "safe"."""
    assert cpe_module.lookup("TotallyMadeUpProduct") is None
    assert cpe_module.cpe_for("TotallyMadeUpProduct", "1.0") is None


@pytest.mark.parametrize("raw,expected", [
    ("1.18.0", "1.18.0"),
    ("1.18.0-ubuntu", "1.18.0"),
    ("1.18.0 (Ubuntu)", "1.18.0"),
    ("2.4.41", "2.4.41"),
    ("6", "6"),
    ("", ""),
    (None, ""),
    ("not-a-version", ""),
])
def test_version_normalisation(raw, expected):
    """NVD indexes numeric-dotted versions; build metadata breaks the match."""
    assert cpe_module.normalise_version(raw) == expected


def test_cpe_string_format():
    cpe_string, version = cpe_module.cpe_for("nginx", "1.18.0")
    assert cpe_string == "cpe:2.3:a:f5:nginx:1.18.0:*:*:*:*:*:*:*"
    assert version == "1.18.0"


def test_missing_version_becomes_a_wildcard():
    """Without a version we still ask about the product, but say so."""
    cpe_string, version = cpe_module.cpe_for("nginx", None)
    assert cpe_string == "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    assert version == ""


# ── Confidence and ranking ───────────────────────────────────────────────────

def _cve(score, cve_id="CVE-2021-0001"):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": "Example issue."}],
            "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score}}]},
            "published": "2021-05-25T00:00:00.000",
            "configurations": [],
        }
    }


def test_version_match_is_not_flagged_for_manual_validation():
    """NVD confirmed the version is in range; that is a finding, not a lead."""
    from app.tasks.vulnscan.nvd_lookup import _finding

    result = _finding(_cve(7.7), "nginx", "1.18.0", "version_match", "cpe:...")
    assert result["requires_manual_validation"] is False
    assert result["severity"] == "high"
    assert "1.18.0 is affected" in result["title"]


def test_product_match_without_a_version_is_demoted():
    """Unknown whether this install is affected, so it must not rank equally."""
    from app.tasks.vulnscan.nvd_lookup import _finding

    result = _finding(_cve(7.7), "nginx", "", "product_match", "cpe:...")
    assert result["requires_manual_validation"] is True
    assert result["severity"] == "medium"  # demoted from high
    assert "version not disclosed" in result["title"]


def test_keyword_candidate_is_reported_as_info():
    """The weakest evidence must not sit at high severity beside real matches."""
    from app.tasks.vulnscan.nvd_lookup import _finding

    result = _finding(_cve(9.8), "SomeProduct", "", "keyword_candidate", "keyword")
    assert result["severity"] == "info"
    assert result["requires_manual_validation"] is True
    assert "keyword text match" in result["description"]


def test_every_finding_states_its_match_basis():
    """A reader must be able to tell a confirmed match from a guess."""
    from app.tasks.vulnscan.nvd_lookup import _finding

    for confidence in ("version_match", "product_match", "keyword_candidate"):
        result = _finding(_cve(7.0), "nginx", "1.18.0", confidence, "q")
        assert f"Match basis: {confidence}" in result["evidence"]
        assert result["confidence"] == confidence


def test_affected_version_range_is_shown_when_nvd_supplies_it():
    from app.tasks.vulnscan.nvd_lookup import _affected_range

    configurations = [{"nodes": [{"cpeMatch": [
        {"versionStartIncluding": "1.16.0", "versionEndExcluding": "1.20.1"}
    ]}]}]
    assert _affected_range(configurations) == "1.16.0 to 1.20.1"


def test_affected_range_is_empty_when_unspecified():
    from app.tasks.vulnscan.nvd_lookup import _affected_range

    assert _affected_range([]) == ""
    assert _affected_range([{"nodes": [{"cpeMatch": [{}]}]}]) == ""
