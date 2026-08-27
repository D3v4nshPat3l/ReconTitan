"""Tests for the Ollama-backed AI narration layer.

No test here contacts a real model. The point of the layer is that it stays
useful when the model is absent, wrong, or slow, so that is what is exercised.
"""

from __future__ import annotations

import pytest

from app.tasks import ai_analysis


@pytest.fixture(autouse=True)
def _clear_probe_cache():
    """Each test starts with no cached view of whether Ollama is up."""
    ai_analysis._probe_cache.update({"checked_at": 0.0, "available": False, "model": "", "error": ""})
    yield
    ai_analysis._probe_cache.update({"checked_at": 0.0, "available": False, "model": "", "error": ""})


def _offline(monkeypatch):
    """Make every provider unreachable."""
    monkeypatch.setattr(ai_analysis.settings, "AI_PROVIDER", "auto")
    monkeypatch.setattr(ai_analysis.settings, "OPENAI_API_KEY", "")
    monkeypatch.setattr(
        ai_analysis, "_ollama_models", lambda: (_ for _ in ()).throw(ConnectionError("refused"))
    )


def _model_returns(monkeypatch, text: str):
    """Pretend a model is installed and always answers with ``text``."""
    monkeypatch.setattr(ai_analysis.settings, "AI_PROVIDER", "auto")
    monkeypatch.setattr(ai_analysis, "_ollama_models", lambda: ["llama3.1:8b"])
    monkeypatch.setattr(ai_analysis, "_call_ollama", lambda *a, **k: text)


# ── Model resolution ────────────────────────────────────────────────────────

def test_blank_model_setting_picks_the_first_installed_model(monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "OLLAMA_MODEL", "")
    monkeypatch.setattr(ai_analysis, "_ollama_models", lambda: ["qwen2.5:1.5b-instruct", "llama3.1:8b"])
    probe = ai_analysis._probe_ollama(force=True)
    assert probe["available"] is True
    assert probe["model"] == "qwen2.5:1.5b-instruct"


def test_configured_model_that_is_not_installed_falls_back(monkeypatch):
    """A stale OLLAMA_MODEL must not take the whole AI layer offline."""
    monkeypatch.setattr(ai_analysis.settings, "OLLAMA_MODEL", "mistral:7b")
    monkeypatch.setattr(ai_analysis, "_ollama_models", lambda: ["llama3.1:8b"])
    probe = ai_analysis._probe_ollama(force=True)
    assert probe["available"] is True
    assert probe["model"] == "llama3.1:8b"


def test_tag_drift_resolves_to_the_installed_tag(monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "OLLAMA_MODEL", "llama3.1")
    monkeypatch.setattr(ai_analysis, "_ollama_models", lambda: ["qwen2.5:1.5b", "llama3.1:8b"])
    assert ai_analysis._probe_ollama(force=True)["model"] == "llama3.1:8b"


def test_reachable_server_with_no_models_is_not_available(monkeypatch):
    monkeypatch.setattr(ai_analysis, "_ollama_models", lambda: [])
    probe = ai_analysis._probe_ollama(force=True)
    assert probe["available"] is False
    assert "no model is pulled" in probe["error"]


def test_unreachable_server_reports_the_reason(monkeypatch):
    _offline(monkeypatch)
    probe = ai_analysis._probe_ollama(force=True)
    assert probe["available"] is False
    assert "ConnectionError" in probe["error"]


# ── Provider selection ──────────────────────────────────────────────────────

def test_provider_none_never_calls_a_model(monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "AI_PROVIDER", "none")

    def _boom(*a, **k):
        raise AssertionError("no provider may be called when AI_PROVIDER=none")

    monkeypatch.setattr(ai_analysis, "_call_ollama", _boom)
    monkeypatch.setattr(ai_analysis, "_call_openai", _boom)
    assert ai_analysis._call_llm("sys", "user") is None


def test_auto_falls_through_to_openai_when_ollama_is_down(monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "AI_PROVIDER", "auto")
    monkeypatch.setattr(ai_analysis, "_call_ollama", lambda *a, **k: None)
    monkeypatch.setattr(ai_analysis, "_call_openai", lambda *a, **k: "from openai")
    assert ai_analysis._call_llm("sys", "user") == "from openai"


def test_ollama_only_never_reaches_openai(monkeypatch):
    """AI_PROVIDER=ollama is the privacy setting: no data may go to a third party."""
    monkeypatch.setattr(ai_analysis.settings, "AI_PROVIDER", "ollama")
    monkeypatch.setattr(ai_analysis, "_call_ollama", lambda *a, **k: None)

    def _boom(*a, **k):
        raise AssertionError("openai must not be contacted when AI_PROVIDER=ollama")

    monkeypatch.setattr(ai_analysis, "_call_openai", _boom)
    assert ai_analysis._call_llm("sys", "user") is None


# ── Degradation ─────────────────────────────────────────────────────────────

def test_summary_falls_back_to_static_text_when_offline(monkeypatch):
    _offline(monkeypatch)
    result = ai_analysis.generate_scan_summary("example.com", [], {"critical": 2, "high": 0})
    assert result["ai_generated"] is False
    assert result["risk_level"] == "CRITICAL"
    assert result["executive_summary"]


def test_verify_falls_back_without_claiming_ai(monkeypatch):
    _offline(monkeypatch)
    result = ai_analysis.verify_finding({"title": "Weak TLS", "severity": "high"}, "example.com")
    assert result["ai_available"] is False
    assert result["assessment"] == "NEEDS_MANUAL_REVIEW"
    assert result["remediation"]


def test_topic_falls_back_to_a_matching_primer(monkeypatch):
    _offline(monkeypatch)
    result = ai_analysis.explain_topic("CORS misconfiguration")
    assert result["ai_generated"] is False
    assert "Cross-Origin" in result["explanation"]


def test_unknown_topic_offline_still_answers(monkeypatch):
    _offline(monkeypatch)
    result = ai_analysis.explain_topic("some check with no primer")
    assert result["explanation"]
    assert result["ai_generated"] is False


def test_garbage_model_output_does_not_crash_the_summary(monkeypatch):
    """A small model can answer with prose where JSON was asked for."""
    _model_returns(monkeypatch, "I'm sorry, I cannot do that.")
    monkeypatch.setattr(ai_analysis.settings, "OPENAI_API_KEY", "")
    result = ai_analysis.generate_scan_summary("example.com", [], {"high": 1})
    assert result["ai_generated"] is False
    assert result["risk_level"] == "HIGH"


# ── Output normalisation ────────────────────────────────────────────────────

@pytest.mark.parametrize(
    "raw,expected",
    [
        ("TRUE_POSITIVE", "TRUE_POSITIVE"),
        ("true positive", "TRUE_POSITIVE"),
        ("likely a true positive", "LIKELY_TRUE_POSITIVE"),
        ("FALSE_POSITIVE", "LIKELY_FALSE_POSITIVE"),
        ("false-positive", "LIKELY_FALSE_POSITIVE"),
        ("probably fine", "NEEDS_MANUAL_REVIEW"),
        (None, "NEEDS_MANUAL_REVIEW"),
    ],
)
def test_assessment_is_snapped_onto_the_known_verdicts(raw, expected):
    assert ai_analysis._normalise_assessment(raw) == expected


@pytest.mark.parametrize("raw", ["very sure", "", None, "HIGHLY"])
def test_unknown_confidence_becomes_medium(raw):
    assert ai_analysis._normalise_confidence(raw) == "medium"


def test_remediation_string_is_split_into_steps():
    assert ai_analysis._as_list("- step one\n- step two") == ["step one", "step two"]


def test_remediation_list_is_preserved():
    assert ai_analysis._as_list(["a", "", "b"]) == ["a", "b"]


# ── Bulk explanation budget ─────────────────────────────────────────────────

def test_bulk_explanation_respects_the_count_cap(monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "AI_MAX_FINDING_EXPLANATIONS", 2)
    monkeypatch.setattr(ai_analysis.settings, "AI_EXPLANATION_CONCURRENCY", 1)
    monkeypatch.setattr(ai_analysis, "explain_finding", lambda f: "explained")

    findings = [{"title": f"f{i}", "severity": "high"} for i in range(5)]
    assert ai_analysis.explain_findings_bulk(findings) == 2
    assert sum(1 for f in findings if f.get("explanation")) == 2


def test_bulk_explanation_prefers_the_worst_findings(monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "AI_MAX_FINDING_EXPLANATIONS", 1)
    monkeypatch.setattr(ai_analysis.settings, "AI_EXPLANATION_CONCURRENCY", 1)
    monkeypatch.setattr(ai_analysis, "explain_finding", lambda f: "explained")

    low = {"title": "low", "severity": "low"}
    critical = {"title": "critical", "severity": "critical"}
    ai_analysis.explain_findings_bulk([low, critical])
    assert critical.get("explanation") == "explained"
    assert "explanation" not in low


def test_bulk_explanation_is_disabled_by_a_zero_cap(monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "AI_MAX_FINDING_EXPLANATIONS", 0)
    findings = [{"title": "f", "severity": "critical"}]
    assert ai_analysis.explain_findings_bulk(findings) == 0
    assert "explanation" not in findings[0]


def test_bulk_explanation_skips_findings_that_already_have_one(monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "AI_MAX_FINDING_EXPLANATIONS", 5)
    monkeypatch.setattr(ai_analysis.settings, "AI_EXPLANATION_CONCURRENCY", 1)
    monkeypatch.setattr(ai_analysis, "explain_finding", lambda f: "fresh")

    findings = [{"title": "f", "severity": "high", "explanation": "already here"}]
    assert ai_analysis.explain_findings_bulk(findings) == 0
    assert findings[0]["explanation"] == "already here"


# ── Status reporting ────────────────────────────────────────────────────────

def test_status_reports_ollama_when_it_is_up(monkeypatch):
    monkeypatch.setattr(ai_analysis.settings, "AI_PROVIDER", "auto")
    monkeypatch.setattr(ai_analysis.settings, "OLLAMA_MODEL", "")
    monkeypatch.setattr(ai_analysis, "_ollama_models", lambda: ["llama3.1:8b"])
    status = ai_analysis.ai_status()
    assert status["active_backend"] == "ollama"
    assert status["model"] == "llama3.1:8b"


def test_status_reports_fallback_and_explains_why(monkeypatch):
    _offline(monkeypatch)
    status = ai_analysis.ai_status()
    assert status["active_backend"] == "fallback"
    assert status["ollama"]["available"] is False
    assert status["ollama"]["error"]
