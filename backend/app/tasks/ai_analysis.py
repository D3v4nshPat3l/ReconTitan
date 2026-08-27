"""
ReconTitan — AI Analysis Module

The scanners stay pure Python. This module is a *narration* layer only: it
never decides what a finding is, it only explains findings that the
deterministic scanners already produced. Every function degrades to a
hand-written fallback when no model is reachable, so a scan never fails
because AI is down.

Providers (selected by settings.AI_PROVIDER):
  ollama — local Ollama server, no API key, nothing leaves the host
  openai — hosted OpenAI
  auto   — Ollama if reachable, else OpenAI if keyed, else static text
  none   — always static text

Capabilities:
  1. Executive summary of a completed scan          (generate_scan_summary)
  2. Plain-English explanation of a single finding  (explain_finding)
  3. Verification + remediation for a finding       (verify_finding)
  4. Explanation of a security topic / category     (explain_topic)
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time

from app.config import settings

logger = logging.getLogger("recontitan.ai")

# Probe results are cached so a dead Ollama server costs one connection attempt
# per minute rather than one per finding.
_PROBE_TTL_SECONDS = 60
_probe_lock = threading.Lock()
_probe_cache: dict[str, object] = {"checked_at": 0.0, "available": False, "model": "", "error": ""}


# ── Provider: Ollama ────────────────────────────────────────────────────────

def _ollama_models() -> list[str]:
    """Return the model tags installed on the configured Ollama server."""
    import requests

    resp = requests.get(f"{settings.OLLAMA_BASE_URL}/api/tags", timeout=5)
    resp.raise_for_status()
    return [m.get("name", "") for m in resp.json().get("models", []) if m.get("name")]


def _probe_ollama(force: bool = False) -> dict:
    """Check whether Ollama is reachable and resolve which model to use.

    If OLLAMA_MODEL is unset or not installed, the first installed model is
    used instead. That keeps a working setup working when the operator has
    pulled a different model than the default.
    """
    now = time.monotonic()
    with _probe_lock:
        if not force and now - float(_probe_cache["checked_at"]) < _PROBE_TTL_SECONDS:
            return dict(_probe_cache)

        result: dict[str, object] = {"checked_at": now, "available": False, "model": "", "error": ""}
        try:
            installed = _ollama_models()
            if not installed:
                result["error"] = "Ollama is reachable but no model is pulled (run: ollama pull llama3.1:8b)"
            else:
                wanted = settings.OLLAMA_MODEL
                if wanted and wanted in installed:
                    chosen = wanted
                elif wanted and any(m.split(":")[0] == wanted.split(":")[0] for m in installed):
                    # Tag drift, e.g. configured "llama3.1" but "llama3.1:8b" installed.
                    chosen = next(m for m in installed if m.split(":")[0] == wanted.split(":")[0])
                else:
                    chosen = installed[0]
                    if wanted:
                        logger.warning(
                            "OLLAMA_MODEL=%s is not installed; falling back to %s", wanted, chosen
                        )
                result["available"] = True
                result["model"] = chosen
        except Exception as e:  # connection refused, DNS failure, timeout, bad JSON
            result["error"] = f"{type(e).__name__}: {str(e)[:160]}"

        _probe_cache.update(result)
        return dict(result)


def _call_ollama(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 800,
    json_mode: bool = False,
) -> str | None:
    """Call the local Ollama chat API. Returns text, or None if unavailable."""
    probe = _probe_ollama()
    if not probe["available"]:
        logger.debug("Ollama unavailable: %s", probe["error"])
        return None

    import requests

    payload: dict = {
        "model": probe["model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "stream": False,
        "keep_alive": settings.OLLAMA_KEEP_ALIVE,
        "options": {
            "temperature": 0.4,
            "num_predict": max_tokens,
            "num_ctx": settings.OLLAMA_NUM_CTX,
        },
    }
    # Small local models are unreliable at "reply with JSON"; Ollama's format
    # flag constrains decoding so the response is always parseable.
    if json_mode:
        payload["format"] = "json"

    try:
        resp = requests.post(
            f"{settings.OLLAMA_BASE_URL}/api/chat",
            json=payload,
            timeout=settings.OLLAMA_TIMEOUT,
        )
        resp.raise_for_status()
        content = (resp.json().get("message") or {}).get("content", "")
        return content.strip() or None
    except Exception as e:
        logger.warning("Ollama call failed: %s: %s", type(e).__name__, str(e)[:200])
        with _probe_lock:  # re-probe next time rather than trusting a stale OK
            _probe_cache["checked_at"] = 0.0
        return None


# ── Provider: OpenAI ────────────────────────────────────────────────────────

def _call_openai(system_prompt: str, user_prompt: str, max_tokens: int = 800) -> str | None:
    """Call OpenAI API. Returns text or None if unavailable."""
    if not settings.OPENAI_API_KEY:
        return None
    try:
        import openai
        client = openai.OpenAI(api_key=settings.OPENAI_API_KEY)
        resp = client.chat.completions.create(
            model=settings.OPENAI_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user",   "content": user_prompt},
            ],
            max_tokens=max_tokens,
            temperature=0.4,
        )
        return resp.choices[0].message.content.strip()
    except Exception as e:
        logger.warning("OpenAI call failed: %s", str(e)[:200])
        return None


# ── Provider dispatch ───────────────────────────────────────────────────────

def _call_llm(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 800,
    json_mode: bool = False,
) -> str | None:
    """Route a prompt to the configured provider. None means 'use the fallback'."""
    provider = settings.AI_PROVIDER

    if provider == "none":
        return None
    if provider == "ollama":
        return _call_ollama(system_prompt, user_prompt, max_tokens, json_mode)
    if provider == "openai":
        return _call_openai(system_prompt, user_prompt, max_tokens)

    # auto: prefer the local model — free, private, and not rate limited.
    result = _call_ollama(system_prompt, user_prompt, max_tokens, json_mode)
    if result:
        return result
    return _call_openai(system_prompt, user_prompt, max_tokens)


def ai_status() -> dict:
    """Report which AI backend is live. Backs GET /api/ai/status and the UI badge."""
    provider = settings.AI_PROVIDER
    status: dict = {
        "provider": provider,
        "enabled": provider != "none",
        "active_backend": "fallback",
        "model": "",
        "ollama": {
            "configured_url": settings.OLLAMA_BASE_URL,
            "configured_model": settings.OLLAMA_MODEL,
            "resolved_model": "",
            "available": False,
            "error": "",
        },
        "openai": {"configured": bool(settings.OPENAI_API_KEY), "model": settings.OPENAI_MODEL},
    }

    if provider in {"auto", "ollama"}:
        probe = _probe_ollama(force=True)
        status["ollama"]["available"] = bool(probe["available"])
        status["ollama"]["error"] = probe["error"]
        status["ollama"]["resolved_model"] = probe["model"]
        if probe["available"]:
            status["active_backend"] = "ollama"
            status["model"] = probe["model"]
            return status

    if provider in {"auto", "openai"} and settings.OPENAI_API_KEY:
        status["active_backend"] = "openai"
        status["model"] = settings.OPENAI_MODEL

    return status


def _active_backend_name() -> str:
    """Cheap backend label for response payloads (never forces a fresh probe)."""
    if settings.AI_PROVIDER == "none":
        return "fallback"
    if settings.AI_PROVIDER in {"auto", "ollama"} and _probe_cache.get("available"):
        return "ollama"
    if settings.AI_PROVIDER in {"auto", "openai"} and settings.OPENAI_API_KEY:
        return "openai"
    return "fallback"


#: Triage verdicts the UI knows how to render.
_ASSESSMENTS = {
    "TRUE_POSITIVE",
    "LIKELY_TRUE_POSITIVE",
    "NEEDS_MANUAL_REVIEW",
    "LIKELY_FALSE_POSITIVE",
}


def _normalise_assessment(value) -> str:
    """Snap a model's verdict onto the allowed set.

    Small local models paraphrase the enum — "FALSE POSITIVE", "true positive",
    "likely a true positive". Rendering those raw would make the UI look like it
    supports verdicts it does not, so anything unrecognised becomes
    NEEDS_MANUAL_REVIEW, which is the honest reading of an unclear answer.
    """
    text = str(value or "").strip().upper().replace(" ", "_").replace("-", "_")
    if text in _ASSESSMENTS:
        return text
    if "FALSE_POSITIVE" in text:
        return "LIKELY_FALSE_POSITIVE"
    if "TRUE_POSITIVE" in text:
        return "LIKELY_TRUE_POSITIVE"
    return "NEEDS_MANUAL_REVIEW"


def _normalise_confidence(value) -> str:
    """Confidence is rendered verbatim, so keep it to the three known levels."""
    text = str(value or "").strip().lower()
    return text if text in {"high", "medium", "low"} else "medium"


def _parse_json_response(raw: str | None) -> dict | None:
    """Pull the first JSON object out of a model response."""
    if not raw:
        return None
    try:
        start = raw.find("{")
        end = raw.rfind("}") + 1
        if start != -1 and end > start:
            parsed = json.loads(raw[start:end])
            return parsed if isinstance(parsed, dict) else None
    except Exception as e:
        logger.warning("Failed to parse AI JSON response: %s", e)
    return None


def _as_list(value) -> list[str]:
    """Models return lists as lists, as newline strings, or as one string."""
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str) and value.strip():
        parts = [p.strip(" -*•\t") for p in value.splitlines() if p.strip(" -*•\t")]
        return parts or [value.strip()]
    return []


def _is_scanner_notice(finding: dict) -> bool:
    """True for findings that describe the scanner, not the target.

    "subfinder Not Installed" and "Port Scan Did Not Run" are operator
    diagnostics. Fed to the model as if they were findings, they came back as
    security advice — a report for packetpulse.live recommended installing
    subfinder, which tells the reader nothing about their own posture.
    """
    title = str(finding.get("title", ""))
    return "Not Installed" in title or "Did Not Run" in title


_COUNT_CLAIM = re.compile(
    r"(\d+)\s+(critical|high|medium|low|informational|info)\b", re.IGNORECASE
)


def _contradicts_counts(text: str, sev_counts: dict) -> str:
    """Return a reason if the text states a severity count that is wrong.

    Instructing the model not to cite figures reduces this but does not stop
    it: qwen2.5:1.5b produced "5 critical, 5 high, and 5 medium issues" for a
    scan whose real counts were 0, 0 and 5, displayed directly beside it. A
    security report that contradicts its own severity bar is worse than one
    with no summary at all, so the claim is checked rather than trusted.
    """
    for match in _COUNT_CLAIM.finditer(text or ""):
        claimed = int(match.group(1))
        level = match.group(2).lower()
        if level in {"informational", "info"}:
            level = "info"
        actual = int(sev_counts.get(level, 0))
        if claimed != actual:
            return f"claimed {claimed} {level}, actual {actual}"
    return ""


def _build_findings_text(findings: list[dict], target: str) -> str:
    """Format findings into a compact text block for the prompt."""
    findings = [f for f in findings if not _is_scanner_notice(f)]
    if not findings:
        return "No vulnerabilities or issues found."

    lines = []
    for i, f in enumerate(findings[:25], 1):   # cap at 25 to stay in context
        sev  = f.get("severity", "info").upper()
        name = f.get("title") or f.get("check") or f.get("tool", "Finding")
        desc = f.get("description") or f.get("value") or ""
        lines.append(f"{i}. [{sev}] {name}: {str(desc)[:200]}")
    return "\n".join(lines)


# ── Capability 1: executive summary ─────────────────────────────────────────

def generate_scan_summary(target: str, findings: list[dict], sev_counts: dict) -> dict:
    """
    Generate an AI executive summary for a completed scan.
    Returns a dict with 'executive_summary', 'risk_level', and 'top_recommendations'.
    """
    findings_text = _build_findings_text(findings, target)
    total = sum(sev_counts.values())
    critical = sev_counts.get("critical", 0)
    high     = sev_counts.get("high", 0)

    system = (
        "You are a senior cybersecurity analyst writing reports for technical teams. "
        "Be concise, precise, and actionable. Use plain language, no marketing fluff. "
        "NEVER state how many issues were found, and never use the words critical, "
        "high, medium or low followed by a number. Those counts are displayed "
        "separately and any figure you write will contradict them. Describe what is "
        "wrong and what it means, not how much of it there is. "
        "Respond with JSON only."
    )
    user = f"""Scan target: {target}

Findings summary:
- Total issues: {total}
- Critical: {critical}, High: {high}, Medium: {sev_counts.get('medium',0)}, Low: {sev_counts.get('low',0)}

Detailed findings:
{findings_text}

Write a JSON response with these exact keys:
{{
  "executive_summary": "2-3 sentences on the security posture, with NO counts or numbers",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|CLEAN",
  "top_recommendations": ["action 1", "action 2", "action 3"]
}}"""

    parsed = _parse_json_response(_call_llm(system, user, max_tokens=500, json_mode=True))
    if parsed and parsed.get("executive_summary"):
        summary_text = str(parsed["executive_summary"]).strip()
        conflict = _contradicts_counts(summary_text, sev_counts)
        if conflict:
            # Fall through to the deterministic summary below. Silently keeping
            # a wrong figure would put a falsehood in a security report.
            logger.warning("Discarding AI summary, it contradicts the counts: %s", conflict)
            parsed = None
    if parsed and parsed.get("executive_summary"):
        return {
            "executive_summary": str(parsed["executive_summary"]).strip(),
            "risk_level": str(parsed.get("risk_level", "MEDIUM")).upper().strip(),
            "top_recommendations": [
                rec for rec in _as_list(parsed.get("top_recommendations"))[:5]
                if not _contradicts_counts(rec, sev_counts)
                and "subfinder" not in rec.lower()
                and "amass" not in rec.lower()
                and "theharvester" not in rec.lower()
            ] or _fallback_recommendations(findings),
            "ai_generated": True,
            "ai_backend": _active_backend_name(),
        }

    # Fallback: generate summary without AI
    if critical > 0:
        risk = "CRITICAL"
        summary = (
            f"{target} has {critical} critical issue(s) requiring immediate attention. "
            f"Total {total} findings detected across all scan modules."
        )
    elif high > 0:
        risk = "HIGH"
        summary = f"{target} has {high} high-severity finding(s). Review and remediate promptly. {total} total findings."
    elif total > 0:
        risk = "MEDIUM"
        summary = f"{target} shows {total} security finding(s), none critical. Review recommendations below."
    else:
        risk = "CLEAN"
        summary = f"No significant security issues detected for {target}. Continue monitoring."

    return {
        "executive_summary": summary,
        "risk_level": risk,
        "top_recommendations": _fallback_recommendations(findings),
        "ai_generated": False,
        "ai_backend": "fallback",
    }


# ── Capability 2: per-finding explanation ───────────────────────────────────

def explain_finding(finding: dict) -> str:
    """
    Generate a plain-English explanation of a single finding.
    """
    title = finding.get("title") or finding.get("check") or finding.get("tool", "Security Issue")
    sev   = finding.get("severity", "info")
    desc  = finding.get("description") or finding.get("value") or ""

    system = (
        "You are a cybersecurity expert explaining vulnerabilities to a developer "
        "who is not a security specialist. Be clear, simple, and include what could "
        "go wrong and how to fix it. Max 3 sentences. Plain prose, no markdown."
    )
    user = (
        "Explain this security finding in plain English:\n"
        f"Title: {title}\nSeverity: {sev}\nDetails: {str(desc)[:300]}"
    )

    result = _call_llm(system, user, max_tokens=200)
    if result:
        return result

    # Fallback explanations by severity
    fallbacks = {
        "critical": f"{title}: This is a critical security issue that could allow attackers to fully compromise the system. Immediate action is required.",
        "high":     f"{title}: A high-severity vulnerability that could lead to significant data exposure or system compromise if exploited.",
        "medium":   f"{title}: A medium-risk finding that should be addressed in your next security update cycle.",
        "low":      f"{title}: A low-severity issue. While not immediately dangerous, fixing it improves overall security posture.",
        "info":     f"{title}: An informational finding. No immediate action required but worth reviewing.",
    }
    return fallbacks.get(sev, f"{title}: Security finding detected. Review and address as appropriate.")


def explain_findings_bulk(findings: list[dict]) -> int:
    """Attach an ``explanation`` to the most important findings, in place.

    One explanation is one model round-trip, and a local CPU model can take
    several seconds each. So this is bounded three ways: how many findings are
    explained, how long the whole pass may take, and how many requests hit the
    model at once. Findings left unexplained keep the static text the report
    already renders — the pass degrades, it does not fail.

    Returns the number of explanations actually generated.
    """
    from concurrent.futures import ThreadPoolExecutor

    limit = settings.AI_MAX_FINDING_EXPLANATIONS
    if limit <= 0 or settings.AI_PROVIDER == "none":
        return 0

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    pending = sorted(
        (f for f in findings if not f.get("explanation") and f.get("severity") in rank),
        key=lambda f: rank.get(f.get("severity"), 9),
    )[:limit]
    if not pending:
        return 0

    deadline = time.monotonic() + settings.AI_EXPLANATION_BUDGET_SECONDS
    done = 0

    def _work(finding: dict) -> bool:
        if time.monotonic() >= deadline:
            return False
        finding["explanation"] = explain_finding(finding)
        return True

    with ThreadPoolExecutor(max_workers=settings.AI_EXPLANATION_CONCURRENCY) as pool:
        for produced in pool.map(_work, pending):
            done += int(produced)

    if done < len(pending):
        logger.info(
            "AI explanation budget exhausted: %d of %d findings explained", done, len(pending)
        )
    return done


# ── Capability 3: finding verification + remediation ────────────────────────

def verify_finding(finding: dict, target: str) -> dict:
    """
    A second opinion on one finding: what it means, what an attacker could do
    with it, how to fix it, and where to read more.

    This is an *explanation and triage* pass, not a re-test. No traffic is sent
    to the target — the model reviews the evidence the scanner already recorded
    and rates how likely it is to be a real issue rather than noise.
    """
    title = finding.get("title") or finding.get("check") or "Unknown Finding"
    sev   = finding.get("severity", "info")
    desc  = finding.get("description") or finding.get("value") or ""

    system = (
        "You are a senior penetration tester triaging a scanner finding. "
        "Judge whether the evidence supports a real issue, and give specific, "
        "actionable remediation referencing real standards (OWASP, NIST, CVE). "
        "Respond with JSON only."
    )
    user = f"""Target: {target}
Finding: {title}
Severity: {sev}
Details: {str(desc)[:400]}

Provide a JSON response:
{{
  "assessment": "TRUE_POSITIVE|LIKELY_TRUE_POSITIVE|NEEDS_MANUAL_REVIEW|LIKELY_FALSE_POSITIVE",
  "confidence": "high|medium|low",
  "explanation": "plain-English explanation of what this means (2 sentences)",
  "impact": "what an attacker could do with this (1 sentence)",
  "remediation": ["fix step 1", "fix step 2"],
  "references": ["OWASP link or standard"]
}}"""

    parsed = _parse_json_response(_call_llm(system, user, max_tokens=500, json_mode=True))
    if parsed and parsed.get("explanation"):
        return {
            "verified": True,
            "ai_available": True,
            "ai_backend": _active_backend_name(),
            "assessment": _normalise_assessment(parsed.get("assessment")),
            "confidence": _normalise_confidence(parsed.get("confidence")),
            "explanation": str(parsed["explanation"]).strip(),
            "impact": str(parsed.get("impact", "")).strip(),
            "remediation": _as_list(parsed.get("remediation")) or [
                "Review the finding details",
                "Apply the relevant security patch or configuration fix",
                "Re-scan after remediation",
            ],
            "references": _as_list(parsed.get("references")) or ["https://owasp.org/www-project-top-ten/"],
        }

    # Fallback
    return {
        "verified": True,
        "ai_available": False,
        "ai_backend": "fallback",
        "assessment": "NEEDS_MANUAL_REVIEW",
        "confidence": "low",
        "explanation": explain_finding(finding),
        "impact": "Could allow unauthorized access or information disclosure.",
        "remediation": [
            "Review the finding details",
            "Apply the relevant security patch or configuration fix",
            "Re-scan after remediation",
        ],
        "references": ["https://owasp.org/www-project-top-ten/"],
    }


# ── Capability 4: topic / category explanation ──────────────────────────────

#: Static primers used when no model is reachable. Keys are matched
#: case-insensitively against the requested topic.
_TOPIC_FALLBACKS = {
    "security headers": "HTTP security headers tell the browser how to treat your site. Missing headers such as Content-Security-Policy, Strict-Transport-Security, or X-Frame-Options leave the browser on permissive defaults, which makes clickjacking, protocol downgrade, and script injection easier to pull off.",
    "ssl": "TLS protects data in transit. Expired certificates, hostname mismatches, or obsolete protocol versions and cipher suites let an attacker on the network path read or alter traffic, and browsers will warn users away from the site.",
    "cors": "Cross-Origin Resource Sharing controls which other websites may read responses from your API. A wildcard origin, or reflecting any Origin back while allowing credentials, lets an attacker's page read authenticated responses on behalf of a logged-in victim.",
    "cookie": "Cookie flags decide how a browser stores and sends session tokens. Without Secure the cookie can travel over plain HTTP, without HttpOnly page scripts can steal it, and without SameSite it is attached to cross-site requests, enabling CSRF.",
    "subdomain takeover": "A subdomain takeover happens when a DNS record still points at a cloud service that no longer owns the resource. Anyone can then claim that resource and serve content from your domain, inheriting its trust, cookies, and reputation.",
    "dns": "DNS records map names to infrastructure and reveal how a target is hosted. They are the starting point for mapping attack surface, and misconfigurations such as open zone transfers or dangling records expose far more than intended.",
    "port": "A port scan lists the network services a host exposes. Every open port is an entry point: the fewer that are reachable from the internet, and the more current their software, the smaller the attack surface.",
    "cve": "A CVE is a public identifier for a specific known vulnerability in a specific software version. When a scan matches a detected product version to a CVE, a documented weakness — often with public exploit code — applies to that version.",
    "injection": "Injection flaws occur when untrusted input is concatenated into an interpreter such as SQL, a shell, an LDAP filter, or a template. The interpreter cannot tell data from instructions, so attacker input becomes executable, which can mean data theft or full server takeover.",
    "xss": "Cross-site scripting means attacker-controlled content is rendered as script in another user's browser. That script runs with the victim's session, so it can read page data, act as that user, or capture credentials.",
    "idor": "Insecure Direct Object Reference means an identifier in a request can be swapped for someone else's and the server returns their data. It is an authorization failure: the app authenticates the user but never checks that the record belongs to them.",
    "waf": "A Web Application Firewall inspects traffic and blocks known attack patterns. It is a useful mitigating layer but not a fix — it changes how hard an attack is, not whether the underlying flaw exists.",
    "osint": "Open Source Intelligence is information collected from public sources such as DNS, certificate transparency logs, web archives, and code repositories. No target system is touched, but it maps the attack surface an adversary sees before sending a single probe.",
}


def explain_topic(topic: str, context: str = "", audience: str = "developer") -> dict:
    """
    Explain a security topic, scan category, or tool in plain English.

    Backs the "explain this" affordance in the report UI: the user clicks a
    category or tool name and gets a teaching answer rather than raw scan data.
    """
    topic = (topic or "").strip()
    if not topic:
        return {"topic": "", "explanation": "No topic supplied.", "ai_generated": False, "ai_backend": "fallback"}

    system = (
        f"You are a security educator explaining concepts to a {audience}. "
        "Cover what the topic is, why it matters, what an attacker gains when it goes wrong, "
        "and how to address it. Use plain prose, 4-6 sentences, no markdown, no bullet points."
    )
    user = f"Explain this web-security topic: {topic}"
    if context:
        user += f"\n\nIt came up in a scan with this context:\n{context[:600]}"

    result = _call_llm(system, user, max_tokens=400)
    if result:
        return {
            "topic": topic,
            "explanation": result,
            "ai_generated": True,
            "ai_backend": _active_backend_name(),
        }

    key = topic.lower()
    for name, text in _TOPIC_FALLBACKS.items():
        if name in key:
            return {"topic": topic, "explanation": text, "ai_generated": False, "ai_backend": "fallback"}

    return {
        "topic": topic,
        "explanation": (
            f"{topic} is one of the checks ReconTitan runs against a target. "
            "Start a local Ollama model to get a full explanation of this topic — see the README "
            "section 'AI explanations (Ollama)'."
        ),
        "ai_generated": False,
        "ai_backend": "fallback",
    }


def _fallback_recommendations(findings: list[dict]) -> list[str]:
    """Generate basic recommendations from finding types when AI is unavailable."""
    recs = set()
    for f in findings:
        sev  = f.get("severity", "")
        desc = (f.get("description") or f.get("title") or "").lower()
        if "ssl" in desc or "tls" in desc:
            recs.add("Upgrade SSL/TLS to TLS 1.3 and disable weak cipher suites.")
        if "header" in desc:
            recs.add("Implement all recommended HTTP security headers (HSTS, CSP, X-Frame-Options).")
        if "cors" in desc:
            recs.add("Restrict CORS to specific trusted origins only.")
        if "cookie" in desc:
            recs.add("Set Secure, HttpOnly, and SameSite flags on all cookies.")
        if sev in ("critical", "high"):
            recs.add("Address all critical and high severity findings immediately.")
    recs.add("Enable continuous monitoring and re-scan after any infrastructure changes.")
    return list(recs)[:5]
