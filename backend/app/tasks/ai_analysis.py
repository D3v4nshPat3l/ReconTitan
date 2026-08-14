"""
ReconTitan — AI Analysis Module

Uses OpenAI GPT to:
  1. Generate human-readable executive summaries of scan findings
  2. Provide plain-English explanations of each vulnerability
  3. Suggest specific remediation steps per finding

Falls back gracefully if OPENAI_API_KEY is not set.
"""

import logging
import json
from app.config import settings

logger = logging.getLogger("recontitan.ai")


def _build_findings_text(findings: list[dict], target: str) -> str:
    """Format findings into a compact text block for the prompt."""
    if not findings:
        return "No vulnerabilities or issues found."

    lines = []
    for i, f in enumerate(findings[:25], 1):   # cap at 25 to stay in context
        sev  = f.get("severity", "info").upper()
        name = f.get("title") or f.get("check") or f.get("tool", "Finding")
        desc = f.get("description") or f.get("value") or ""
        lines.append(f"{i}. [{sev}] {name}: {str(desc)[:200]}")
    return "\n".join(lines)


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
        "Be concise, precise, and actionable. Use plain language — no marketing fluff."
    )
    user = f"""Scan target: {target}

Findings summary:
- Total issues: {total}
- Critical: {critical}, High: {high}, Medium: {sev_counts.get('medium',0)}, Low: {sev_counts.get('low',0)}

Detailed findings:
{findings_text}

Write a JSON response with these exact keys:
{{
  "executive_summary": "2-3 sentence overview of the security posture",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|CLEAN",
  "top_recommendations": ["action 1", "action 2", "action 3"]
}}"""

    raw = _call_openai(system, user, max_tokens=500)
    if raw:
        try:
            # Extract JSON from response
            start = raw.find("{")
            end   = raw.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(raw[start:end])
        except Exception as e:
            logger.warning("Failed to parse AI summary JSON: %s", e)

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
    }


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
        "go wrong and how to fix it. Max 3 sentences."
    )
    user = f"Explain this security finding in plain English:\nTitle: {title}\nSeverity: {sev}\nDetails: {desc[:300]}"

    result = _call_openai(system, user, max_tokens=200)
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


def verify_finding(finding: dict, target: str) -> dict:
    """
    AI-powered verification and remediation advice for a specific finding.
    """
    title = finding.get("title") or finding.get("check") or "Unknown Finding"
    sev   = finding.get("severity", "info")
    desc  = finding.get("description") or finding.get("value") or ""

    system = (
        "You are a senior penetration tester providing remediation advice. "
        "Be specific, actionable, and reference real standards (OWASP, NIST, CVE)."
    )
    user = f"""Target: {target}
Finding: {title}
Severity: {sev}
Details: {desc[:400]}

Provide a JSON response:
{{
  "verified": true,
  "explanation": "plain-English explanation of what this means (2 sentences)",
  "impact": "what an attacker could do with this (1 sentence)",
  "remediation": "specific fix steps as a list",
  "references": ["OWASP link or standard"]
}}"""

    raw = _call_openai(system, user, max_tokens=400)
    if raw:
        try:
            start = raw.find("{")
            end   = raw.rfind("}") + 1
            if start != -1 and end > start:
                return json.loads(raw[start:end])
        except Exception:
            pass

    # Fallback
    return {
        "verified": True,
        "explanation": explain_finding(finding),
        "impact": "Could allow unauthorized access or information disclosure.",
        "remediation": ["Review the finding details", "Apply the relevant security patch or configuration fix", "Re-scan after remediation"],
        "references": ["https://owasp.org/www-project-top-ten/"],
        "ai_available": False,
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
