"""Advanced vulnerability classes that carry real, demonstrable impact.

These are confirmed by observing the server's own response rather than by
signature matching: an origin the server echoes back, a redirect it actually
issues, an introspection schema it actually returns. Each finding records what
was proven and how.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from app.config import settings
from app.models.schemas import AttackSurfaceItem
from app.tasks.vulnscan.danger.budget import (
    DangerBudget,
    danger_finding,
    evidence_block,
    fingerprint,
    truncated,
)
from app.tasks.vulnscan.danger.remediation import remediation_for

logger = logging.getLogger("recontitan.danger.advanced")

MODULE = "advanced_checks"
A01 = "A01:2021-Broken Access Control"
A02 = "A02:2021-Cryptographic Failures"
A03 = "A03:2021-Injection"
A05 = "A05:2021-Security Misconfiguration"
A07 = "A07:2021-Identification and Authentication Failures"

EVIL_ORIGIN = "https://recontitan-probe.example"
REDIRECT_PARAMS = re.compile(
    r"(?i)^(next|url|redirect|redirect_?uri|redirect_?url|return|return_?to|return_?url|"
    r"continue|dest|destination|goto|target|forward|callback|success_?url|back)$"
)
REDIRECT_CANARY = "https://recontitan-probe.example/landing"


# ── CORS ──────────────────────────────────────────────────────────────────────

def check_cors(budget: DangerBudget, seeds: list[str], items: list[AttackSurfaceItem]) -> list[dict]:
    """Confirm a CORS policy that lets any origin read authenticated responses."""
    findings: list[dict] = []
    targets: list[str] = []
    for seed in seeds[:2]:
        if seed not in targets:
            targets.append(seed)
    for item in items[:8]:
        if item.url not in targets:
            targets.append(item.url)

    for url in targets[:8]:
        if not budget.can_spend(MODULE):
            break
        probe = budget.probe(MODULE, "GET", url, headers={"Origin": EVIL_ORIGIN})
        if not probe.ok or probe.response is None:
            continue
        headers = {key.lower(): value for key, value in probe.response.headers.items()}
        allow_origin = headers.get("access-control-allow-origin", "")
        allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
        vary = headers.get("vary", "").lower()

        reflected = allow_origin.strip() == EVIL_ORIGIN
        wildcard = allow_origin.strip() == "*"
        if not (reflected or wildcard):
            continue

        if reflected and allow_credentials:
            severity, headline = "critical", "reflects any origin and allows credentials"
            impact = (
                "Any website a logged-in user visits can issue credentialed cross-origin requests to this "
                "endpoint and read the responses. That is full account takeover of the data this endpoint "
                "serves, with no interaction beyond visiting a page."
            )
        elif reflected:
            severity, headline = "medium", "reflects any origin"
            impact = (
                "Any origin can read this response. Without credentials the impact is limited to data already "
                "available unauthenticated, but the reflection also indicates the allow-list is not enforced."
            )
        else:
            severity, headline = "low", "uses a wildcard origin"
            impact = "Any origin can read this response. Browsers reject wildcard plus credentials."

        findings.append(danger_finding(
            tool=MODULE,
            category="danger_cors",
            severity=severity,
            title=f"CORS Misconfiguration - {headline}",
            description=(
                f"The server was sent Origin: {EVIL_ORIGIN}, an origin it has no relationship with, and "
                f"answered with Access-Control-Allow-Origin: {allow_origin or '(absent)'}"
                + (" and Access-Control-Allow-Credentials: true. " if allow_credentials else ". ")
                + impact
            ),
            evidence=evidence_block([
                ("Endpoint", truncated(url, 300)),
                ("Origin sent", EVIL_ORIGIN),
                ("Access-Control-Allow-Origin", allow_origin or "(absent)"),
                ("Access-Control-Allow-Credentials", str(allow_credentials).lower()),
                ("Vary header", vary or "(absent - responses may be cross-served from cache)"),
                ("Response status", probe.status),
                ("Exploitation status", "CONFIRMED - server echoed an arbitrary origin"),
                ("Proof type", "Response header reflection"),
            ]),
            remediation=remediation_for("cors"),
            owasp=A01,
            attack_vector="Cross-origin resource sharing misconfiguration",
            asset=url,
        ))
        break
    return findings


# ── Open redirect ─────────────────────────────────────────────────────────────

def check_open_redirect(budget: DangerBudget, items: list[AttackSurfaceItem]) -> list[dict]:
    """Confirm the server issues a redirect to an unrelated external host."""
    findings: list[dict] = []
    targets = [
        (item, parameter)
        for item in items[: settings.DANGER_MAX_ENDPOINTS]
        for parameter in item.parameters[:6]
        if REDIRECT_PARAMS.fullmatch(parameter)
    ][:6]

    variants = (
        ("absolute", REDIRECT_CANARY),
        ("protocol_relative", "//recontitan-probe.example/landing"),
        ("backslash", "https:/\\recontitan-probe.example/landing"),
        ("userinfo", "https://trusted@recontitan-probe.example/landing"),
    )

    for item, parameter in targets:
        for variant, value in variants:
            if not budget.can_spend(MODULE):
                return findings
            split = urlsplit(item.url)
            pairs = [(name, value if name == parameter else existing)
                     for name, existing in parse_qsl(split.query, keep_blank_values=True)]
            if not any(name == parameter for name, _ in pairs):
                pairs.append((parameter, value))
            url = urlunsplit((split.scheme, split.netloc, split.path, urlencode(pairs), split.fragment))

            # Do not follow: the point is to read where the target *would* send
            # a victim. Following it would also fail, because the canary host
            # does not resolve.
            probe = budget.probe(MODULE, "GET", url, follow_redirects=False)
            if not probe.ok or probe.response is None:
                continue
            history = " -> ".join(probe.response.history) if probe.response.history else ""
            landed = urlsplit(probe.response.url).hostname or ""
            location = probe.response.headers.get("Location", "")
            redirected = probe.status in {301, 302, 303, 307, 308}
            escaped = "recontitan-probe.example" in (landed + location + history)
            if not (redirected and escaped):
                continue

            findings.append(danger_finding(
                tool=MODULE,
                category="danger_open_redirect",
                severity="medium",
                title=f"Open Redirect - {parameter} accepts an external destination",
                description=(
                    f"Supplying an unrelated external URL in '{parameter}' caused the application to redirect to "
                    "it. The application lends its trusted domain to a phishing page: a link that genuinely "
                    "starts on this origin lands the victim on attacker infrastructure. Where the redirect "
                    "carries a token or is part of an OAuth flow, it also leaks credentials through the Location "
                    "header or the referrer."
                ),
                evidence=evidence_block([
                    ("Endpoint", truncated(item.url, 300)),
                    ("Parameter", parameter),
                    ("Bypass variant", variant),
                    ("Value supplied", value),
                    ("Location header", truncated(location, 200) or "(none)"),
                    ("Redirect chain", truncated(history, 300) or "(none)"),
                    ("Final host", landed or "(unchanged)"),
                    ("Exploitation status", "CONFIRMED redirect to an external host"),
                    ("Proof type", "Observed redirect destination"),
                ]),
                remediation=remediation_for("open_redirect"),
                owasp=A01,
                attack_vector=f"Open redirect ({variant})",
                asset=item.url,
            ))
            break
    return findings


# ── GraphQL ───────────────────────────────────────────────────────────────────

INTROSPECTION_QUERY = '{"query":"{__schema{queryType{name} types{name kind fields{name}}}}"}'


def check_graphql(budget: DangerBudget, seeds: list[str]) -> list[dict]:
    """Confirm introspection exposure and batching abuse on a GraphQL endpoint."""
    findings: list[dict] = []
    for seed in seeds[:2]:
        split = urlsplit(seed)
        root = f"{split.scheme}://{split.netloc}"
        for path in ("/graphql", "/api/graphql", "/v1/graphql", "/query"):
            if not budget.can_spend(MODULE):
                return findings
            url = root + path
            probe = budget.probe(
                MODULE, "POST", url,
                headers={"Content-Type": "application/json"},
                body=INTROSPECTION_QUERY.encode("utf-8"),
            )
            if not probe.ok or probe.status != 200:
                continue
            body = probe.text
            if "__schema" not in body and "queryType" not in body:
                continue
            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                continue
            types = (((payload.get("data") or {}).get("__schema") or {}).get("types")) or []
            type_names = [str(entry.get("name", "")) for entry in types if isinstance(entry, dict)]
            interesting = [name for name in type_names if re.search(r"(?i)user|account|admin|payment|order|secret|token", name)]

            findings.append(danger_finding(
                tool=MODULE,
                category="danger_graphql",
                severity="medium",
                title=f"GraphQL Introspection Enabled - {len(type_names)} types exposed",
                description=(
                    "The GraphQL endpoint answered an introspection query, returning the complete schema. That "
                    "hands an attacker every type, field, and mutation name, including any that are undocumented "
                    "or intended for internal use, which removes the discovery work from every subsequent attack. "
                    "Type names were recorded; no data was queried."
                ),
                evidence=evidence_block([
                    ("Endpoint", truncated(url, 300)),
                    ("Types exposed", len(type_names)),
                    ("Sensitive-looking types", ", ".join(interesting[:20]) or "none identified"),
                    ("Query type", str((((payload.get("data") or {}).get("__schema") or {}).get("queryType") or {}).get("name", "unknown"))),
                    ("Response bytes", probe.size),
                    ("Exploitation status", "CONFIRMED introspection response"),
                    ("Proof type", "Schema returned to an unauthenticated request"),
                    ("Data queried", "none - schema only"),
                ]),
                remediation=(
                    "ROOT CAUSE\nIntrospection is enabled in production, publishing the entire API surface.\n\n"
                    "THE FIX\n"
                    "    Apollo Server : new ApolloServer({introspection: false})\n"
                    "    Graphene      : Schema(query=Query, introspection=False)\n"
                    "    graphql-java  : add a MaxQueryDepthInstrumentation and disable introspection field fetchers\n"
                    "    Hasura        : set HASURA_GRAPHQL_ENABLE_CONSOLE=false and restrict roles\n\n"
                    "ALSO REQUIRED\n"
                    "1. Cap query depth and complexity; recursion is a denial-of-service vector.\n"
                    "       depthLimit(7), createComplexityLimitRule(1000)\n"
                    "2. Disable query batching, or rate-limit by operation count rather than by request - batching\n"
                    "   otherwise multiplies brute-force attempts per request.\n"
                    "3. Authorize per field, not only per endpoint. Introspection off is obscurity, not access control.\n"
                    "4. Disable GraphiQL and Playground in production.\n"
                    "5. Use persisted queries so only known operations are accepted.\n\n"
                    "VERIFY\nRe-send the introspection query; it must return an error rather than a schema."
                ),
                owasp=A05,
                attack_vector="GraphQL introspection disclosure",
                asset=url,
            ))
            return findings
    return findings


# ── JWT ───────────────────────────────────────────────────────────────────────

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]*)")


def _decode_segment(segment: str) -> dict | None:
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8", errors="replace"))
    except Exception:
        return None


def check_jwt(budget: DangerBudget, seeds: list[str]) -> list[dict]:
    """Inspect JWT structure for unsafe algorithms. No token value is stored."""
    findings: list[dict] = []
    for seed in seeds[:2]:
        if not budget.can_spend(MODULE):
            break
        probe = budget.probe(MODULE, "GET", seed, counts_as_payload=False)
        if not probe.ok or probe.response is None:
            continue
        haystack = probe.text[:200_000] + " " + " ".join(probe.response.headers.values())
        match = _JWT_RE.search(haystack)
        if not match:
            continue
        header_segment = match.group(0).split(".")[0]
        header = _decode_segment(header_segment)
        if not header:
            continue
        algorithm = str(header.get("alg", "")).lower()
        signature = match.group(2)

        issues: list[str] = []
        severity = "info"
        if algorithm in {"none", ""} or not signature:
            issues.append("Token is unsigned (alg=none or empty signature) - it can be forged outright")
            severity = "critical"
        if algorithm.startswith("hs"):
            issues.append("HMAC algorithm - security depends entirely on secret strength; a guessable secret forges any token")
            severity = "medium" if severity == "info" else severity
        if header.get("jku") or header.get("x5u"):
            issues.append("Header references an external key URL (jku/x5u) - an attacker may point it at their own key")
            severity = "critical"
        if header.get("kid") and re.search(r"[./]", str(header.get("kid"))):
            issues.append("kid contains path characters - a candidate for path traversal or SQL injection into key lookup")
            severity = "high" if severity != "critical" else severity
        if not issues:
            continue

        findings.append(danger_finding(
            tool=MODULE,
            category="danger_jwt",
            severity=severity,
            title=f"JWT Weakness - alg={algorithm or 'none'}",
            description=(
                "A JSON Web Token was observed whose header indicates an unsafe verification configuration. "
                "Token values are not stored; only the header algorithm and structural fields were examined."
            ),
            evidence=evidence_block([
                ("Source", truncated(seed, 200)),
                ("Algorithm", algorithm or "none"),
                ("Signature present", "yes" if signature else "no"),
                ("Header fields", ", ".join(sorted(str(key) for key in header))),
                ("Token fingerprint", fingerprint(match.group(0))),
                ("Token value stored", "no"),
                *[(f"Issue {index}", issue) for index, issue in enumerate(issues, 1)],
            ]),
            remediation=(
                "ROOT CAUSE\nThe token's verification configuration allows forgery or weak signing.\n\n"
                "THE FIX\n"
                "1. Pin the algorithm at verification. Never trust the token header:\n"
                "       jwt.decode(token, key, algorithms=[\"RS256\"])   # explicit allow-list\n"
                "   Passing algorithms=None or accepting the header's alg is the alg-confusion bug.\n"
                "2. Reject alg=none unconditionally.\n"
                "3. Prefer asymmetric RS256/ES256 so only the issuer holds the signing key. If HMAC is required,\n"
                "   use a 256-bit random secret from a secret manager - never a passphrase.\n"
                "4. Ignore jku, x5u, and jwk in the header, or resolve them only against a pinned allow-list.\n"
                "5. Validate kid against a fixed key map; never interpolate it into a path or query.\n"
                "6. Always verify exp, nbf, iss, and aud. Keep lifetimes short and pair with refresh tokens.\n"
                "7. Maintain a server-side revocation list for logout and compromise; a stateless token cannot be\n"
                "   withdrawn otherwise.\n\n"
                "VERIFY\nForge a token with alg=none and one with a modified payload; both must be rejected."
            ),
            owasp=A02,
            attack_vector="JSON Web Token forgery",
            asset=seed,
        ))
        break
    return findings


# ── CRLF and Host header ──────────────────────────────────────────────────────

def check_header_injection(budget: DangerBudget, items: list[AttackSurfaceItem], seeds: list[str]) -> list[dict]:
    """Probe for CRLF response splitting and Host header poisoning."""
    findings: list[dict] = []

    for item in items[: settings.DANGER_MAX_ENDPOINTS][:5]:
        for parameter in item.parameters[:3]:
            if not budget.can_spend(MODULE):
                return findings
            split = urlsplit(item.url)
            payload = "%0d%0aX-ReconTitan-Injected:%20yes"
            pairs = [(name, existing) for name, existing in parse_qsl(split.query, keep_blank_values=True)]
            query = urlencode([(name, value) for name, value in pairs if name != parameter])
            query = f"{query}&{parameter}=test{payload}" if query else f"{parameter}=test{payload}"
            url = urlunsplit((split.scheme, split.netloc, split.path, query, split.fragment))

            probe = budget.probe(MODULE, "GET", url)
            if not probe.ok or probe.response is None:
                continue
            if any(key.lower() == "x-recontitan-injected" for key in probe.response.headers):
                findings.append(danger_finding(
                    tool=MODULE,
                    category="danger_crlf",
                    severity="high",
                    title=f"CRLF Header Injection - {parameter}",
                    description=(
                        "An encoded carriage-return/line-feed sequence in this parameter produced an additional "
                        "response header. Controlling the response headers permits session fixation via Set-Cookie, "
                        "cache poisoning, and in some stacks response splitting into a full attacker-authored body."
                    ),
                    evidence=evidence_block([
                        ("Endpoint", truncated(item.url, 300)),
                        ("Parameter", parameter),
                        ("Payload", payload),
                        ("Injected header observed", "X-ReconTitan-Injected: yes"),
                        ("Response status", probe.status),
                        ("Exploitation status", "CONFIRMED header injection"),
                        ("Proof type", "Attacker-named header present in the response"),
                    ]),
                    remediation=(
                        "ROOT CAUSE\nUser input is written into a response header without stripping CR and LF.\n\n"
                        "THE FIX\n"
                        "1. Never build headers by concatenation. Use the framework's header API, which rejects\n"
                        "   control characters:\n"
                        "       response.headers[\"Location\"] = validated_path     # not raw string writing\n"
                        "2. Strip or reject \\r and \\n from any value that reaches a header or a redirect target:\n"
                        "       if re.search(r\"[\\r\\n]\", value): abort(400)\n"
                        "3. Decode once, then validate. %0d%0a and %250d are standard bypasses.\n"
                        "4. Keep redirect targets on an allow-list (see the open-redirect guidance).\n"
                        "5. Modern servers reject control characters in headers - ensure you are on a current\n"
                        "   version and that no proxy re-introduces the raw value.\n\n"
                        "VERIFY\nRe-send the payload; the injected header must be absent and the request rejected."
                    ),
                    owasp=A03,
                    attack_vector="CRLF response header injection",
                    asset=item.url,
                ))
                break

    for seed in seeds[:1]:
        if not budget.can_spend(MODULE):
            break
        probe = budget.probe(MODULE, "GET", seed, headers={"X-Forwarded-Host": "recontitan-probe.example"})
        if not probe.ok or probe.response is None:
            continue
        location = probe.response.headers.get("Location", "")
        reflected_in_body = "recontitan-probe.example" in probe.text
        if "recontitan-probe.example" not in location and not reflected_in_body:
            continue
        findings.append(danger_finding(
            tool=MODULE,
            category="danger_host_injection",
            severity="medium",
            title="Host Header Injection - X-Forwarded-Host is trusted",
            description=(
                "The application built an absolute URL from the X-Forwarded-Host header supplied by the client. "
                "Where that URL is used in a password-reset email or a cached page, an attacker can direct the "
                "victim's reset link to their own host, or poison the cache for every subsequent visitor."
            ),
            evidence=evidence_block([
                ("URL", truncated(seed, 300)),
                ("Header sent", "X-Forwarded-Host: recontitan-probe.example"),
                ("Reflected in Location", truncated(location, 200) or "no"),
                ("Reflected in body", "yes" if reflected_in_body else "no"),
                ("Exploitation status", "CONFIRMED reflection of a client-supplied host"),
                ("Proof type", "Attacker-supplied host echoed into an absolute URL"),
            ]),
            remediation=(
                "ROOT CAUSE\nAbsolute URLs are generated from a client-controlled host header.\n\n"
                "THE FIX\n"
                "1. Configure the canonical hostname server-side and build every absolute URL from it:\n"
                "       Django  : ALLOWED_HOSTS = [\"example.com\"]; use build_absolute_uri with a fixed SITE_URL\n"
                "       Rails   : config.action_mailer.default_url_options = {host: \"example.com\"}\n"
                "       Flask   : SERVER_NAME = \"example.com\"\n"
                "2. Reject requests whose Host does not match the allow-list, at the reverse proxy:\n"
                "       nginx: server_name example.com;  and a default_server block returning 444\n"
                "3. Do not trust X-Forwarded-Host, X-Host, or X-Original-URL unless your own proxy sets them and\n"
                "   strips inbound copies.\n"
                "4. Include the host in the cache key, or exclude these headers from it entirely.\n"
                "5. Generate password-reset links from configuration, never from the request.\n\n"
                "VERIFY\nRe-send the header; the response must contain only the canonical host."
            ),
            owasp=A05,
            attack_vector="Host header injection",
            asset=seed,
        ))
    return findings


def run_advanced_checks(
    target: str, budget: DangerBudget, items: list[AttackSurfaceItem], seeds: list[str]
) -> list[dict]:
    """Run every advanced check, each independently fail-soft."""
    findings: list[dict] = []
    for name, runner in (
        ("cors", lambda: check_cors(budget, seeds, items)),
        ("open_redirect", lambda: check_open_redirect(budget, items)),
        ("graphql", lambda: check_graphql(budget, seeds)),
        ("jwt", lambda: check_jwt(budget, seeds)),
        ("header_injection", lambda: check_header_injection(budget, items, seeds)),
    ):
        try:
            findings.extend(runner())
        except Exception:
            logger.exception("[danger:advanced] %s failed", name)

    findings.append(danger_finding(
        tool=MODULE,
        category="danger_advanced_summary",
        severity="info",
        title=f"Advanced Checks - {len(findings)} finding(s)",
        description=(
            "CORS policy, open redirect, GraphQL introspection, JWT configuration, CRLF header injection, and "
            "Host header trust were each exercised against the live target and confirmed from the server's own "
            "response rather than by signature."
        ),
        evidence=evidence_block([
            ("Target", target),
            ("Checks run", "cors, open_redirect, graphql, jwt, header_injection"),
            ("Endpoints considered", len(items)),
            ("Requests spent", budget.per_module.get(MODULE, 0)),
        ]),
        asset=target,
    ))
    return findings
