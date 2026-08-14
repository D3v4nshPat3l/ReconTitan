# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | Yes |
| < 0.4 | No |

## Reporting a vulnerability

Report security issues privately. Do not open a public issue for an unpatched vulnerability.

1. Open a [GitHub security advisory](https://github.com/D3v4nshPat3l/ReconTitan/security/advisories/new) on the repository, or contact the maintainer directly.
2. Include the affected version, reproduction steps, impact, and any proof-of-concept material.
3. Allow a reasonable window for a fix before public disclosure.

Please do not run active testing against infrastructure you do not own in order to demonstrate an issue in ReconTitan.

## Authorized use

ReconTitan is a security assessment tool. Running it against systems you do not own or lack written permission to test is unlawful in most jurisdictions. The operator, not the project, is responsible for every scan.

By default the platform fails closed:

- private, reserved, loopback, and non-routable targets are rejected (`ALLOW_PRIVATE_TARGETS=false`)
- intrusive third-party tools are disabled (`ENABLE_ACTIVE_VULN_TOOLS=false`)
- **Danger Mode is disabled** (`ALLOW_DANGER_MODE=false`)
- production configuration is validated at startup and refuses to boot with default secrets, wildcard CORS, or a missing API key

## Danger Mode

Danger Mode (`scan_type=danger`) is the only profile that sends active attack-simulation traffic. It carries stricter requirements than every other profile.

### Authorization requirements

Danger Mode may be used **only** when all of the following are true:

1. You own the target system, **or** you hold explicit written permission from the owner to perform active security testing against it.
2. The authorization names the target scope and covers the categories of testing Danger Mode performs (injection probing, directory and traversal fuzzing, identifier enumeration, DNS zone-transfer attempts).
3. The testing window and any rate constraints in that authorization are respected.
4. You retain the authorization record alongside the resulting report.

A bug bounty program's published scope counts as written permission only for assets and test types that program explicitly allows. Many programs prohibit automated active scanning — check before enabling.

### Two-step opt-in

Danger Mode cannot be started by accident. Both are required, and both are re-checked:

1. **Environment opt-in** — `ALLOW_DANGER_MODE=true`. While false, `/api/scan` and `/api/test-scan` reject `scan_type=danger` with HTTP 403 and an explanatory message.
2. **Typed acknowledgement** — every request must carry `danger_acknowledgement` equal to `I am authorized`, compared in constant time. The dashboard requires a checkbox plus the typed phrase before the scan button unlocks, and never restores that state from storage.

The gate is re-evaluated inside the Celery task, so a scan queued before the profile was disabled will not execute afterwards.

### Safety guarantees

Danger Mode is a **simulation**. These properties are enforced in code:

| Guarantee | How it is enforced |
|---|---|
| No data is created, modified, or deleted | All probes are read-only canaries; the only POST bodies sent are benign fixed values and one empty body for method-variation checks |
| No credential stuffing | The login rate-limit check resubmits a single fixed non-credential value; no wordlist is iterated and no account is targeted |
| No reverse shell is ever connected | Command-injection points are documented as vectors. The scanner generates no connecting payload, starts no listener, and opens no outbound channel from the target |
| No third-party hosts are contacted | SSRF probes use private/loopback canary addresses that the scanner never dereferences itself |
| No secrets are stored | Response bodies, object contents, session tokens, and credential-shaped strings are reduced to a truncated SHA-256 fingerprint |
| Bounded traffic | Hard ceilings on total requests, per-module requests, payloads, endpoints, crawl pages, and enumerated identifiers |
| Rate-limit aware | Fixed inter-request pacing plus exponential backoff when the target returns `429` or `503` |
| Never claims exploitation | Every finding sets `requires_manual_validation: true` and is worded as a candidate |
| Fail-soft | A failing stage is recorded and the remaining stages continue |

### What Danger Mode deliberately does not do

- It does not attempt out-of-band XXE by default (`DANGER_ENABLE_XXE_OOB=false`).
- It does not brute-force credentials, session tokens, or API keys.
- It does not attempt denial of service, resource exhaustion, or mass enumeration.
- It does not exfiltrate, transmit, or persist any data read from the target.
- It does not evade detection; the default user agent identifies the scanner.

### Reviewing Danger Mode output

Treat every result as a lead:

- Reproduce the exact request recorded in the evidence from an authorized test system.
- Rule out caching, load balancing, CDN behaviour, and dynamic content before accepting a differential or timing signal.
- Confirm practical impact before changing a finding to verified.
- Read a NOT TESTED OWASP category as unassessed, not as clean.

## Operational hardening

For a public deployment:

- set a unique `SECRET_KEY` and `API_ACCESS_KEY` of at least 32 random characters
- set explicit `CORS_ORIGINS`; never `*`
- keep `RECONTITAN_DEBUG=false` so API documentation stays disabled
- terminate TLS at Nginx and keep the shipped security headers
- keep `ALLOW_PRIVATE_TARGETS=false` so the scanner cannot be pointed at internal networks
- enforce shared rate limits at the edge; the built-in limiter is process-local
- restrict who can reach the API, since the access key is a shared secret rather than per-user identity

## Third-party data sharing

Optional integrations submit the target to external providers. Review each provider's privacy, authorization, and retention policy before supplying an API key.
