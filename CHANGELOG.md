# Changelog

All notable ReconTitan changes are documented here.

## [Unreleased]

## [0.5.0] - 2026-08-19


### Added

- `API_ACCESS_KEYS` — named API keys (`label:secret,label:secret`) alongside the existing single `API_ACCESS_KEY`, which is unchanged and recorded as `default`. The label is an audit handle, not a privilege: it gives attribution (`api_caller` on every audit record) and independent revocation, so a leaked credential no longer forces every consumer to rotate the one shared secret.
- `mongo/migrate-existing-deployment.js` — idempotent migration creating the least-privilege application user on a deployment whose volume predates the init script. Mongo runs `/docker-entrypoint-initdb.d` only on an empty data directory, so those deployments were silently still running as the Mongo root user.

- Local AI narration through **Ollama** (`AI_PROVIDER`, `OLLAMA_BASE_URL`, `OLLAMA_MODEL`). The scanners stay pure Python — the model only explains findings they already produced. `AI_PROVIDER=auto` prefers a local model, falls back to OpenAI when keyed, and falls back again to built-in static text, so a scan never fails because AI is unavailable. With `ollama`, finding text never leaves the host.
- `GET /api/ai/status`, `POST /api/ai/explain` (explain a security topic or scan category), and `POST /api/ai/explain-finding`. The report page shows which backend answered, so a canned fallback is never mistaken for a model's judgement.
- An **Explain this topic** button in the finding modal, teaching the concept behind a finding rather than restating it.
- `ALLOW_HACKERTARGET` (default `false`) gating the two calls to `api.hackertarget.com`.
- Per-scan AI narration budget: `AI_MAX_FINDING_EXPLANATIONS`, `AI_EXPLANATION_BUDGET_SECONDS`, `AI_EXPLANATION_CONCURRENCY`. A slow local model cannot hold a synchronous scan open.
- Test coverage for the previously untested scanner modules — security headers, cookies, CORS, robots/sitemap, WAF detection, crt.sh, DNS, HTTP probing, Wayback, TLS analysis, threat intelligence, and username OSINT — plus the AI endpoints. 428 tests, up from 323.

- **Danger Mode** (`scan_type=danger`), a bounded intermediate penetration-test simulation profile that runs the recon, OSINT, and vulnerability groups plus a staged active-testing pipeline mapped to the OWASP Top 10 (2021).
- Two-step opt-in gate: `ALLOW_DANGER_MODE` (default `false`) plus a constant-time typed acknowledgement (`I am authorized`), enforced in the routers and re-checked inside the Celery task. Requests are rejected with 403 otherwise.
- Danger stages: detailed recon with bounded subdomain brute-forcing, DNS AXFR zone-transfer attempts, attack-surface inventory, SQL/command/HTML/XSS/SSTI/XXE/NoSQL/SSRF injection probing, directory fuzzing, encoded path traversal, IDOR differential enumeration, reverse-shell possibility assessment, and the OWASP coverage matrix.
- `DangerBudget`: a shared request/payload ceiling with inter-request pacing and exponential backoff on `429`/`503`, so no module can exceed its bounds.
- New Pydantic models `AttackSurfaceItem`, `InjectionTestResult`, `OwaspCoverageEntry`, and `DangerModeSummary`; findings gained `requires_manual_validation`, `owasp_category`, `attack_vector`, `confidence`, and `affected_asset`.
- Danger Mode section in the PDF report (manual-validation banner, execution summary, OWASP coverage matrix, attack-surface inventory, injection matrix, danger check results) and matching dashboard report cards.
- Frontend Danger Mode profile card with a checkbox plus typed-confirmation gate and danger-stage progress telemetry.
- `RATE_LIMIT_DANGER` application ceiling and a dedicated Nginx `scan` rate-limit zone for scan dispatch.
- `SECURITY.md` and `docs/DANGER_MODE.md` covering authorization requirements, safety bounds, and result interpretation.
- Unit and end-to-end Danger Mode tests, including a local fixture server so no test contacts an external host.

### Changed

- `POST /api/verify` now returns a triage verdict (`TRUE_POSITIVE` / `LIKELY_TRUE_POSITIVE` / `NEEDS_MANUAL_REVIEW` / `LIKELY_FALSE_POSITIVE`) with a confidence level, instead of an unconditional `verified: true`. Verdicts outside that set are normalised to `NEEDS_MANUAL_REVIEW`. It remains an explanation pass over recorded evidence — it does not re-test the target.
- `subfinder` and `amass` report **"Not Installed — Enumeration Skipped"** instead of returning nothing, matching what `theHarvester` already did. Silence was indistinguishable from "this target has no subdomains".
- The port scan reports **"Port Scan Did Not Run"**, naming the actual cause, rather than implying no ports are open when nothing ran.

- `safe_request` now accepts bounded `POST` with a body, keeping destination pinning, redirect revalidation, and response-size limits; redirects drop the body per browser convention.
- Celery routes `run_danger_scan` to a dedicated `danger` queue, and the Compose worker consumes it.
- Recon and OSINT tools run concurrently (`SCAN_TOOL_CONCURRENCY`, default 8). They are independent and network-bound, so a phase previously cost the sum of every tool's timeout. Danger stages still run sequentially because each feeds the next.
- `safe_request` reuses keep-alive connections per pinned destination (`HTTP_POOL_MAX_IDLE`) and caches validated DNS resolutions briefly (`DNS_CACHE_TTL_SECONDS`). Repeat requests to one host measured 16x faster; an `example.com` danger scan went from 253s to 65s for identical work. Pool keys include the resolved address and the hostname used for SNI and certificate verification, so a reused connection is always the destination that was validated.

### Fixed

- **`sitemap.xml` analysis never worked on any deployment.** It parsed with `BeautifulSoup(text, "xml")`, which requires `lxml` — a dependency that was never declared in `requirements.txt`. The resulting `FeatureNotFound` was swallowed by the surrounding `except Exception`, so the parser threw on every scan and logged only at debug level. It now uses `lxml` when present and stdlib `html.parser` otherwise.
- **HTML error pages were parsed as `robots.txt`.** The content-type gate tested `"text" in Content-Type`, which also matches `text/html`, so a host answering `/robots.txt` with a 200 HTML error page produced a finding reading "robots.txt Analyzed — 0 Disallow entries". Now gated on `text/plain`.
- `.env.example` shipped `ALLOW_DANGER_MODE=true`, contradicting the code default, the README, and `deploy.sh`. Copying it — the documented setup step — silently enabled intrusive active scanning.
- `waf_detect` was declared as requiring the `wafw00f` binary, but `run_wafw00f` only matches response headers and never spawns a process. `GET /api/capabilities` therefore reported a fully working module as unavailable.

- **Danger Mode never completed on Linux/Docker deployments.** `orchestrate_scan` runs every phase inline in one Celery task, but that task inherited the *per-tool* `task_time_limit` of 900s while the danger profile's worst case is roughly 3400s. The worker hard-killed the scan partway through — frequently during recon or OSINT, before any danger stage ran. Because a signal kill bypasses the `except` block, the scan was left at `status: running` with no error. The orchestrator now gets its own ceiling derived from the phase budgets, and a soft-limit handler records the failure so a stopped scan reports why instead of hanging. This did not reproduce on Windows dev boxes, which use the synchronous `/api/test-scan` path and never involve Celery.
- A scan stopped by the time limit is no longer redelivered to another worker, which previously could restart the full scan against the target indefinitely.
- `DANGER_MAX_SCAN_SECONDS` is now passed to the `api` and `worker` services. It was documented in `.env.example` but never wired into Compose, so setting it had no effect on Linux and the danger phase was pinned to the 240s default.

### Security

- **`api.hackertarget.com` received the target address on every recon scan**, from the port-scan fallback and the reverse-IP lookup — with no API key, no configuration flag, and no mention in the documentation. Authorization to scan a host does not extend to disclosing it to an unrelated service. Both calls are now behind `ALLOW_HACKERTARGET`, default off. This is the same class of issue as the automatic `web-check.xyz` submission removed in 0.3.0.
- Every keyless third-party service a default scan contacts (`crt.sh`, `ipinfo.io`, `web.archive.org`, `api.hackertarget.com`) is now documented in the README and `.env.example`.

- Danger Mode never creates, modifies, or deletes target data, never performs credential stuffing, never connects a reverse shell, never contacts third-party hosts, and fingerprints rather than stores response bodies, object contents, and secrets. Every danger finding is labelled a candidate requiring manual validation.

## [0.4.1] - 2026-07-24

### Changed

- Rebuilt PDF reports with a compact risk cover, scan timeline, severity cards, methodology, module coverage, color-coded findings index, structured metadata, risk context, manual validation steps, clickable references, and appendices.
- Normalized WHOIS datetime, list, and nested values so reports no longer expose raw Python representations.
- Replaced fragile evidence paragraphs with structured key/value tables or safely wrapped preformatted blocks.
- Reduced browser export payload size by sending only fields used by the PDF renderer.

### Fixed

- Corrected low-contrast severity badges in PDF index tables.
- Prevented long evidence values and URLs from crossing page margins.
- Reduced unnecessary blank pages and forced whitespace around finding and appendix sections.
- Added report generation timing and content-length response headers for export diagnostics.

## [0.4.0] - 2026-07-24

### Added

- Professional PDF report generator and stored-scan/browser export endpoints.
- Subdomain takeover, JavaScript file, favicon hash, and technology stack analysis.
- Full, recon-only, OSINT-only, and vulnerability-focused scan profiles.
- Public `/api/capabilities` metadata endpoint.
- Architecture, workflow, and hero SVG assets.
- Beginner Windows, Docker, API, troubleshooting, and GitHub publishing documentation.
- Security and profile regression tests.

### Changed

- Upgraded dashboard and report UI for responsive high-density displays.
- Expanded synchronous scans to honor profiles and optional intelligence integrations.
- Improved PDF methodology, tool coverage, finding presentation, remediation, and limitations.
- Corrected report navigation to reuse a completed browser result rather than immediately rerunning the scan.
- Centralized canonical capability and tool-profile metadata.

### Security

- Corrected middleware order so the security layer is outermost.
- Added request IDs, framing validation, strict JSON content types, export-specific rate limiting, and rate-limiter memory cleanup.
- Kept active vulnerability tools opt-in and takeover detection conservative.

### Fixed

- Removed the duplicate `/api/verify` route stub.
- Removed duplicate POST-body scanning.
- Replaced wildcard CORS examples with explicit local origins.
- Added missing `INTELX_API_KEY` configuration.
- Excluded internal project-plan files from release tracking.

## [0.3.0] - 2026-07-23

- Initial hardened external-assessment release and security review.
