# Changelog

All notable ReconTitan changes are documented here.

## [Unreleased]

### Added

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

- `safe_request` now accepts bounded `POST` with a body, keeping destination pinning, redirect revalidation, and response-size limits; redirects drop the body per browser convention.
- Celery routes `run_danger_scan` to a dedicated `danger` queue, and the Compose worker consumes it.

### Security

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
