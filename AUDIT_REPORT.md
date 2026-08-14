# ReconTitan v0.3.0 Security and Functionality Audit

**Audit date:** July 24, 2026
**Scope:** uploaded `ReconTitan-master.zip`, compared with the public `master` repository snapshot
**Method:** manual code review, threat modeling, targeted code changes, automated tests, static searches, and configuration syntax validation

## Executive result

The reviewed project had useful defensive middleware and modular scanners, but it was not safe to describe as fully production-ready. The most important gaps were server-side request forgery exposure, no production authentication for a publicly reachable scanner, blocking work on the async event loop, overly privileged database access, duplicate routes/body handling, misleading or duplicated scanner behavior, and deployment/configuration defects.

The revised project materially improves those areas and adds the five requested features. The local automated suite passes, and the application/Nginx/frontend/deployment syntax checks pass. This does **not** prove that every external integration, container image, optional scanner binary, or live target behavior works in every environment; those limits are listed below.

## Requested features implemented

### PDF report export

- `POST /api/report/pdf` renders browser-supplied results without persisting them.
- `GET /api/scan/{scan_id}/report.pdf` renders stored scan data.
- Filenames are sanitized against path traversal and unsafe characters.
- Report text is escaped, bounded, paginated, and includes severity summary, executive summary, evidence, and remediation.
- Responses use `application/pdf`, `nosniff`, and `no-store`.

### Subdomain takeover checks

- Enumerates certificate-derived subdomains with a configured cap.
- Resolves CNAMEs and matches known SaaS provider suffixes.
- Raises a high-severity candidate only for provider CNAME NXDOMAIN or a known unclaimed-resource HTTP fingerprint.
- Inconclusive DNS failures remain informational to reduce false positives.
- Findings explicitly require manual provider-side verification.

### JavaScript file analysis

- Downloads only bounded, same-origin JavaScript assets.
- Caps file count, bytes per file, inline script count, and page size.
- Detects risky DOM/JavaScript sinks, likely API endpoints, and source-map references.
- Detects common secret formats but never returns the raw secret; evidence contains only a short SHA-256 fingerprint.

### Favicon hash lookup

- Discovers declared icons or falls back to `/favicon.ico`.
- Generates MD5, SHA-256, and Shodan-compatible signed MurmurHash3.
- Optionally queries Shodan count data when a key is configured.
- Uses the safe outbound client for target-host fetches.

### Technology stack detection

- Uses headers, HTML metadata, cookies, and referenced assets.
- Detects common servers, frameworks, CMS platforms, CDNs, analytics, and frontend libraries.
- Separately flags server/framework version disclosure.
- Feeds detected product names into NVD keyword candidate lookup instead of incorrectly searching by domain name.

## Security defects fixed

### Critical/high impact

1. **Outbound SSRF and DNS rebinding** — Target requests could reach private/loopback resources. Public targets are now validated at submission and worker execution. Target HTTP requests pin validated IPs, preserve TLS hostname verification, revalidate redirects, and enforce download limits.
2. **Unauthenticated production scanner** — Production now requires a random API access key. Protected endpoints accept `X-ReconTitan-Key` or Bearer authentication. Invalid key attempts are rate limited.
3. **MongoDB root application access** — The application now uses a dedicated `readWrite` user for only the ReconTitan database. Root credentials stay in the Mongo container.
4. **Broad secret exposure between containers** — Removed Compose `env_file` inheritance and explicitly scoped environment variables. The Celery worker does not receive the browser API key or application secret.
5. **Blocking scanner in `async def` route** — Blocking quick-scan, PDF, verification, and PyMongo-backed routes are synchronous FastAPI handlers and therefore run in the thread pool.
6. **Duplicate `/api/verify` route** — Removed the placeholder route so the real implementation is unambiguous.
7. **Duplicate request-body scan** — Request bodies are read and inspected once, with a hard size cap.
8. **Unexpected public aggregator disclosure** — Removed the automatic `web-check.xyz` target submission from scan orchestration; built-in modules perform the relevant checks directly.

### Deployment and browser hardening

- Production config fails closed for weak/default secrets, missing access key, wildcard CORS, or localhost domain.
- Configuration now loads per `Settings` instance rather than frozen class attributes.
- Nginx API headers no longer disappear through `add_header` inheritance and duplicate upstream values are hidden.
- CSP no longer permits inline scripts; inline canvas logic moved to external JavaScript.
- Browser output uses HTML escaping and safe URL schemes; dynamic click handlers no longer require inline attributes.
- Nginx, API, and worker filesystems are read-only with temporary writable mounts.
- API and worker containers drop all Linux capabilities; Nginx receives only the capabilities it needs.
- Docker installation uses Docker's signed apt repository rather than piping a remote script into a root shell.
- Deployment health checks run inside the API container rather than against an unpublished host port.
- The deployment script's shell quoting and repeatability defects were corrected.
- Security headers cover HSTS, CSP, frame/content protections, referrer and permissions policy, DNS prefetch, download behavior, permitted cross-domain policy, and API cross-origin isolation controls.

### Scanner behavior and data quality

- Active Nuclei, Nikto, directory fuzzing, and SQLMap checks are opt-in and disabled by default.
- Removed duplicate port-scan execution.
- Scan type selection now controls the phases/tools actually run.
- NVD candidate lookup uses detected technologies and clearly labels matches as needing validation.
- CORS probing no longer disables TLS certificate verification.
- SSL checks connect to a validated pinned address while verifying the original hostname.
- WAF detection no longer invokes an uncontrolled target subprocess in the default path.
- Pydantic mutable defaults were replaced with factories.
- MongoDB now has a unique `scan_id` index plus status, target, and date indexes.
- Error responses are sanitized and stack traces remain server-side.

## Verification performed

| Check | Result |
|---|---|
| Python automated suite | **35 passed** |
| Python bytecode compilation | Passed |
| Frontend JavaScript syntax (`node --check`) | Passed for both scripts |
| Deployment shell syntax (`bash -n`) | Passed |
| Nginx configuration syntax with temporary certificate/root/upstream | Passed |
| Compose YAML structure and required hardening fields | Passed |
| Private/loopback target rejection | Automated pass |
| Safe redirect and response-size behavior | Automated pass |
| API-key enforcement and invalid-key rate limiting | Automated pass |
| Injection, hidden paths, scanner UA, dangerous headers | Automated pass |
| Security response headers and CSP | Automated pass |
| PDF generation, escaping, large evidence, filename sanitization | Automated pass |
| JavaScript secret redaction and analysis helpers | Automated pass |
| Favicon MurmurHash implementation | Automated pass |
| Takeover provider/fingerprint logic | Automated pass |
| Production configuration fail-closed behavior | Automated pass |

CI is configured to repeat compilation/tests/syntax validation and additionally run `pip-audit`, Bandit, and `docker compose config`. Dependabot monitors Python, GitHub Actions, and Docker dependencies.

## Controls verified as applied

- Target syntax, DNS, and public-address validation
- Redirect revalidation and TLS hostname validation
- Request-body size limiting
- Query/body injection screening for network-dispatch fields
- Three-tier process-local rate limiting and temporary blocking
- Production API access key
- Explicit CORS and trusted hosts
- Production docs disabled
- Global sanitized exception handling
- Scanner user-agent and dangerous routing-header blocking
- Security headers on normal and early-exit responses
- Server framework header suppression
- Browser output encoding and safe link schemes
- Non-root API/worker image user
- Read-only filesystems and dropped capabilities
- Separate Mongo root/application users
- Secret files excluded from Git
- CI dependency/static checks

## Known limitations and residual risk

1. **No live arbitrary-target end-to-end scan was performed.** That would require explicit authorization and stable internet access to the selected target.
2. **Docker images were not built or started in this execution environment.** Compose structure and Nginx configuration were validated, but runtime image/tool compatibility still needs a staging deployment.
3. **`pip-audit` and Bandit were configured in CI but were not installed locally in this environment.** The local Python environment also contains unrelated packages, so its `pip check` output is not evidence about the clean ReconTitan requirements set.
4. **Optional API integrations were not exercised** because credentials were not provided.
5. **Optional CLI scanners may not be present in the base image.** Missing integrations fail soft. Active tools are intentionally disabled until explicitly enabled and installed.
6. **Rate limiting is in-memory and per API process.** A horizontally scaled deployment needs a shared Redis/gateway limiter.
7. **The production API key is one shared secret.** It does not provide individual users, roles, revocation history, or per-user audit logs.
8. **Heuristic findings require validation.** Stack fingerprints, takeover indicators, source-map exposure, secret patterns, and NVD keyword matches can produce false positives or incomplete results.
9. **External intelligence services receive target indicators** when their integrations are enabled. Operators must review privacy, terms, and authorization.
10. **Container image tags and GitHub Action major tags are not digest/SHA pinned.** Dependabot reduces staleness, but high-assurance deployments should pin and regularly rotate verified digests/commit SHAs.
11. **Mongo initialization scripts run only on a new volume.** Existing deployments need a documented migration to create the application user.

## Overall assessment

The revised code is substantially safer and more coherent than the uploaded baseline, and the requested features are integrated into both scan orchestration and the report UI. It is suitable for staging and controlled authorized testing. A production release should still complete a fresh Docker build, CI dependency audit, staging deployment, and authorized end-to-end scan before public exposure.

---

## v0.4.0 Follow-up - July 24, 2026

The enhanced release added professional PDF reporting, conservative subdomain takeover detection, bounded JavaScript analysis, favicon hashing, technology-stack detection, selectable scan profiles, and a redesigned UI.

Additional controls implemented during the follow-up review:

- Security middleware moved outermost so headers and request correlation wrap early trusted-host failures.
- Duplicate/conflicting HTTP request framing is rejected.
- JSON-only endpoints enforce JSON content types.
- PDF export uses a separate throttle.
- In-memory rate-limit state is periodically swept.
- Scan profile and capability metadata are centralized and exposed through `/api/capabilities`.
- Completed browser scans are reused by the report page instead of triggering an unintended second scan.

Validation: 41 backend tests passed at the time of the follow-up implementation, followed by a final release test run documented in the delivery summary.
