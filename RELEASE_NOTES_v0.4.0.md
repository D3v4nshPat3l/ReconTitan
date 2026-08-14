# ReconTitan 0.4.0 - Enhanced Assessment and Reporting

Release date: July 24, 2026

## Highlights

- Professional server-side PDF reports with cover, severity dashboard, methodology, tool coverage, findings, remediation, and limitations.
- Conservative subdomain takeover detection using certificate discovery, CNAME provider correlation, NXDOMAIN evidence, and unclaimed-service fingerprints.
- Bounded same-scope JavaScript analysis with redacted secret fingerprints, risky DOM sinks, endpoints, and source maps.
- Favicon MD5, SHA-256, and Shodan-compatible MurmurHash3 generation with optional correlation.
- Multi-signal technology stack and version-disclosure detection.
- Selectable full, recon-only, OSINT-only, and vulnerability-focused scan profiles.
- Public `/api/capabilities` metadata endpoint.
- Premium responsive dashboard and report interface.

## Security improvements

- Corrected middleware order so security headers wrap trusted-host and CORS responses.
- Added request IDs and framing checks.
- Added strict content-type handling on JSON-only routes.
- Added a dedicated PDF export throttle and bounded rate-limiter cleanup.
- Preserved safe public-target validation, DNS rebinding resistance, bounded downloads, and non-root deployment.

## Important behavior

Intrusive tools remain disabled until `ENABLE_ACTIVE_VULN_TOOLS=true`. Results from takeover, technology, CVE, and AI modules require manual validation. Use only on authorized targets.
