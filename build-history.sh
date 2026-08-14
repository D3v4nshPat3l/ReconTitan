#!/usr/bin/env bash
# Builds a structured commit history that mirrors how the project is layered.
set -e
c() { msg="$1"; shift; git add -- "$@" 2>/dev/null || true; git diff --cached --quiet || git commit -q -m "$msg"; echo "  ✓ $msg"; }

c "chore: add license and gitignore"                                LICENSE .gitignore
c "docs: add contributing guide"                                    CONTRIBUTING.md
c "feat(config): environment configuration with production validation" backend/app/config.py backend/app/__init__.py
c "feat(targeting): target normalization and SSRF defense"          backend/app/targeting.py
c "feat(http): pinned, bounded HTTP client with redirect revalidation" backend/app/tasks/http_client.py backend/app/tasks/__init__.py
c "feat(security): 27-category injection screening middleware"      backend/app/middleware
c "feat(models): Pydantic v2 request and response schemas"          backend/app/models
c "feat(db): MongoDB connection handling"                           backend/app/database.py
c "feat(queue): Celery application and queue routing"               backend/app/celery_app.py
c "feat(recon): WHOIS and DNS record enumeration"                   backend/app/tasks/recon/whois_lookup.py backend/app/tasks/recon/dns_lookup.py backend/app/tasks/recon/__init__.py
c "feat(recon): certificate transparency and archive discovery"     backend/app/tasks/recon/crtsh.py backend/app/tasks/recon/wayback.py
c "feat(recon): IP intelligence and HTTP probing"                   backend/app/tasks/recon/ipinfo.py backend/app/tasks/recon/httpx_probe.py
c "feat(recon): passive subdomain enumeration"                      backend/app/tasks/recon/subfinder_amass.py
c "feat(recon): technology stack fingerprinting"                    backend/app/tasks/recon/tech_stack.py
c "feat(recon): favicon hash correlation"                           backend/app/tasks/recon/favicon_hash.py
c "feat(recon): bounded JavaScript asset analysis"                  backend/app/tasks/recon/js_analysis.py
c "feat(recon): conservative subdomain takeover detection"          backend/app/tasks/recon/subdomain_takeover.py
c "feat(recon): port exposure scanning"                             backend/app/tasks/recon/port_scan.py
c "feat(osint): security header and TLS analysis"                   backend/app/tasks/osint/security_headers.py backend/app/tasks/osint/ssl_check.py backend/app/tasks/osint/__init__.py
c "feat(osint): CORS, cookie, and robots checks"                    backend/app/tasks/osint/cors_check.py backend/app/tasks/osint/cookie_check.py backend/app/tasks/osint/robots_sitemap.py
c "feat(osint): WAF and CDN detection"                              backend/app/tasks/osint/waf_detect.py
c "feat(osint): threat intelligence integrations"                   backend/app/tasks/osint/threat_intel.py backend/app/tasks/osint/username_osint.py
c "feat(vuln): NVD CVE candidate lookup"                            backend/app/tasks/vulnscan
c "feat(ai): AI analysis and finding explanation"                   backend/app/tasks/ai_analysis.py
c "feat(tasks): Celery scan orchestration"                          backend/app/tasks/scan_tasks.py
c "feat(services): capability and profile metadata"                 backend/app/services/capabilities.py backend/app/services/__init__.py
c "feat(api): capabilities, scans, reports, and news routers"       backend/app/routers
c "feat(api): FastAPI entry point and middleware stack"             backend/app/main.py
c "feat(report): PDF report generator"                              backend/app/services/pdf_report.py
c "feat(ui): scan console dashboard"                                frontend/index.html frontend/dashboard.css frontend/dashboard.js
c "feat(ui): interactive masonry report"                            frontend/report.html frontend/report.css frontend/report.js
c "feat(ui): static assets and news styling"                        frontend/favicon.svg frontend/robots.txt frontend/news_extras.css
c "feat(danger): opt-in gate, safety bounds, and OWASP catalogue"   backend/app/services/danger_mode.py
c "feat(danger): bounded request budget with pacing and backoff"    backend/app/tasks/vulnscan/danger/budget.py backend/app/tasks/vulnscan/danger/__init__.py
c "feat(danger): WAF-evasion payload library"                       backend/app/tasks/vulnscan/danger/payloads.py
c "feat(danger): exploitation confirmation engine"                  backend/app/tasks/vulnscan/danger/exploit.py
c "feat(danger): code-level remediation library"                    backend/app/tasks/vulnscan/danger/remediation.py
c "feat(danger): attack surface inventory"                          backend/app/tasks/vulnscan/danger/attack_surface.py
c "feat(danger): detailed recon and AXFR zone transfer attempts"    backend/app/tasks/vulnscan/danger/recon.py backend/app/tasks/vulnscan/danger/dns_axfr.py
c "feat(danger): eight injection testing classes"                   backend/app/tasks/vulnscan/danger/injection.py
c "feat(danger): DOM source-to-sink dataflow analysis"              backend/app/tasks/vulnscan/danger/dom.py
c "feat(danger): business logic flaw detection"                     backend/app/tasks/vulnscan/danger/business_logic.py
c "feat(danger): data exposure quantification"                      backend/app/tasks/vulnscan/danger/data_exposure.py
c "feat(danger): CORS, redirect, GraphQL, JWT, and header checks"   backend/app/tasks/vulnscan/danger/advanced.py
c "feat(danger): IDOR differential and directory traversal"         backend/app/tasks/vulnscan/danger/idor.py backend/app/tasks/vulnscan/danger/directory.py
c "feat(danger): reverse shell vector assessment"                   backend/app/tasks/vulnscan/danger/reverse_shell.py
c "feat(danger): OWASP Top 10 coverage matrix"                      backend/app/tasks/vulnscan/danger/owasp.py
c "feat(danger): staged pipeline coordinator with deadline guard"   backend/app/tasks/vulnscan/danger/pipeline.py
c "test: API security, targeting, and HTTP client coverage"         backend/tests/test_api_security.py backend/tests/test_targeting.py backend/tests/test_http_client.py backend/tests/conftest.py
c "test: feature, capability, and configuration coverage"           backend/tests/test_features.py backend/tests/test_capabilities.py backend/tests/test_config.py
c "test: PDF rendering and frontend security rules"                 backend/tests/test_pdf.py backend/tests/test_frontend_security.py
c "test: Danger Mode gate, budget, and classification"              backend/tests/test_danger_mode.py
c "test: end-to-end fixture and exploitation integration"           backend/tests/test_danger_integration.py backend/tests/test_danger_exploit_integration.py
c "build: Python dependencies and container image"                  backend/requirements.txt backend/requirements-dev.txt backend/Dockerfile backend/.dockerignore backend/start.bat
c "feat(infra): Docker Compose stack"                               docker-compose.yml mongo deploy.sh
c "feat(infra): hardened Nginx configuration"                       nginx
c "ci: GitHub Actions workflow and Dependabot"                      .github
c "docs: environment configuration reference"                       .env.example
c "docs: architecture, pipeline, and profile diagrams"              docs/assets
c "docs: scan screenshots across all profiles"                      docs/screenshots
c "docs: Danger Mode documentation and publishing guide"            docs
c "docs: security policy and authorization requirements"            SECURITY.md
c "docs: changelog, release notes, and audit report"                CHANGELOG.md RELEASE_NOTES_v0.4.0.md RELEASE_NOTES_v0.4.1.md AUDIT_REPORT.md
c "docs: README with setup, features, and screenshots"              README.md
c "chore: include remaining project files"                          .
echo "Total commits: $(git rev-list --count HEAD)"
