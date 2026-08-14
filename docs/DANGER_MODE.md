# Danger Mode

**Full Intermediate Penetration Test Simulation** — profile key `danger`.

> ⚠️ **Danger Mode sends active attack-simulation traffic.** Run it only against systems you own or hold explicit written permission to assess. Unauthorized active testing is illegal in most jurisdictions. See [`SECURITY.md`](../SECURITY.md#danger-mode) for the authorization requirements.

---

## What it is

Danger Mode runs everything the safe profiles run — `recon_only`, `osint_only`, and `vuln_only` — and then adds a staged active-testing pipeline mapped to the OWASP Top 10 (2021).

It is a **simulation**, not an exploitation framework. It sends bounded, benign canary payloads, classifies the response signal, captures the request metadata as evidence, and emits a candidate finding. It never confirms exploitation, never modifies target data, and never opens a shell.

## Opt-in

Two independent controls, both required:

```bash
# 1. Environment opt-in (default: false)
ALLOW_DANGER_MODE=true
```

```bash
# 2. Typed acknowledgement on every request
danger_acknowledgement=I am authorized
```

Without both, the API responds **403** with an explanatory message. The gate is checked in the router *and* re-checked inside the Celery task, so a scan queued before the profile was disabled will not run afterwards. The dashboard requires a checkbox plus the typed phrase and never restores that state from `localStorage`.

### Starting a danger scan

Synchronous (no MongoDB or Celery needed):

```bash
curl "http://127.0.0.1:8000/api/test-scan?target=example.com&scan_type=danger&danger_acknowledgement=I%20am%20authorized"
```

Queued:

```bash
curl -X POST http://127.0.0.1:8000/api/scan -H "Content-Type: application/json" -d '{"target":"example.com","scan_type":"danger","danger_acknowledgement":"I am authorized"}'
```

Checking whether the server has it enabled:

```bash
curl -s http://127.0.0.1:8000/api/capabilities | python -c "import json,sys; print(json.load(sys.stdin)['danger_mode'])"
```

---

## Pipeline stages

Stages run in dependency order. Each is independently fail-soft: a stage that raises is recorded in `stages_failed` and the pipeline continues.

```
danger_recon → danger_axfr → attack_surface
    → injection_sqli → injection_command → injection_html → injection_xss
    → injection_ssti → injection_xxe → injection_ssrf → injection_nosql
    → reverse_shell_assessment → dom_injection
    → directory_fuzzing → path_traversal → idor_testing
    → business_logic → data_exposure → advanced_checks
    → owasp_matrix
```

## Detection versus exploitation

Detection is broad and cheap; exploitation is precise and only runs where it is warranted. A finding is promoted to `[EXPLOITED]` only when the engine reproduced the condition and captured proof.

| Class | Proof technique | Proof value captured |
|---|---|---|
| SQL injection | Boolean differential (TRUE renders the record, FALSE does not), or numeric arithmetic | Database version banner |
| Command injection | Shell evaluates `$((a*b))` | Computed product, then OS name |
| SSTI | Engine evaluates `{{a*b}}` while the literal disappears | Computed product, engine family |
| XSS | Reflection-context analysis | Context (javascript / attribute / body) and surviving characters |
| Path traversal | System-file signature match | Signature name, byte count, fingerprint |
| CORS | Server echoes an arbitrary `Origin` with credentials | The response headers |
| Open redirect | Server issues the redirect to an external canary | The `Location` header |

### Guards against false positives

Confirmation is deliberately conservative, because a scanner that cries wolf is worse than one that stays quiet:

- **Value sensitivity.** Numeric arithmetic is only meaningful if the endpoint's output actually varies with the parameter. If every value renders the same page, `id=1-0` matching `id=1` proves nothing and is discarded.
- **Silent defaults.** An application that falls back to a default when `int()` raises is indistinguishable from one that evaluates arithmetic. Obvious garbage (`2zqx`) must *also* be rejected before arithmetic counts.
- **Reflection is not XSS.** A reflected value whose breakout characters are encoded is reported at low severity and explicitly not marked exploited.
- **Template literals.** SSTI requires the computed product present *and* the literal expression absent.
- **One-hop DOM flows** are labelled candidates rather than confirmed, because static analysis cannot prove nothing sanitized the value in between.

## Remediation

Every finding carries a complete, code-level fix: root cause, the vulnerable and corrected patterns in the relevant languages, configuration changes, defence-in-depth steps, and a **VERIFY** section describing how to confirm the fix. The full library lives in `backend/app/tasks/vulnscan/danger/remediation.py`.

### 1. `danger_recon`

Combines certificate-transparency and passive sources with a bounded brute-force sweep of a built-in wordlist (`DANGER_SUBDOMAIN_BRUTE_LIMIT` names), then probes the first `DANGER_MAX_HOSTS` candidates over HTTPS then HTTP and fingerprints each live host. Produces the seed URLs the crawler consumes.

### 2. `danger_axfr`

Enumerates A, AAAA, MX, TXT, NS, SOA, CNAME, and SRV records, then attempts an AXFR zone transfer against every authoritative name server.

- **Success → high severity.** The zone is summarized by record-node count and host names. The raw zone is never stored in full.
- **Refusal → informational.** This is the correct configuration and is recorded for coverage.

### 3. `attack_surface`

Crawls up to `DANGER_MAX_CRAWL_PAGES` in-scope pages and classifies every discovered input point:

| Type | Meaning |
|---|---|
| `login_form` | Password field or auth-shaped action |
| `search_form` | Search/query-shaped field |
| `upload_form` | File input or upload-shaped action |
| `generic_form` | Any other form |
| `query_param` | URL query parameter |
| `api_endpoint` | Path matching `/api/`, `/v1/`, `/graphql`, … |
| `object_reference` | Parameter or path segment holding an object identifier |
| `url_param` | Parameter that accepts a URL (drives SSRF testing) |

Out-of-scope links are dropped; the crawler never leaves the target's domain scope.

### 4. Injection modules

All share one contract: read the inventory, send a bounded documented payload set, classify the signal, store request metadata **without** response content, emit a candidate finding.

| Module | Techniques | Canaries |
|---|---|---|
| `injection_sqli` | error, boolean-blind, UNION, time-based blind, header-borne | `'`, `"`, `' OR '1'='1' -- <canary>`, `' UNION SELECT NULL -- <canary>`, one `SLEEP(2)` probe |
| `injection_command` | direct vs blind classification | `;echo <canary>`, `\| id`, `$(printf <canary>)`, backticks, encoded newline |
| `injection_html` | unescaped rendering | `<b><canary></b>`, `<!-- <canary> -->` |
| `injection_xss` | reflected, stored, DOM-based | inert `<script>window.__recontitan='<canary>'</script>`, attribute break, `javascript:` URI |
| `injection_ssti` | template evaluation | `{{7*7}}`, `${7*7}`, `#{7*7}`, Velocity `#set` |
| `injection_xxe` | entity processing | DOCTYPE with one **internal** entity resolving to a fixed string — no external entity, no file read |
| `injection_nosql` | operator injection | `{"$ne": null}`, `{"$gt": ""}`, `param[$ne]` |
| `injection_ssrf` | server-side fetch | private/loopback canary compared against a public control URL |

**Signal classification** (`reflected` / `error` / `timing` / `differential` / `none`) is always relative to a baseline request of the same endpoint. Probes that find nothing are still recorded in the matrix so coverage gaps stay visible.

### 5. `reverse_shell_assessment`

For every command-injection candidate, emits a sub-finding that:

- classifies the injection context (direct output vs blind)
- names the interpreter families that would typically be present (bash/sh, netcat, python, php, perl, powershell) as *hypothetical*
- states exactly what evidence would confirm the vector
- records `Connection attempted by ReconTitan: no` and `Payload generated by ReconTitan: no`

**This module contains no connecting payload of any kind and executes nothing on the target.** It exists so an authorized tester knows where to look during manual validation.

### 6. `directory_fuzzing` and `path_traversal`

Directory fuzzing requests `DANGER_DIR_BUST_WORDLIST` built-in paths and classifies responses against a randomly generated not-found baseline, filtering soft-404s. It reports responsive paths, high-interest paths (`.git`, `.env`, backups, credentials, management endpoints), directory listings, and verbose error output.

Traversal probing targets file-serving parameters with seven encoding variants:

`../` · `..%2f` · `%2e%2e%2f` · `....//` · `%252e%252e%252f` · `..;/` · `..\` (Windows)

A hit is reported only when the response matches a known system-file **signature**. The response body is fingerprinted and discarded — evidence records the signature name, never the file contents.

### 7. `idor_testing`

Extracts object references from query parameters and path segments, detects the identifier format (numeric, UUIDv1–v5, base64-encoded numeric, opaque), and enumerates up to `DANGER_IDOR_MAX_IDS` adjacent identifiers.

Differential analysis compares status, body size, and a content fingerprint against a baseline. A second identical baseline request establishes whether the page is stable — on a stable page a differing fingerprint is decisive, on a dynamic page it falls back to a size delta. This is what prevents both false negatives (two records of equal length) and false positives (timestamps and CSRF tokens).

It also compares an unauthenticated `POST` (empty body) against the `GET` baseline to surface method-based authorization gaps.

**Object contents are never read into evidence, stored, or transmitted** — only fingerprints, sizes, and status codes.

### 8. `owasp_matrix`

Runs the remaining OWASP categories and builds the coverage matrix.

| Category | Covered by |
|---|---|
| A01 Broken Access Control | `idor_testing`, forced browsing in `directory_fuzzing` |
| A02 Cryptographic Failures | TLS protocol/cipher review, plaintext-HTTP detection, JS secret fingerprinting |
| A03 Injection | all `injection_*` modules |
| A04 Insecure Design | login rate-limit observation, password-reset exposure, unvalidated upload |
| A05 Security Misconfiguration | debug/default endpoints, directory listing, verbose errors, headers, AXFR |
| A06 Vulnerable and Outdated Components | NVD candidates plus known-vulnerable version fingerprints |
| A07 Identification and Authentication Failures | CSRF token absence, password-policy hints, session cookie flags |
| A08 Software and Data Integrity Failures | missing subresource integrity, deserialization indicators |
| A09 Security Logging and Monitoring Failures | missing headers plus absence of observable rate limiting |
| A10 SSRF | `injection_ssrf` |

**TESTED means a module ran, not that the application is clean. NOT TESTED means unassessed.**

---

## Safety bounds

| Bound | Variable | Default |
|---|---|---:|
| **Wall-clock ceiling** | `DANGER_MAX_SCAN_SECONDS` | **240 s** |
| Targets per scan | `DANGER_MODE_MAX_TARGETS` | 1 |
| Hosts probed | `DANGER_MAX_HOSTS` | 5 |
| Total requests | `DANGER_MAX_REQUESTS_TOTAL` | 500 |
| Requests per module | `DANGER_MAX_REQUESTS_PER_MODULE` | 80 |
| Payloads per scan | `DANGER_MAX_PAYLOADS_PER_SCAN` | 400 |
| Endpoints tested | `DANGER_MAX_ENDPOINTS` | 15 |
| Pages crawled | `DANGER_MAX_CRAWL_PAGES` | 10 |
| Pacing delay | `DANGER_REQUEST_DELAY_MS` | 150 ms |
| Probe timeout | `DANGER_REQUEST_TIMEOUT` | 12 s |
| Blind SQL delay | `DANGER_TIME_DELAY_SECONDS` | 2 s |
| Brute-force names | `DANGER_SUBDOMAIN_BRUTE_LIMIT` | 100 |
| Directory wordlist | `DANGER_DIR_BUST_WORDLIST` | 120 |
| Identifiers per reference | `DANGER_IDOR_MAX_IDS` | 10 |
| Out-of-band XXE | `DANGER_ENABLE_XXE_OOB` | off |
| Danger scans per minute | `RATE_LIMIT_DANGER` | 2 |

Every outbound probe passes through a single shared budget that enforces the ceilings, paces requests, and applies exponential backoff when the target returns `429` or `503`. When the budget is exhausted the scan stops early and the summary sets `budget_exhausted: true` so partial coverage is visible rather than silent.

### The wall-clock deadline

Request counting alone cannot bound a scan: pacing sleeps and per-probe timeouts mean a slow target consumes far more *time* than *requests*. `DANGER_MAX_SCAN_SECONDS` is therefore a second, independent ceiling:

- The clock starts at the **first danger stage**, not when the scan is accepted, so the recon/OSINT/vulnerability groups that run first never consume the danger budget.
- Pacing sleeps and per-probe timeouts are clamped to the time remaining, so no single probe can overrun the deadline by its full timeout.
- Once the deadline passes, every remaining stage becomes a no-op and is recorded in `stages_skipped`. `owasp_matrix` still runs, because it *is* the coverage report.
- A `danger_coverage` finding is emitted explaining what was skipped and why.

The result is that a danger scan **always terminates and always returns a report**, even against a target that is slow, throttling, or partly unreachable. A typical scan takes 3–6 minutes end to end.

---

## Output

### `danger_summary`

Returned by `/api/test-scan`, persisted on the scan record, and included in `/api/scan/{id}/report`:

```json
{
  "enabled": true,
  "target": "example.com",
  "stages_completed": ["danger_recon", "attack_surface", "..."],
  "stages_failed": [],
  "attack_surface": [{"id": "as_...", "url": "...", "method": "POST",
                      "input_type": "login_form", "parameters": ["username", "password"]}],
  "injection_matrix": [{"endpoint": "...", "injection_type": "sql",
                        "payload_category": "error", "signal": "error",
                        "status_code": 500, "requires_manual_validation": true}],
  "owasp_coverage": [{"category": "A03:2021-Injection", "tested": true, "findings": 2}],
  "requests_sent": 214,
  "payloads_sent": 158,
  "budget_exhausted": false
}
```

### Finding shape

Danger findings extend the standard finding with:

| Field | Meaning |
|---|---|
| `requires_manual_validation` | Always `true` for danger findings |
| `owasp_category` | OWASP Top 10 (2021) identifier |
| `attack_vector` | Short description of the technique |
| `confidence` | Always a candidate label, never "confirmed" |
| `affected_asset` | The specific URL or host, not just the target |

### Reports

The dashboard report page adds a danger banner plus Danger Findings, OWASP Coverage, Attack Surface, and Injection Matrix cards. The PDF adds a dedicated Danger Mode section with the manual-validation banner, execution summary, coverage matrix, inventory, injection matrix, and danger check results. All danger findings also appear in the standard findings index with severity colour coding.

---

## Interpreting results

1. **Reproduce the exact request** recorded in the evidence from an authorized test system.
2. **Rule out infrastructure.** Caching, load balancing, CDN behaviour, and dynamic content produce differential and timing signals that look like findings.
3. **Confirm impact** before marking anything verified.
4. **A reverse-shell sub-finding is documentation.** Confirm the underlying command injection first, and validate further only with written approval.
5. **NOT TESTED is not clean.** Cover those categories with authenticated dynamic testing, code review, or a manual engagement.

---

## Testing

Danger Mode has unit coverage in `backend/tests/test_danger_mode.py` (gate, discovery, classification, bounds, secret hygiene) and end-to-end coverage in `backend/tests/test_danger_integration.py`, which starts a deliberately weak fixture server on `127.0.0.1` and drives the real pinned HTTP client against it. **No test contacts an external host.**

```bash
pytest -q backend/tests
```
