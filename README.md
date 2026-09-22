<div align="center">

<img src="docs/screenshots/home.png" alt="ReconTitan" width="100%">

<br><br>

# ReconTitan

### External Attack Surface Assessment

**Point it at a domain. Get back everything that domain shows the internet — enumerated, checked against known weaknesses, and written up with the evidence behind every claim.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.139-009688?style=flat-square&logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Tests](https://img.shields.io/badge/tests-698%20passing-65A30D?style=flat-square)](#testing)
[![Modules](https://img.shields.io/badge/modules-45-A3E635?style=flat-square)](#what-it-checks)
[![OWASP](https://img.shields.io/badge/OWASP-Top%2010-22D3EE?style=flat-square)](#owasp-coverage)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](#docker-compose--history-workers-no-time-limit)
[![Version](https://img.shields.io/badge/version-0.5.0-8B5CF6?style=flat-square)](CHANGELOG.md)
[![License](https://img.shields.io/badge/license-MIT-475569?style=flat-square)](LICENSE)

<br>

**[Quick start](#quick-start)** · **[First scan](#your-first-scan)** · **[How it works](#how-it-works)** · **[The report](#the-report)** · **[Profiles](#scan-profiles)** · **[Modules](#what-it-checks)** · **[Danger Mode](#danger-mode)** · **[Config](#configuration)** · **[API](#api-reference)** · **[Deploy](#deployment)** · **[Troubleshooting](#troubleshooting)** · **[FAQ](#faq)**

</div>

---

## Table of contents

<table>
<tr><td valign="top" width="50%">

**Getting started**

- [Why ReconTitan exists](#why-recontitan-exists)
- [Quick start](#quick-start)
  - [Windows](#windows)
  - [macOS and Linux](#macos-and-linux)
  - [Manual install](#manual-install-any-platform)
  - [What setup touches](#what-setup-touches)
  - [Removing it](#removing-it)
- [Your first scan](#your-first-scan)
- [Requirements](#requirements)

**Understanding it**

- [How it works](#how-it-works)
  - [The pipeline](#the-pipeline)
  - [Evidence grading](#evidence-grading--the-rule-everything-obeys)
  - [Architecture](#architecture)
- [The report](#the-report)
  - [Scan output](#scan-output)
  - [Exploit awareness](#exploit-awareness--kev--epss)
  - [Attack surface tree](#attack-surface-tree)
  - [Attack paths](#attack-paths--how-the-findings-connect)
  - [Triage](#triage--recording-that-a-finding-was-reviewed)
  - [Per-card controls](#every-card-explains-itself-and-every-card-can-be-re-run)
  - [Exports](#exports)
- [The SOC console](#the-soc-console)

</td><td valign="top" width="50%">

**Using it**

- [Scan profiles](#scan-profiles)
- [What it checks](#what-it-checks)
  - [OWASP coverage](#owasp-coverage)
- [Danger Mode](#danger-mode)
- [Configuration](#configuration)
  - [Core settings](#core-settings)
  - [Scan alerts](#scan-alerts)
  - [Deep port scanning](#deep-port-scanning)
  - [AI explanations](#ai-explanations)
- [API reference](#api-reference)

**Operating it**

- [Project structure](#project-structure)
- [Deployment](#deployment)
  - [Docker Compose](#docker-compose--history-workers-no-time-limit)
  - [Other targets](#other-deployment-targets)
- [Testing](#testing)
- [Release evidence](#release-evidence)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Contributing](#contributing)
- [Legal](#legal)
- [License](#license)

</td></tr>
</table>

---

## Why ReconTitan exists

Most scanners hand you raw tool output and leave the interpretation to you. You get a wall of JSON, a severity colour, and no way to tell whether the tool actually *saw* something or merely *guessed* from a version string.

ReconTitan is built the other way round. Three commitments shape every part of it:

<table>
<tr>
<td width="33%" valign="top">

### Evidence, always

**Every finding carries the evidence that produced it.** Not a severity badge and a CVE number — the actual response header, the certificate field, the DNS answer. If you cannot audit a claim, you cannot act on it.

</td>
<td width="33%" valign="top">

### Honest about gaps

**A check that could not run says so**, and names the fallback it used instead. A tool that never admits *"I couldn't check this"* is a tool you cannot trust, because silence and success look identical.

</td>
<td width="33%" valign="top">

### Candidate-graded

**It never claims a confirmed exploit.** It tells you what it saw and what would confirm it. That distinction is enforced in the code and covered by tests — not just in the wording of the report.

</td>
</tr>
</table>

Point it at a domain and it will:

| Stage | What happens |
|---|---|
| **Map the attack surface** | WHOIS, DNS, certificate transparency, archived URLs, subdomains, live hosts, open ports, hosting attribution |
| **Analyse what it found** | TLS, security headers, cookie flags, CORS, technology fingerprints, JavaScript inventory, WAF detection, subdomain-takeover exposure |
| **Match known weaknesses** | CVE candidates by CPE version range, OWASP Top 10 categorisation |
| **Prioritise real-world risk** | CISA KEV status and FIRST EPSS probability rank version-confirmed CVEs without confusing exploit *activity* with CVSS *severity* |
| **Record what you decided** | Mark a finding false positive, accepted risk or confirmed real, with a required reason; the decision is remembered and re-applied to later scans |
| **Correlate into attack paths** | Join entry point, service, software, CVE and technique into one chain, labelling each link `confirmed`, `supported` or `possible` |
| **Optionally simulate an attacker** | Bounded, paced, explicitly authorised active probes |
| **Write it up** | An interactive report plus PDF, JSON and HTML export |

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Quick start

**One command. It checks what you have, installs only what's missing, and tells you before it does anything.**

### Windows

```
setup.bat
```

Double-click it, or run it from a terminal.

### macOS and Linux

```bash
bash setup.sh
```

Alternatively: `chmod +x setup.sh` followed by `./setup.sh`.

> `setup.sh` is for macOS and Linux **only**. Run it under Git Bash on Windows and it stops and points you at `setup.bat` — Windows lays virtual environments out differently, and continuing would overwrite a working one.

The script prints its full plan before touching anything, then walks through six steps out loud:

| Step | What it does |
|:--:|---|
| **1** | Find Python 3.11+ — if missing, show you the exact command it wants to run and **wait for a yes** |
| **2** | Create a private environment inside this folder (`.venv/`) |
| **3** | Install this project's packages **into that folder only** — your system Python is untouched |
| **4** | Offer to install **nmap**, so port scanning stays on your machine |
| **5** | Write a `.env` config file from the annotated example |
| **6** | Start the scanner at **<http://127.0.0.1:8000>** |

Then open **<http://127.0.0.1:8000>**.

### Manual install (any platform)

If you would rather run the steps yourself, or the script's environment assumptions don't match yours:

```bash
git clone https://github.com/D3v4nshPat3l/ReconTitan.git
```

```bash
cd ReconTitan
```

```bash
python -m venv .venv
```

Activate it — **`source .venv/bin/activate`** on macOS/Linux, **`.venv\Scripts\activate`** on Windows — then:

```bash
pip install -r requirements.txt
```

```bash
cp .env.example .env
```

Start the API from inside `backend/`:

```bash
cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

> **Local launchers use synchronous scans** and do not need Redis or a Celery worker, even if MongoDB is already running. Set `ASYNC_SCANS_ENABLED=false` (the setup scripts do this for you) to guarantee it. Docker Compose explicitly enables queued scans instead.
>
> MongoDB is **optional** — without it, scanning works exactly the same and history simply isn't persisted.

### What setup touches

It touches **three things**, all inside this directory:

| | |
|---|---|
| `.venv/` | A private Python environment. A folder, not a system change |
| `.env` | Your local config, created from the example |
| `.recontitan-install.log` | A record of what it made, so the uninstaller knows |

It **won't** install anything system-wide without asking first, won't modify anything outside this folder, and won't run a scan by itself.

Danger Mode retains the project's enabled default and still requires typed acknowledgement per scan; existing `.env` settings are preserved across re-runs. Python 3.11+ is required, including inside a reused `.venv`.

### Removing it

```
uninstall.bat          ·          bash uninstall.sh
```

Goes through five items one at a time — the environment, your config, bytecode caches, Python, and nmap — showing what each is, where it lives and how much space it uses. **The default for every question is keep.** Nothing is deleted unless you type `y` for that specific item.

Python and nmap are only offered if *setup* installed them, and on Linux the uninstaller refuses to remove Python at all: the package manager and desktop depend on it.

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Your first scan

1. **Open <http://127.0.0.1:8000>.** The scan panel is on the landing page.
2. **Type a target you are allowed to scan.** A bare hostname — `example.com`, not `https://example.com/path`. An IP address works too.
3. **Pick a profile.** Start with **Recon Only** (20–55s) to see the shape of the output before committing to a **Full** scan.
4. **Press Scan and watch the live log.** Every stage announces itself with a timestamp. This is the part that tells you the tool is working rather than hung.
5. **Read the report.** Each card is one module. Use **ⓘ** to learn what a card means and **↺** to re-run just that check.
6. **Triage what you reviewed.** Open a finding, mark it `Confirmed real`, `False positive` or `Accepted risk`, and write the reason. Next week's scan will remember.
7. **Export it** as PDF, JSON or HTML when you need to hand it to someone.

> ### ⚠️ Before you scan anything
>
> **Only scan systems you own or have explicit written permission to test.** Safe targets to learn on: domains you own, deliberately vulnerable apps you run yourself (OWASP Juice Shop, DVWA, WebGoat), or bug-bounty programmes whose scope **explicitly permits** automated scanning. See [Legal](#legal).

### Requirements

| | Needed | Notes |
|---|---|---|
| **Python** | 3.11 or newer | Checked by setup, including inside a reused `.venv` |
| **Disk** | ~500 MB | The venv and its packages |
| **nmap** | Optional | Without it, port scanning falls back to a third-party API that must be told your target's address. With it, scanning stays local |
| **MongoDB** | Optional | Scan history and the SOC console. Absent = scanning still works, storage silently no-ops |
| **Redis + Celery** | Docker only | Queued scans with no time limit. Local launchers are synchronous and need neither |
| **Ollama** | Optional | Local AI explanations. Without any provider, summaries fall back to a deterministic template |
| **API keys** | Optional | Threat-intel modules skip silently without one — they cost nothing and simply don't appear |

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## How it works

### The pipeline

A scan is a staged pipeline, and each stage feeds the next. That is why a `full` scan finds things a `vuln_only` scan cannot: CVE matching needs the technology fingerprints OSINT produced, which needed the live hosts recon produced.

```
     target domain
          │
          ▼
  ┌───────────────┐   WHOIS · DNS (A/AAAA/MX/NS/TXT/CNAME/SOA, SPF, DMARC)
  │  1. RECON     │   crt.sh · Wayback · ipinfo · httpx · subfinder · amass
  └───────┬───────┘
          │  subdomains, live hosts, IPs, infrastructure
          ▼
  ┌───────────────┐   TLS · security headers · cookies · CORS · tech stack
  │  2. OSINT     │   favicon hash · JS inventory · takeover · WAF
  │     & WEB     │   VirusTotal · Shodan · GreyNoise · Censys · theHarvester
  └───────┬───────┘
          │  technology and version fingerprints
          ▼
  ┌───────────────┐   port_scan (nmap, or API fallback)
  │  3. VULN      │   nvd_cve — CPE version-range matching
  └───────┬───────┘   optional: nuclei · nikto · dir_fuzzing · sqlmap
          │  CVE candidates
          ▼
  ┌───────────────┐   CISA KEV lookup · FIRST EPSS probability + percentile
  │  4. EXPLOIT   │   → URGENT / HIGH / ELEVATED / STANDARD / VERIFY
  │     INTEL     │   fail-soft: unreachable => "unavailable", never "not exploited"
  └───────┬───────┘
          │
          ▼
  ┌───────────────┐   only when explicitly authorised — see Danger Mode
  │  5. DANGER    │   20 bounded, paced, non-destructive active stages
  └───────┬───────┘
          │
          ▼
  ┌───────────────┐   triage decisions re-applied · attack paths correlated
  │  6. REPORT    │   AI summary (local by default) · PDF / JSON / HTML export
  └───────────────┘
```

Stages are **fail-soft throughout**. A module that times out, hits a rate limit or finds no binary reports that fact and the pipeline continues. A scan never dies because one third-party API was slow.

### Evidence grading — the rule everything obeys

This is the single idea the whole tool is built around, so it is worth stating plainly. Every claim ReconTitan makes is tagged with **how it knows**:

| Grade | Means | Example |
|---|---|---|
| `confirmed` | Observed directly, or safely proven **on this target** | A response header that is genuinely absent; a certificate that genuinely expires in 12 days |
| `supported` | Several observations agree, or an authoritative source does | A detected version falls inside a CVE's affected range |
| `possible` | A plausible next step that **was never executed** | The technique an attacker *would* use against that CVE |

A `possible` step never gets promoted by association. **CISA KEV proves a vulnerability is exploited in the wild — it never proves this host was exploited.** A KEV entry therefore appears as a `supported` step reading *"this does not prove exploitation of this target"*, and it can never lift a path to confirmed. That rule is covered by tests, not just by wording.

### Architecture

Three separate applications, deliberately:

```
┌──────────────────────────────────────────────────────────────────┐
│  PUBLIC APP  —  backend/app/main.py  (FastAPI, port 8000)        │
│                                                                  │
│  frontend/          index.html · report.html · JS modules        │
│  app/routers/       scans · reports · triage · ai · news         │
│  app/tasks/         recon/ · osint/ · vulnscan/ · ai_analysis    │
│  app/services/      attack_paths · triage · danger_mode · pdf    │
│  app/middleware/    security — rate limit, anti-injection        │
│  app/targeting.py   SSRF guard: refuses private/internal targets │
│                                                                  │
│  ✗ has no admin routes at all                                    │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  SOC CONSOLE  —  backend/app/admin/  (separate ASGI app, 9000)   │
│  run_admin.py locally · never routed publicly in production      │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  WORKER  —  Celery (Docker only)                                 │
│  app/celery_app.py · app/tasks/scan_tasks.py                     │
└──────────────────────────────────────────────────────────────────┘
```

**The console being a separate ASGI application is a security property, not a layout choice.** The public app has no admin routes mounted, so no public-routing bug — no path-traversal quirk, no middleware ordering mistake — can expose it.

Persistence is optional by design. Triage decisions live in `triage.json` (move it with `TRIAGE_STORE_PATH`), so review state works without MongoDB, like everything else here.

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## The report

### Scan output

A real `full` scan of `example.com` — **25 modules, 34 findings, 64 seconds.**

<div align="center">
<img src="docs/screenshots/report-masthead.png" alt="Report masthead showing the scanned target with severity breakdown" width="100%">
</div>

<div align="center">
<img src="docs/screenshots/report-findings.png" alt="Report cards showing TLS, DNS, subdomains, WHOIS, headers and CVE candidates" width="100%">
</div>

Every card is a module. Notice what an honest scanner looks like: a check that could not run says so and names its fallback rather than reporting nothing. **Subdomains** found 9 and lists them. **HTTP Security** marks five headers `Missing` with a link to analyse each. A tool that never says *"I couldn't check this"* is a tool you cannot trust.

### Exploit awareness — KEV + EPSS

The **Vulnerabilities** card is exploit-aware. Version-confirmed CVEs are ordered by an operational priority:

| Priority | Assigned when |
|---|---|
| `URGENT` | The CVE is in CISA's **Known Exploited Vulnerabilities** catalogue |
| `HIGH` · `ELEVATED` | EPSS likelihood/percentile or CVSS warrants faster attention |
| `STANDARD` | Version-confirmed, no elevated exploit signal |
| `VERIFY` | Product-only or keyword match — **always**, even when the CVE is widely exploited |

That last row is the important one. A product-only match stays `VERIFY` no matter how exploited the CVE is in the wild, **because threat activity does not prove that the detected installation is affected.**

Opening a finding shows the KEV result, EPSS probability, percentile, and the exact reasons behind its priority; the same fields are preserved in JSON and PDF exports.

**This enrichment is fail-soft.** If CISA or FIRST is unreachable, the scan still completes and labels the missing status as `unavailable` instead of falsely saying the CVE is not exploited. Results are cached for six hours by default. An `URGENT` CVE also triggers the email and desktop alerts even when its base CVSS severity is below `high`.

**Only CVE identifiers are sent to FIRST** — the target hostname, IP and evidence are never submitted. Set `EXPLOIT_INTEL_ENABLED=false` to disable the network enrichment entirely, or tune `EXPLOIT_INTEL_TIMEOUT_SECONDS` and `EXPLOIT_INTEL_CACHE_TTL_SECONDS` in `.env`.

### Attack surface tree

The report has a separate **Attack surface** tab inspired by the animated node-link navigation of OSINT Framework. The normal **Scan output** remains the default and keeps its original position.

In the second tab, selecting a compact circular node grows its connected branch downward with a smooth enter/update transition; collapsing it retracts that branch. Children remain in one width-bounded vertical tree instead of spreading into horizontal cards, and the canvas stays within the report width.

The hierarchy covers subdomains, IP addresses, open services, technologies, web input points, severity-grouped findings, and scanner coverage. Finding leaves open the existing evidence modal, and **the tree never launches extra probes** — it is a view of data the scan already collected.

### Attack paths — how the findings connect

A third tab, **Attack paths**, answers the question a list of findings does not: *how would someone actually get in, and what would they reach next?* It correlates evidence the scan already collected into ordered chains — entry point → exposed service → software → known vulnerability → technique → impact — and **sends no traffic of its own**.

The reason it is worth having is also the reason it is easy to get wrong. A tool that renders a plausible-looking kill chain teaches you to trust a story it cannot support. So every step carries one of three labels, and the view never flattens them:

| Label | Means |
|---|---|
| `confirmed` | Observed or safely proven **on this target** |
| `supported` | Several observations agree, or an authoritative source does |
| `possible` | A plausible next step that **was never executed** |

Each path states its weakest link in words, not only in colour: *"The chain ends in a step that was never executed. Treat the outcome as unproven."*

Four kinds of path come out of this:

- **Confirmed** — a Danger Mode stage executed a bounded proof. Every step is `confirmed`, and the impact shown is the one the scanner actually demonstrated, not a generic list.
- **Version-confirmed** — the detected version falls inside a CVE's affected range. The service, software and CVE links are `confirmed`; the technique is `possible`, because no exploit was run.
- **Supported** — an exposure that is real but whose consequence was not tested, such as a database port reachable from the internet.
- **Blocked** — a route the scanner tested where a control held. Kept deliberately: knowing *which* control is holding is worth as much as knowing where a hole is. A blocked path shows no impact at all.

Payload and encoding analysis is reported the same way. Where the scanner determined that output encoding neutralised the characters a payload needed, the path says so explicitly — *"Context html_attribute: unescaped breakout characters none; encoded characters &quot; &lt; &gt; &amp;"* — rather than leaving a reflected parameter looking exploitable.

Every step that came from a finding is clickable (and keyboard-reachable), opening that finding's full evidence. The tab is hidden entirely when a scan produced nothing to correlate.

### Triage — recording that a finding was reviewed

Without this, every finding is permanently equal. Somebody reviews a report, works out that three CVE candidates do not apply to their build, and has **nowhere to put that**. The next scan shows the same three with the same weight, the report never gets quieter, and people stop reading it. A scanner nobody reads finds nothing.

Open any finding and choose one of four states:

| State | Effect |
|---|---|
| `Open` | Not yet reviewed. The default. |
| `Confirmed real` | Reviewed and verified. **Does not suppress** — it raises confidence. |
| `False positive` | Reviewed and not real here. Removed from the counts and the attack paths. |
| `Accepted risk` | Real, and the owner has chosen to live with it. Removed from the counts. |

**Decisions survive re-scans.** Finding ids are a fresh uuid every run, so triage keys on a *fingerprint* derived from what the finding **is** — its CVE, its endpoint and parameter, its scanner. Mark something reviewed today and next week's scan still knows.

That fingerprint is the hard part, and it is deliberately conservative:

- **Under-normalising** means the fingerprint changes and you re-triage something — annoying.
- **Over-normalising** means two findings collapse to one key, and suppressing one **silently hides the other** — a real vulnerability buried by a tool you trusted.

So volatile-but-meaningless text is collapsed (`valid for 53 more days`, `2 Open Port(s) Found`) while anything identifying is not: `Port: 3306/mysql` and `Port: 22/ssh` stay separate decisions, and a blanket digit rule would have merged them.

**Two rules stop this becoming a way to hide problems**, which is the obvious failure mode of any suppression feature:

1. **Suppressing requires a written reason.** A decision with no rationale is deletion with extra steps, so the *server* rejects it — not just the form.
2. **Nothing is ever deleted.** Suppressed findings stay in the report and in every export, carrying their state, reason and timestamp. The report gains a banner stating how many are suppressed and why, with a toggle to reveal them. **A quiet report always says why it is quiet.**

Decisions live in `triage.json` (set `TRIAGE_STORE_PATH` to move it), so this works without MongoDB like everything else here.

### Every card explains itself, and every card can be re-run

Two controls sit in the corner of each card.

**ⓘ tells you what you are looking at** — what the section shows, how the data was actually obtained, and how to read it. Not a tooltip repeating the title: it is the difference between *"Subdomains: 9"* and knowing those names came from Certificate Transparency logs, which means they were **certified rather than confirmed live**, and that `dev` and `staging` are the interesting ones because they are usually less hardened than production while being just as reachable.

**↺ runs that one check again** — a single module, not the whole scan. Useful when a check timed out, when a third-party API was rate-limited, or when you have just fixed something and want to confirm it. The card dims, names the scanner it is running, and swaps in the new result; findings the module no longer reports **disappear rather than lingering**. If the check fails, the card says why and keeps the data it already had.

Refresh is deliberately limited to the safe-profile scanners. The Danger Mode stages are gated on a typed acknowledgement, and a button cannot collect one — so those cards carry a ⓘ and no ↺ rather than a control that would fire active attack traffic on a single click.

### Exports

| Format | How | Contains |
|---|---|---|
| **Interactive** | The report page itself | All three tabs, evidence modals, triage controls |
| **PDF** | `GET /api/scan/{scan_id}/report.pdf` | Findings, evidence, KEV/EPSS fields, triage state |
| **JSON** | `GET /api/scan/{scan_id}/report` | The full structured result — the machine-readable source of truth |
| **HTML** | From the report page | A self-contained copy to archive or send |

Suppressed findings appear in **every** export, carrying their state, reason and timestamp.

### The scanner

<div align="center">
<img src="docs/screenshots/scanner.png" alt="Scan panel with target field and five profiles" width="100%">
</div>

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## The SOC console

A separate, hardened application answering the question the scanner cannot: **who is using your deployment?**

<div align="center">
<img src="docs/screenshots/soc-console.png" alt="SOC console overview" width="100%">
<br><sub><b>Overview</b> — threat events, injections blocked, auth failures, hourly traffic, attack classes</sub>
</div>

<br>

<div align="center">
<img src="docs/screenshots/soc-detections.png" alt="Detections view" width="49%">
<img src="docs/screenshots/soc-threats.png" alt="Threat sources" width="49%">
<br><sub><b>Detections</b> — behavioural patterns, each stating what it cannot distinguish · <b>Threats</b> — sources ranked by blocked volume</sub>
</div>

<br>

<div align="center">
<img src="docs/screenshots/soc-events.png" alt="Event feed" width="100%">
<br><sub><b>Event Feed</b> — every security-relevant request, IST timestamps, filterable</sub>
</div>

<details>
<summary><b>More console views</b></summary>
<br>
<div align="center">
<img src="docs/screenshots/soc-devices.png" alt="Clients view" width="100%">
<br><sub><b>Clients</b> — grouped by address and headers. The caveat is deliberate: these identify traffic patterns, not people</sub>
<br><br>
<img src="docs/screenshots/soc-blocklist.png" alt="Blocklist" width="100%">
<br><sub><b>Blocklist</b> — hosts ReconTitan refuses to <i>scan</i>, and callers it refuses to <i>serve</i></sub>
<br><br>
<img src="docs/screenshots/soc-lock.png" alt="Console authentication" width="60%">
</div>
</details>

Run it locally with:

```bash
python run_admin.py
```

In production it is **not routed publicly**. Reach it over an SSH tunnel instead:

```bash
ssh -N -L 9000:127.0.0.1:9000 user@your-server
```

The console is a **separate ASGI application**. The public app has no admin routes at all, so no public-routing bug can expose it.

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Scan profiles

Measured against `example.com` on a home connection — not estimates.

| Profile | API value | Modules | Typical | What you get |
|---|---|:--:|---|---|
| **Recon Only** | `recon_only` | 8 | 20–55s | WHOIS, DNS, certificate transparency, archives, live hosts, subdomains |
| **OSINT & Web Analysis** | `osint_only` | 15 | 10–25s | TLS, headers, cookies, CORS, tech stack, JS, takeover, threat intel |
| **Vulnerability Focus** | `vuln_only` | 2 | 5–15s | Port exposure and CVE candidates |
| **Full Safe Scan** | `full` | 25 | 60–120s | All of the above, one report |
| **Danger Mode** | `danger` | 25 + 20 | 3–6 min | Everything, **plus** bounded active penetration-test simulation |

**Which one should you run?**

- **Auditing something for the first time** → `full`. The stages feed each other, and a partial profile will miss CVEs simply because nothing fingerprinted the technology.
- **Watching a domain you already know** → `recon_only` on a schedule. New subdomains and certificate entries are the earliest signal that something changed.
- **Checking one fix** → open the report and press **↺** on that single card instead of re-scanning.
- **You have written authorisation and a scoped engagement** → `danger`. See [Danger Mode](#danger-mode) first.

> ### Full and Danger Mode take time, and that is the tool working, not hanging
>
> The scanner makes real requests to certificate-transparency logs, the Wayback Machine, DNS resolvers and the NVD — public services that are sometimes slow. Danger Mode is slower still *by design*: it paces its traffic and backs off when the target signals throttling. **A danger scan that finished in twenty seconds would be one that hammered the target.**
>
> Watch the live log — every stage announces itself with a timestamp.

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## What it checks

**45 modules across four groups.** Expand each for the full list.

<details open>
<summary><b>Recon — 8 modules</b></summary>
<br>

| Module | What it does |
|---|---|
| `whois` | Registrar, registration and expiry dates, registrant organisation |
| `dns_lookup` | A, AAAA, MX, NS, TXT, CNAME, SOA + SPF/DMARC, queried concurrently |
| `crt.sh` | Certificate transparency logs — names that were *certified*, not confirmed live |
| `wayback` | Archived URLs, which surface endpoints that are no longer linked |
| `ipinfo` | Hosting attribution, ASN, geographic location |
| `httpx_probe` | Which discovered hosts actually answer |
| `subfinder` | Passive subdomain enumeration |
| `amass` | Deeper subdomain enumeration across more sources |

</details>

<details>
<summary><b>Web &amp; OSINT — 15 modules</b></summary>
<br>

| Module | What it does |
|---|---|
| `tech_stack` | Framework and version fingerprints — the input CVE matching depends on |
| `favicon_hash` | Correlates hosts by favicon, finding related infrastructure |
| `js_analysis` | Inventories bundled JavaScript and the endpoints inside it |
| `subdomain_takeover` | Dangling CNAMEs pointing at unclaimed third-party services |
| `security_headers` | CSP, HSTS, X-Frame-Options, and the rest — present, missing or weak |
| `ssl_check` | Certificate validity, chain, expiry, protocol and cipher posture |
| `robots_sitemap` | Paths the site itself advertises |
| `cors_check` | Cross-origin policy, including reflected-origin misconfigurations |
| `cookie_check` | `Secure`, `HttpOnly`, `SameSite` flags |
| `waf_detect` | Whether a WAF is in front, and which |
| `virustotal` · `shodan` · `greynoise` · `censys` | Threat intelligence — **skip silently without an API key** |
| `theharvester` | Public email and hostname harvesting |

Threat-intel modules cost nothing without a key and simply don't appear in the report.

</details>

<details>
<summary><b>Vulnerability — 2 modules, plus 4 optional</b></summary>
<br>

| Module | What it does |
|---|---|
| `port_scan` | nmap when present, HackerTarget API as fallback — and it says which it used |
| `nvd_cve` | CVE candidates by CPE version range, then KEV/EPSS enrichment |

With `ENABLE_ACTIVE_VULN_TOOLS=true` **and** the binaries installed:

`nuclei` · `nikto` · `dir_fuzzing` · `sqlmap`

These are off by default because they are intrusive relative to the "bounded, non-intrusive" promise the standard profiles make.

</details>

<details>
<summary><b>Danger Mode — 20 stages</b></summary>
<br>

`danger_recon` · `danger_axfr` · `attack_surface` · seven injection families (SQLi, command, HTML, XSS, SSTI, XXE, SSRF, NoSQL) · `reverse_shell_assessment` · `dom_injection` · `directory_fuzzing` · `path_traversal` · `idor_testing` · `business_logic` · `data_exposure` · `advanced_checks` · `owasp_matrix`

Every stage is bounded, paced and non-destructive. See [Danger Mode](#danger-mode).

</details>

### OWASP coverage

| Category | Covered by |
|---|---|
| **A01** Broken Access Control | IDOR testing, path traversal, business logic |
| **A02** Cryptographic Failures | TLS analysis, cookie flags |
| **A03** Injection | Seven injection families, DOM analysis |
| **A04** Insecure Design | Business logic, rate-limit observation |
| **A05** Misconfiguration | Headers, CORS, directory exposure |
| **A06** Vulnerable Components | Tech fingerprinting into CVE matching |
| **A07** Auth Failures | Credential handling, session flags |
| **A08** Integrity Failures | JavaScript inventory |
| **A09** Logging Failures | Inference from response behaviour |
| **A10** SSRF | Dedicated probe family |

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Danger Mode

Danger Mode sends **real attack traffic**. Not pretend — the probes are genuine, they are simply bounded, paced and non-destructive.

### Three deliberate acts to get in

| | Who does it | What |
|:--:|---|---|
| **1** | The operator | Sets `ALLOW_DANGER_MODE=true` in `.env` and restarts |
| **2** | The user | Ticks an authorisation checkbox in the UI |
| **3** | The user | Types the exact phrase **`I am authorized`** |

The phrase is required by the **API itself**, not the form — so the gate cannot be bypassed by calling the endpoint directly. The current phrase is published by `GET /api/capabilities`.

### What keeps it safe

- **Bounded** — hard ceilings on total requests, requests per module, payloads and endpoints
- **Paced** — configurable delay between probes, exponential backoff on 429/503
- **Time-capped** — at the limit, remaining stages are skipped and **the report is still produced**
- **Non-destructive** — nothing is created, modified or deleted
- **Evidence-only** — response bodies are fingerprinted, never stored
- **Always candidate-graded** — `requires_manual_validation` is unconditionally true

Full detail: **[`docs/DANGER_MODE.md`](docs/DANGER_MODE.md)**

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Configuration

Everything is environment variables; **[`.env.example`](.env.example)** is the annotated reference.

### Core settings

The ones you're most likely to touch:

| Variable | Default | Purpose |
|---|---|---|
| `RECONTITAN_DEBUG` | `true` | `false` in production — disables `/api/docs`, strips error detail |
| `DOMAIN` | `localhost` | Hostname for host-header validation. **No scheme** |
| `CORS_ORIGINS` | `http://localhost:8000` | Browser origin — **with** scheme |
| `API_ACCESS_KEY` | *(empty)* | Set it and every `/api/` route needs `X-ReconTitan-Key` |
| `ALLOW_DANGER_MODE` | `true` | Master switch for active testing |
| `ALLOW_PRIVATE_TARGETS` | `false` | Allow scanning private/internal addresses — for a local lab only |
| `ASYNC_SCANS_ENABLED` | varies | `false` for synchronous local scans; Compose sets it `true` |
| `AI_PROVIDER` | `auto` | `auto`, `ollama`, `openai`, or `none` |
| `TRIAGE_STORE_PATH` | `triage.json` | Where review decisions are stored |
| `EXPLOIT_INTEL_ENABLED` | `true` | KEV/EPSS enrichment. `false` disables all outbound intel lookups |
| `EXPLOIT_INTEL_CACHE_TTL_SECONDS` | `21600` | Six hours |
| `EMAIL_ALERTS_ENABLED` | `false` | Send a server-side email when a scan reaches the alert threshold |
| `ALERT_MIN_SEVERITY` | `high` | `high` or `critical`; lower-severity findings never trigger an alert |
| `ALERT_EMAIL_RECIPIENTS` | *(empty)* | Comma-separated, operator-configured; **never accepted from the browser** |
| `NMAP_DEEP_SCAN` | `false` | Deep port scan + NSE scripts. See below |
| `NMAP_DEEP_PORTS` | `1-10000` | TCP range a deep scan covers. Any nmap `-p` expression |
| `NMAP_DEEP_SCRIPTS` | *(50 scripts)* | NSE scripts a deep scan runs. Any nmap `--script` expression |

> `DOMAIN` and `CORS_ORIGINS` look inconsistent on purpose. `DOMAIN` is a hostname for Host-header matching; `CORS_ORIGINS` is a browser origin and must carry `https://`.

### Scan alerts

**Desktop notifications** are optional per browser. Enable **Notify this device** on the scan screen and accept the browser permission prompt; ReconTitan then notifies only for high or critical findings. The choice is stored only in that browser.

**Email alerts** are disabled by default. Configure SMTP only in the server's `.env`, then restart the API and worker:

```ini
EMAIL_ALERTS_ENABLED=true
ALERT_MIN_SEVERITY=high
ALERT_EMAIL_RECIPIENTS=security@example.com,oncall@example.com
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-smtp-user
SMTP_PASSWORD=your-smtp-password
SMTP_FROM=ReconTitan Alerts <alerts@example.com>
SMTP_USE_TLS=true
```

The email contains severity counts and up to ten finding titles — **not** raw evidence or scanner output. If mail delivery fails, the scan still completes and the failure is recorded only in server logs.

### Deep port scanning

The setup script offers to install **nmap**. Without it, port scanning falls back to a third-party API that has to be told your target's address; with it, scanning stays on your machine.

```ini
NMAP_DEEP_SCAN=true
```

turns the default probe into a sweep of `NMAP_DEEP_PORTS` (ports 1-10000 by default), maximum version intensity, and the NSE scripts matched by `NMAP_DEEP_SCRIPTS`.

The range stops short of all 65,535 because every open port also draws version probes and a script run — an all-ports sweep runs past `SCAN_TIMEOUT_NMAP_DEEP`, and **a scan that times out reports nothing at all**. Set `NMAP_DEEP_PORTS=1-65535` if you have the hours. MongoDB (27017) and Elasticsearch (9300) sit above the default range — name them if you want them: `1-10000,9300,27017`. NSE output is parsed into findings — a `VULNERABLE:` result becomes a medium-severity finding attributed to its port.

<details>
<summary><b>Why a curated script list, not a category</b></summary>
<br>

`--script all` is 611 scripts and `--script default` is over 100, and neither is chosen for what this tool looks at. Worse, both include things that do more than look:

- **`broadcast-*`** run in nmap's *pre-scan* phase, before your target is touched at all. They enumerate **the scanning machine's own network** — DHCP servers, MAC addresses, internal DNS, per-interface topology — and write it into a report about someone else's host. `broadcast-dhcp-discover` is categorised `safe`, so an allow-list built from `safe` or `default` still pulls it in.
- **`brute`** attempt credentials. **`dos`** and **`exploit`** attack rather than observe — `http-shellshock` sends a live payload, which is why it is not in the list below.
- Several `default` HTTP scripts walk hundreds of URL paths per port. Directory discovery belongs to the ffuf/gobuster module, not to the port scanner.

</details>

`NMAP_DEEP_SCRIPTS` is instead a named list of **50**, covering TLS posture, HTTP configuration, service and version disclosure, and the vuln checks whose signal justifies their cost:

| Area | Scripts |
|---|---|
| **TLS** | `ssl-cert` `ssl-enum-ciphers` `ssl-date` `ssl-dh-params` `ssl-heartbleed` `ssl-poodle` `ssl-ccs-injection` `sslv2-drown` `tls-alpn` |
| **HTTP** | `http-title` `http-headers` `http-server-header` `http-methods` `http-security-headers` `http-robots.txt` `http-git` `http-open-proxy` `http-cors` `http-cookie-flags` `http-webdav-scan` `http-auth` `http-internal-ip-disclosure` `http-trace` `http-generator` `http-vuln-cve2017-5638` |
| **SSH / DNS** | `ssh-hostkey` `ssh2-enum-algos` `ssh-auth-methods` `dns-recursion` `dns-nsid` `dns-zone-transfer` |
| **SMB** | `smb-os-discovery` `smb-security-mode` `smb2-security-mode` `smb-protocols` `smb-vuln-ms17-010` |
| **Databases** | `mysql-info` `mysql-empty-password` `ms-sql-info` `mongodb-info` `redis-info` |
| **Mail / FTP** | `smtp-commands` `smtp-open-relay` `imap-capabilities` `ftp-anon` `ftp-syst` |
| **Remote access** | `rdp-ntlm-info` `rdp-enum-encryption` `vnc-info` `banner` |

Every one is detection-only. The setting takes any nmap `--script` expression, so a category selector or `all` can be set instead — check it first:

```bash
nmap --script-help "<your expression>"
```

**It is off by default on purpose.** The standard profiles promise bounded, non-intrusive traffic; NSE vuln scripts actively probe rather than observe, and a scan that took 10 seconds now takes minutes. Turn it on where you would be comfortable running nmap by hand against the same target.

**On privilege.** `-sS` and `-O` need raw sockets. ReconTitan never invokes `sudo` itself — a network-facing service that shells out as root is a worse problem than the one it solves. Without the privilege it uses `-sT`, says so in the report, and gives you the fix:

```bash
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

That grants nmap the one capability it needs and leaves the scanner unprivileged.

**Not included, deliberately.** Decoy scanning (`-D`), fragmentation (`-f`), `--data-length`, `--ttl`, `--source-port` and user-agent spoofing find nothing extra — they exist to defeat attribution and evade intrusion detection. Decoys forge the source address, so the target's logs implicate machines with no part in the scan. The `exploit` NSE category is excluded for the same reason: it attempts exploitation, which would contradict this tool's guarantee that every finding is candidate-graded and nothing is modified. Run nmap directly if an engagement genuinely calls for them.

### AI explanations

AI explanations run through a local [Ollama](https://ollama.com) model by default — **findings never leave your machine** unless you explicitly choose `openai`. Without any provider, summaries fall back to a deterministic template, so the report is never blank.

| `AI_PROVIDER` | Behaviour |
|---|---|
| `auto` | Use Ollama if reachable, otherwise the deterministic template |
| `ollama` | Local model only |
| `openai` | Sends finding text to OpenAI — an explicit, opt-in choice |
| `none` | Deterministic template only |

Setup guide: **[`docs/OLLAMA_SETUP.md`](docs/OLLAMA_SETUP.md)**

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## API reference

Interactive docs are served at **`/api/docs`** whenever `RECONTITAN_DEBUG=true`. They are disabled in production on purpose.

If `API_ACCESS_KEY` is set, **every** `/api/` route requires the header:

```
X-ReconTitan-Key: <your key>
```

### Core endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/health` | Liveness — returns app name, status and version |
| `GET` | `/api/capabilities` | Available modules, scan profiles, Danger Mode state and the acknowledgement phrase |
| `POST` | `/api/scan` | Start a scan |
| `GET` | `/api/scan/{scan_id}/status` | Progress and live log |
| `POST` | `/api/scan/{scan_id}/cancel` | Stop a running scan |
| `GET` | `/api/scan/{scan_id}/report` | Full structured JSON report |
| `GET` | `/api/scan/{scan_id}/report.pdf` | PDF export |
| `POST` | `/api/report/pdf` | Render a PDF from a supplied report body |
| `GET` | `/api/rescan` | Re-run a single module against an existing scan |
| `GET` · `POST` | `/api/triage` | Read and record finding decisions |
| `POST` | `/api/verify` | Mark a finding verified |
| `POST` | `/api/ai/explain` · `/api/ai/explain-finding` | AI explanation for a scan or a single finding |
| `GET` | `/api/news` · `/api/news/refresh` | Security news feed |

### Starting a scan

```bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_type": "full"}'
```

| Field | Type | Notes |
|---|---|---|
| `target` | string, 3–253 chars | **Required.** Public domain or IP — `example.com`, `1.1.1.1` |
| `scan_type` | enum | `full` (default) · `recon_only` · `osint_only` · `vuln_only` · `danger` |
| `danger_acknowledgement` | string | **Required when `scan_type=danger`.** Must equal the phrase published by `GET /api/capabilities` |

### Fetching the report

```bash
curl http://127.0.0.1:8000/api/scan/<scan_id>/report
```

### Checking the deployment is healthy

```bash
curl http://127.0.0.1:8000/api/health
```

```json
{"status":"healthy","app":"ReconTitan","version":"0.5.0"}
```

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Project structure

```
ReconTitan/
│
├── backend/
│   ├── app/
│   │   ├── main.py            FastAPI public application
│   │   ├── config.py          Settings — every knob, read from .env
│   │   ├── database.py        MongoDB access (optional at runtime)
│   │   ├── targeting.py       SSRF guard — refuses private/internal targets
│   │   ├── preflight.py       Config audit; exits non-zero on unsafe settings
│   │   ├── celery_app.py      Queued scans (Docker)
│   │   │
│   │   ├── routers/           scans · reports · triage · ai · news · capabilities
│   │   ├── tasks/             recon/ · osint/ · vulnscan/ · ai_analysis · scan_tasks
│   │   ├── services/          attack_paths · triage · danger_mode · pdf_report
│   │   │                      alerts · audit · blocklist · detections
│   │   ├── models/            Pydantic request and response schemas
│   │   ├── middleware/        security — rate limiting, anti-injection
│   │   └── admin/             SOC console — a SEPARATE ASGI app
│   │
│   └── tests/                 39 test modules, 650 backend cases
│
├── frontend/
│   ├── index.html             Scan panel and landing page
│   ├── report.html            The report — three tabs
│   ├── report.js              Card rendering and evidence modals
│   ├── attack-paths.js        Attack-path correlation view
│   ├── attack-surface-tree.js Node-link attack surface tree
│   ├── triage.js              Review decisions
│   ├── findings-explorer.js   Filtering and search
│   ├── scan-progress.js       Live log streaming
│   ├── admin.html/.js/.css    SOC console UI
│   └── tests/                 48 Node test cases
│
├── docs/
│   ├── DANGER_MODE.md         The active-testing contract in full
│   ├── DEPLOYMENT.md          Production deployment
│   ├── DESIGN.md              Design decisions and rationale
│   ├── OLLAMA_SETUP.md        Local AI setup
│   ├── VERCEL_DEPLOYMENT.md   Serverless deployment
│   ├── GITHUB_PUBLISHING.md   Release process
│   └── screenshots/           Checked-in visual evidence
│
├── api/index.py               Serverless entry point
├── nginx/ · mongo/            Reverse proxy and database config
├── docker-compose.yml         API + worker + Redis + Mongo + console
├── run_admin.py               Launch the SOC console locally
├── setup.bat · setup.sh       Guided install
├── uninstall.bat · .sh        Guided removal
└── .env.example               Annotated configuration reference
```

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Deployment

### Docker Compose — history, workers, no time limit

Use this when you want saved scan history, the SOC console, Celery workers and unbounded Danger Mode.

```bash
cp .env.example .env
```

Generate real secrets and fill them in — Compose refuses to start with blanks, deliberately:

```bash
python -c "import secrets; [print(secrets.token_urlsafe(48)) for _ in range(5)]"
```

Fill: `DOMAIN` · `CORS_ORIGINS` · `SECRET_KEY` · `API_ACCESS_KEY` · `MONGO_USER` · `MONGO_PASS` · `REDIS_PASSWORD` · `ADMIN_TOKEN`

```bash
docker compose up -d
```

Then **audit the configuration before trusting it**:

```bash
docker compose exec api python -m app.preflight
```

That exits non-zero if anything is genuinely unsafe, and reports the failures that would otherwise be silent — a missing NVD key turning rate-limited 403s into what looks like *"no CVEs found"*, or a missing Redis making a limit of 5 quietly become 5 × instance count.

The console is not routed publicly. Reach it over SSH:

```bash
ssh -N -L 9000:127.0.0.1:9000 user@your-server
```

### Other deployment targets

| Target | Guide |
|---|---|
| **Production server** | [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) |
| **Vercel / serverless** | [`docs/VERCEL_DEPLOYMENT.md`](docs/VERCEL_DEPLOYMENT.md) — entry point is `api/index.py`, config in `vercel.json` |
| **Reverse proxy** | `nginx/` holds the configuration used in front of the API |

> **Set `RECONTITAN_DEBUG=false` in production.** It disables `/api/docs` and strips error detail from responses.

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Testing

```powershell
python -c "import sys; sys.modules['service_identity']=None; import pytest; raise SystemExit(pytest.main(['-q','backend/tests','--deselect=backend/tests/test_serverless.py::test_admin_console_is_not_on_the_public_origin_on_a_server','--deselect=backend/tests/test_serverless.py::test_admin_console_is_mounted_when_serverless','--deselect=backend/tests/test_serverless.py::test_panel_probing_is_still_blocked_when_admin_is_mounted']))"
```

```bash
node --test frontend/tests/*.test.cjs
```

```
650 passed, 11 skipped, 3 deselected
48 frontend tests passed
```

<details>
<summary><b>Full release verification (Windows)</b></summary>
<br>

The release verification command also runs compilation, linting, and JavaScript syntax checks:

```powershell
python -c "import sys; sys.modules['service_identity']=None; import pytest; raise SystemExit(pytest.main(['-q','backend/tests','--deselect=backend/tests/test_serverless.py::test_admin_console_is_not_on_the_public_origin_on_a_server','--deselect=backend/tests/test_serverless.py::test_admin_console_is_mounted_when_serverless','--deselect=backend/tests/test_serverless.py::test_panel_probing_is_still_blocked_when_admin_is_mounted']))"
node --test frontend/tests/*.test.cjs
python -m compileall -q backend/app
python -m ruff check backend/app
node --check frontend/report.js
node --check frontend/attack-paths.js
```

</details>

The three deselected checks require a serverless deployment topology; the eleven skipped cases are environment-dependent integrations. The local launcher is intentionally synchronous, so Redis and Celery are not required for the verified local path.

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Release evidence

The checked-in visual evidence set lives in [`docs/screenshots/`](docs/screenshots/) and covers the landing page, scanner, report masthead, report findings, and SOC console views. **These are local application captures, not stock mockups.**

The current release was also smoke-tested against the running local service:

| Check | Result |
|---|---|
| Backend regression suite | **650 passed**, 11 skipped, 3 serverless-only checks deselected |
| Frontend Node suite | **48 passed** |
| Python compilation and lint | Passed |
| JavaScript syntax checks | Passed for report and attack-path modules |
| `/api/health` | `healthy`, version `0.5.0` |
| `/` and `/report.html` | HTTP `200` |
| `recon_only` streaming smoke test | Completed HTTP `200` stream |

This evidence is intentionally paired with candidate grading: a page showing a CVE or a possible attack path **is not presented as proof that the target was exploited**.

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Troubleshooting

The setup scripts handle most of these, but if you're installing by hand:

<details>
<summary><b>Install and environment</b></summary>
<br>

**`module 'lib' has no attribute 'GEN_EMAIL'`** — Anaconda ships a patched `pyOpenSSL` that conflicts with `cryptography`. Use a clean venv; run `conda deactivate` first.

**`The token '&&' is not a valid statement separator`** — Windows PowerShell 5.1 has no `&&`. Use `;` or Git Bash.

**`Activate.ps1 cannot be loaded`** — run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, which applies to that window only.

**Port 8000 busy** — `python -m uvicorn app.main:app --port 8080`, or find the process with `netstat -ano | findstr :8000`.

</details>

<details>
<summary><b>Scanning behaviour</b></summary>
<br>

**Console empty, history never saves** — MongoDB isn't reachable. Deliberately non-fatal: scanning continues, storage silently no-ops. Confirm with `python -m app.preflight`.

**`Open Ports: Binary not installed`** — not an error. nmap isn't on PATH, so it used the API fallback and said so.

**Danger Mode stays `LOCKED`** — all three are required: `ALLOW_DANGER_MODE=true` (**restart after changing**), the checkbox, and `I am authorized` typed exactly.

**`Malicious input blocked` on localhost** — working as designed; the SSRF guard refuses private targets. Set `ALLOW_PRIVATE_TARGETS=true` for a local lab.

**A scan seems frozen** — check the live log. If the last line is Wayback, crt.sh or NVD, it's waiting on someone else's server.

**Every CVE says `VERIFY`** — that is correct when only the product was matched, not a version. Version-confirmed matches are the only ones that can be promoted.

</details>

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## FAQ

<details>
<summary><b>Do I need MongoDB, Redis or Docker to use it?</b></summary>
<br>

No. The local launchers run synchronous scans and need none of them. MongoDB adds saved history and the SOC console; Redis and Celery add queued, time-unbounded scans. Everything else works without them — including triage, which stores decisions in a JSON file.

</details>

<details>
<summary><b>Does my scan data leave my machine?</b></summary>
<br>

Only where a check inherently requires it. Reconnaissance queries public services (crt.sh, Wayback, DNS, NVD) with the target you typed. KEV/EPSS enrichment sends **only CVE identifiers** — never the hostname, IP or evidence. AI explanations use a **local** Ollama model by default; `openai` is an explicit opt-in. Set `EXPLOIT_INTEL_ENABLED=false` and `AI_PROVIDER=none` to remove both outbound paths.

</details>

<details>
<summary><b>Why does a scan take two minutes?</b></summary>
<br>

Because it is making real requests to public services that are sometimes slow, and Danger Mode deliberately paces itself and backs off when a target signals throttling. A danger scan that finished in twenty seconds would be one that hammered the target.

</details>

<details>
<summary><b>Why won't it confirm a vulnerability?</b></summary>
<br>

Because confirming one would mean exploiting it. ReconTitan tells you what it observed and what would confirm it. Even in Danger Mode, `requires_manual_validation` is unconditionally true.

</details>

<details>
<summary><b>Can I hide findings I don't care about?</b></summary>
<br>

You can mark them `False positive` or `Accepted risk` — with a written reason, enforced by the server. They are removed from the counts but **never deleted**: they stay in the report and in every export, and a banner states how many are suppressed and why.

</details>

<details>
<summary><b>Can I scan localhost or an internal IP?</b></summary>
<br>

Not by default — the SSRF guard refuses private targets. Set `ALLOW_PRIVATE_TARGETS=true` for a local lab.

</details>

<details>
<summary><b>Is it safe to run Danger Mode against production?</b></summary>
<br>

It sends real attack traffic. It is bounded, paced and non-destructive, and it creates, modifies and deletes nothing — but it is still active testing, and it needs the same written authorisation any penetration test would. Read [`docs/DANGER_MODE.md`](docs/DANGER_MODE.md) first.

</details>

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Contributing

Contributions are welcome. See **[CONTRIBUTING.md](CONTRIBUTING.md)** for the full guide, and **[SECURITY.md](SECURITY.md)** for reporting a vulnerability in ReconTitan itself.

Before opening a pull request:

```bash
python -m compileall -q backend/app
```

```bash
python -m ruff check backend/app
```

```bash
node --test frontend/tests/*.test.cjs
```

**The one rule that is not negotiable:** a change may not weaken evidence grading. If a patch makes the tool state something more confidently than the evidence supports — promoting a `possible` step, treating KEV membership as proof a host was exploited, or letting a suppression happen without a recorded reason — it will not be merged, however useful it otherwise is. Those rules are covered by tests for exactly that reason.

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## Legal

> ### Only scan systems you own or have explicit written permission to test.

Unauthorised scanning is illegal in most jurisdictions — the **CFAA** in the US, the **Computer Misuse Act** in the UK, the **IT Act** in India. Passive reconnaissance sits in a grey area. **Danger Mode does not**: it sends active attack traffic and is unambiguously covered.

Safe targets to learn on:

- Domains you own
- Deliberately vulnerable apps you run yourself — **OWASP Juice Shop**, **DVWA**, **WebGoat**
- Bug-bounty programmes whose scope **explicitly permits** automated scanning

If you deploy this where others can reach it, scan traffic originates from **your** infrastructure. You receive the abuse report, whoever typed the domain.

<div align="right"><sub><a href="#table-of-contents">▲ back to top</a></sub></div>

---

## License

MIT — see [LICENSE](LICENSE). Copyright © 2026 Devansh Patel

<div align="center">
<br>
<sub>Built by <a href="https://github.com/D3v4nshPat3l">Devansh Patel</a></sub>
<br><br>
<sub><a href="#recontitan">▲ back to top</a></sub>
</div>
