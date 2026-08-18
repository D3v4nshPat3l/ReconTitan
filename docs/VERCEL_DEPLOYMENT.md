# Deploying ReconTitan on Vercel

ReconTitan was built as a Docker stack with a Celery worker, Redis, and
MongoDB. Vercel runs neither long-lived processes nor system packages, so this
deployment is a **reduced but genuinely working** configuration rather than the
full product. This document states exactly what changes, so a gap is a decision
you made rather than something discovered later during an engagement.

For the complete platform — every module, background scans, and the isolated
admin console — use `deploy.sh` on a VPS instead.

---

## What runs, and what does not

25 of 30 scan modules run unchanged, including **every Danger Mode stage**,
because the danger pipeline is pure HTTP.

| Area | On Vercel |
|---|---|
| Recon — WHOIS, DNS, crt.sh, Wayback, IP intel, HTTP probe | Works |
| OSINT — headers, TLS, CORS, cookies, robots, tech stack, favicon, JS analysis, takeover, threat intel | Works |
| CVE matching — NVD by CPE version range | Works |
| Danger Mode — all 20 stages, OWASP matrix, exploitation confirmation | Works |
| Reports — interactive, JSON, HTML, PDF | Works |
| SOC console | Works, with weaker isolation (see below) |
| `port_scan` (nmap), `subfinder`, `amass`, `waf_detect`, `theharvester` | **Skipped** — no system packages |
| `nuclei`, `nikto`, `sqlmap`, `dir_fuzzing` | **Skipped** — also off by default anyway |
| Background scans via `POST /api/scan` | **Refused** — no worker process exists |

`GET /api/capabilities` reports this at runtime under `runtime`, listing which
modules are unavailable. A skipped module is recorded as skipped rather than
returning nothing, because "found nothing" and "never ran" must not look the
same in a security report.

### Two constraints worth understanding before you commit

**Scan duration is capped by the function timeout.** `vercel.json` requests
`maxDuration: 300`, which needs a plan that permits it; the Hobby tier is
lower. A measured Danger Mode scan of `example.com` takes ~65s and fits
comfortably, but a slow target will be cut off mid-scan. On a VPS the same
scan has a 1320s budget.

**The admin console loses its structural isolation.** On a VPS the console is
bound to loopback, never proxied by nginx, and sits on a Docker network the
scanner cannot reach — there is no network path to attack. Vercel has no host,
no SSH, and no private networking, so the console is **publicly reachable and
defended by its token alone**: a 64-character secret, constant-time compared,
with escalating lockout and full audit logging. That is a strong lock on a
public door, which is not the same as no door. Choose it deliberately.

---

## 1 · Create the two managed services

Vercel provides no database and no broker. Both have free tiers.

**MongoDB Atlas** — stores scans, findings, and the audit trail. Create a free
M0 cluster, add a database user, and allow access from `0.0.0.0/0` (Vercel's
egress addresses are not fixed). Copy the connection string.

**Upstash Redis** — backs rate limiting and admin lockout. Create a database
and copy the `rediss://` URL.

Redis is **not optional here.** Rate limits and lockout counters otherwise live
in each instance's memory, and Vercel runs many instances: a limit of 5 becomes
5 per instance, and admin brute-force protection disappears because an attacker
simply retries until a fresh instance answers. Nothing errors when this is
missing — the protection just silently stops working.

## 2 · Generate secrets

```bash
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48)); print('API_ACCESS_KEY=' + secrets.token_urlsafe(48)); print('ADMIN_TOKEN=' + secrets.token_urlsafe(48))"
```

## 3 · Import the repository

In the Vercel dashboard: **Add New → Project → Import** your GitHub repo.
Leave the framework preset as *Other*; `vercel.json` supplies the build and
routing configuration.

## 4 · Set the environment variables

Under **Settings → Environment Variables**, for the Production environment:

| Variable | Value |
|---|---|
| `RECONTITAN_DEBUG` | `false` |
| `DOMAIN` | your Vercel domain, e.g. `recontitan.vercel.app` |
| `SECRET_KEY` | generated above |
| `API_ACCESS_KEY` | generated above |
| `CORS_ORIGINS` | `https://your-domain` — never `*` |
| `TRUSTED_HOSTS` | your domain |
| `MONGO_HOST` … | from the Atlas connection string |
| `MONGO_USER`, `MONGO_PASS`, `MONGO_DB`, `MONGO_AUTH_SOURCE` | from Atlas |
| `REDIS_URL` | the full `rediss://` URL from Upstash |
| `SHARED_STATE_ENABLED` | `true` |
| `ADMIN_ENABLED` | `true` |
| `ADMIN_TOKEN` | generated above |
| `ALLOW_DANGER_MODE` | `true` only for targets you are authorised to assess |
| `NVD_API_KEY` | optional but recommended — unkeyed NVD returns 403s that look identical to "no vulnerabilities found" |

`SERVERLESS` needs no value: Vercel sets `VERCEL=1` and the app detects it.

The app refuses to start in production with a default `SECRET_KEY`, wildcard
CORS, or a missing `API_ACCESS_KEY`, so a misconfiguration fails loudly rather
than serving an unprotected deployment.

## 5 · Deploy and verify

```bash
curl https://your-domain/api/health
```

```bash
curl https://your-domain/api/capabilities | python -m json.tool
```

Check the `runtime` block reports `"deployment": "serverless"` and lists the
unavailable modules. Then open the site, enter the API access key when
prompted, and run a Recon Only scan against a target you own.

The admin console is at `https://your-domain/admin/`.

## 6 · Restrict the admin console

Since the console is publicly routed in this deployment, add what isolation you
can:

- keep `ADMIN_TOKEN` long and secret; it is the only barrier
- lower `ADMIN_MAX_FAILURES` (default 5) and raise `ADMIN_LOCKOUT_SECONDS`
  (default 900)
- watch the SOC console's `admin.login_failed` counter — every attempt is
  audited, and a rising count means someone found the path
- if your plan offers Vercel Firewall or IP allowlisting, restrict `/admin`
  to your own addresses

---

## Moving to a VPS later

Nothing here forks the codebase. The same repository runs the full stack with:

```bash
./deploy.sh
```

That restores background scans, the binary-backed modules, the 1320-second
scan budget, and the loopback-isolated admin console. The only change is where
it runs.
