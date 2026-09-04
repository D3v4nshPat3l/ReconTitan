# Deploying ReconTitan

Three shapes, in increasing order of effort. Pick one.

| Shape | Needs | Async scans | Audit trail / admin console |
|---|---|---|---|
| **Local** — one process | Python 3.11+ | no (synchronous endpoint) | no, unless MongoDB is running |
| **Docker Compose** — full stack | Docker | yes (Celery workers) | yes |
| **Serverless** — Vercel | Vercel account, managed Redis + Mongo | no | yes, mounted on the public origin |

---

## A. Local development

The recommended interactive installers are `setup.bat` on Windows and
`bash setup.sh` on Linux/macOS. They use a repository-local `.venv` and force
`ASYNC_SCANS_ENABLED=false` for the launched process. This stays synchronous
even if MongoDB or Redis happens to be installed. No Celery worker is started.

For manual installation on **Windows (Command Prompt)**:

```bash
python -m venv .venv
```

```bat
.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
```

```bat
copy .env.example .env
```

```bat
set "ASYNC_SCANS_ENABLED=false"
.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --port 8000
```

On **Linux/macOS**, use a Python 3.11+ interpreter:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r backend/requirements.txt
cp -n .env.example .env
ASYNC_SCANS_ENABLED=false .venv/bin/python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

Existing `.env` files are kept. An old or incompatible `.venv` must be renamed
by the operator before setup can recreate it. On older Linux distributions,
setup stops with an explanation if configured repositories do not offer Python
3.11+; it does not add third-party repositories or accept Python 3.10.

Open <http://127.0.0.1:8000>. Scans run through the synchronous `/api/test-scan` endpoint,
so **no Redis, no Celery, and no MongoDB are required** to scan and read a report.

MongoDB is only needed for stored scan history and the admin console (section D).

> **Windows / Anaconda note.** If `python` is Anaconda's and you see
> `AttributeError: module 'lib' has no attribute 'GEN_EMAIL'`, that is a pyOpenSSL
> mismatch in that environment and the app cannot import at all. Either use a clean venv
> as above, or repair it with `pip install --upgrade "pyOpenSSL>=23.2.0"`.

---

## B. Docker Compose (recommended for a real deployment)

The supplied production stack assumes a Linux host. `deploy.sh` automates
Ubuntu 22.04/24.04 only; run it from a path such as `/opt/recontitan` using
`sudo bash deploy.sh`. Existing `.env` credentials are preserved. If database
volumes survive but `.env` is missing, restore the original credentials before
rerunning deployment. Do not generate new passwords for existing MongoDB users.

Compose enables asynchronous scans explicitly because it also starts the worker.
For a separately managed worker outside Compose, set `ASYNC_SCANS_ENABLED=true`
only after configuring MongoDB, Redis and a Celery worker consuming the queues.

### 1. Configure

```bash
cp .env.example .env
```

Generate every secret — none may be left at a default:

```bash
python -c "import secrets; [print(f'{k}={secrets.token_urlsafe(48)}') for k in ('SECRET_KEY','API_ACCESS_KEY','ADMIN_TOKEN','REDIS_PASSWORD','MONGO_ROOT_PASS','MONGO_PASS')]"
```

Minimum production set in `.env`:

```bash
RECONTITAN_DEBUG=false
DOMAIN=scanner.example.com
CORS_ORIGINS=https://scanner.example.com
SECRET_KEY=<32+ chars>
API_ACCESS_KEY=<32+ chars>
TRUSTED_HOSTS=scanner.example.com
MONGO_ROOT_USER=recontitan_root
MONGO_ROOT_PASS=<generated>
MONGO_USER=recontitan_app
MONGO_PASS=<generated>
REDIS_PASSWORD=<generated>
```

**The app refuses to start if any of these are weak or missing.** That is deliberate —
it fails closed rather than launching an unauthenticated public scanner:

```
Unsafe production configuration: SECRET_KEY must be a random value of at least 32
characters; API_ACCESS_KEY (or API_ACCESS_KEYS) must be set...; DOMAIN must be set
in production
```

### 2. Launch

Before a manual Compose launch, provide a valid TLS certificate at
`nginx/certs/fullchain.pem` and its key at `nginx/certs/privkey.pem` (or use the
Ubuntu deployment script to obtain them). Nginx cannot start without these files.
Also populate `ADMIN_TOKEN`, which Compose requires even when the console is disabled.

Danger Mode retains the project's enabled default and its typed-acknowledgement
gate. Set `ALLOW_DANGER_MODE=false` to disable the feature entirely.

```bash
docker compose up -d
```

### 3. Verify

```bash
curl -s https://scanner.example.com/api/health
```

```bash
curl -s -H "X-ReconTitan-Key: $API_ACCESS_KEY" https://scanner.example.com/api/capabilities
```

Check `runtime.binary_modules_unavailable` in that response. It lists scanner modules
skipped because their binary is absent — see
[Installing the optional scanners](../README.md#-installing-the-optional-scanners).
**A skipped module is not evidence the target is unaffected.**

---

## C. Pre-flight checklist

Work through this before exposing anything publicly.

### Must

- [ ] `RECONTITAN_DEBUG=false` — otherwise `/api/docs` is public and errors leak detail
- [ ] `SECRET_KEY`, `API_ACCESS_KEY` random, 32+ characters, never committed
- [ ] `CORS_ORIGINS` is your exact origin, never `*`
- [ ] `DOMAIN` and `TRUSTED_HOSTS` set to the real hostname
- [ ] `.env` is not in git (`.gitignore` already excludes it — confirm with `git status`)
- [ ] TLS terminated at nginx with a valid certificate
- [ ] `ALLOW_DANGER_MODE=false` unless you have written authorization for every target
- [ ] Mongo application user created, not root — see section D

### Should

- [ ] `ADMIN_TOKEN` set and the admin port **not** published publicly (loopback + SSH tunnel)
- [ ] `AUDIT_ENABLED=true` so scans are attributable
- [ ] `NVD_API_KEY` set — without one, rate limiting produces 403s that look identical to "no CVEs found"
- [ ] `API_ACCESS_KEYS` instead of one shared key, if more than one consumer
- [ ] Backups configured for the `mongo_data` volume

### Deliberate decisions

- [ ] `ALLOW_HACKERTARGET` — leave `false` unless you accept disclosing target addresses to a third party
- [ ] `AI_PROVIDER` — `ollama` keeps finding text on your host; `openai` sends it off-site

---

## D. MongoDB

### Fresh deployment

`mongo/init/01-create-app-user.js` runs automatically on first start and creates the
least-privilege application user. Nothing to do.

### Existing deployment created before that script

Mongo runs `/docker-entrypoint-initdb.d` **only when the data directory is empty**, so an
older volume has no application user and never will — it keeps running as Mongo **root**.

```bash
docker compose cp mongo/migrate-existing-deployment.js mongo:/tmp/migrate.js
```

```bash
docker compose exec -T mongo mongosh -u "$MONGO_ROOT_USER" -p "$MONGO_ROOT_PASS" --authenticationDatabase admin --eval "var APP_DB='recontitan', APP_USER='recontitan_app', APP_PASS='<password>', ROTATE=false" /tmp/migrate.js
```

Idempotent and safe to re-run. Then set `MONGO_USER` / `MONGO_PASS` /
`MONGO_AUTH_SOURCE=recontitan` and recreate `api` and `worker`.

### Local MongoDB on Windows (without Docker)

Installing MongoDB as a Windows service **requires Administrator rights**. Run this from a
terminal opened with "Run as administrator":

```bash
winget install --id MongoDB.Server --accept-package-agreements --accept-source-agreements
```

Then confirm the service is running:

```bash
powershell -Command "Get-Service MongoDB"
```

Without MongoDB the app still scans and reports normally — only stored history and the
admin console are unavailable, and every admin panel will read `MongoDB unavailable`.

---

## E. Admin SOC console

The console is a **separate ASGI application on its own port**. The public app contains no
admin routes at all, so no public-routing bug can expose it.

```bash
python run_admin.py
```

It binds to loopback. Reach a remote deployment through a tunnel, never by publishing the
port:

```bash
ssh -N -L 9000:127.0.0.1:9000 user@your-server
```

Then open <http://127.0.0.1:9000> and paste `ADMIN_TOKEN`.

Views: Overview, Threats, Event Feed, Scan Activity, **Clients**, Targets.

> **On the Clients view.** It groups requests by a hash of source address plus
> self-reported headers. Every input to that hash is client-controlled, shared behind NAT,
> and changes with browser or network. It identifies traffic patterns, **not devices or
> people**, and the console says so above the table.

---

## F. Known gaps

Honest list of what is not done, so nobody discovers these in production.

| Gap | Impact | Status |
|---|---|---|
| Container images and GitHub Action tags are not digest-pinned | A moved tag changes what you build | Dependabot reduces staleness; pin digests for high assurance |
| `subfinder`, `amass`, `theHarvester` absent from the image | Those modules skip — reported explicitly, never silent | See README |
| Rate limiting is per-process without Redis | Limits multiply by instance count | Set `REDIS_PASSWORD`/`REDIS_URL`; `SHARED_STATE_ENABLED` then activates |
| API keys have no roles, scopes, or revocation history | All-or-nothing access | Put an authenticating proxy in front if you need real identities |
| `AUDIT_REPORT.md` audits v0.3.0 | Danger Mode, admin console, serverless, and AI are **not** independently audited | Commission a fresh review before public exposure |
