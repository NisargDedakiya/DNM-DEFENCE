# Track 1 Automation Platform

An automated Managed Security Service Provider (MSSP) platform: continuous
asset discovery, vulnerability scanning, dark web/threat intel monitoring,
cloud security posture management (AWS/GCP/Azure), AI-generated reports, and
a client portal — built to let one person deliver security services to
10–15 clients without drowning in manual work. Every module from the
original spec has a real, working implementation; see [Roadmap](#roadmap)
for the honest per-module status.

**Stack:** FastAPI + PostgreSQL + Celery/Redis on the backend, React + Vite
on the frontend, real recon tools (subfinder, httpx, naabu, nuclei, amass,
nmap) run as subprocesses, Claude for AI-generated report content.

---

## Table of contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
  - [Option A — Docker (recommended)](#option-a--docker-recommended)
  - [Option B — Manual / local development setup](#option-b--manual--local-development-setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Running the tests](#running-the-tests)
- [Database migrations](#database-migrations)
- [Project structure](#project-structure)
- [Security notice](#security-notice)
- [Expanded services (Social Engineering, Mobile, Web3, AI/ML, DevSecOps)](#whats-new--track1-expanded-services-5-new-services-16-tools)
- [Advanced services (Red Team, Zero Day Research, DFIR, Hardware/IoT, Threat Hunting)](#whats-new--track1-advanced-services-5-new-services-6-tools)

---

## Prerequisites

### Option A: Docker (recommended)

This is the easiest path — Docker builds and installs every tool listed in
Option B for you, **including every optional deeper-enrichment tool**
(`apktool`/`jadx`/`trufflehog` for MOB-1, `mythril` for WEB3-1,
`kube-score`/`kubesec`/`hadolint` for DSO-4, `checksec` for IOT-1, plus a
working `binwalk` CLI for IOT-1 — see `backend/Dockerfile`'s "Optional
deeper-enrichment tools" section). All you need on your machine is:

| Tool | Version | Check with |
|---|---|---|
| [Docker Engine](https://docs.docker.com/engine/install/) | 24+ | `docker --version` |
| [Docker Compose](https://docs.docker.com/compose/install/) (plugin, `docker compose`, not the old standalone `docker-compose`) | v2 | `docker compose version` |

Each optional tool installs independently and non-fatally — a stale
release URL for any one of them logs a build-time warning and moves on
rather than failing the whole image, matching the same graceful-degrade
philosophy those tools already have at runtime (the app just skips that
one signal if the tool isn't present). Pass
`docker compose build --build-arg INSTALL_OPTIONAL_TOOLS=false` (or set it
in a `docker-compose.override.yml`) if you'd rather skip all of them for a
smaller, faster image and only use the core (always-installed) tools.

### Option B: Manual / local development setup

If you're not using Docker, install these yourself:

| Tool | Version | Why | Install |
|---|---|---|---|
| [Python](https://www.python.org/downloads/) | 3.11+ | Backend runtime | `python3 --version` |
| [Node.js](https://nodejs.org/) | 20+ | Frontend runtime | `node --version` |
| [PostgreSQL](https://www.postgresql.org/download/) | 15+ | Primary database | `psql --version` |
| [Redis](https://redis.io/docs/getting-started/installation/) | 7+ | Celery broker/result backend, per-client scan concurrency locking | `redis-server --version` |
| [Go](https://go.dev/doc/install) | 1.21+ | Only needed to build the recon tools below | `go version` |

**Security/recon tools** (installed as Go binaries, except `nmap`/`dig`
which come from your OS package manager). Every recon function degrades
gracefully and logs a warning if its tool isn't found — you don't need
all of these to run the app, just to get real scan results instead of
empty ones:

```bash
# Go-based recon tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/owasp-amass/amass/v4/...@master
nuclei -update-templates

# make sure $(go env GOPATH)/bin (usually ~/go/bin) is on your PATH
export PATH="$PATH:$(go env GOPATH)/bin"

# OS packages (Debian/Ubuntu example — adjust for your platform)
sudo apt-get install -y nmap dnsutils
```

**PDF report generation** (WeasyPrint) needs a few native rendering
libraries. Skip this if you don't need PDF/DOCX report export locally:

```bash
# Debian/Ubuntu
sudo apt-get install -y libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0 libcairo2

# macOS (Homebrew)
brew install pango cairo gdk-pixbuf
```

**Optional, only if you'll audit GCP or Azure cloud accounts** (Module 4):
the `google-cloud-storage`, `google-api-python-client`, `azure-identity`,
`azure-mgmt-*` Python packages — see the "Optional" section of
`backend/requirements.txt`. AWS auditing (`boto3`) is always installed.

**Expanded services** (Social Engineering, Mobile, Web3, AI/ML, DevSecOps —
see [What's new — Track1 Expanded Services](#whats-new--track1-expanded-services-5-new-services-16-tools)):
the primary tool for every one of the 16 new tools is a `pip install`
already in `backend/requirements.txt` (`androguard`, `slither-analyzer`,
`semgrep`, `web3`, `checkov`, `openai`, `bleach`, `jsonschema`) — nothing
extra to install for the default path. A few *optional* enrichment tools
degrade gracefully (log a warning, skip that signal) if you don't install
them (Option A/Docker installs all of these for you automatically):

| Tool | Used by | Install |
|---|---|---|
| `apktool` / `jadx` | MOB-1 (deeper Android decompilation) | [apktool](https://ibotpeaches.github.io/Apktool/install/) / [jadx](https://github.com/skylot/jadx#downloads) |
| `trufflehog` | MOB-1 (deeper secret scanning) | `pip install trufflehog` or see [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) |
| `mythril` (`myth`) | WEB3-1 (deeper Solidity symbolic execution) | `pip install mythril` (needs a solc toolchain) |
| `kube-score` / `hadolint` / `kubesec` | DSO-4 (deeper Kubernetes/Dockerfile enrichment) | see each tool's own install docs |

`echidna` (Solidity property-based fuzzing) is intentionally **not**
auto-invoked — it needs contract-specific invariant test functions that
can't be generically generated, so it stays a manual analyst step.

**Advanced services** (Red Team Operations, Zero Day Research, DFIR,
Hardware/IoT Security, Threat Hunting — see
[What's new — Track1 Advanced Services](#whats-new--track1-advanced-services-5-new-services-6-tools)):
`python-evtx` (DFIR-2 Windows EVTX parsing) and `binwalk` (IOT-1 firmware
extraction) are both already in `backend/requirements.txt`. A few more
*optional* tools degrade gracefully if you don't install them (Option A/
Docker installs `checksec` and a working `binwalk` CLI for you
automatically — see below):

| Tool | Used by | Install |
|---|---|---|
| `checksec` | IOT-1 (binary hardening enrichment on extracted ELF files) | see [slimm609/checksec.sh](https://github.com/slimm609/checksec.sh) |
| `AFL++` / `LibFuzzer` / `Boofuzz` | ZD-1 (fuzzing jobs are analyst-updated tracking records — this platform does not orchestrate live fuzzing, see below) | run these yourself; log status/crashes into the FuzzingJob tracker |

Note: the `binwalk` package on PyPI ships without its native extraction
core on some platforms — if extraction genuinely isn't available on your
system, IOT-1 automatically falls back to scanning the raw firmware
bytes directly rather than failing the analysis.

---

## Installation

### Option A: Docker (recommended)

```bash
git clone <this-repo-url>
cd DNM-DEFENCE

cp backend/.env.example backend/.env
# edit backend/.env — at minimum set ANTHROPIC_API_KEY and change SECRET_KEY
# (recon/threat-intel API keys are optional; each integration degrades
# gracefully and just skips that signal if its key is empty)

docker compose up --build
```

This starts Postgres, Redis, the FastAPI API, a Celery worker, Celery beat
(the scheduler), and the frontend dev server — and runs database
migrations automatically on startup.

```bash
# one-time: create your first admin login
docker compose exec api python -m app.scripts.create_admin you@yourcompany.com
```

- API + interactive docs: http://localhost:8000/docs (docs only mount when `ENV=development`)
- Portal: http://localhost:5173

### Option B: Manual / local development setup

**Backend:**
```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# edit .env: point DATABASE_URL at your local Postgres, set ANTHROPIC_API_KEY,
# change SECRET_KEY, set REDIS_URL if not running on localhost:6379

alembic upgrade head
python -m app.scripts.create_admin you@yourcompany.com

uvicorn app.main:app --reload
```

**Celery worker + beat scheduler** (separate terminals, same venv):
```bash
celery -A app.workers.celery_app worker --loglevel=info
celery -A app.workers.celery_app beat --loglevel=info
```

**Frontend:**
```bash
cd frontend
npm install
npm run dev
```
Visit http://localhost:5173 — it proxies `/api` requests to the backend on `:8000`.

---

## Configuration

All configuration lives in `backend/.env` (see `backend/.env.example` for
the full list with defaults). The essentials:

| Variable | Required | Purpose |
|---|---|---|
| `SECRET_KEY` | Yes | JWT signing key — the app refuses to start in non-dev mode with the placeholder value |
| `ANTHROPIC_API_KEY` | Yes | Powers AI report/digest/remediation generation |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `REDIS_URL` / `CELERY_BROKER_URL` / `CELERY_RESULT_BACKEND` | Yes | Redis connection for Celery + scan concurrency locking |
| `ENCRYPTION_KEY` | Yes (once you register any cloud account) | Fernet key encrypting stored cloud credentials — generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `ALLOWED_ORIGINS` | Yes outside dev | Comma-separated portal origin(s) for CORS |
| `SHODAN_API_KEY`, `CENSYS_API_ID`/`SECRET`, `HIBP_API_KEY`, `DEHASHED_API_KEY`, `GITHUB_TOKEN` | No | Optional threat-intel integrations — each one just skips its signal if unset |
| `SENDGRID_API_KEY`, `SLACK_BOT_TOKEN` | No | Email/Slack alert delivery — alerts are still drafted and logged without these |
| `FORCE_HTTPS`, `MFA_REQUIRED_FOR_STAFF` | No | Harden before any real deployment — see [Security notice](#security-notice) |
| `OPENAI_API_KEY` | No | SE-3 Whisper call transcription — without it, supply a transcript manually |
| `GOOGLE_CSE_API_KEY` / `GOOGLE_CSE_CX` | No | SE-1 OSINT Google dorking |
| `TELEGRAM_BOT_TOKEN` | No | WEB3-3 on-chain alert channel (in addition to Slack) |
| `ETHERSCAN_API_KEY` | No | WEB3-3 on-chain transaction/event history |
| `JIRA_BASE_URL` / `JIRA_API_TOKEN` / `JIRA_EMAIL` | No | DSO-2 ticket creation |
| `PUBLIC_API_BASE_URL` | No | Base URL used to build SE-2 phishing tracking-pixel/landing-page links — set to your real deployed API origin outside local dev |
| `ONCHAIN_POLL_INTERVAL_MINUTES` | No | WEB3-3 poll interval, default 5 minutes |

**Before deploying anywhere other than localhost**, at minimum: change
`SECRET_KEY` to a long random value, set `ALLOWED_ORIGINS` to your real
portal domain, and set `FORCE_HTTPS=true`.

---

## Usage

Once the app is running and you've created an admin account:

**1. Log in to the portal** at http://localhost:5173, or get an API token directly:
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -d "username=you@yourcompany.com&password=yourpassword" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
```

**2. Onboard a client** — this automatically queues baseline recon (subdomain
enumeration) as soon as the client is created:
```bash
curl -X POST http://localhost:8000/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Test Client","root_domain":"example.com","contact_email":"you@example.com"}'
```

**3. Check scan progress and discovered assets:**
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/clients/{client_id}/scans
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/clients/{client_id}/assets
```

**4. Trigger scans on demand** (vulnerability, dark web/threat intel, cloud
audit) and **generate an AI-drafted monthly report** — see the module
sections below for the full set of endpoints, or just drive it all from the
portal UI at `/clients/{client_id}`, which has one-click buttons for each.

**5. Explore the full API** at http://localhost:8000/docs (Swagger UI,
dev mode only) — every router is documented with its auth/tenant-isolation
behavior.

> **Important — authorized scanning only.** Only ever scan domains you have
> explicit written authorization for (a signed client scope agreement, or
> your own test targets like OWASP Juice Shop / `scanme.nmap.org`). Active
> scanning (naabu full-range port scans, brute-force subdomain enumeration,
> nuclei's `default-logins` credential checks) against domains you don't
> control is illegal.

---

## Running the tests

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

Tests run against an isolated sqlite DB (no Postgres/Redis required), so
this works standalone without `docker compose up`. `pytest tests/ -v --cov=app --cov-report=term-missing`
adds a coverage report, matching what CI runs.

## Database migrations

```bash
cd backend
alembic revision --autogenerate -m "describe your change"
alembic upgrade head
```

`docker-compose`'s `api` service runs `alembic upgrade head` automatically
on every start, so this only matters when you've changed a model and need
to generate the migration for it. Autogenerate against sqlite produces
spurious `NUMERIC`→`UUID` noise on every id/foreign-key column (sqlite has
no native UUID type) — safe to drop from the generated migration file; see
the comment in `backend/alembic/versions/8d2b7ca2c7e3_add_risk_analysis.py`.

## Project structure

```
backend/
  app/
    api/            FastAPI routers (one per resource: clients, assets, findings, ...)
    core/           auth, config, db session, crypto, rate limiting, audit logging
    models/         SQLAlchemy models (single models.py, all entities)
    schemas/        shared Pydantic schemas (routers also define local *Out/*Update models)
    services/       one file per module — the actual business logic (recon.py, vuln_scan.py,
                     threat_intel.py, cspm.py, ai_reports.py, compliance.py, notifications.py, ...)
    workers/        Celery app + tasks.py (every scheduled/triggered background job)
    templates/      Jinja2 templates for report HTML→PDF rendering
  alembic/          database migrations
  tests/            pytest suite — one file per feature area, mocked external calls
  loadtest/         Locust scenarios
frontend/
  src/
    api/client.js   the only file that talks to the backend — thin axios wrappers
    pages/          one component per portal page (Dashboard, Assets, Findings, ...)
    components/     shared UI pieces (SeverityBadge, RiskScoreRadial, ...)
packages/
  llm-output-sanitizer/   standalone pip-installable package (AI-3) — its own
                          pyproject.toml, README, and test suite; not a
                          dependency of the main platform, dogfooded via a
                          lazy import in app/services/ai_reports.py
```

Each module maps directly to a file in `app/services/` and a set of Celery
tasks in `app/workers/tasks.py` — follow the pattern already set by
`services/recon.py`, `services/threat_intel.py`, and `services/cspm.py`.

## Security notice

This platform is itself a security tool — it performs active scanning,
stores client credentials, and handles sensitive findings data. Before any
real deployment:

- Change `SECRET_KEY` from the placeholder; set `ENCRYPTION_KEY`.
- Set `FORCE_HTTPS=true` and `ALLOWED_ORIGINS` to your real domain(s).
- Only register **read-only** cloud credentials (AWS `SecurityAudit`/
  `ReadOnlyAccess` managed policy, or the GCP/Azure equivalents) — never
  give this platform write access to a client's cloud account.
- Only scan domains under a signed authorization/scope agreement.

## What's new in this update — Module 2

- `app/services/vuln_scan.py` — wraps `nuclei`, parses JSONL output into
  `Finding` rows with severity, CVSS (nuclei's score, or a severity-band
  default when it's missing), CVE ID, and business-context-adjusted score
- Dedup engine: `dedup_hash = sha256(client_id + template_id + matched_at)`
  — the same vuln on the same host across scan runs never creates a
  duplicate row
- Re-scan verification (Feature 2.4): findings marked `in_remediation`
  that don't reappear in the next scan are auto-flipped to `verified`
  with a `resolved_at` timestamp
- SLA deadlines are set per-finding from the client's `sla_hours_critical`
  / `sla_hours_high` fields at creation time
- `check_default_credentials()` — conservative, non-exploitative check for
  exposed Jenkins/Grafana/phpMyAdmin panels (Feature 2.2), not yet wired
  into the scheduled task
- New endpoints: `GET/PATCH /api/clients/{id}/findings`,
  `POST /api/clients/{id}/findings/scan`
- `nuclei` now installs in the Docker image alongside the other recon tools

Try it:
```bash
curl -X POST http://localhost:8000/api/clients/{client_id}/findings/scan
curl http://localhost:8000/api/clients/{client_id}/findings?severity=critical
```

## What's new in this update — Module 3

- `app/services/threat_intel.py` — HIBP breach domain search (Feature 3.1),
  GitHub code-search-based secret leak detection (Feature 3.2), AlienVault
  OTX blocklist correlation for client IPs (Feature 3.3)
- Each hit becomes a `Finding` (breaches → high severity, GitHub leads →
  high, blocklist hits → medium), deduped per-source so re-scans don't
  spam duplicates
- Every check degrades gracefully and logs a warning if its API key isn't
  set (`HIBP_API_KEY`, `GITHUB_TOKEN`) — the platform still runs, it just
  skips that signal
- New daily beat schedule entry + `POST /api/clients/{id}/findings/dark-web-scan`
- **Not implemented**: paste-site/dark-web crawling and ransomware-blog
  monitoring — these need a paid feed (Flare, DarkOwl) or Tor infra. There's
  a documented extension point at the bottom of `threat_intel.py` for when
  you pick one.

Try it:
```bash
curl -X POST http://localhost:8000/api/clients/{client_id}/findings/dark-web-scan
```

## What's new in this update — Module 4

- `app/core/crypto.py` — Fernet encryption for cloud credentials. Generate
  a key and put it in `.env` before registering any cloud account:
  ```bash
  python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
  ```
- `app/services/cspm.py` — AWS auditing (Feature 4.1): S3 public
  bucket/ACL/encryption checks, IAM (root MFA, user MFA, stale access
  keys >90 days), security groups (0.0.0.0/0 on 22/3389/3306/5432), EBS/RDS
  encryption gaps, RDS public accessibility, CloudTrail logging status,
  GuardDuty enablement
- New endpoints: `POST /api/clients/{id}/cloud-accounts` (register a
  read-only AWS account), `POST /api/clients/{id}/cloud-accounts/audit`
- **Not implemented**: Feature 4.2 (GCP/Azure auditing) and Feature 4.3
  (configuration drift detection / baseline snapshots) — extension point
  documented at the bottom of `cspm.py`

Try it:
```bash
curl -X POST http://localhost:8000/api/clients/{client_id}/cloud-accounts \
  -H "Content-Type: application/json" \
  -d '{"provider":"aws","account_identifier":"123456789012","access_key_id":"AKIA...","secret_access_key":"...","region":"us-east-1"}'

curl -X POST http://localhost:8000/api/clients/{client_id}/cloud-accounts/audit
```

**The registered IAM user must be read-only** — attach AWS's `SecurityAudit`
or `ReadOnlyAccess` managed policy, never anything with write permissions.

## What's new in this update — Module 5

- `app/services/ai_reports.py` — the full pipeline: gather this month's
  findings from the DB → Claude API writes a plain-English executive
  summary (from aggregate counts/titles only, never raw evidence) →
  Jinja2 renders an HTML report → WeasyPrint exports PDF → python-docx
  exports an editable Word version
- New `Report` table: stores exec summary, risk score snapshot, file
  paths, and a `share_token` for read-only links (Feature 6.5)
- Risk score (0–100) computed from open finding severity counts, shown
  as a colored badge at the top of the report
- Feature 5.2 — `draft_alert_for_finding` drafts a client-facing alert for
  a single finding, logged for review (auto-send/email delivery not wired
  yet — see roadmap)
- Feature 5.3 — weekly digest task generates a plain-English digest per
  client from their 10 most recent findings (Monday 7 AM beat schedule)
- New endpoints:
  `POST /api/clients/{id}/reports/generate`,
  `GET /api/clients/{id}/reports`,
  `GET /api/clients/{id}/reports/{report_id}/pdf|docx`,
  `GET /api/shared-reports/{share_token}/pdf` (no auth — unguessable
  token only, matches the "share link for investors/auditors" spec)

Try it:
```bash
curl -X POST http://localhost:8000/api/clients/{client_id}/reports/generate
# wait a few seconds for the Celery worker to finish
curl http://localhost:8000/api/clients/{client_id}/reports
curl http://localhost:8000/api/clients/{client_id}/reports/{report_id}/pdf -o report.pdf
```

**Not implemented**: actual email/Slack delivery of alerts and digests
(currently logged, not sent) — needs SendGrid/Slack webhook wiring, which
is a small addition once you're ready for it.

## What's new in this update — Module 6

- `frontend/` — React + Vite + Tailwind client portal, dark security-ops
  aesthetic (near-black base, amber signal accent, IBM Plex Sans/Mono)
- **Feature 6.1** Overview page: radial risk-score badge, open findings
  by severity, one-click scan triggers, recent alerts, scan history
- **Feature 6.2** Asset Inventory: full table of discovered assets with
  liveness status and last-seen timestamps
- **Feature 6.3** Vulnerability Tracker: filterable by severity,
  expandable rows with remediation guidance, client-side status updates
  (acknowledge / in remediation / resolved / disputed) that PATCH the API
- **Feature 6.5** Report Library: lists generated reports, PDF/DOCX
  download links, generate-on-demand button, share-link display
- **Not implemented**: Feature 6.4 (Compliance Center — SOC 2/ISO
  27001/DPDP checklists) and Feature 6.6 (Phishing Simulation Dashboard) —
  both need backend data models that don't exist yet (no compliance
  tracking or phishing campaign tables built so far)

Run it:
```bash
cd frontend && npm install && npm run dev
# or via docker compose up --build (frontend service already wired in)
```
Visit http://localhost:5173 — proxies `/api` to the backend on :8000.

## What's new in this update — closing all deferred items

- **GCP/Azure CSPM auditing** — `cspm.py` now has `audit_gcp()` (public
  Cloud Storage buckets, firewall rules open to 0.0.0.0/0 on sensitive
  ports, public Cloud SQL IPs) and `audit_azure()` (public Blob Storage,
  open NSG inbound rules). `run_cloud_audit()` dispatches by provider.
  Cloud SDKs are listed as optional deps in `requirements.txt` — install
  only what you need.
- **Cloud asset discovery (Feature 1.4)** — `discover_aws_assets()`
  enumerates EC2/S3/RDS/Lambda and upserts them into the same `Asset`
  table subdomains live in, so cloud resources show up in the portal's
  Asset Inventory too.
- **Config drift detection (Feature 4.3)** — `CloudAccount.config_baseline`
  stores a resource→issues snapshot after every audit; the next audit
  diffs against it and raises a `Finding` for anything newly exposed that
  wasn't there before (fixes don't count as drift — only new exposure does).
- **Email/Slack delivery** — `app/services/notifications.py` sends via
  SendGrid (email) and per-client Slack webhooks. Alert drafting,
  weekly digests, and SLA breach detection now actually send — except
  critical alert auto-send, which stays opt-in: needs both the platform
  flag `AUTO_SEND_CRITICAL_ALERTS=true` AND the client's own
  `auto_send_critical_alerts=true`. Otherwise alerts are drafted +
  logged, sendable manually via `POST /findings/{id}/send-alert`.
- **Phishing Simulation Dashboard (Feature 6.6)** — `PhishingCampaign` +
  `PhishingResult` models, full CRUD API, and a portal page with
  click/report/credential-submission rates and an awareness trend
  indicator. This tracks results — it does not send phishing emails
  itself (needs a dedicated sending domain kept separate from prod mail
  to protect deliverability). Point an external tool like GoPhish at
  `POST /phishing-campaigns/{id}/results` as a webhook, or import a CSV.
- **Pentest scheduling** — still genuinely stubbed. No `PentestSchedule`
  model exists; this is the one item with no partial implementation,
  since it needs a scheduling UI decision (recurring quarterly? per-client
  custom dates?) before the data model makes sense.

Try the new pieces:
```bash
# GCP/Azure account registration uses the same endpoint, different fields
curl -X POST http://localhost:8000/api/clients/{client_id}/cloud-accounts \
  -d '{"provider":"gcp","account_identifier":"my-project","service_account_json":{...}}'

# Manual alert send after reviewing the AI draft
curl -X POST http://localhost:8000/api/clients/{client_id}/findings/{finding_id}/send-alert

# Phishing campaign
curl -X POST http://localhost:8000/api/clients/{client_id}/phishing-campaigns \
  -d '{"name":"Q3 IT Reset Test","template_name":"IT password reset","target_count":40}'
```

## What's new in this update — Closing Production Operations

The last genuinely open items were all in "production operations." Closed
what's actually buildable as code; flagged what isn't.

- **Load/performance testing** (`backend/loadtest/locustfile.py`) —
  Locust scenarios simulating realistic portal traffic (dashboard checks,
  findings lookups, not just hammering one endpoint), plus a dedicated
  auth-stress scenario. **Actually run against a live server, not just
  written**: 10 concurrent users, 15 seconds, real uvicorn instance.
  Results: legitimate endpoints (`/health`, `/api/clients`) had 0%
  failure; the login-stress scenario correctly got rate-limited (66/70
  rapid attempts returned 429) — concrete proof the rate limiter holds
  under real concurrency, not just sequential test calls. Run it yourself:
  `locust -f backend/loadtest/locustfile.py --host http://localhost:8000`
- **Backup restore verification** — `backup_postgres.sh` now spins up a
  throwaway Postgres container, restores the just-created backup into
  it, confirms 10+ tables came back, then discards the container. A
  backup that exists on disk but doesn't actually restore is worse than
  no backup (false confidence) — this catches that.
- **API documentation refinement** — real OpenAPI description, per-tag
  descriptions for every router (auth, clients, assets, findings, cloud,
  reports, compliance, phishing, pentest, audit), and documented
  authentication/tenant-isolation/rate-limit behavior at the top level so
  `/docs` is actually useful to someone integrating against this API.
- **Platform self-testing (the practical form of "pentest yourself")** —
  a real external penetration test needs a human and isn't something to
  fake here, but expanded the automated security suite with what
  automated testing *can* catch: an **IDOR test** (confirmed a finding
  belonging to client A cannot be touched via client B's URL — returns
  404, not leaked data), a **mass-assignment test** (confirmed
  `auto_send_critical_alerts`/`is_active` can't be set through the
  onboarding schema even though they exist on the model), a password-
  exposure check, and a malformed-input handling check. **24/24 tests
  passing**, up from 20.

**Genuinely still not code-buildable, flagged rather than faked**:
- Grafana dashboards — need your real traffic patterns from Prometheus
  once it's been running against production traffic for a while; a
  generic dashboard template would be closer to theater than a real tool
- A real external penetration test — hire someone or run OWASP ZAP/Burp
  against a staging deployment; this is a different discipline than
  writing more application code, and claiming to have "pentested" the
  platform via automated unit tests would be a meaningfully overstated
  claim

## What's new in this update — Real Tool Depth + AI Expansion

Addressing the specific gap flagged: real tool integration beyond the
lighter substitutes used earlier, deeper threat intel, and AI going
beyond report-writing into remediation and risk analysis.

- **Nmap** — `-sV` service/version detection, run as an enrichment pass
  on hosts naabu already found open ports on (naabu stays the primary
  port *discovery* tool since it's much faster at scale; nmap adds the
  detail naabu doesn't capture). Feeds `Port.service_version`.
- **Wappalyzer** — real signature-database tech fingerprinting via
  `python-Wappalyzer`, as a deeper complement to httpx's built-in
  `-tech-detect` (which stays as the fast default; Wappalyzer's database
  catches more but is slower).
- **SSLyze** — real TLS configuration scanning (weak protocols/ciphers),
  distinct from the stdlib-`ssl` expiry check already in
  `dns_ssl_monitor.py` (which handles cert expiry; SSLyze handles
  protocol/cipher strength).
- **Shodan + Censys** — host exposure lookups against both indexes (they
  don't fully overlap). Shodan hits tagged with CVEs become high-severity
  findings; unremarkable exposure becomes low-severity awareness findings.
- **Abuse.ch (ThreatFox)** — free, no-key-required IOC lookup. An IP
  tagged here is a stronger signal than a generic blocklist hit, so it's
  scored critical rather than medium.
- **IOC correlation** — the dark web scan task now resolves A records for
  live subdomains (not just pre-populated `AssetType.ip` rows, which are
  usually empty) so Shodan/Censys/Abuse.ch actually have IPs to check
  against, capped at 30 per run to keep external API volume sane.
- **AI-generated remediation** — `POST /findings/{id}/ai-remediation`
  generates finding-specific guidance via Claude, distinct from the
  static per-issue templates (which remain as the always-available
  fallback if the AI call fails — this is additive, not a replacement).
- **AI risk analysis** — monthly reports now include a second, more
  technical narrative alongside the plain-English executive summary:
  what pattern connects this month's top findings, which one poses the
  most realistic business risk, and what to prioritize next. New
  `Report.risk_analysis` column, rendered in both PDF and DOCX.

**Verified**: full test suite still passes (20/20) after these changes;
generated a new Alembic migration for `Report.risk_analysis` and
hand-trimmed it after autogenerate produced ~50 lines of spurious
NUMERIC→UUID noise (a known sqlite-vs-custom-type quirk in autogenerate
— worth knowing about if you generate migrations locally against sqlite
before applying to Postgres).

**Still honestly not done**, because they're either infrastructure
choices or need a decision only you can make: IOC database as a proper
first-class model (currently correlation happens inline per-scan rather
than persisting a queryable IOC table — worth building if you want a
dedicated Threat Dashboard), EPSS/KEV catalog enrichment on top of CVE
data (needs picking a data source and refresh cadence), and Teams/
Discord/SMS notification channels (same pattern as email/Slack, just
needs API credentials for whichever you actually want).

## What's new — Production Readiness

- **Alembic migrations** — real schema migrations instead of relying on
  `create_all` (which only ever ran in dev mode anyway). Initial migration
  generated and verified: applies cleanly, creates all 13 tables correctly.
  `docker-compose`'s `api` service now runs `alembic upgrade head` before
  starting uvicorn. Going forward: `alembic revision --autogenerate -m "..."`
  after any model change, then `alembic upgrade head`.
- **Automated tests** — 20 tests covering auth (login, lockout, the
  timing-attack fix), tenant isolation (client A genuinely cannot read
  client B's data — this was flagged as untested in the last audit), and
  the SSRF fix. All passing. `cd backend && pytest tests/ -v`
- **CI pipeline** (`.github/workflows/ci.yml`) — runs the test suite with
  coverage, checks for model changes missing a migration, lints
  (non-blocking for now), builds the frontend, and builds both Docker
  images, on every push/PR to `main`/`develop`.
- **Sentry** — optional (`SENTRY_DSN` in `.env`; leave empty to disable).
  Captures unhandled exceptions with FastAPI + SQLAlchemy context.
  `send_default_pii=False` explicitly, since this app handles client
  security data — request bodies/headers are never sent to Sentry.
- **Prometheus metrics** — `/metrics` endpoint (request counts, latency
  histograms, in-progress requests), verified returning real data. Point
  a Prometheus scrape config at it; wire up Grafana dashboards on your
  end once you have metrics flowing somewhere.
- **Real health checks** — `/health` now actually queries the database
  instead of just confirming the process is running, and returns 503 if
  the DB is unreachable — the difference between a load balancer knowing
  the API is degraded vs. happily routing traffic to a broken instance.
- **Backup/restore scripts** (`scripts/backup_postgres.sh`,
  `restore_postgres.sh`) — `pg_dump` + gzip + retention pruning, meant for
  a cron job. Documented rather than hardcoded because backup destination
  (S3/GCS/local) varies per deployment.

**Verified, not just written**: ran the full pytest suite (20/20 passing),
generated and applied the Alembic migration against a real sqlite DB and
confirmed all tables appear, hit `/metrics` and confirmed real Prometheus
output, validated the docker-compose YAML.

**Deliberately not done** (infra/ops decisions, not app code):
- Grafana dashboards themselves — you'll want to build these around your
  actual traffic patterns, not a generic template
- Zero-downtime deployment — depends on your hosting choice (blue-green
  on a VM, rolling update on k8s, etc.); the app itself has no state that
  blocks this (stateless API + Celery workers), so it's a deploy-config
  question, not a code one
- CI currently builds Docker images but doesn't push/deploy anywhere —
  add that once you've picked a registry and target environment

## What's new — Self Security Audit

Actually reviewed the code for exploitable issues (not a features
checklist this time) and fixed what I found:

- **SSRF via Slack webhook** *(real vulnerability, now fixed)* —
  `Client.slack_webhook_url` was passed straight to a server-side
  `httpx.post()` with no validation. A malicious or careless value
  (e.g. `http://169.254.169.254/latest/meta-data/`, the AWS metadata
  endpoint) would have made the server issue that request. Now validated
  at the schema level: only genuine `https://hooks.slack.com/services/...`
  URLs are accepted. **Verified**: a metadata-endpoint URL now gets
  rejected with 422 before it's ever stored.
- **User-enumeration via login timing** *(real vulnerability, now fixed)*
  — the login endpoint skipped the bcrypt comparison entirely when the
  email didn't exist, making "wrong password" and "no such account"
  distinguishable by response time. Added a constant-time path that
  always runs a real bcrypt comparison (against a dummy hash when no
  user exists). **Verified**: response times for existing vs.
  non-existent accounts are now within noise of each other.
- **Stack trace / internal error leakage** — added a catch-all exception
  handler; any unhandled server error now returns a generic `{"detail":
  "Internal server error"}` instead of whatever FastAPI's default error
  page would show, while the full trace still goes to server-side logs.
  **Verified**: an actual runtime error in testing produced the clean
  generic response, not a leaked trace.
- **Insecure defaults reaching production** — the app now refuses to
  start outside `ENV=development` if `SECRET_KEY` is still the
  placeholder value, `ENCRYPTION_KEY` is unset, or `ALLOWED_ORIGINS`
  is empty (previously that last case silently fell back to allowing
  any Host header). Fail closed instead of fail open.
- **Interactive API docs exposed in production** — `/docs`, `/redoc`,
  and `/openapi.json` now only mount when `ENV=development`. A public API
  schema is a reconnaissance gift; no reason to ship it live.
- **bcrypt's silent 72-byte truncation** — passwords are now explicitly
  truncated to 72 bytes before hashing/verifying (matching bcrypt's real
  limit) instead of relying on the library's silent behavior, and the
  registration schema's `max_length` was tightened to match.
- **MFA code brute-forcing** — `/mfa/confirm` had no rate limit; a
  6-digit TOTP code is only ~1 million possibilities. Now capped at
  10 attempts/minute.
- **HTTPS enforcement** — `FORCE_HTTPS=true` now actually redirects
  HTTP→HTTPS (`HTTPSRedirectMiddleware`), not just adding the HSTS header
  as before.

**What I checked and found already handled correctly** (worth noting so
it's clear this wasn't a rubber-stamp pass): SQL injection (SQLAlchemy
ORM throughout, no raw string interpolation into queries), JWT algorithm
confusion (algorithm is hardcoded on both sign and verify), mass
assignment (every `model_dump()` call maps to a schema with an explicit
field allow-list, not raw request bodies), path traversal on report
downloads (file paths come from DB lookups by UUID, never from user
input), tenant isolation (`require_client_access`, built and tested
earlier), CORS wildcard (removed several rounds ago), rate limiting and
brute-force lockout (already in place).

**What's still worth doing, flagged rather than silently skipped**:
- `X-Forwarded-For` isn't trusted for rate-limiting if you put this
  behind a reverse proxy/load balancer — configure `slowapi`'s
  `key_func` for your specific proxy setup once you know it (Cloudflare,
  ALB, and nginx each expose the real client IP differently)
- Report `share_token` links don't expire — fine for now since they're
  unguessable (24 bytes of entropy), but add an `expires_at` check if
  these ever get shared outside a controlled audience
- No token revocation/logout endpoint — a stolen JWT is valid until its
  12-hour expiry with no way to kill it early. Worth a token blocklist
  (Redis, since it's already in the stack) before this handles anything
  sensitive at scale

## What's new — Audit Report Follow-ups

An external audit of the platform flagged real gaps in the Security
Review section (most of the "missing security services" it listed were
already built in earlier rounds — see the module status table below).
Closed the genuine gaps:

- **Audit logging** — every non-GET API request is logged automatically
  (method/path/status/user/IP) via middleware, plus explicit richer
  entries (`auth.login_success`, `auth.login_failed`, `user.create_staff`,
  etc.) from sensitive endpoints. Read-only `GET /api/audit-logs`
  (admin-only, filterable by client/user/action) — no delete/edit
  endpoint exists for this table on purpose.
- **MFA enforcement** — TOTP (Google Authenticator-compatible) via
  `pyotp`. `POST /api/auth/mfa/enroll` returns a QR code, `/mfa/confirm`
  activates it. Once enabled, login requires `password:code` in the
  password field (kept OAuth2-form-compatible rather than adding a
  non-standard field). `MFA_REQUIRED_FOR_STAFF=true` makes it mandatory
  for admin/analyst accounts.
- **API key rotation** — `CloudAccount.credentials_rotated_at` tracked on
  every registration; `POST /cloud-accounts/{id}/rotate-credentials`
  replaces stored creds and resets the clock; a weekly task flags any
  account that hasn't rotated within `CLOUD_CREDENTIAL_ROTATION_DAYS`
  (default 90)
- **DNS monitoring** — daily task diffs A/MX/NS/TXT records against a
  stored baseline; a changed A or NS record raises a critical finding
  (the classic DNS hijacking signal)
- **SSL certificate monitoring** — same daily task checks every live
  host's TLS cert for expiry (30-day warning window) and unreachability
- **Amass integration** — now runs alongside subfinder on every
  subdomain enum (passive mode only); results are merged and deduped,
  since the two tools' data sources only partially overlap

**Verified live**, not just compiled: ran the app with `TestClient`,
confirmed audit logs actually populate on login, MFA enrollment returns a
working QR/secret, and 6 rapid bad-password attempts correctly hit the
rate limiter before the lockout logic even engages.

**Not code — infrastructure/ops decisions the audit also flagged**:
- **Secrets management** — cloud credentials are Fernet-encrypted in the
  DB (already built), which is reasonable for this scale; a dedicated
  secrets manager (AWS Secrets Manager, Vault) is a deployment-time
  upgrade, not something to hardcode into the app
- **SIEM integration** — the audit log table is the source; piping it to
  a SIEM (Splunk, Elastic, Datadog) is a log-shipper configuration once
  you pick one, not app code
- **WAF compatibility** — the app doesn't need code changes for this;
  it's a reverse-proxy/CDN layer (Cloudflare, AWS WAF) you'd put in
  front of it
- **Backup and disaster recovery** — a PostgreSQL backup/replication
  policy on whatever you host on, not something the app itself does
- **Tenant isolation testing** — `require_client_access` is the
  mechanism (built two rounds ago); writing automated tests that try to
  break it is the next real step here, not new app code

## What's new — Security Hardening

Seven concrete gaps closed, all verified with a live smoke test (health
check, security headers, auth gate, CORS) before packaging:

- **API rate limiting** — `slowapi`, default 100 req/min per IP across
  the whole API (`RATE_LIMIT_DEFAULT`), returns a clean 429 JSON response
  instead of a stack trace when exceeded
- **Brute-force protection** — login is rate-limited tighter
  (`RATE_LIMIT_LOGIN`, default 5/min) AND has per-account lockout:
  5 consecutive failed logins locks that account for 15 minutes
  (`LOGIN_LOCKOUT_ATTEMPTS`/`LOGIN_LOCKOUT_MINUTES`), independent of IP —
  this stops slow, distributed credential-stuffing that a pure IP rate
  limit wouldn't catch
- **CSP + security headers** — `SecurityHeadersMiddleware` adds
  `Content-Security-Policy: default-src 'none'` (this is a JSON API, not
  server-rendered HTML — nothing should execute), `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`,
  and HSTS when `FORCE_HTTPS=true`
- **Request validation** — password fields now enforce min/max length at
  the schema level (`Field(min_length=8, max_length=128)`), and a
  middleware rejects any request body over 5MB before it's even parsed
- **API versioning** — `X-API-Version` response header on every request,
  driven by `settings.API_VERSION`. Full path-based versioning
  (`/api/v2/...`) is a bigger refactor across every router's prefix —
  noted as a follow-up, not done here, since it'd touch every file for no
  functional gain until there's an actual v2 to ship
- **Better CORS** — replaced the hardcoded `localhost:5173` with an
  explicit allow-list from `ALLOWED_ORIGINS` (comma-separated in `.env`),
  scoped `allow_methods`/`allow_headers` instead of wildcards, plus
  `TrustedHostMiddleware` outside dev mode

**Before deploying anywhere other than localhost**: set `ALLOWED_ORIGINS`
to your real portal domain, set `FORCE_HTTPS=true`, and change
`SECRET_KEY` to a long random value — none of the defaults in
`.env.example` are safe to ship as-is.

## What's new — Authentication & Authorization

Every API endpoint (except the health check and the public share-link PDF
download) now requires a valid JWT. This was the biggest real gap in the
platform — everything up to this point ran with zero access control.

- **Three roles**: `admin`/`analyst` (your team, full access across all
  clients) and `client` (a client's own portal user, hard-scoped to their
  `client_id` — enforced server-side via `require_client_access`, not
  just hidden in the UI)
- **Tenant isolation**: every `/api/clients/{client_id}/...` router now
  carries `dependencies=[Depends(require_client_access)]`, so a
  client-role user's token literally cannot read another client's data
  no matter what URL they construct
- Passwords hashed with bcrypt; tokens are 12-hour JWTs (HS256, signed
  with `SECRET_KEY` — **change this in `.env` before any real deployment**)
- New endpoints: `POST /api/auth/login` (OAuth2 password flow),
  `GET /api/auth/me`, `POST /api/auth/register-staff` (admin-only),
  `POST /api/auth/register-client-user` (staff-only, provisions a
  client's portal login)
- Frontend: a login page, JWT stored in localStorage, sent automatically
  on every request via an axios interceptor, auto-redirect to `/login`
  on a 401. Client-role users skip the "All Clients" list and land
  straight on their own dashboard.

**Bootstrap the first admin account** (chicken-and-egg: `register-staff`
requires an existing admin token, so the very first one is created via CLI):
```bash
docker compose exec api python -m app.scripts.create_admin you@yourcompany.com
```
Then log in at `/login` with that account, and use `/api/auth/register-staff`
or `/api/auth/register-client-user` for everyone else.

**Known limitation**: no refresh-token rotation yet — tokens just expire
after 12 hours and the user re-logs in. Fine for an internal tool at this
stage; worth adding before this has enough client users to make re-login
annoying.

## What's new — pentest scheduling (the last spec gap)

- `PentestSchedule` model supports two modes:
  - **Recurring** (quarterly/semi_annual/annual) — completing an
    engagement auto-advances `next_due_date` by the interval, no manual
    re-scheduling needed
  - **Custom** — one-off engagements (pre-fundraise pentest, irregular
    timing); completing one does NOT auto-schedule the next, the analyst
    sets a fresh date explicitly
- Daily task (`pentest_reminder_check`, 8 AM UTC) sends a reminder 14 days
  before `next_due_date` via the same email/Slack `notifications` service,
  and flags anything past due as `overdue`
- New endpoints: `POST/GET/PATCH /api/clients/{id}/pentest-schedule`,
  `POST .../pentest-schedule/complete`
- Portal: a Pentest Schedule widget on the client dashboard — shows days
  until/overdue, lets you schedule, complete, or reschedule an engagement

Try it:
```bash
curl -X POST http://localhost:8000/api/clients/{client_id}/pentest-schedule \
  -d '{"frequency":"quarterly","next_due_date":"2026-10-01T00:00:00","scope_notes":"External network + web app"}'

curl -X POST http://localhost:8000/api/clients/{client_id}/pentest-schedule/complete
# next_due_date auto-advances to 2027-01-01 for a quarterly schedule
```

## What's new — Closing the Spec-Gap Audit

An audit against the original product spec document found the previous
"Roadmap — status: complete" claim below was overstated: several
Feature-2.x/3.x items existed only as log lines, dead code that was never
called, or stubs, and three real bugs meant the app didn't reliably start
at all (`bcrypt`>=4.1 broke every password hash/verify call via an
incompatible `passlib`, `weasyprint` was hard-imported at module load and
broke the app in any environment without its system libs including CI, and
a scheduled Celery task referenced a function that didn't exist). All of
that is now fixed and every real gap the audit found is closed, verified
with real tests and — for the frontend — a live browser click-through, not
just written and assumed to work:

- **Bug fixes**: `bcrypt` pinned below the version that breaks `passlib`;
  `weasyprint` lazy-imported so the app starts without it installed; the
  missing DNS/SSL monitoring beat task restored (it was dead code stranded
  inside an unrelated function); a missing `timedelta` import that would
  have crashed several scheduled tasks at runtime.
- **Module 1**: active subdomain brute-force, HTTP security header
  analysis, CVE matching against fingerprinted tech (free CIRCL API),
  GCP/Azure cloud asset discovery, the previously-dead SSLyze scan wired
  into the schedule, and new-subdomain/new-port/dangerous-service alerts
  converted from log lines into real Findings.
- **Module 2**: CVSS vector strings, real business-context severity
  scoring (`Asset.is_internal`), default-credential checks via nuclei's
  own `default-logins` templates, JWT weakness detection, OAuth2/OIDC
  misconfiguration checks, SPF/DKIM/DMARC validation, finding
  assignment + enforced status-workflow transitions, and a trend
  dashboard endpoint.
- **Module 3**: best-effort free-source paste-site monitoring (psbdmp.ws),
  optional DeHashed integration, and the free Emerging Threats
  compromised-IP blocklist.
- **Module 4**: GCP project-level IAM over-privilege detection, Azure Key
  Vault access-policy review, Azure AD security-defaults check, and a
  unified multi-cloud findings view in the portal.
- **Module 5**: client branding on generated reports, a real
  per-control compliance section (was a hardcoded placeholder even when
  real compliance data existed), a risk-score trend chart embedded in
  both PDF and DOCX, and the weekly digest grounded in this week's actual
  CVE/threat-intel hits instead of asking Claude to recall "current"
  threats from training data.
- **Module 6**: a real dashboard trend chart (Recharts — installed since
  early on but never actually used until now), asset tech-stack/port/risk
  detail, real per-asset risk scoring (the column existed but nothing
  ever wrote to it), compliance evidence upload/download and a real
  per-control PDF export, pentest report upload/download, and phishing
  result anonymization that's actually enforced server-side (was a
  code-comment convention with nothing behind it) plus a training-
  completion rollup. Also fixed a pre-existing bug found while wiring
  this up: authenticated file downloads used plain `<a href>` tags, but
  this app has no cookie session — the JWT lives in `localStorage` and is
  attached via an axios interceptor, so a bare anchor tag never sent the
  token and every download would 401 for a real logged-in user.
- **Module 7**: SLA escalation now writes real state
  (`escalation_count`/`escalated_at`, surfaced as a portal badge) and
  re-drafts a critical alert on each new breach, instead of just logging
  the same warning every hour forever. Fair per-client scan scheduling
  wired up via `MAX_CONCURRENT_SCANS_PER_CLIENT` (declared in config
  since early on, never actually read until now) backed by a Redis
  counter.

**Genuinely still outside pure code**: Tor-indexed dark-web content and
ransomware-group blog monitoring need a paid feed (Flare, DarkOwl) or
Tor-capable crawling infrastructure — there's a documented extension
point at the bottom of `threat_intel.py` for whenever you pick one.

**Verified, not just written**: 116/116 backend tests pass (up from the
24 that existed before this pass), every new Alembic migration applies
and downgrades cleanly against a fresh database, and a full visual
verification pass — seeded realistic data, logged into the actual portal
through a real browser, clicked through every changed page and the new
upload/status-transition/expand interactions — confirmed everything
renders and behaves correctly with zero console errors.

## What's new — Track1 Expanded Services (5 new services, 16 tools)

A second spec document (`Track1_Expanded_Services.docx`) defines 5 new
service lines beyond the core platform above, 16 custom tools total. All
16 are implemented, with three deliberate scope boundaries carried
through every one of them the same way the first spec pass handled
Tor/dark-web crawling — built where it's genuinely code, documented as
an extension point where it isn't:

- **Physical security testing and vishing calls stay supporting-tools
  only.** Tailgating, badge cloning, dumpster diving, and USB-drop tests
  need an in-person analyst; full vishing needs someone to actually dial
  a phone under a signed consent form. Neither is code. What *is* code: a
  checklist/engagement tracker for the physical assessment, and an
  upload-and-analyze tool for a vishing call recording already made
  under the engagement's own legal process.
- **LinkedIn/social-media scraping is a documented extension point, not
  built.** It violates LinkedIn's ToS and risks account/IP bans — OSINT-1
  ships everything safe and free instead (WHOIS/DNS, email-pattern
  analysis, Google dorking, GitHub OSINT, job-listing analysis, Claude
  synthesis) and flags social data as needing a paid provider (Proxycurl,
  PDL) or manual analyst input.
- **AI-3's package is real but not published to PyPI** — that's the
  project owner's own PyPI account/credentials, a real-world action this
  codebase can't take on its own.

### Service 1 — Social Engineering & Physical Security

- **SE-1 OSINT Profiling Engine** (`services/osint.py`) — WHOIS + DNS
  history, email-pattern guessing, Google dorking (Custom Search API,
  key-gated), GitHub OSINT, job-listing tech-stack analysis, and a
  Claude-synthesized attacker-perspective narrative. PDF export.
- **SE-2 Phishing Campaign Builder & Tracker** (extends `api/phishing.py`) —
  CSV target import, an HTML template builder with per-target
  personalization, a tracking pixel + credential-harvest landing page
  (`api/phishing_public.py`, unauthenticated by design), and a
  Claude-drafted per-employee debrief. The landing page never stores a
  submitted password — only the boolean fact that a submission happened,
  same privacy stance as the original Phishing Simulation module.
- **SE-3 Vishing Call Analyser** (`services/vishing.py`) — upload a
  recording (Whisper transcription, key-gated) or paste a transcript
  directly; Claude identifies social-engineering techniques used,
  extracts any information disclosed, and assigns a risk rating.
- **Physical security tracker** — plain engagement/checklist CRUD
  (`api/physical_security.py`), seeded with one row per test type
  (tailgating/badge cloning/dumpster diving/visitor access/clean
  desk/USB drop) — a tracker, not automation.

### Service 2 — Mobile App Security

- **MOB-1 Static Analyser** (`services/mobile_sast.py`) — `androguard`
  (pure Python, no JVM) parses APKs for manifest flags
  (`allowBackup`/`debuggable`/cleartext traffic), exported components,
  hardcoded secrets, and weak-crypto references; iOS `.ipa` parsing uses
  only stdlib (`zipfile`+`plistlib`). Maps findings to a MASVS L1/L2
  checklist with a compliance score. `apktool`/`jadx`/`trufflehog` are
  optional deeper enrichment.
- **MOB-2 API Traffic Interceptor** (`services/mobile_traffic.py`) —
  imports a HAR file (the standard export from Burp Suite, Chrome
  DevTools, mitmproxy, Charles) instead of integrating with Burp Suite
  Pro's REST API directly; discovers endpoints, flags sensitive data in
  transit, classifies authenticated vs. unauthenticated calls, and
  generates an OpenAPI-lite doc.
- **MOB-3 MASVS Compliance Report** — the client-facing side of the
  Mobile App Security page: finding browser, MASVS score, and a
  Claude-drafted executive summary per scan.

### Service 3 — Blockchain & Web3 Security

- **WEB3-1 Smart Contract Scanner** (`services/web3_scan.py`) —
  `slither-analyzer` (direct Python API) + `semgrep` (a small bundled
  Solidity ruleset at `app/rules/semgrep_solidity.yml`) as the two
  always-available engines, deduped by line/rule-family, with Claude
  false-positive annotation. `mythril` is optional deeper enrichment;
  `echidna` fuzzing is a documented manual step (it needs contract-
  specific invariant tests that can't be auto-generated).
- **WEB3-2 Audit Report Generator** (`services/web3_report.py`) — a
  Jinja2/WeasyPrint PDF in an audit-firm style plus a Markdown export,
  with a "public mode" that redacts exploit detail on critical/high
  findings for external sharing.
- **WEB3-3 On-Chain Transaction Monitor** (`services/onchain_monitor.py`) —
  polls a registered contract address on an interval (`ONCHAIN_POLL_INTERVAL_MINUTES`,
  default 5 minutes — not block-by-block; see the Context note in the
  code) via Etherscan, flagging large transfers, known admin-function
  calls, and a naive same-block flash-loan-pattern heuristic. Alerts
  route to Telegram and/or the client's existing Slack webhook.

### Service 4 — AI/ML Model Security Testing

- **AI-1 Prompt Injection Testing Suite** (`services/ai_security_testing.py`) —
  a curated ~40-payload library across direct-injection/
  indirect-injection/jailbreak/system-prompt-extraction categories,
  delivered against a client-configured target endpoint, with Claude
  classifying whether each attack actually succeeded (grounded in the
  real response text). Successes sync into the normal Vulnerability
  Tracker.
- **AI-2 AI Security Posture Dashboard** (`services/ai_posture.py`) — an
  AI/ML feature + library-stack inventory, CVE monitoring against that
  stack (same free CIRCL API pattern as Module 1's CVE matching), and an
  OWASP LLM Top 10 checklist that reuses the existing Compliance Center
  (`framework=owasp_llm`) instead of a parallel checklist system.
- **AI-3 LLM Output Sanitiser** (`packages/llm-output-sanitizer/`) — a
  real, standalone, pip-installable package: XSS stripping, regex (+
  optional Claude-semantic) PII detection, prompt-leakage heuristics,
  and JSON-schema validation. Dogfooded as a wrapper around the report
  generator's Claude output before it's rendered into HTML.

### Service 5 — DevSecOps Pipeline & CI/CD Security

- **DSO-1 Pipeline Security Orchestrator** (`services/devsecops.py`) —
  deploys one of 5 pre-built GitHub Actions security-gate workflows
  (Python/FastAPI, Node/Express, React, Go, Java/Spring — dependency
  audit + SAST + secret scanning) to a client's repo via PyGithub, then
  polls run results into Findings. GitLab/Jenkins are documented
  extension points, not implemented.
- **DSO-2 Security Finding Triage Assistant** (`services/triage.py`) —
  parses SARIF/Trivy-JSON/OWASP-Dependency-Check-XML into a common
  shape; Claude annotates false-positive verdicts, recalibrated
  severity, and a concrete fix suggestion per finding. Jira ticket
  creation via direct REST calls; a weekly cross-client digest task.
- **DSO-3 Developer Security Scorecard** (`services/scorecard.py`) —
  pipeline health score, vulnerabilities/secrets blocked, and mean
  time-to-fix, aggregated from the existing Finding table (matched by
  title prefix — `[Pipeline]`/`[CI Scan]`/`[IaC]` — the same source-
  tagging convention `cspm.py` uses for cloud-provider tagging, not a
  new column). Daily snapshots, a trend endpoint, PDF export.
- **DSO-4 IaC Security Scanner** (`services/iac_scan.py`) — `checkov`
  (CLI) as the primary Terraform/CloudFormation/Kubernetes/Dockerfile/
  Compose scanner, `kube-score`/`hadolint`/`kubesec` as optional
  enrichment, Claude fix suggestions, and PR-comment posting that reuses
  DSO-1's GitHub client.

**Verified, not just written**: 266/266 backend tests pass (up from 116
at the end of the first spec pass), every new Alembic migration applies
and downgrades cleanly (including a Postgres `ALTER TYPE ... ADD VALUE`
for the new `owasp_llm` compliance framework enum value, guarded to only
run on that dialect), the standalone `llm-output-sanitizer` package has
its own green test suite, and the frontend builds clean with all 5 new
pages wired into routing/navigation.

A full local stack (Postgres + Redis + backend + Celery worker +
frontend, no Docker daemon available in this environment, so run
directly) plus a real Chromium browser pass caught one genuine
**pre-existing** bug, present since the very first commit and unrelated
to anything above: `Sidebar.jsx` read `useParams()` for `clientId`, but
`<Sidebar>` is rendered as a sibling of `<Routes>` in `App.jsx`, not
inside the matched route's subtree — so `useParams()` there always
returned `{}`, meaning **the entire per-client sidebar section (every
existing nav link — Overview, Assets, Findings, Compliance, Phishing,
Reports — plus all 5 new Expanded Services links) never rendered on any
client page, for anyone.** Fixed by reading `clientId` from
`useLocation().pathname` instead (a Router-level context available
everywhere, unlike `useParams()`), and confirmed with a real click-
through: sidebar renders correctly and every link navigates.

## What's new — Track1 Advanced Services (5 new services, 6 tools)

A third spec document (`Track1_Advanced_Services.docx`) defines 5 more
service lines beyond the core platform and the Expanded Services pass
above: Red Team Operations, Zero Day Research & Responsible Disclosure,
Digital Forensics & Incident Response, Hardware & IoT Security Testing,
and Continuous Threat Hunting — 6 custom tools total (RT-1, ZD-1,
DFIR-1, DFIR-2, IOT-1, TH-1).

**This entire phase uses a different access model than everything above
it.** Every tool in this spec doc is labeled `[ANALYST]`/`[AUTO]` — never
`[CLIENT]` — and two of the six are explicitly captioned "Internal Only"
/ "Analyst Only" in the doc's own UI mockups. So unlike every router
built in the first two spec passes (which use `require_client_access`,
letting a client see their own data), **every router in this phase uses
`require_staff`.** A client-role login gets a 403 on all six tools and
never sees the "Advanced Services" sidebar section at all — this is
covered by an explicit test per router, not just reliance on the shared
dependency, since it's the one place the access model differs from
everything else in the codebase.

Two of the six tools needed an explicit scope boundary, the same way the
first two spec passes handled Tor/dark-web crawling and LinkedIn
scraping — built where it's genuinely code, not stretched into
something riskier than the platform should be:

- **RT-1 (Red Team Operations) is a tracking/logging tool only.** It
  does not run a C2 server or execute attacks — a human operator runs
  real tooling (Cobalt Strike, Havoc, Sliver, etc.) outside this
  platform and logs what happened here afterward: operation workspace,
  timeline, implant/infrastructure trackers, ATT&CK tagging, AI
  narrative + purple-team debrief export. This mirrors how real-world
  red-team tracking tools (Ghostwriter, RedELK) actually work.
- **ZD-1 (Zero Day Research) is a tracking platform + optional local
  fuzz hook.** Research-target board, disclosure tracker with a real
  90-day countdown, real CVE/NVD API v2 lookups, HackerOne/Bugcrowd
  submission tracking, GitHub Security Advisory publishing, Claude
  disclosure-advisory drafting. `FuzzingJob` is an analyst-updated
  tracking record (status, crashes found) for a campaign run with
  AFL++/LibFuzzer/Boofuzz *outside* this platform — not a live fuzzing
  orchestration engine, which would be a substantially more dual-use-
  sensitive build than the tracking system around it.

Everything else (DFIR case management + log analysis, firmware
analysis, threat hunting) is unambiguously legitimate defensive/tracking
tooling and gets a full build, reusing existing infrastructure
throughout: `app/core/crypto.py`'s Fernet encryption (already used for
`CloudAccount`) for per-client SIEM/EDR credentials, `threat_intel.py`'s
Shodan/Censys/blocklist checks for IoC enrichment, `devsecops.py`'s
GitHub client for Security Advisory publishing, and a new shared
`app/services/attack_framework.py` (bundled MITRE ATT&CK reference + a
best-effort live technique-name lookup against MITRE's own public `cti`
GitHub JSON + real ATT&CK Navigator layer export) used by both RT-1's
and TH-1's heatmaps instead of duplicating that format logic twice.

### Service 1 — Red Team Operations (RT-1)

- **Operation workspace** (`services/red_team.py`, `api/red_team.py`) —
  operations, a technique-tagged action timeline, implant tracker,
  infrastructure tracker (C2 servers/phishing domains/redirectors/
  payload hosts).
- **ATT&CK heatmap** — builds a real Navigator-format JSON layer from
  the operation's own logged, technique-tagged timeline entries.
- **C2 infrastructure exposure check** — reuses Module 3's Shodan lookup
  to verify the team's own C2/redirector IPs aren't already
  fingerprinted, pointed at the operator's own infra instead of a
  target's.
- **AI attack narrative + purple-team Markdown export** — Claude writes
  the narrative strictly from the real logged timeline; the purple-team
  export is a plain data table for the debrief session, no AI involved.

### Service 2 — Zero Day Research & Responsible Disclosure (ZD-1)

- **Research target + finding tracker** (`services/zero_day.py`,
  `api/zero_day.py`) — not client-scoped by default (`client_id` is
  nullable: null means independent research, set means a
  client-commissioned engagement), so this is a top-level
  `/api/zero-day` router rather than nested under `/clients/{id}`.
- **Real CVE/NVD lookups** — MITRE's CVE Services API for a lightweight
  existence check, NVD API v2 for full CVSS/description detail.
- **Disclosure deadline countdown** — a standard 90-day, Project-Zero-
  style countdown from the vendor-notified date, surfaced directly on
  every finding.
- **HackerOne/Bugcrowd submission tracking + GitHub Security Advisory
  publishing** — real API calls, both key-gated and degrading
  gracefully; GHSA publishing reuses DSO-1's PyGithub client.
- **Claude-drafted disclosure advisories**, grounded strictly in the
  finding's own recorded fields.

### Service 3 — Digital Forensics & Incident Response (DFIR-1 + DFIR-2)

- **Case manager** (`services/dfir.py`, `api/dfir.py`) — cases,
  evidence, IoCs, a forensic timeline, and an IR retainer dashboard.
- **Evidence integrity** — MD5 + SHA256 are always computed server-side
  from the uploaded bytes, never trusted from the client, with an
  append-only chain-of-custody log (no prior entry is ever rewritten or
  removed).
- **IoC export** — real STIX 2.1 bundles, Sigma detection rules, or CSV.
- **Forensic log analyzer** (`services/dfir_log_analysis.py`) — parses
  AWS CloudTrail, Azure Activity Log, and GCP Audit Log (JSON), syslog/
  nginx-apache-combined/Palo Alto CSV (regex), and Windows EVTX (via
  `python-evtx`) into one normalized event shape, then runs heuristic
  auth-anomaly detection (repeated failures, off-hours access) and
  regex-based IoC extraction uniformly over all of them.
- **Executive/technical reports + log narratives** — Claude-written,
  grounded strictly in the case's own recorded evidence/IoCs/timeline or
  the log analyzer's own parsed events — the same "do not invent"
  discipline as every prior AI narrative function in this codebase.

### Service 4 — Hardware & IoT Security Testing (IOT-1)

- **Firmware analyzer** (`services/firmware_analysis.py`,
  `api/firmware.py`) — upload-then-`/analyze`, same two-step pattern as
  MOB-1.
- **binwalk extraction** degrades gracefully not just on a missing
  binary but on *any* non-zero exit or timeout (a broken/incompatible
  local binwalk install shouldn't crash the whole analysis) — falls back
  to scanning the raw firmware bytes directly instead of the extracted
  filesystem.
- **Component identification** — signature-matches BusyBox, Linux
  kernel, OpenSSL, Dropbear, uClibc, lighttpd, and U-Boot version
  strings out of extracted (or raw) text.
- **Secret scanning** reuses `mobile_sast.py`'s `SECRET_PATTERNS`
  directly rather than a second copy of the same regex set.
- **Real NVD API v2 CVE matching** per identified component, plus
  optional `checksec` binary-hardening enrichment on any extracted ELF
  files.

### Service 5 — Continuous Threat Hunting (TH-1)

- **Shared hypothesis library** (`services/threat_hunting.py`,
  `api/threat_hunting.py`) — not client-scoped, seeded with 20 starter
  hypotheses spanning common ATT&CK tactics, plus a Claude-generate
  endpoint for industry-tailored hypotheses.
- **Client-scoped hunt operations** with a findings tracker.
- **Real SIEM/EDR querying** against a client's own registered
  connection (same Fernet-encrypted-credential pattern as
  `CloudAccount`) — real Elasticsearch `_search`, Splunk search-export,
  and CrowdStrike OAuth2 + Detections API calls, all degrading to an
  empty result (never raising) if the connection is unconfigured or
  temporarily unreachable.
- **IoC enrichment** reuses Module 3's Shodan/Censys/blocklist checks
  directly instead of a third implementation of the same lookups.
- **ATT&CK coverage heatmap** reuses `attack_framework.py`'s Navigator
  layer export, built from completed hunts' underlying hypothesis
  techniques.

**Verified, not just written**: 414/414 backend tests pass (up from 274
at the end of the Expanded Services pass — 140 new tests across this
phase, including an explicit client-role-gets-403 test for every one of
the 6 new routers), every new Alembic migration applies and downgrades
cleanly (5 migrations: shared `SiemConnection`, RT-1, ZD-1, DFIR, IOT-1,
TH-1), and the frontend builds clean with all 5 new pages (RT-1 and
TH-1 share none, ZD-1 is a global page, the rest are per-client) wired
into routing and a new "Advanced Services" sidebar section gated
`isStaff && clientId` (or just `isStaff` for ZD-1's global page) —
invisible to the client role entirely, not just inaccessible.

A full local stack (Postgres + Redis + backend + Celery worker +
frontend, run directly, no Docker daemon in this environment) plus a
real Chromium browser pass caught one genuine, pre-existing bug that
the sqlite-backed test suite structurally can't see: every Alembic
migration since the Expanded Services pass (`d4e7b1a29f63` onward —
SE-1/SE-2/SE-3 through this phase's own 5 new migrations) declared
`id` primary keys and foreign-key columns referencing `clients.id`/
`users.id`/sibling tables as `sa.String()`, while every ORM model in
`app/models/models.py` declares that same column as
`Column(UUID(as_uuid=False), ...)`. sqlite doesn't enforce column
affinity strictly enough to notice; a real, freshly-created Postgres
database does — `alembic upgrade head` failed outright on the very
first mismatched foreign key (`osint_profiles.client_id`), and even
after stamping past that, ordinary ORM calls like `db.refresh()` on any
affected table raised `operator does not exist: character varying =
uuid`, caught live by a Playwright pass that created a Red Team
Operation through the real UI and hit a 500. Fixed by changing every
affected `sa.String()` column declaration in the 11 affected migration
files to `sa.UUID(as_uuid=False)`, matching what the ORM models
actually declare — re-verified end to end: `alembic upgrade head` /
`downgrade base` against a genuinely empty Postgres database, real
create-then-refresh calls against every affected table (both this
phase's new tables and the pre-existing Expanded Services ones), and
the same Playwright script re-run clean (operation creation succeeds,
renders in the UI) plus the full staff/client access-boundary matrix
(18 checks: sidebar visibility, page loads, and 403s) all passing.

## Roadmap

Every module and feature from the Track 1 spec has a real implementation.
The one exception is genuinely outside pure code (see above):

1. ✅ Module 1 — Asset Discovery (subdomains incl. active brute-force,
   ports, cloud assets across AWS/GCP/Azure, tech fingerprinting, CVE
   matching, security headers)
2. ✅ Module 2 — Vulnerability Detection (nuclei, CVSS + vector, dedup,
   re-scan verification, JWT/OAuth/email-security checks, lifecycle
   workflow, trend dashboard)
3. 🟡 Module 3 — Dark web/threat intel (HIBP, DeHashed, GitHub secrets,
   paste-site search, OTX/Abuse.ch/Emerging Threats blocklists — Tor/
   ransomware-blog monitoring needs a paid feed, see above)
4. ✅ Module 4 — CSPM (AWS, GCP, Azure auditing + config drift detection)
5. ✅ Module 5 — AI Report Generation (monthly reports w/ branding + trend
   chart, alert drafting, data-grounded weekly digests)
6. ✅ Module 6 — Client Portal (overview + trend, assets, findings,
   compliance w/ evidence + export, phishing w/ anonymization, reports,
   pentest scheduling)
7. ✅ Module 7 — Scheduling automation, health monitoring, real SLA
   escalation, fair per-client scheduling, pentest reminders, email/Slack
   delivery
8. ✅ Service 1 (Expanded) — Social Engineering & Physical Security
   (OSINT profiling, phishing builder/tracker, vishing analyser,
   physical security checklist — see above for scope boundaries)
9. ✅ Service 2 (Expanded) — Mobile App Security (Android/iOS static
   analysis, HAR traffic import, MASVS compliance)
10. ✅ Service 3 (Expanded) — Blockchain & Web3 Security (Slither/Semgrep
    contract scanning, audit reports, on-chain monitoring)
11. ✅ Service 4 (Expanded) — AI/ML Model Security (prompt injection
    testing, AI security posture, standalone output-sanitizer package)
12. ✅ Service 5 (Expanded) — DevSecOps Pipeline & CI/CD Security
    (pipeline gates, scanner-output triage, developer scorecard, IaC
    scanning)
13. ✅ Service 1 (Advanced) — Red Team Operations (tracking/logging
    workspace, ATT&CK heatmap, C2 exposure check, AI narrative +
    purple-team export — see above for the tracking-only scope boundary)
14. ✅ Service 2 (Advanced) — Zero Day Research & Responsible Disclosure
    (research/finding tracker, real CVE/NVD lookups, 90-day disclosure
    countdown, bounty submission + GHSA publishing)
15. ✅ Service 3 (Advanced) — DFIR (case manager w/ chain-of-custody
    evidence hashing, STIX/Sigma/CSV IoC export, multi-format forensic
    log analyzer incl. Windows EVTX)
16. ✅ Service 4 (Advanced) — Hardware & IoT Security Testing (firmware
    extraction, component ID, secret scanning, real NVD CVE matching)
17. ✅ Service 5 (Advanced) — Continuous Threat Hunting (shared
    hypothesis library, real SIEM/EDR querying, IoC enrichment, ATT&CK
    coverage heatmap)

Each module maps directly to a file in `app/services/` and a set of Celery
tasks in `app/workers/tasks.py` — follow the pattern already set by
`services/recon.py`, `services/threat_intel.py`, and `services/cspm.py`.

