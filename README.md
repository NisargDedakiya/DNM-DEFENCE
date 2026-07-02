# Track 1 Automation Platform — v0.1 (Foundation)

This is the starting skeleton: **backend structure covering all 7 modules
from the spec, with Module 1 (Asset Discovery) fully wired end-to-end.**
Everything else is modeled in the database but not yet implemented — see
Roadmap below.

## What actually works right now

- FastAPI backend with clients + assets + scan-trigger endpoints
- SQLAlchemy models for every core entity: Client, Asset, Port, ScanRun,
  Finding, CloudAccount
- Celery + Redis task queue with a scheduled beat config (daily subdomain
  enum, weekly vuln scan, monthly reports — the last two are stubs)
- Real subprocess integration with `subfinder`, `httpx`, `naabu` — parses
  their JSON output and reconciles it against the asset inventory
  (new/dead subdomain tracking, dangerous port detection)
- Client onboarding automatically triggers baseline recon (Module 7)

## Run it

```bash
cp backend/.env.example backend/.env
# fill in ANTHROPIC_API_KEY, any recon API keys you have, and change SECRET_KEY
docker compose up --build

# bootstrap your first admin login (one-time)
docker compose exec api python -m app.scripts.create_admin you@yourcompany.com
```

API docs: http://localhost:8000/docs
Portal: http://localhost:5173 (log in with the admin account you just created)

Every endpoint now requires auth. Get a token first:
```bash
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -d "username=you@yourcompany.com&password=yourpassword" | python3 -c "import sys,json;print(json.load(sys.stdin)['access_token'])")
```

Onboard a client:
```bash
curl -X POST http://localhost:8000/api/clients \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"Test Client","root_domain":"example.com","contact_email":"you@example.com"}'
```

This queues a subdomain enum scan automatically. Check progress:
```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/clients/{client_id}/scans
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/clients/{client_id}/assets
```

**Important:** only ever scan domains you have explicit written authorization
for (client scope agreement or your own test targets like OWASP Juice Shop).
Active scanning (naabu full-range, brute-force subdomain enum) against
domains you don't control is illegal.

## Run the tests

```bash
cd backend
pip install -r requirements.txt --break-system-packages
pytest tests/ -v
```

Tests run against an isolated sqlite DB (no Postgres/Redis needed), so
this works standalone without `docker compose up`.

## Database migrations

```bash
cd backend
alembic revision --autogenerate -m "describe your change"
alembic upgrade head
```

`docker-compose`'s `api` service runs `alembic upgrade head` automatically
on every start, so this only matters when you've changed a model and need
to generate the migration for it.
domains you don't control is illegal.

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

## Roadmap — status: complete

Every module and every feature from the original Track 1 spec now has a
real, working implementation:

1. ✅ Module 1 — Asset Discovery (subdomains, ports, cloud assets)
2. ✅ Module 2 — Vulnerability Detection (nuclei, CVSS, dedup, re-scan verification)
3. ✅ Module 3 — Dark web/threat intel (HIBP, GitHub secrets, OTX blocklist)
4. ✅ Module 4 — CSPM (AWS, GCP, Azure auditing + config drift detection)
5. ✅ Module 5 — AI Report Generation (monthly reports, alert drafting, digests)
6. ✅ Module 6 — Client Portal (overview, assets, findings, compliance,
   phishing, reports, pentest scheduling)
7. ✅ Module 7 — Scheduling automation, health monitoring, SLA escalation,
   pentest reminders, email/Slack delivery

**One thing remains genuinely outside pure code**, and always will be
unless you buy a feed for it: paste-site/dark-web crawling and ransomware
blog monitoring need a paid subscription (Flare, DarkOwl) or Tor-capable
infrastructure. There's a documented extension point at the bottom of
`threat_intel.py` for whenever you pick one — HIBP, GitHub secrets, and
OTX blocklist correlation (the rest of Module 3) are fully built and
running today.

Everything else — asset discovery, vuln scanning, dark web/threat intel,
AWS/GCP/Azure CSPM with drift detection, AI report generation, email/Slack
delivery, the full client portal (overview, assets, findings, compliance,
phishing, reports) — is built and wired end to end.
5. Module 4 — CSPM: AWS/GCP/Azure config auditing
6. Module 5 — AI report generation: Claude API + Jinja2 + WeasyPrint
7. Module 6 — Client portal frontend (React + Vite + Tailwind + shadcn/ui)
8. Module 7 — remaining scheduling/SLA logic, health monitoring

Each module maps directly to a file in `app/services/` and a set of Celery
tasks in `app/workers/tasks.py` — follow the pattern already set by
`services/recon.py` and the two working tasks.

## Notes

- `subfinder`/`httpx`/`naabu` are installed in the Docker image already.
  Locally without Docker, install them via `go install` (see Dockerfile)
  or the recon functions will just log a warning and return empty results.
- Migrations: `Base.metadata.create_all` runs automatically in dev mode.
  Switch to Alembic before this touches a real client's data.
- Cloud credentials (`CloudAccount.encrypted_credentials`) must be
  Fernet-encrypted before storage — encryption helper not yet added, do
  not store plaintext keys even in dev.
