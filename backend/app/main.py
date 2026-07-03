import logging

import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.sqlalchemy import SqlalchemyIntegration
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi.errors import RateLimitExceeded

from app.core.config import settings
from app.core.database import Base, engine
from app.core.security_middleware import limiter, SecurityHeadersMiddleware
from app.core.audit import log_action as core_log_action
from app.core.database import SessionLocal
from app.api import (
    clients, assets, findings, cloud, reports, compliance, phishing, phishing_public, pentest, auth, audit,
    osint, vishing, physical_security, mobile_security, web3_security, ai_security, devsecops,
)

# Import models so Base.metadata knows about every table before create_all
from app.models import models  # noqa: F401

logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 5 * 1024 * 1024  # 5MB — generous for JSON payloads, blocks abusive oversized bodies

INSECURE_DEFAULTS = {"change-me-in-production", ""}
if settings.ENV != "development":
    if settings.SECRET_KEY in INSECURE_DEFAULTS:
        raise RuntimeError("SECRET_KEY is unset or using the insecure default — refusing to start outside development. Set a long random value in .env.")
    if not settings.ENCRYPTION_KEY:
        raise RuntimeError("ENCRYPTION_KEY is unset — refusing to start outside development. Cloud credentials cannot be safely stored without it.")

if settings.SENTRY_DSN:
    sentry_sdk.init(
        dsn=settings.SENTRY_DSN,
        environment=settings.ENV,
        integrations=[FastApiIntegration(), SqlalchemyIntegration()],
        traces_sample_rate=0.1,  # 10% of requests get performance tracing — adjust once you know real traffic volume
        send_default_pii=False,  # never send request bodies/headers by default; this handles client security data
    )

OPENAPI_DESCRIPTION = """
Track 1 Managed Security Services Platform API.

Automates the security services described in the platform spec: asset
discovery, vulnerability scanning, threat intelligence, cloud security
posture management, AI-generated reporting, compliance tracking, and
phishing simulation.

## Authentication

Every endpoint except `/health` requires a Bearer token. Get one via
`POST /api/auth/login` (OAuth2 password flow — form fields `username`
and `password`). See the `auth` tag below for the full flow including
MFA and staff/client user provisioning.

## Tenant isolation

Client-role users are scoped to their own `client_id` at the API layer
(not just hidden in a UI) — every `/api/clients/{client_id}/...` route
verifies the token's `client_id` matches the URL before returning data.

## Rate limits

Default 100 requests/minute per IP across the API; login is limited
tighter (5/minute) with additional per-account lockout after repeated
failures. Exceeding a limit returns `429`.
"""

TAGS_METADATA = [
    {"name": "auth", "description": "Login, MFA enrollment, and staff/client user provisioning."},
    {"name": "clients", "description": "Client onboarding and the master client roster. Staff-only for listing/creating."},
    {"name": "assets", "description": "Discovered subdomains, cloud resources, and open ports for a client."},
    {"name": "findings", "description": "Vulnerability, threat-intel, and cloud-misconfiguration findings, plus scan triggers."},
    {"name": "cloud", "description": "Cloud account registration (AWS/GCP/Azure), credential rotation, and CSPM audit triggers."},
    {"name": "reports", "description": "AI-generated monthly reports (PDF/DOCX) and public read-only share links."},
    {"name": "compliance", "description": "SOC 2 / ISO 27001 / India DPDP control checklists and progress tracking."},
    {"name": "phishing", "description": "Phishing simulation campaign tracking and awareness trend reporting."},
    {"name": "pentest", "description": "Recurring or custom penetration test scheduling with automated reminders."},
    {"name": "audit", "description": "Read-only audit trail of API mutations. Admin-only."},
    {"name": "osint", "description": "SE-1 OSINT reconnaissance profiling (WHOIS/DNS/email-patterns/dorking/GitHub/job-listings)."},
    {"name": "vishing", "description": "SE-3 vishing call recording upload, transcription, and technique/risk analysis."},
    {"name": "physical-security", "description": "Physical security assessment checklist tracking (human-run, not automated)."},
    {"name": "mobile-security", "description": "MOB-1/2/3 mobile app static analysis, HAR traffic import, and MASVS compliance reporting."},
    {"name": "web3-security", "description": "WEB3-1/2/3 smart contract scanning, audit report generation, and on-chain transaction monitoring."},
    {"name": "ai-security", "description": "AI-1/2 prompt injection testing and AI security posture (library CVEs + OWASP LLM Top 10)."},
    {"name": "devsecops", "description": "DSO-1/2/3/4 pipeline gate deployment, scanner-output triage, developer scorecard, and IaC scanning."},
]

app = FastAPI(
    title=settings.APP_NAME,
    description=OPENAPI_DESCRIPTION,
    version=f"0.1.0-{settings.API_VERSION}",
    openapi_tags=TAGS_METADATA,
    contact={"name": "Track 1 Platform"},
    docs_url="/docs" if settings.ENV == "development" else None,
    redoc_url="/redoc" if settings.ENV == "development" else None,
    openapi_url="/openapi.json" if settings.ENV == "development" else None,
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded. Please slow down."})


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """
    Catches anything that slips past route-level error handling. Logs the
    full exception server-side but returns a generic message to the
    client — stack traces, file paths, and internal exception text must
    never reach an API response, since they can leak implementation
    details useful to an attacker.
    """
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}: {exc}")
    return JSONResponse(status_code=500, content={"detail": "Internal server error."})


# --- Security middleware, order matters (outermost added last) ---
app.add_middleware(SecurityHeadersMiddleware)

if settings.FORCE_HTTPS:
    app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins_list,  # explicit allow-list from settings, no wildcard
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

if settings.ENV != "development":
    # Fail closed: if ALLOWED_ORIGINS wasn't configured for this environment,
    # reject unrecognized Host headers rather than silently allowing "*".
    if not settings.allowed_origins_list:
        raise RuntimeError("ALLOWED_ORIGINS must be set outside development — refusing to start with an open host allow-list.")
    trusted_hosts = [o.split("//")[-1].split(":")[0] for o in settings.allowed_origins_list] + ["localhost"]
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=trusted_hosts)


@app.middleware("http")
async def limit_body_size_and_tag_version(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"detail": "Request body too large."})
    response = await call_next(request)
    response.headers["X-API-Version"] = settings.API_VERSION
    return response


@app.middleware("http")
async def audit_log_mutations(request: Request, call_next):
    """
    Safety-net audit trail: logs every non-GET request's method/path/status
    automatically, regardless of whether the endpoint calls log_action()
    explicitly for a more detailed entry. Best-effort -- never blocks the
    actual request if logging fails.
    """
    response = await call_next(request)

    if request.method != "GET" and request.url.path.startswith("/api") and request.url.path != "/api/auth/login":
        try:
            from app.core.auth import decode_token
            user_email, user_id = None, None
            authz = request.headers.get("authorization", "")
            if authz.startswith("Bearer "):
                try:
                    payload = decode_token(authz.split(" ", 1)[1])
                    user_email, user_id = payload.get("email"), payload.get("sub")
                except Exception:
                    pass

            db = SessionLocal()
            try:
                core_log_action(
                    db, action=f"{request.method} {request.url.path}",
                    user=type("U", (), {"id": user_id, "email": user_email})() if user_id else None,
                    detail={"status_code": response.status_code},
                    ip_address=request.client.host if request.client else None,
                )
            finally:
                db.close()
        except Exception:
            pass  # audit logging must never break the actual request

    return response


app.include_router(clients.router)
app.include_router(assets.router)
app.include_router(findings.router)
app.include_router(cloud.router)
app.include_router(reports.router)
app.include_router(reports.share_router)
app.include_router(compliance.router)
app.include_router(phishing.router)
app.include_router(phishing_public.router)
app.include_router(pentest.router)
app.include_router(auth.router)
app.include_router(audit.router)
app.include_router(osint.router)
app.include_router(vishing.router)
app.include_router(physical_security.router)
app.include_router(mobile_security.router)
app.include_router(web3_security.router)
app.include_router(ai_security.router)
app.include_router(devsecops.router)

if settings.ENABLE_METRICS:
    # Exposes GET /metrics in Prometheus text format: request counts, latency
    # histograms, and in-progress requests by route. Point a Prometheus
    # scrape config at this path; excludes /metrics and /health from its
    # own metrics to avoid noise.
    Instrumentator(excluded_handlers=["/metrics", "/health"]).instrument(app).expose(app, include_in_schema=False)


@app.on_event("startup")
def on_startup():
    # Dev convenience only -- use Alembic migrations in production, not create_all.
    if settings.ENV == "development":
        Base.metadata.create_all(bind=engine)


@app.get("/health")
def health():
    """
    Liveness + readiness in one: confirms the process is up AND the
    database is actually reachable, since a process that's running but
    can't reach Postgres should not be reported healthy to a load
    balancer or orchestrator.
    """
    from sqlalchemy import text
    db_ok = True
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
    except Exception as e:
        db_ok = False
        logger.error(f"Health check DB connectivity failure: {e}")

    status_code = 200 if db_ok else 503
    return JSONResponse(status_code=status_code, content={
        "status": "ok" if db_ok else "degraded",
        "env": settings.ENV, "api_version": settings.API_VERSION, "database": "ok" if db_ok else "unreachable",
    })
