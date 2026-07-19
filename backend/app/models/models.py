"""
Core data model for the platform. Deliberately normalized around three
concepts: Client (who we serve), Asset (what we monitor for them), and
Finding (what we discovered). Every other module (reports, alerts, portal)
reads from these tables — it does not duplicate scan logic.
"""
import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    Column, String, Boolean, DateTime, ForeignKey, Integer, Text, Enum, Float, JSON
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


def gen_uuid():
    return str(uuid.uuid4())


class UserRole(str, enum.Enum):
    admin = "admin"       # full platform access — your team
    analyst = "analyst"   # your team, no user management
    client = "client"     # client-side portal user, scoped to their own client_id


class AuditLog(Base):
    """
    Immutable-by-convention record of who did what. Not enforced at the
    DB level as append-only (that needs a DB-level trigger/permission
    setup which varies by hosting provider) — treat this table as
    write-once from the application layer and never expose a DELETE/PATCH
    endpoint for it.
    """
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    user_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)  # null for unauthenticated attempts (e.g. failed login)
    user_email = Column(String(255), nullable=True)  # denormalized so the log survives user deletion
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False)  # e.g. "client.create", "finding.status_update", "cloud_account.register"
    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(255), nullable=True)
    ip_address = Column(String(64), nullable=True)
    detail = Column(JSON, default=dict)  # before/after values or other context — never raw credentials
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    email = Column(String(255), nullable=False, unique=True, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), nullable=False, default=UserRole.analyst)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=True)  # set only for role=client
    is_active = Column(Boolean, default=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    mfa_secret = Column(String(64), nullable=True)  # TOTP secret, set once MFA is enrolled
    mfa_enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class Client(Base):
    __tablename__ = "clients"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    name = Column(String(255), nullable=False)
    root_domain = Column(String(255), nullable=False, index=True)
    industry = Column(String(100), nullable=True)
    contact_email = Column(String(255), nullable=False)
    slack_webhook_url = Column(String(500), nullable=True)
    sla_hours_critical = Column(Integer, default=24)
    sla_hours_high = Column(Integer, default=72)
    auto_send_critical_alerts = Column(Boolean, default=False)  # Feature 5.2 — opt-in per client
    dns_baseline = Column(JSON, nullable=True)  # DNS drift monitoring baseline snapshot
    logo_url = Column(String(500), nullable=True)  # Feature 5.1 — client branding on generated reports
    brand_color = Column(String(20), nullable=True)  # hex color, e.g. "#1a73e8"
    phishing_show_employee_names = Column(Boolean, default=False)  # Feature 6.6 — opt-in to named (not anonymized) phishing results for client-role viewers
    plan = Column(String(20), nullable=False, default="enterprise", server_default="enterprise")  # subscription tier — see app/core/plans.py
    onboarded_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)

    assets = relationship("Asset", back_populates="client", cascade="all, delete-orphan")
    scan_runs = relationship("ScanRun", back_populates="client", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="client", cascade="all, delete-orphan")
    cloud_accounts = relationship("CloudAccount", back_populates="client", cascade="all, delete-orphan")


class AssetType(str, enum.Enum):
    subdomain = "subdomain"
    ip = "ip"
    cloud_resource = "cloud_resource"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    asset_type = Column(Enum(AssetType), nullable=False)
    value = Column(String(500), nullable=False)  # hostname, IP, or ARN
    source = Column(String(100), nullable=True)  # crtsh, brute-force, shodan, boto3, etc.
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_alive = Column(Boolean, default=True)
    tech_stack = Column(JSON, default=dict)  # {"web_server": "nginx", "cms": "wordpress 5.2", ...}
    risk_score = Column(Float, default=0.0)  # 0-100, derived from open findings
    is_internal = Column(Boolean, default=False)  # Feature 2.1 business-context scoring: internal/dev vs internet-facing prod

    client = relationship("Client", back_populates="assets")
    ports = relationship("Port", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset")

    __table_args__ = ()


class Port(Base):
    __tablename__ = "ports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("assets.id"), nullable=False, index=True)
    port_number = Column(Integer, nullable=False)
    protocol = Column(String(10), default="tcp")
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(255), nullable=True)
    is_dangerous = Column(Boolean, default=False)  # RDP/Telnet/DB exposed publicly
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    asset = relationship("Asset", back_populates="ports")


class ScanStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    completed = "completed"
    failed = "failed"


class ScanType(str, enum.Enum):
    subdomain_enum = "subdomain_enum"
    port_scan = "port_scan"
    vuln_scan = "vuln_scan"
    cloud_audit = "cloud_audit"
    dark_web_scan = "dark_web_scan"


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.queued)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    new_assets_found = Column(Integer, default=0)
    new_findings_found = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    raw_output_path = Column(String(500), nullable=True)  # where raw tool output is stored

    client = relationship("Client", back_populates="scan_runs")


class Severity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, enum.Enum):
    new = "new"
    acknowledged = "acknowledged"
    in_remediation = "in_remediation"
    resolved = "resolved"
    verified = "verified"
    disputed = "disputed"


class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    asset_id = Column(UUID(as_uuid=False), ForeignKey("assets.id"), nullable=True, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(Severity), nullable=False)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)  # e.g. "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    cve_id = Column(String(50), nullable=True, index=True)
    status = Column(Enum(FindingStatus), default=FindingStatus.new)
    evidence = Column(JSON, default=dict)
    remediation_steps = Column(Text, nullable=True)
    dedup_hash = Column(String(64), nullable=False, index=True)  # prevents duplicate findings
    created_at = Column(DateTime, default=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    sla_deadline = Column(DateTime, nullable=True)
    assigned_to = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    escalated_at = Column(DateTime, nullable=True)  # Module 7 SLA escalation — set on first breach notification
    escalation_count = Column(Integer, default=0)

    client = relationship("Client", back_populates="findings")
    asset = relationship("Asset", back_populates="findings")
    assignee = relationship("User")


class CloudProvider(str, enum.Enum):
    aws = "aws"
    gcp = "gcp"
    azure = "azure"


class ReportType(str, enum.Enum):
    monthly_security = "monthly_security"
    threat_digest = "threat_digest"


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    report_type = Column(Enum(ReportType), nullable=False)
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    executive_summary = Column(Text, nullable=True)
    risk_analysis = Column(Text, nullable=True)  # technical risk narrative, distinct from the plain-English exec summary
    risk_score = Column(Float, nullable=True)  # 0-100 snapshot at report time
    pdf_path = Column(String(500), nullable=True)
    docx_path = Column(String(500), nullable=True)
    share_token = Column(String(64), nullable=True, unique=True)  # for Feature 6.5 read-only share links
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class ComplianceFramework(str, enum.Enum):
    soc2 = "soc2"
    iso27001 = "iso27001"
    india_dpdp = "india_dpdp"
    owasp_llm = "owasp_llm"  # AI-2 — OWASP LLM Top 10, reuses the existing ComplianceControl shape


class ComplianceControlStatus(str, enum.Enum):
    missing = "missing"
    in_progress = "in_progress"
    implemented = "implemented"


class ComplianceControl(Base):
    __tablename__ = "compliance_controls"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    framework = Column(Enum(ComplianceFramework), nullable=False)
    control_id = Column(String(50), nullable=False)  # e.g. "CC6.1", "A.9.2.1", "DPDP-4"
    control_name = Column(String(500), nullable=False)
    status = Column(Enum(ComplianceControlStatus), default=ComplianceControlStatus.missing)
    evidence_notes = Column(Text, nullable=True)
    evidence_file_path = Column(String(500), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class PhishingCampaignStatus(str, enum.Enum):
    draft = "draft"
    running = "running"
    completed = "completed"


class PhishingCampaignType(str, enum.Enum):
    phishing = "phishing"
    spear_phishing = "spear_phishing"


class PhishingCampaign(Base):
    __tablename__ = "phishing_campaigns"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    template_name = Column(String(255), nullable=True)  # e.g. "IT password reset", "Invoice overdue"
    campaign_type = Column(Enum(PhishingCampaignType), default=PhishingCampaignType.phishing)  # SE-2
    template_html = Column(Text, nullable=True)  # SE-2 — supports {target_name}/{target_role}/{tracking_pixel}/{tracking_link} variables
    status = Column(Enum(PhishingCampaignStatus), default=PhishingCampaignStatus.draft)
    target_count = Column(Integer, default=0)
    sent_count = Column(Integer, default=0)
    opened_count = Column(Integer, default=0)
    clicked_count = Column(Integer, default=0)
    reported_count = Column(Integer, default=0)  # employees who flagged it as phishing — the good outcome
    credential_submitted_count = Column(Integer, default=0)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")
    results = relationship("PhishingResult", back_populates="campaign", cascade="all, delete-orphan")
    targets = relationship("PhishingTarget", back_populates="campaign", cascade="all, delete-orphan")


class PhishingTarget(Base):
    """
    SE-2 per-target personalization + tracking. Distinct from PhishingResult
    (which is the anonymized-by-convention outcome log fed by an external
    tool like GoPhish) -- a PhishingTarget is created up front from a CSV
    import and carries its own tracking_token so this platform can serve
    the pixel/landing page itself for campaigns built with the builder here.
    """
    __tablename__ = "phishing_targets"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    campaign_id = Column(UUID(as_uuid=False), ForeignKey("phishing_campaigns.id"), nullable=False, index=True)
    name = Column(String(255), nullable=True)
    role = Column(String(255), nullable=True)
    email = Column(String(255), nullable=False)
    tracking_token = Column(String(64), nullable=False, unique=True, index=True)
    sent_at = Column(DateTime, nullable=True)
    opened = Column(Boolean, default=False)
    opened_at = Column(DateTime, nullable=True)
    clicked = Column(Boolean, default=False)
    clicked_at = Column(DateTime, nullable=True)
    submitted_credentials = Column(Boolean, default=False)  # boolean only -- the actual submitted password is never stored
    submitted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    campaign = relationship("PhishingCampaign", back_populates="targets")


class PhishingResult(Base):
    """Per-employee outcome. employee_identifier should be anonymized (e.g. hashed or 'Employee #3')
    unless the client has explicitly opted into named reporting — enforce that at the API layer."""
    __tablename__ = "phishing_results"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    campaign_id = Column(UUID(as_uuid=False), ForeignKey("phishing_campaigns.id"), nullable=False, index=True)
    employee_identifier = Column(String(255), nullable=False)
    opened = Column(Boolean, default=False)
    clicked = Column(Boolean, default=False)
    reported = Column(Boolean, default=False)
    submitted_credentials = Column(Boolean, default=False)
    training_completed = Column(Boolean, default=False)
    event_at = Column(DateTime, default=datetime.utcnow)

    campaign = relationship("PhishingCampaign", back_populates="results")


class PentestFrequency(str, enum.Enum):
    quarterly = "quarterly"
    semi_annual = "semi_annual"
    annual = "annual"
    custom = "custom"  # one-off, non-recurring — next_due_date is set manually each time


class PentestStatus(str, enum.Enum):
    scheduled = "scheduled"
    in_progress = "in_progress"
    completed = "completed"
    overdue = "overdue"


class PentestSchedule(Base):
    """
    One row per client's ongoing pentest cadence. For 'custom' frequency,
    next_due_date is set explicitly and does not auto-advance — the
    analyst sets the next date after each engagement. For recurring
    frequencies, completing an engagement auto-advances next_due_date.
    """
    __tablename__ = "pentest_schedules"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    frequency = Column(Enum(PentestFrequency), nullable=False, default=PentestFrequency.quarterly)
    next_due_date = Column(DateTime, nullable=False)
    last_completed_date = Column(DateTime, nullable=True)
    status = Column(Enum(PentestStatus), default=PentestStatus.scheduled)
    scope_notes = Column(Text, nullable=True)  # what's in/out of scope for this engagement
    report_file_path = Column(String(500), nullable=True)  # uploaded pentest report from the last engagement
    reminder_sent_at = Column(DateTime, nullable=True)  # tracks the 2-week-out reminder so it only fires once
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class MetricSnapshot(Base):
    """
    One row per client per day: open-finding counts by severity + the
    computed risk score at that point in time. Backing store for every
    trend chart in the spec (dashboard 3/6/12mo trend, vuln lifecycle
    trend, report risk-score trend) -- written once daily instead of
    each surface keeping its own history.
    """
    __tablename__ = "metric_snapshots"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    snapshot_date = Column(DateTime, nullable=False, index=True)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)

    client = relationship("Client")


class CloudAccount(Base):
    __tablename__ = "cloud_accounts"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    provider = Column(Enum(CloudProvider), nullable=False)
    account_identifier = Column(String(255), nullable=False)  # AWS account ID, GCP project, Azure sub ID
    encrypted_credentials = Column(Text, nullable=False)  # Fernet-encrypted, read-only creds
    is_active = Column(Boolean, default=True)
    last_audited_at = Column(DateTime, nullable=True)
    config_baseline = Column(JSON, nullable=True)  # Feature 4.3 — resource->issues snapshot from first audit
    credentials_rotated_at = Column(DateTime, default=datetime.utcnow)  # Feature: API key rotation tracking

    client = relationship("Client", back_populates="cloud_accounts")


# --- Track1_Expanded_Services.docx — Service 1: Social Engineering & Physical Security ---

class OSINTProfile(Base):
    """SE-1 — one row per generated OSINT reconnaissance snapshot for a client."""
    __tablename__ = "osint_profiles"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    generated_at = Column(DateTime, default=datetime.utcnow)
    findings = Column(JSON, default=dict)  # whois, dns_records, email_patterns, google_dorks, github_hits, job_listing_tech, narrative
    report_path = Column(String(500), nullable=True)

    client = relationship("Client")


class VishingRiskRating(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class VishingEngagement(Base):
    """
    SE-3 — analysis of a single vishing test call recording. The call
    itself is placed by a human analyst under the engagement's own
    consent process; this row starts once a recording (or manually
    supplied transcript) exists.
    """
    __tablename__ = "vishing_engagements"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    scenario = Column(String(500), nullable=True)  # e.g. "IT helpdesk password reset pretext"
    recording_path = Column(String(500), nullable=True)
    transcript = Column(Text, nullable=True)
    analysis = Column(JSON, default=dict)  # techniques_identified, disclosures, risk_rating, summary
    risk_rating = Column(Enum(VishingRiskRating), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class PhysicalAssessmentStatus(str, enum.Enum):
    scheduled = "scheduled"
    in_progress = "in_progress"
    completed = "completed"


class PhysicalTestType(str, enum.Enum):
    tailgating = "tailgating"
    badge_cloning = "badge_cloning"
    dumpster_diving = "dumpster_diving"
    visitor_access = "visitor_access"
    clean_desk = "clean_desk"
    usb_drop = "usb_drop"


class PhysicalSecurityAssessment(Base):
    """
    Physical security engagement tracker. Deliberately a plain
    checklist/engagement record, not an automation target -- tailgating,
    badge cloning, dumpster diving, and USB-drop tests require an
    in-person analyst and can't be scripted.
    """
    __tablename__ = "physical_security_assessments"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    site_name = Column(String(255), nullable=True)
    scheduled_date = Column(DateTime, nullable=True)
    status = Column(Enum(PhysicalAssessmentStatus), default=PhysicalAssessmentStatus.scheduled)
    summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")
    checklist_items = relationship("PhysicalSecurityChecklistItem", back_populates="assessment", cascade="all, delete-orphan")


class PhysicalSecurityChecklistItem(Base):
    __tablename__ = "physical_security_checklist_items"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    assessment_id = Column(UUID(as_uuid=False), ForeignKey("physical_security_assessments.id"), nullable=False, index=True)
    test_type = Column(Enum(PhysicalTestType), nullable=False)
    attempted = Column(Boolean, default=False)
    outcome_notes = Column(Text, nullable=True)
    severity = Column(Enum(Severity), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    assessment = relationship("PhysicalSecurityAssessment", back_populates="checklist_items")


# --- Track1_Expanded_Services.docx — Service 2: Mobile App Security ---

class MobilePlatform(str, enum.Enum):
    android = "android"
    ios = "ios"


class MobileScanStatus(str, enum.Enum):
    queued = "queued"
    completed = "completed"
    failed = "failed"


class MobileAppScan(Base):
    """MOB-1/MOB-3 — one row per uploaded mobile app static analysis."""
    __tablename__ = "mobile_app_scans"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    platform = Column(Enum(MobilePlatform), nullable=False)
    original_filename = Column(String(255), nullable=True)
    file_path = Column(String(500), nullable=True)
    status = Column(Enum(MobileScanStatus), default=MobileScanStatus.queued)
    app_label = Column(String(255), nullable=True)  # Android package name / iOS bundle identifier
    findings = Column(JSON, default=list)  # list of MASVS-tagged finding dicts, see mobile_sast.py
    masvs_score = Column(Integer, nullable=True)
    executive_summary = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class MobileTrafficImport(Base):
    """MOB-2 — one row per imported HAR traffic capture, optionally tied to a MobileAppScan."""
    __tablename__ = "mobile_traffic_imports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    mobile_app_scan_id = Column(UUID(as_uuid=False), ForeignKey("mobile_app_scans.id"), nullable=True, index=True)
    discovered_endpoints = Column(JSON, default=list)
    sensitive_data_hits = Column(JSON, default=list)
    auth_classification = Column(JSON, default=dict)
    openapi_lite = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")
    mobile_app_scan = relationship("MobileAppScan")


# --- Track1_Expanded_Services.docx — Service 3: Blockchain & Web3 Security ---

class ContractAuditStatus(str, enum.Enum):
    queued = "queued"
    completed = "completed"
    failed = "failed"


class SmartContractAudit(Base):
    """WEB3-1/WEB3-2 — one row per submitted Solidity contract audit."""
    __tablename__ = "smart_contract_audits"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    contract_name = Column(String(255), nullable=True)
    contract_source = Column(Text, nullable=True)
    network = Column(String(50), default="ethereum")
    status = Column(Enum(ContractAuditStatus), default=ContractAuditStatus.queued)
    solc_version_hint = Column(String(50), nullable=True)
    findings = Column(JSON, default=list)
    report_path = Column(String(500), nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class OnChainMonitor(Base):
    """WEB3-3 — one row per contract address under interval-based on-chain monitoring."""
    __tablename__ = "onchain_monitors"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    contract_address = Column(String(255), nullable=False)
    network = Column(String(50), default="ethereum")
    alert_thresholds = Column(JSON, default=dict)  # e.g. {"large_transfer_native_wei": 10**19}
    telegram_chat_id = Column(String(100), nullable=True)
    last_checked_block = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    last_alerts = Column(JSON, default=list)  # most recent poll's alerts, for the dashboard
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


# --- Track1_Expanded_Services.docx — Service 4: AI/ML Security ---

class PromptInjectionTest(Base):
    """AI-1 — one row per prompt injection test run against a client's LLM-integrated endpoint."""
    __tablename__ = "prompt_injection_tests"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    target_url = Column(String(500), nullable=False)
    results = Column(JSON, default=list)  # full list of {payload, response_text, classification}
    success_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class AIFeatureInventory(Base):
    """AI-2 — a client-declared AI/ML feature and its library stack, for CVE monitoring + the posture dashboard."""
    __tablename__ = "ai_feature_inventory"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    feature_name = Column(String(255), nullable=False)
    feature_type = Column(String(100), nullable=True)  # e.g. "chatbot", "rag_pipeline", "recommendation_model"
    library_stack = Column(JSON, default=dict)  # {"langchain": "0.1.0", "openai": "1.40.0", ...}
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


# --- Track1_Expanded_Services.docx — Service 5: DevSecOps Pipeline & CI/CD Security ---

class PipelineProvider(str, enum.Enum):
    github = "github"
    gitlab = "gitlab"    # documented extension point -- not implemented
    jenkins = "jenkins"  # documented extension point -- not implemented


class PipelineIntegration(Base):
    """DSO-1 — one row per repo registered for gate deployment + run polling. PipelineFinding is NOT a separate table -- it reuses Finding with a "[Pipeline]"/"[CI Scan]"/"[IaC]" title prefix, the same source-tagging convention cspm.py uses for cloud provider tagging."""
    __tablename__ = "pipeline_integrations"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    provider = Column(Enum(PipelineProvider), default=PipelineProvider.github)
    repo_full_name = Column(String(255), nullable=False)  # e.g. "acme/backend"
    gate_config = Column(JSON, default=dict)  # {"template": "python_fastapi", "block_on_severity": "high"}
    is_active = Column(Boolean, default=True)
    last_synced_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class DeveloperScorecardSnapshot(Base):
    """DSO-3 — one rollup per client per day. Same shape idea as MetricSnapshot from the first spec pass."""
    __tablename__ = "developer_scorecard_snapshots"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    snapshot_date = Column(DateTime, nullable=False, index=True)
    metrics = Column(JSON, default=dict)  # {"pipeline_health_score", "vulnerabilities_blocked", "secrets_blocked", "mttr_hours", ...}

    client = relationship("Client")


# --- Track1_Advanced_Services.docx — shared: TH-1 SIEM/EDR credential storage ---

class SiemProvider(str, enum.Enum):
    elastic = "elastic"
    splunk = "splunk"
    crowdstrike = "crowdstrike"
    sentinelone = "sentinelone"


class SiemConnection(Base):
    """TH-1 — a client's own SIEM/EDR API credentials, same shape and Fernet-encryption pattern as CloudAccount."""
    __tablename__ = "siem_connections"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    provider = Column(Enum(SiemProvider), nullable=False)
    base_url = Column(String(500), nullable=True)
    encrypted_credentials = Column(Text, nullable=False)  # Fernet-encrypted, read-only query creds
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


# --- Track1_Advanced_Services.docx — RT-1 Red Team Operations ---
# Tracking/logging tool only: this platform does not run a C2 server or execute
# attacks. A human red teamer operates real tooling (Cobalt Strike, Havoc, etc.)
# outside this platform and logs what they did here -- same model as Ghostwriter/RedELK.

class RedTeamOperationStatus(str, enum.Enum):
    planning = "planning"
    active = "active"
    complete = "complete"


class RedTeamTimelinePhase(str, enum.Enum):
    recon = "recon"
    initial_access = "initial_access"
    lateral_movement = "lateral_movement"
    persistence = "persistence"
    exfiltration = "exfiltration"
    objective = "objective"


class RedTeamDetectionStatus(str, enum.Enum):
    detected = "detected"
    not_detected = "not_detected"
    partial = "partial"


class RedTeamInfraType(str, enum.Enum):
    c2_server = "c2_server"
    phishing_domain = "phishing_domain"
    payload_host = "payload_host"
    redirector = "redirector"


class RedTeamOperation(Base):
    """RT-1 — one row per red team engagement. Analyst-only workspace, never client-visible."""
    __tablename__ = "red_team_operations"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    name = Column(String(255), nullable=False)
    objective = Column(Text, nullable=True)
    threat_actor = Column(String(255), nullable=True)  # emulated actor/profile, e.g. "FIN7"
    status = Column(Enum(RedTeamOperationStatus), default=RedTeamOperationStatus.planning)
    start_date = Column(DateTime, nullable=True)
    end_date = Column(DateTime, nullable=True)
    roe_signed = Column(Boolean, default=False)  # Rules of Engagement signed off
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class RedTeamTimelineEntry(Base):
    """RT-1 — one row per logged action during an operation. This is the actual C2/attack activity log, entered by the operator after the fact."""
    __tablename__ = "red_team_timeline_entries"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    operation_id = Column(UUID(as_uuid=False), ForeignKey("red_team_operations.id"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False)
    phase = Column(Enum(RedTeamTimelinePhase), nullable=False)
    action = Column(Text, nullable=False)
    host = Column(String(255), nullable=True)
    user_context = Column(String(255), nullable=True)
    tool_used = Column(String(255), nullable=True)
    outcome = Column(Text, nullable=True)
    detected = Column(Enum(RedTeamDetectionStatus), default=RedTeamDetectionStatus.not_detected)
    attack_technique_id = Column(String(20), nullable=True)  # free text, e.g. "T1566.001"
    evidence_path = Column(String(500), nullable=True)  # UUID-derived storage filename

    operation = relationship("RedTeamOperation")


class RedTeamImplant(Base):
    """RT-1 — tracked implant/beacon, mirroring what the real C2 tool (outside this platform) reports."""
    __tablename__ = "red_team_implants"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    operation_id = Column(UUID(as_uuid=False), ForeignKey("red_team_operations.id"), nullable=False, index=True)
    host = Column(String(255), nullable=False)
    ip_address = Column(String(64), nullable=True)
    username = Column(String(255), nullable=True)
    implant_type = Column(String(100), nullable=True)  # e.g. "beacon", "havoc-demon"
    persistence = Column(String(255), nullable=True)  # persistence mechanism description
    checkin_freq_seconds = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    deployed_at = Column(DateTime, default=datetime.utcnow)

    operation = relationship("RedTeamOperation")


class RedTeamInfrastructure(Base):
    """RT-1 — attacker-owned infra tracker (C2 servers, phishing domains, redirectors, payload hosts)."""
    __tablename__ = "red_team_infrastructure"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    operation_id = Column(UUID(as_uuid=False), ForeignKey("red_team_operations.id"), nullable=False, index=True)
    infra_type = Column(Enum(RedTeamInfraType), nullable=False)
    identifier = Column(String(255), nullable=False)  # IP, domain, or hostname
    provider = Column(String(255), nullable=True)  # e.g. "DigitalOcean", "Namecheap"
    notes = Column(Text, nullable=True)

    operation = relationship("RedTeamOperation")


# --- Track1_Advanced_Services.docx — ZD-1 Zero Day Research & Responsible Disclosure ---
# Tracking platform + optional local fuzz hook: FuzzingJob is an analyst-updated
# tracking record (status, crashes found), not a live AFL++/LibFuzzer/Boofuzz
# orchestration engine -- see plan Context for the confirmed scope boundary.

class ResearchStatus(str, enum.Enum):
    identified = "identified"
    active = "active"
    paused = "paused"
    complete = "complete"


class ResearchFindingStatus(str, enum.Enum):
    researching = "researching"
    confirmed = "confirmed"
    disclosed = "disclosed"
    published = "published"


class FuzzingJobStatus(str, enum.Enum):
    queued = "queued"
    running = "running"
    stopped = "stopped"
    completed = "completed"


class ResearchTarget(Base):
    """ZD-1 — a piece of software/firmware/protocol under active vulnerability research. client_id is nullable: null means independent Track-A research, set means client-commissioned Track-B."""
    __tablename__ = "research_targets"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    vendor = Column(String(255), nullable=True)
    version = Column(String(100), nullable=True)
    language = Column(String(100), nullable=True)
    source_url = Column(String(500), nullable=True)
    bug_bounty_url = Column(String(500), nullable=True)
    max_bounty = Column(Integer, nullable=True)  # USD, whole-dollar
    priority = Column(String(20), default="medium")
    status = Column(Enum(ResearchStatus), default=ResearchStatus.identified)
    total_hours = Column(Integer, default=0)
    total_earned = Column(Integer, default=0)  # USD, whole-dollar
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class ResearchFinding(Base):
    """ZD-1 — one candidate/confirmed vulnerability discovered in a research target."""
    __tablename__ = "research_findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    target_id = Column(UUID(as_uuid=False), ForeignKey("research_targets.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    cve_id = Column(String(20), nullable=True, index=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(Enum(Severity), nullable=True)
    vuln_class = Column(String(255), nullable=True)  # e.g. "Buffer Overflow", "SQLi", "Auth Bypass"
    description = Column(Text, nullable=True)
    poc_path = Column(String(500), nullable=True)  # UUID-derived storage filename
    status = Column(Enum(ResearchFindingStatus), default=ResearchFindingStatus.researching)
    vendor_notified = Column(DateTime, nullable=True)
    patch_released = Column(DateTime, nullable=True)
    published_at = Column(DateTime, nullable=True)
    bounty_amount = Column(Integer, nullable=True)  # USD, whole-dollar
    bounty_platform = Column(String(50), nullable=True)  # "hackerone" | "bugcrowd" | "direct"
    created_at = Column(DateTime, default=datetime.utcnow)

    target = relationship("ResearchTarget")


class FuzzingJob(Base):
    """ZD-1 — an analyst-updated tracking record for a fuzzing campaign run OUTSIDE this platform (AFL++/LibFuzzer/Boofuzz). Not orchestrated here -- see module docstring."""
    __tablename__ = "fuzzing_jobs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    target_id = Column(UUID(as_uuid=False), ForeignKey("research_targets.id"), nullable=False, index=True)
    fuzzer = Column(String(50), nullable=False)  # "afl++" | "libfuzzer" | "boofuzz" | other
    target_binary_path = Column(String(500), nullable=True)
    corpus_path = Column(String(500), nullable=True)
    status = Column(Enum(FuzzingJobStatus), default=FuzzingJobStatus.queued)
    crashes_found = Column(Integer, default=0)
    execs_per_sec = Column(Integer, nullable=True)
    started_at = Column(DateTime, nullable=True)
    ended_at = Column(DateTime, nullable=True)

    target = relationship("ResearchTarget")


# --- Track1_Advanced_Services.docx — DFIR-1 Case Manager + DFIR-2 Log Analyser ---

class DfirCaseStatus(str, enum.Enum):
    active = "active"
    contained = "contained"
    closed = "closed"


class DfirCase(Base):
    """DFIR-1 — one row per incident response engagement."""
    __tablename__ = "dfir_cases"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    case_number = Column(String(50), unique=True, nullable=False)  # e.g. "DFIR-2026-0001"
    incident_type = Column(String(255), nullable=True)
    severity = Column(Enum(Severity), default=Severity.medium)
    status = Column(Enum(DfirCaseStatus), default=DfirCaseStatus.active)
    discovered_at = Column(DateTime, nullable=True)
    contained_at = Column(DateTime, nullable=True)
    closed_at = Column(DateTime, nullable=True)
    initial_vector = Column(String(255), nullable=True)
    affected_systems = Column(JSON, default=list)  # list[str] of hostnames/systems
    data_exfiltrated = Column(Boolean, default=False)
    retainer_hours_used = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


class DfirEvidence(Base):
    """DFIR-1 — acquired evidence artifact. Hashes are computed server-side on upload, never trusted from the client."""
    __tablename__ = "dfir_evidence"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("dfir_cases.id"), nullable=False, index=True)
    evidence_type = Column(String(100), nullable=True)  # e.g. "disk image", "memory dump", "log export"
    source_host = Column(String(255), nullable=True)
    acquisition_tool = Column(String(255), nullable=True)
    md5_hash = Column(String(32), nullable=True)
    sha256_hash = Column(String(64), nullable=True)
    file_size_bytes = Column(Integer, nullable=True)
    storage_path = Column(String(500), nullable=True)  # UUID-derived storage filename
    acquired_at = Column(DateTime, default=datetime.utcnow)
    acquired_by = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    chain_of_custody = Column(JSON, default=list)  # append-only list of {"timestamp", "custodian", "action"}

    case = relationship("DfirCase")


class DfirIoc(Base):
    """DFIR-1 — an indicator of compromise attributed to a case."""
    __tablename__ = "dfir_iocs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("dfir_cases.id"), nullable=False, index=True)
    ioc_type = Column(String(50), nullable=False)  # "ip" | "domain" | "hash" | "email" | "url" | other
    value = Column(String(500), nullable=False)
    confidence = Column(String(20), default="medium")  # low | medium | high
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    context = Column(Text, nullable=True)
    attack_technique_id = Column(String(20), nullable=True)

    case = relationship("DfirCase")


class DfirTimelineEntry(Base):
    """DFIR-1 — one entry in the incident's forensic timeline (super-timeline style)."""
    __tablename__ = "dfir_timeline_entries"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("dfir_cases.id"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False)
    event_description = Column(Text, nullable=False)
    source = Column(String(255), nullable=True)  # e.g. "EVTX 4624", "CloudTrail", "analyst note"
    host = Column(String(255), nullable=True)
    attack_technique_id = Column(String(20), nullable=True)

    case = relationship("DfirCase")


class IrRetainer(Base):
    """DFIR-1 — a client's incident response retainer agreement."""
    __tablename__ = "ir_retainers"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    tier = Column(String(50), nullable=True)  # e.g. "Bronze", "Silver", "Gold"
    hours_included_per_year = Column(Integer, default=0)
    hours_used = Column(Integer, default=0)
    response_sla_hours = Column(Integer, nullable=True)
    last_tabletop_at = Column(DateTime, nullable=True)

    client = relationship("Client")


class DfirLogAnalysisJob(Base):
    """DFIR-2 — one row per uploaded log file, processed synchronously on upload (same shape/pattern as MobileAppScan)."""
    __tablename__ = "dfir_log_analysis_jobs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("dfir_cases.id"), nullable=False, index=True)
    original_filename = Column(String(255), nullable=True)
    log_type = Column(String(50), nullable=True)  # "cloudtrail" | "azure" | "gcp" | "syslog" | "web_access" | "paloalto" | "evtx"
    events_count = Column(Integer, default=0)
    anomalies = Column(JSON, default=list)
    iocs = Column(JSON, default=list)
    narrative = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    case = relationship("DfirCase")


class FirmwareScanStatus(str, enum.Enum):
    queued = "queued"
    completed = "completed"
    failed = "failed"


class FirmwareAnalysisJob(Base):
    """IOT-1 — one row per uploaded firmware image, same shape/pattern as MobileAppScan."""
    __tablename__ = "firmware_analysis_jobs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    original_filename = Column(String(255), nullable=True)
    file_path = Column(String(500), nullable=True)
    status = Column(Enum(FirmwareScanStatus), default=FirmwareScanStatus.queued)
    component_summary = Column(JSON, default=dict)  # {"BusyBox": "1.31.1", "OpenSSL": "1.1.1k", ...}
    findings = Column(JSON, default=dict)  # {"components": {...}, "secrets": [...], "cves": [...], "extracted": bool}
    executive_summary = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")


# --- Track1_Advanced_Services.docx — TH-1 Continuous Threat Hunting ---

class HuntHypothesisSource(str, enum.Enum):
    manual = "manual"
    ai_generated = "ai_generated"
    cti_feed = "cti_feed"


class HuntOperationStatus(str, enum.Enum):
    planned = "planned"
    active = "active"
    complete = "complete"


class HuntOutcome(str, enum.Enum):
    threat_found = "threat_found"
    negative = "negative"
    inconclusive = "inconclusive"


class HuntHypothesis(Base):
    """TH-1 — a reusable hunt hypothesis. NOT client-scoped: this is a shared library analysts draw hunts from."""
    __tablename__ = "hunt_hypotheses"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    attack_technique = Column(String(20), nullable=True)
    data_sources = Column(JSON, default=list)  # e.g. ["EDR", "DNS logs", "auth logs"]
    industries = Column(JSON, default=list)  # e.g. ["fintech", "healthcare"] -- empty means industry-agnostic
    priority = Column(String(20), default="medium")
    hunt_count = Column(Integer, default=0)
    last_positive_at = Column(DateTime, nullable=True)
    source = Column(Enum(HuntHypothesisSource), default=HuntHypothesisSource.manual)
    created_at = Column(DateTime, default=datetime.utcnow)


class HuntOperation(Base):
    """TH-1 — one client-scoped hunt run against a hypothesis from the shared library."""
    __tablename__ = "hunt_operations"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    hypothesis_id = Column(UUID(as_uuid=False), ForeignKey("hunt_hypotheses.id"), nullable=False, index=True)
    analyst_id = Column(UUID(as_uuid=False), ForeignKey("users.id"), nullable=True)
    status = Column(Enum(HuntOperationStatus), default=HuntOperationStatus.planned)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    outcome = Column(Enum(HuntOutcome), nullable=True)
    hours_spent = Column(Integer, default=0)

    client = relationship("Client")
    hypothesis = relationship("HuntHypothesis")


class HuntFinding(Base):
    """TH-1 — a finding surfaced during a hunt operation."""
    __tablename__ = "hunt_findings"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    hunt_id = Column(UUID(as_uuid=False), ForeignKey("hunt_operations.id"), nullable=False, index=True)
    severity = Column(Enum(Severity), default=Severity.medium)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    evidence = Column(JSON, default=dict)
    iocs = Column(JSON, default=list)  # list[{"ioc_type": ..., "value": ...}]
    attack_technique_id = Column(String(20), nullable=True)
    confirmed = Column(Boolean, default=False)
    escalated_to_ir = Column(Boolean, default=False)

    hunt = relationship("HuntOperation")


class AlertLog(Base):
    """Persisted record of every alert notification this platform has attempted to send (Module 5.2/5.3, SLA escalation, DSO-2 triage digest) — exportable so a client/analyst can download the send history."""
    __tablename__ = "alert_logs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    client_id = Column(UUID(as_uuid=False), ForeignKey("clients.id"), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=False), ForeignKey("findings.id"), nullable=True)
    alert_type = Column(String(50), nullable=False)  # finding_alert | sla_breach | weekly_threat_digest | weekly_triage_digest
    subject = Column(String(500), nullable=False)
    channel_email_sent = Column(Boolean, default=False)
    channel_slack_sent = Column(Boolean, default=False)
    sent_at = Column(DateTime, default=datetime.utcnow)

    client = relationship("Client")
    finding = relationship("Finding")
