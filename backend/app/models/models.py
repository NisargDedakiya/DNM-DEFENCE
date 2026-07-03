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
