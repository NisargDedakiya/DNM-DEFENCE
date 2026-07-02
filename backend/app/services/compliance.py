"""
Module 6.4 — Compliance Center backend.

Seeds each new client with a starter checklist for SOC 2, ISO 27001, and
India's DPDP Act. These are NOT exhaustive audit-ready control sets —
they're a representative starting checklist a founder can track progress
against and expand with their auditor. Treat as a starting point, not a
certified mapping.
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.models import Client, ComplianceControl, ComplianceFramework, ComplianceControlStatus

SOC2_STARTER_CONTROLS = [
    ("CC1.1", "Board and management demonstrate commitment to integrity and ethical values"),
    ("CC6.1", "Logical access security measures restrict access to authorized users"),
    ("CC6.6", "System boundaries are protected from unauthorized access (firewalls, network segmentation)"),
    ("CC7.2", "Security incidents are identified, evaluated, and responded to"),
    ("CC8.1", "Changes to infrastructure and software are authorized, tested, and approved"),
    ("A1.2", "Environmental protections, backup, and recovery infrastructure are in place"),
]

ISO27001_STARTER_CONTROLS = [
    ("A.5.1", "Policies for information security are defined and approved by management"),
    ("A.6.1", "Information security roles and responsibilities are defined"),
    ("A.8.1", "Inventory of information assets is maintained"),
    ("A.9.2", "User access provisioning is formally managed"),
    ("A.12.6", "Technical vulnerabilities are identified and remediated in a timely manner"),
    ("A.16.1", "Information security incidents are managed via a defined process"),
]

INDIA_DPDP_STARTER_CONTROLS = [
    ("DPDP-1", "Notice is given to data principals describing personal data processing"),
    ("DPDP-2", "Consent is obtained and is free, specific, informed, and unambiguous"),
    ("DPDP-3", "Data principal rights (access, correction, erasure) can be fulfilled on request"),
    ("DPDP-4", "Reasonable security safeguards are implemented to prevent personal data breaches"),
    ("DPDP-5", "Data breaches are reported to the Data Protection Board and affected principals"),
    ("DPDP-6", "Data retention limits are defined and enforced for personal data"),
]

FRAMEWORK_SEEDS = {
    ComplianceFramework.soc2: SOC2_STARTER_CONTROLS,
    ComplianceFramework.iso27001: ISO27001_STARTER_CONTROLS,
    ComplianceFramework.india_dpdp: INDIA_DPDP_STARTER_CONTROLS,
}


def seed_compliance_controls(db: Session, client: Client) -> int:
    """Called once on client onboarding (Module 7 workflow). Idempotent — skips if already seeded."""
    existing = db.query(ComplianceControl).filter_by(client_id=client.id).count()
    if existing > 0:
        return 0

    now = datetime.utcnow()
    created = 0
    for framework, controls in FRAMEWORK_SEEDS.items():
        for control_id, control_name in controls:
            db.add(ComplianceControl(
                client_id=client.id, framework=framework, control_id=control_id,
                control_name=control_name, status=ComplianceControlStatus.missing,
                updated_at=now,
            ))
            created += 1
    db.commit()
    return created
