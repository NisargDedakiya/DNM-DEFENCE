from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import require_client_access
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Client, Finding, FindingStatus
from app.schemas.schemas import ScanTriggerResponse
from app.services import ai_reports, notifications
from app.workers.tasks import run_vuln_scan_for_client, run_dark_web_scan_for_client

router = APIRouter(prefix="/api/clients/{client_id}/findings", tags=["findings"], dependencies=[Depends(require_client_access)])


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    asset_id: str | None
    title: str
    description: str | None
    severity: str
    cvss_score: float | None
    cve_id: str | None
    status: str
    remediation_steps: str | None
    created_at: datetime
    resolved_at: datetime | None
    sla_deadline: datetime | None


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@router.get("", response_model=list[FindingOut])
def list_findings(
    client_id: str,
    severity: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
):
    _require_client(client_id, db)
    q = db.query(Finding).filter_by(client_id=client_id)
    if severity:
        q = q.filter(Finding.severity == severity)
    if status:
        q = q.filter(Finding.status == status)
    return q.order_by(Finding.cvss_score.desc()).all()


@router.patch("/{finding_id}", response_model=FindingOut)
def update_finding_status(client_id: str, finding_id: str, payload: FindingStatusUpdate, db: Session = Depends(get_db)):
    """Feature 6.3 — client updates finding status (ack/in-progress/disputed/resolved)."""
    _require_client(client_id, db)
    finding = db.query(Finding).filter_by(id=finding_id, client_id=client_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    finding.status = payload.status
    if payload.status == FindingStatus.resolved:
        finding.resolved_at = datetime.utcnow()
    db.commit()
    db.refresh(finding)
    return finding


@router.post("/scan", response_model=ScanTriggerResponse)
def trigger_vuln_scan(client_id: str, severity_filter: str | None = None, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    task = run_vuln_scan_for_client.delay(client_id, severity_filter)
    return ScanTriggerResponse(message="Vulnerability scan queued", task_id=task.id)


@router.post("/dark-web-scan", response_model=ScanTriggerResponse)
def trigger_dark_web_scan(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    task = run_dark_web_scan_for_client.delay(client_id)
    return ScanTriggerResponse(message="Dark web / threat intel scan queued", task_id=task.id)


@router.post("/{finding_id}/send-alert")
def send_alert_now(client_id: str, finding_id: str, db: Session = Depends(get_db)):
    """Manual send — human reviewed the AI draft and wants it sent now, regardless of auto-send settings."""
    client = _require_client(client_id, db)
    finding = db.query(Finding).filter_by(id=finding_id, client_id=client_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    draft = ai_reports.draft_alert_notification(finding)
    result = notifications.notify_finding_alert(client, finding.title, finding.severity.value, draft)
    return {"draft": draft, "sent": result}


@router.post("/{finding_id}/ai-remediation")
def generate_ai_remediation_for_finding(client_id: str, finding_id: str, db: Session = Depends(get_db)):
    """
    On-demand AI-generated remediation, more specific than the static
    per-issue templates set at finding-creation time. Doesn't overwrite
    the stored remediation_steps automatically -- returns the suggestion
    for review; the caller decides whether to apply it via a normal
    finding update if you add one, or just read it in the portal.
    """
    _require_client(client_id, db)
    finding = db.query(Finding).filter_by(id=finding_id, client_id=client_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    suggestion = ai_reports.generate_ai_remediation(finding.title, finding.description, finding.evidence)
    if not suggestion:
        return {"remediation": finding.remediation_steps, "ai_generated": False,
                "note": "AI generation failed or is unavailable — showing the existing static remediation instead."}
    return {"remediation": suggestion, "ai_generated": True}
