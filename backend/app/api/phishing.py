"""
Feature 6.6 — Phishing Simulation Dashboard.

This module tracks campaign results; it does not send phishing emails
itself (that requires a dedicated sending domain/infrastructure kept
separate from production mail to avoid reputation damage — wire an
external phishing simulation tool, e.g. GoPhish, and have it POST results
back to /results, or import a CSV export from one).
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import require_client_access, get_current_user
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Client, PhishingCampaign, PhishingResult, PhishingCampaignStatus, User, UserRole

router = APIRouter(prefix="/api/clients/{client_id}/phishing-campaigns", tags=["phishing"], dependencies=[Depends(require_client_access)])


class CampaignCreate(BaseModel):
    name: str
    template_name: str | None = None
    target_count: int = 0


class CampaignOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    name: str
    template_name: str | None
    status: str
    target_count: int
    sent_count: int
    opened_count: int
    clicked_count: int
    reported_count: int
    credential_submitted_count: int
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class ResultIn(BaseModel):
    employee_identifier: str  # should already be anonymized upstream unless client opted into named data
    opened: bool = False
    clicked: bool = False
    reported: bool = False
    submitted_credentials: bool = False
    training_completed: bool = False


class ResultOut(BaseModel):
    id: str
    employee_identifier: str
    opened: bool
    clicked: bool
    reported: bool
    submitted_credentials: bool
    training_completed: bool
    event_at: datetime


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_campaign(client_id: str, campaign_id: str, db: Session) -> PhishingCampaign:
    c = db.query(PhishingCampaign).filter_by(id=campaign_id, client_id=client_id).first()
    if not c:
        raise HTTPException(404, "Campaign not found")
    return c


@router.post("", response_model=CampaignOut, status_code=201)
def create_campaign(client_id: str, payload: CampaignCreate, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    campaign = PhishingCampaign(client_id=client_id, **payload.model_dump())
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    return campaign


@router.get("", response_model=list[CampaignOut])
def list_campaigns(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(PhishingCampaign).filter_by(client_id=client_id).order_by(PhishingCampaign.created_at.desc()).all()


@router.post("/{campaign_id}/start", response_model=CampaignOut)
def start_campaign(client_id: str, campaign_id: str, db: Session = Depends(get_db)):
    campaign = _require_campaign(client_id, campaign_id, db)
    campaign.status = PhishingCampaignStatus.running
    campaign.started_at = datetime.utcnow()
    db.commit()
    db.refresh(campaign)
    return campaign


@router.post("/{campaign_id}/results", status_code=201)
def record_result(client_id: str, campaign_id: str, payload: ResultIn, db: Session = Depends(get_db)):
    """
    Called by an external phishing simulation tool (e.g. GoPhish webhook)
    or a CSV importer as each employee interacts with the campaign.
    """
    campaign = _require_campaign(client_id, campaign_id, db)

    db.add(PhishingResult(campaign_id=campaign_id, **payload.model_dump()))

    campaign.sent_count += 1
    if payload.opened:
        campaign.opened_count += 1
    if payload.clicked:
        campaign.clicked_count += 1
    if payload.reported:
        campaign.reported_count += 1
    if payload.submitted_credentials:
        campaign.credential_submitted_count += 1

    db.commit()
    return {"message": "recorded"}


@router.get("/{campaign_id}/results", response_model=list[ResultOut])
def list_results(client_id: str, campaign_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Feature 6.6 — per-employee results. employee_identifier is masked to
    'Employee #N' for client-role viewers unless the client has opted
    into named data (Client.phishing_show_employee_names) -- staff
    (admin/analyst) always see the real identifier since they're the
    ones running the assessment. This was previously just a code-comment
    convention on the model with nothing actually enforcing it.
    """
    client = _require_client(client_id, db)
    _require_campaign(client_id, campaign_id, db)
    results = db.query(PhishingResult).filter_by(campaign_id=campaign_id).order_by(PhishingResult.event_at).all()

    show_names = user.role in (UserRole.admin, UserRole.analyst) or client.phishing_show_employee_names
    out = []
    for i, r in enumerate(results, start=1):
        identifier = r.employee_identifier if show_names else f"Employee #{i}"
        out.append(ResultOut(
            id=r.id, employee_identifier=identifier, opened=r.opened, clicked=r.clicked,
            reported=r.reported, submitted_credentials=r.submitted_credentials,
            training_completed=r.training_completed, event_at=r.event_at,
        ))
    return out


@router.get("/{campaign_id}/training-completion")
def training_completion(client_id: str, campaign_id: str, db: Session = Depends(get_db)):
    """Feature 6.6 — % of employees who completed the post-campaign training module, previously captured but never aggregated anywhere."""
    _require_client(client_id, db)
    _require_campaign(client_id, campaign_id, db)
    results = db.query(PhishingResult).filter_by(campaign_id=campaign_id).all()
    total = len(results)
    completed = sum(1 for r in results if r.training_completed)
    return {
        "total_employees": total, "completed": completed,
        "percent_completed": round(100 * completed / total) if total else 0,
    }


@router.post("/{campaign_id}/complete", response_model=CampaignOut)
def complete_campaign(client_id: str, campaign_id: str, db: Session = Depends(get_db)):
    campaign = _require_campaign(client_id, campaign_id, db)
    campaign.status = PhishingCampaignStatus.completed
    campaign.completed_at = datetime.utcnow()
    db.commit()
    db.refresh(campaign)
    return campaign


@router.get("/trend")
def training_trend(client_id: str, db: Session = Depends(get_db)):
    """Feature 6.6 — is employee security awareness improving over time? Click-rate per campaign, oldest first."""
    _require_client(client_id, db)
    campaigns = db.query(PhishingCampaign).filter_by(client_id=client_id).order_by(PhishingCampaign.created_at).all()
    return [{
        "campaign": c.name, "date": c.created_at.isoformat(),
        "click_rate": round(100 * c.clicked_count / c.sent_count, 1) if c.sent_count else None,
        "report_rate": round(100 * c.reported_count / c.sent_count, 1) if c.sent_count else None,
    } for c in campaigns]
