from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_client_access
from app.core.entitlements import require_feature
from app.core.database import get_db
from app.models.models import (
    Client, PhysicalSecurityAssessment, PhysicalSecurityChecklistItem, PhysicalTestType,
)

router = APIRouter(prefix="/api/clients/{client_id}/physical-security", tags=["physical-security"], dependencies=[Depends(require_client_access), Depends(require_feature("phishing_simulations"))])


class ChecklistItemOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    test_type: str
    attempted: bool
    outcome_notes: str | None
    severity: str | None


class ChecklistItemUpdate(BaseModel):
    attempted: bool | None = None
    outcome_notes: str | None = None
    severity: str | None = None


class AssessmentCreate(BaseModel):
    site_name: str | None = None
    scheduled_date: datetime | None = None


class AssessmentUpdate(BaseModel):
    status: str | None = None
    summary: str | None = None


class AssessmentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    site_name: str | None
    scheduled_date: datetime | None
    status: str
    summary: str | None
    created_at: datetime
    checklist_items: list[ChecklistItemOut] = []


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_assessment(client_id: str, assessment_id: str, db: Session) -> PhysicalSecurityAssessment:
    a = db.query(PhysicalSecurityAssessment).filter_by(id=assessment_id, client_id=client_id).first()
    if not a:
        raise HTTPException(404, "Assessment not found")
    return a


@router.post("", response_model=AssessmentOut, status_code=201)
def create_assessment(client_id: str, payload: AssessmentCreate, db: Session = Depends(get_db)):
    """
    Physical security engagement tracker. This is a checklist/engagement
    record, not automation -- tailgating, badge cloning, dumpster diving,
    and USB-drop tests require an in-person analyst and are out of scope
    for this codebase to perform itself. Seeds one checklist row per
    PhysicalTestType so nothing gets forgotten during the on-site visit.
    """
    _require_client(client_id, db)
    assessment = PhysicalSecurityAssessment(client_id=client_id, site_name=payload.site_name, scheduled_date=payload.scheduled_date)
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    for test_type in PhysicalTestType:
        db.add(PhysicalSecurityChecklistItem(assessment_id=assessment.id, test_type=test_type))
    db.commit()
    db.refresh(assessment)
    return assessment


@router.get("", response_model=list[AssessmentOut])
def list_assessments(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(PhysicalSecurityAssessment).filter_by(client_id=client_id).order_by(PhysicalSecurityAssessment.created_at.desc()).all()


@router.patch("/{assessment_id}", response_model=AssessmentOut)
def update_assessment(client_id: str, assessment_id: str, payload: AssessmentUpdate, db: Session = Depends(get_db)):
    assessment = _require_assessment(client_id, assessment_id, db)
    if payload.status is not None:
        assessment.status = payload.status
    if payload.summary is not None:
        assessment.summary = payload.summary
    db.commit()
    db.refresh(assessment)
    return assessment


@router.patch("/{assessment_id}/checklist/{item_id}", response_model=ChecklistItemOut)
def update_checklist_item(client_id: str, assessment_id: str, item_id: str, payload: ChecklistItemUpdate, db: Session = Depends(get_db)):
    _require_assessment(client_id, assessment_id, db)
    item = db.query(PhysicalSecurityChecklistItem).filter_by(id=item_id, assessment_id=assessment_id).first()
    if not item:
        raise HTTPException(404, "Checklist item not found")
    if payload.attempted is not None:
        item.attempted = payload.attempted
    if payload.outcome_notes is not None:
        item.outcome_notes = payload.outcome_notes
    if payload.severity is not None:
        item.severity = payload.severity
    db.commit()
    db.refresh(item)
    return item
