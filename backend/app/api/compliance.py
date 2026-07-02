from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import require_client_access
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Client, ComplianceControl, ComplianceControlStatus

router = APIRouter(prefix="/api/clients/{client_id}/compliance", tags=["compliance"], dependencies=[Depends(require_client_access)])


class ComplianceControlOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    framework: str
    control_id: str
    control_name: str
    status: str
    evidence_notes: str | None
    updated_at: datetime


class ComplianceUpdate(BaseModel):
    status: ComplianceControlStatus | None = None
    evidence_notes: str | None = None


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@router.get("", response_model=list[ComplianceControlOut])
def list_controls(client_id: str, framework: str | None = None, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    q = db.query(ComplianceControl).filter_by(client_id=client_id)
    if framework:
        q = q.filter(ComplianceControl.framework == framework)
    return q.order_by(ComplianceControl.framework, ComplianceControl.control_id).all()


@router.get("/summary")
def compliance_summary(client_id: str, db: Session = Depends(get_db)):
    """Percentage-implemented rollup per framework — powers the Compliance Center header."""
    _require_client(client_id, db)
    controls = db.query(ComplianceControl).filter_by(client_id=client_id).all()
    summary = {}
    for c in controls:
        fw = c.framework.value
        summary.setdefault(fw, {"total": 0, "implemented": 0, "in_progress": 0, "missing": 0})
        summary[fw]["total"] += 1
        summary[fw][c.status.value] += 1
    for fw, s in summary.items():
        s["percent_implemented"] = round(100 * s["implemented"] / s["total"]) if s["total"] else 0
    return summary


@router.patch("/{control_id}", response_model=ComplianceControlOut)
def update_control(client_id: str, control_id: str, payload: ComplianceUpdate, db: Session = Depends(get_db)):
    """Client (or analyst) updates control status and can attach evidence notes/file references."""
    _require_client(client_id, db)
    control = db.query(ComplianceControl).filter_by(id=control_id, client_id=client_id).first()
    if not control:
        raise HTTPException(404, "Control not found")

    if payload.status is not None:
        control.status = payload.status
    if payload.evidence_notes is not None:
        control.evidence_notes = payload.evidence_notes
    control.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(control)
    return control
