import os
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_staff
from app.core.database import get_db
from app.models.models import (
    Client, RedTeamOperation, RedTeamOperationStatus, RedTeamTimelineEntry, RedTeamTimelinePhase,
    RedTeamDetectionStatus, RedTeamImplant, RedTeamInfrastructure, RedTeamInfraType,
)
from app.services.red_team import (
    generate_attck_heatmap, check_c2_infra_exposure, generate_attack_narrative, generate_purple_team_export,
)

# RT-1 is analyst/admin tooling only — never exposed to the client role. See
# Track1_Advanced_Services.docx: every tool in this doc is [ANALYST]/[AUTO],
# and this one's UI mockup is explicitly labeled "Internal Only".
router = APIRouter(prefix="/api/clients/{client_id}/red-team", tags=["red-team"], dependencies=[Depends(require_staff)])

_EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "red-team-evidence")
os.makedirs(_EVIDENCE_DIR, exist_ok=True)


class OperationCreate(BaseModel):
    name: str
    objective: str | None = None
    threat_actor: str | None = None
    status: RedTeamOperationStatus = RedTeamOperationStatus.planning
    start_date: datetime | None = None
    end_date: datetime | None = None
    roe_signed: bool = False


class OperationUpdate(BaseModel):
    name: str | None = None
    objective: str | None = None
    threat_actor: str | None = None
    status: RedTeamOperationStatus | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    roe_signed: bool | None = None


class OperationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_id: str
    name: str
    objective: str | None
    threat_actor: str | None
    status: str
    start_date: datetime | None
    end_date: datetime | None
    roe_signed: bool
    created_at: datetime


class TimelineEntryCreate(BaseModel):
    timestamp: datetime
    phase: RedTeamTimelinePhase
    action: str
    host: str | None = None
    user_context: str | None = None
    tool_used: str | None = None
    outcome: str | None = None
    detected: RedTeamDetectionStatus = RedTeamDetectionStatus.not_detected
    attack_technique_id: str | None = None


class TimelineEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    operation_id: str
    timestamp: datetime
    phase: str
    action: str
    host: str | None
    user_context: str | None
    tool_used: str | None
    outcome: str | None
    detected: str
    attack_technique_id: str | None
    evidence_path: str | None


class ImplantCreate(BaseModel):
    host: str
    ip_address: str | None = None
    username: str | None = None
    implant_type: str | None = None
    persistence: str | None = None
    checkin_freq_seconds: int | None = None
    is_active: bool = True


class ImplantUpdate(BaseModel):
    is_active: bool | None = None
    persistence: str | None = None
    checkin_freq_seconds: int | None = None


class ImplantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    operation_id: str
    host: str
    ip_address: str | None
    username: str | None
    implant_type: str | None
    persistence: str | None
    checkin_freq_seconds: int | None
    is_active: bool
    deployed_at: datetime


class InfrastructureCreate(BaseModel):
    infra_type: RedTeamInfraType
    identifier: str
    provider: str | None = None
    notes: str | None = None


class InfrastructureOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    operation_id: str
    infra_type: str
    identifier: str
    provider: str | None
    notes: str | None


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_operation(client_id: str, operation_id: str, db: Session) -> RedTeamOperation:
    op = db.query(RedTeamOperation).filter_by(id=operation_id, client_id=client_id).first()
    if not op:
        raise HTTPException(404, "Operation not found")
    return op


@router.post("/operations", response_model=OperationOut, status_code=201)
def create_operation(client_id: str, payload: OperationCreate, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    op = RedTeamOperation(client_id=client_id, **payload.model_dump())
    db.add(op)
    db.commit()
    db.refresh(op)
    return op


@router.get("/operations", response_model=list[OperationOut])
def list_operations(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(RedTeamOperation).filter_by(client_id=client_id).order_by(RedTeamOperation.created_at.desc()).all()


@router.get("/operations/{operation_id}", response_model=OperationOut)
def get_operation(client_id: str, operation_id: str, db: Session = Depends(get_db)):
    return _require_operation(client_id, operation_id, db)


@router.patch("/operations/{operation_id}", response_model=OperationOut)
def update_operation(client_id: str, operation_id: str, payload: OperationUpdate, db: Session = Depends(get_db)):
    op = _require_operation(client_id, operation_id, db)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(op, field, value)
    db.commit()
    db.refresh(op)
    return op


@router.delete("/operations/{operation_id}", status_code=204)
def delete_operation(client_id: str, operation_id: str, db: Session = Depends(get_db)):
    op = _require_operation(client_id, operation_id, db)
    db.delete(op)
    db.commit()


@router.post("/operations/{operation_id}/timeline", response_model=TimelineEntryOut, status_code=201)
def add_timeline_entry(client_id: str, operation_id: str, payload: TimelineEntryCreate, db: Session = Depends(get_db)):
    _require_operation(client_id, operation_id, db)
    entry = RedTeamTimelineEntry(operation_id=operation_id, **payload.model_dump())
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.get("/operations/{operation_id}/timeline", response_model=list[TimelineEntryOut])
def list_timeline(client_id: str, operation_id: str, db: Session = Depends(get_db)):
    _require_operation(client_id, operation_id, db)
    return db.query(RedTeamTimelineEntry).filter_by(operation_id=operation_id).order_by(RedTeamTimelineEntry.timestamp).all()


@router.post("/operations/{operation_id}/timeline/{entry_id}/evidence", response_model=TimelineEntryOut)
def upload_timeline_evidence(client_id: str, operation_id: str, entry_id: str,
                              file: UploadFile = File(...), db: Session = Depends(get_db)):
    _require_operation(client_id, operation_id, db)
    entry = db.query(RedTeamTimelineEntry).filter_by(id=entry_id, operation_id=operation_id).first()
    if not entry:
        raise HTTPException(404, "Timeline entry not found")

    ext = os.path.splitext(file.filename or "")[1].lower()
    stored_name = f"{uuid.uuid4().hex}{ext}"
    dest_path = os.path.join(_EVIDENCE_DIR, stored_name)
    with open(dest_path, "wb") as f:
        f.write(file.file.read())
    entry.evidence_path = dest_path
    db.commit()
    db.refresh(entry)
    return entry


@router.post("/operations/{operation_id}/implants", response_model=ImplantOut, status_code=201)
def add_implant(client_id: str, operation_id: str, payload: ImplantCreate, db: Session = Depends(get_db)):
    _require_operation(client_id, operation_id, db)
    implant = RedTeamImplant(operation_id=operation_id, **payload.model_dump())
    db.add(implant)
    db.commit()
    db.refresh(implant)
    return implant


@router.get("/operations/{operation_id}/implants", response_model=list[ImplantOut])
def list_implants(client_id: str, operation_id: str, db: Session = Depends(get_db)):
    _require_operation(client_id, operation_id, db)
    return db.query(RedTeamImplant).filter_by(operation_id=operation_id).order_by(RedTeamImplant.deployed_at.desc()).all()


@router.patch("/operations/{operation_id}/implants/{implant_id}", response_model=ImplantOut)
def update_implant(client_id: str, operation_id: str, implant_id: str, payload: ImplantUpdate, db: Session = Depends(get_db)):
    _require_operation(client_id, operation_id, db)
    implant = db.query(RedTeamImplant).filter_by(id=implant_id, operation_id=operation_id).first()
    if not implant:
        raise HTTPException(404, "Implant not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(implant, field, value)
    db.commit()
    db.refresh(implant)
    return implant


@router.post("/operations/{operation_id}/infrastructure", response_model=InfrastructureOut, status_code=201)
def add_infrastructure(client_id: str, operation_id: str, payload: InfrastructureCreate, db: Session = Depends(get_db)):
    _require_operation(client_id, operation_id, db)
    infra = RedTeamInfrastructure(operation_id=operation_id, **payload.model_dump())
    db.add(infra)
    db.commit()
    db.refresh(infra)
    return infra


@router.get("/operations/{operation_id}/infrastructure", response_model=list[InfrastructureOut])
def list_infrastructure(client_id: str, operation_id: str, db: Session = Depends(get_db)):
    _require_operation(client_id, operation_id, db)
    return db.query(RedTeamInfrastructure).filter_by(operation_id=operation_id).all()


@router.get("/operations/{operation_id}/infrastructure/exposure-check")
def check_infrastructure_exposure(client_id: str, operation_id: str, db: Session = Depends(get_db)):
    """Checks the operation's own tracked infra IPs against Shodan, so the team can verify their C2/redirectors aren't already fingerprinted."""
    _require_operation(client_id, operation_id, db)
    infra = db.query(RedTeamInfrastructure).filter_by(operation_id=operation_id).all()
    implants = db.query(RedTeamImplant).filter_by(operation_id=operation_id).all()
    ip_addresses = list({i.identifier for i in infra if i.identifier} | {i.ip_address for i in implants if i.ip_address})
    return {"exposure": check_c2_infra_exposure(ip_addresses)}


@router.get("/operations/{operation_id}/heatmap")
def get_heatmap(client_id: str, operation_id: str, db: Session = Depends(get_db)):
    _require_operation(client_id, operation_id, db)
    entries = db.query(RedTeamTimelineEntry).filter_by(operation_id=operation_id).all()
    return generate_attck_heatmap(entries)


@router.get("/operations/{operation_id}/narrative", response_class=PlainTextResponse)
def get_narrative(client_id: str, operation_id: str, db: Session = Depends(get_db)):
    op = _require_operation(client_id, operation_id, db)
    entries = db.query(RedTeamTimelineEntry).filter_by(operation_id=operation_id).order_by(RedTeamTimelineEntry.timestamp).all()
    return generate_attack_narrative(op, entries)


@router.get("/operations/{operation_id}/purple-team-export", response_class=PlainTextResponse)
def get_purple_team_export(client_id: str, operation_id: str, db: Session = Depends(get_db)):
    op = _require_operation(client_id, operation_id, db)
    entries = db.query(RedTeamTimelineEntry).filter_by(operation_id=operation_id).order_by(RedTeamTimelineEntry.timestamp).all()
    return generate_purple_team_export(op, entries)
