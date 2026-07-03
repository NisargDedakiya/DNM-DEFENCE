import os
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_client_access
from app.core.database import get_db
from app.models.models import Client, VishingEngagement, VishingRiskRating
from app.services.vishing import transcribe_recording, analyze_transcript

router = APIRouter(prefix="/api/clients/{client_id}/vishing-engagements", tags=["vishing"], dependencies=[Depends(require_client_access)])

_RECORDING_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "vishing-recordings")
os.makedirs(_RECORDING_DIR, exist_ok=True)
_ALLOWED_AUDIO_EXTENSIONS = {".mp3", ".wav", ".m4a", ".ogg", ".flac"}


class EngagementCreate(BaseModel):
    scenario: str | None = None
    transcript: str | None = None  # allows a manually-supplied transcript for engagements with no recording


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    scenario: str | None
    transcript: str | None
    analysis: dict
    risk_rating: str | None
    created_at: datetime


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_engagement(client_id: str, engagement_id: str, db: Session) -> VishingEngagement:
    e = db.query(VishingEngagement).filter_by(id=engagement_id, client_id=client_id).first()
    if not e:
        raise HTTPException(404, "Engagement not found")
    return e


@router.post("", response_model=EngagementOut, status_code=201)
def create_engagement(client_id: str, payload: EngagementCreate, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    engagement = VishingEngagement(client_id=client_id, scenario=payload.scenario, transcript=payload.transcript, analysis={})
    db.add(engagement)
    db.commit()
    db.refresh(engagement)
    return engagement


@router.get("", response_model=list[EngagementOut])
def list_engagements(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(VishingEngagement).filter_by(client_id=client_id).order_by(VishingEngagement.created_at.desc()).all()


@router.post("/{engagement_id}/recording", response_model=EngagementOut)
def upload_recording(client_id: str, engagement_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """SE-3 — audio upload of a call already recorded under the engagement's own consent process. UUID-derived storage filename, same path-traversal-safe pattern as compliance evidence upload."""
    engagement = _require_engagement(client_id, engagement_id, db)
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in _ALLOWED_AUDIO_EXTENSIONS:
        raise HTTPException(422, f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(_ALLOWED_AUDIO_EXTENSIONS))}")
    stored_name = f"{engagement_id}_{uuid.uuid4().hex}{ext}"
    dest_path = os.path.join(_RECORDING_DIR, stored_name)
    with open(dest_path, "wb") as f:
        f.write(file.file.read())
    engagement.recording_path = dest_path
    db.commit()
    db.refresh(engagement)
    return engagement


@router.post("/{engagement_id}/analyze", response_model=EngagementOut)
def analyze_engagement(client_id: str, engagement_id: str, db: Session = Depends(get_db)):
    """SE-3 — transcribes (if needed) and runs Claude-based technique/disclosure/risk analysis."""
    engagement = _require_engagement(client_id, engagement_id, db)
    if not engagement.transcript and engagement.recording_path and os.path.exists(engagement.recording_path):
        engagement.transcript = transcribe_recording(engagement.recording_path)

    result = analyze_transcript(engagement.transcript or "", engagement.scenario or "")
    engagement.analysis = result
    if result.get("risk_rating") in VishingRiskRating.__members__:
        engagement.risk_rating = result["risk_rating"]
    db.commit()
    db.refresh(engagement)
    return engagement
