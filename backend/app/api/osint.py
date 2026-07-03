import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_client_access
from app.core.database import get_db
from app.models.models import Client, OSINTProfile
from app.services.osint import generate_osint_profile, export_osint_profile_pdf

router = APIRouter(prefix="/api/clients/{client_id}/osint", tags=["osint"], dependencies=[Depends(require_client_access)])

_EXPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "generated_reports")
os.makedirs(_EXPORT_DIR, exist_ok=True)


class OSINTGenerateIn(BaseModel):
    employee_names: list[str] = []
    careers_page_url: str | None = None


class OSINTProfileOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    generated_at: datetime
    findings: dict


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@router.post("/generate", response_model=OSINTProfileOut, status_code=201)
def generate_profile(client_id: str, payload: OSINTGenerateIn, db: Session = Depends(get_db)):
    """SE-1 — runs WHOIS/DNS/email-pattern/Google-dork/GitHub/job-listing checks and synthesizes a Claude narrative."""
    client = _require_client(client_id, db)
    return generate_osint_profile(db, client, payload.employee_names, payload.careers_page_url)


@router.get("", response_model=list[OSINTProfileOut])
def list_profiles(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(OSINTProfile).filter_by(client_id=client_id).order_by(OSINTProfile.generated_at.desc()).all()


@router.get("/{profile_id}/export/pdf")
def export_pdf(client_id: str, profile_id: str, db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    profile = db.query(OSINTProfile).filter_by(id=profile_id, client_id=client_id).first()
    if not profile:
        raise HTTPException(404, "Profile not found")
    safe_name = client.name.replace(" ", "_").replace("/", "-")
    output_path = os.path.join(_EXPORT_DIR, f"{safe_name}_osint_{profile.id}.pdf")
    export_osint_profile_pdf(profile, client, output_path)
    return FileResponse(output_path, media_type="application/pdf", filename=os.path.basename(output_path))
