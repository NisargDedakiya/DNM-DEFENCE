import os
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from app.core.auth import require_client_access
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Client, ComplianceControl, ComplianceControlStatus
from app.services.compliance import get_compliance_summary, generate_compliance_report_pdf

router = APIRouter(prefix="/api/clients/{client_id}/compliance", tags=["compliance"], dependencies=[Depends(require_client_access)])

_EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "compliance-evidence")
_EXPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "generated_reports")
os.makedirs(_EVIDENCE_DIR, exist_ok=True)
os.makedirs(_EXPORT_DIR, exist_ok=True)
_ALLOWED_EVIDENCE_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".txt"}


class ComplianceControlOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    framework: str
    control_id: str
    control_name: str
    status: str
    evidence_notes: str | None
    has_evidence: bool
    updated_at: datetime

    @classmethod
    def from_control(cls, control: ComplianceControl) -> "ComplianceControlOut":
        """Manual construction (not straight from_attributes) so has_evidence can be derived
        without exposing the raw server-side evidence_file_path to the client."""
        return cls(
            id=control.id, framework=control.framework.value, control_id=control.control_id,
            control_name=control.control_name, status=control.status.value,
            evidence_notes=control.evidence_notes, has_evidence=bool(control.evidence_file_path),
            updated_at=control.updated_at,
        )


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
    controls = q.order_by(ComplianceControl.framework, ComplianceControl.control_id).all()
    return [ComplianceControlOut.from_control(c) for c in controls]


@router.get("/summary")
def compliance_summary(client_id: str, db: Session = Depends(get_db)):
    """Percentage-implemented rollup per framework — powers the Compliance Center header."""
    _require_client(client_id, db)
    return get_compliance_summary(db, client_id)


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
    return ComplianceControlOut.from_control(control)


@router.post("/{control_id}/evidence", response_model=ComplianceControlOut)
def upload_evidence(client_id: str, control_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """
    Feature 6.4 — evidence upload. Stored on disk under a UUID-derived
    filename (never the client-supplied original name) so the download
    endpoint's path is always DB-lookup-derived, never influenced by
    user input -- same path-traversal-safe pattern as report downloads.
    """
    _require_client(client_id, db)
    control = db.query(ComplianceControl).filter_by(id=control_id, client_id=client_id).first()
    if not control:
        raise HTTPException(404, "Control not found")

    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in _ALLOWED_EVIDENCE_EXTENSIONS:
        raise HTTPException(422, f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(_ALLOWED_EVIDENCE_EXTENSIONS))}")

    stored_name = f"{control_id}_{uuid.uuid4().hex}{ext}"
    dest_path = os.path.join(_EVIDENCE_DIR, stored_name)
    with open(dest_path, "wb") as f:
        f.write(file.file.read())

    control.evidence_file_path = dest_path
    control.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(control)
    return ComplianceControlOut.from_control(control)


@router.get("/{control_id}/evidence")
def download_evidence(client_id: str, control_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    control = db.query(ComplianceControl).filter_by(id=control_id, client_id=client_id).first()
    if not control or not control.evidence_file_path or not os.path.exists(control.evidence_file_path):
        raise HTTPException(404, "No evidence file uploaded for this control")
    return FileResponse(control.evidence_file_path, filename=os.path.basename(control.evidence_file_path))


@router.get("/export/pdf")
def export_compliance_report(client_id: str, db: Session = Depends(get_db)):
    """Feature 6.4/6.5 — real per-control compliance status report for auditors/investors."""
    client = _require_client(client_id, db)
    safe_name = client.name.replace(" ", "_").replace("/", "-")
    output_path = os.path.join(_EXPORT_DIR, f"{safe_name}_compliance_{datetime.utcnow().strftime('%Y-%m-%d')}.pdf")
    generate_compliance_report_pdf(db, client, output_path)
    return FileResponse(output_path, media_type="application/pdf", filename=os.path.basename(output_path))
