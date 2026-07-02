import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import require_client_access
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Client, Report
from app.schemas.schemas import ScanTriggerResponse
from app.workers.tasks import generate_report_for_client

router = APIRouter(prefix="/api/clients/{client_id}/reports", tags=["reports"], dependencies=[Depends(require_client_access)])


class ReportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    report_type: str
    period_start: datetime
    period_end: datetime
    executive_summary: str | None
    risk_score: float | None
    created_at: datetime
    share_token: str | None


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@router.post("/generate", response_model=ScanTriggerResponse)
def trigger_report_generation(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    task = generate_report_for_client.delay(client_id)
    return ScanTriggerResponse(message="Monthly report generation queued", task_id=task.id)


@router.get("", response_model=list[ReportOut])
def list_reports(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(Report).filter_by(client_id=client_id).order_by(Report.created_at.desc()).all()


@router.get("/{report_id}/pdf")
def download_report_pdf(client_id: str, report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter_by(id=report_id, client_id=client_id).first()
    if not report or not report.pdf_path or not os.path.exists(report.pdf_path):
        raise HTTPException(404, "Report PDF not found")
    return FileResponse(report.pdf_path, media_type="application/pdf",
                         filename=os.path.basename(report.pdf_path))


@router.get("/{report_id}/docx")
def download_report_docx(client_id: str, report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter_by(id=report_id, client_id=client_id).first()
    if not report or not report.docx_path or not os.path.exists(report.docx_path):
        raise HTTPException(404, "Report DOCX not found")
    return FileResponse(report.docx_path,
                         media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                         filename=os.path.basename(report.docx_path))


# Feature 6.5 — read-only share link (no client auth required, just the
# unguessable token). Kept as a separate top-level route since investors/
# auditors accessing this won't have a client_id in their URL context.
share_router = APIRouter(prefix="/api/shared-reports", tags=["reports"])


@share_router.get("/{share_token}/pdf")
def download_shared_report(share_token: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter_by(share_token=share_token).first()
    if not report or not report.pdf_path or not os.path.exists(report.pdf_path):
        raise HTTPException(404, "Report not found")
    return FileResponse(report.pdf_path, media_type="application/pdf",
                         filename=os.path.basename(report.pdf_path))
