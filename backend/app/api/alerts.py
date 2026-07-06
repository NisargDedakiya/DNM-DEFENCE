from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_client_access
from app.core.database import get_db
from app.models.models import AlertLog, Client
from app.services.notifications import export_alert_log_csv

router = APIRouter(prefix="/api/clients/{client_id}/alerts", tags=["alerts"], dependencies=[Depends(require_client_access)])


class AlertLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    finding_id: str | None
    alert_type: str
    subject: str
    channel_email_sent: bool
    channel_slack_sent: bool
    sent_at: datetime


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@router.get("", response_model=list[AlertLogOut])
def list_alert_log(client_id: str, db: Session = Depends(get_db)):
    """The full history of alert/notification sends for this client — findings alerts, SLA breaches, weekly digests."""
    _require_client(client_id, db)
    return db.query(AlertLog).filter_by(client_id=client_id).order_by(AlertLog.sent_at.desc()).all()


@router.get("/export/csv", response_class=PlainTextResponse)
def export_alert_log(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    entries = db.query(AlertLog).filter_by(client_id=client_id).order_by(AlertLog.sent_at.desc()).all()
    return export_alert_log_csv(entries)
