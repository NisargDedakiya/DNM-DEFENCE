from datetime import datetime

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_admin
from app.core.database import get_db
from app.models.models import AuditLog, User

router = APIRouter(prefix="/api/audit-logs", tags=["audit"])


class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    user_email: str | None
    client_id: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    ip_address: str | None
    detail: dict
    created_at: datetime


@router.get("", response_model=list[AuditLogOut])
def list_audit_logs(
    client_id: str | None = None,
    user_email: str | None = None,
    action: str | None = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Admin-only. Read-only by design -- no PATCH/DELETE exposed for this table."""
    q = db.query(AuditLog)
    if client_id:
        q = q.filter(AuditLog.client_id == client_id)
    if user_email:
        q = q.filter(AuditLog.user_email == user_email)
    if action:
        q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    return q.order_by(AuditLog.created_at.desc()).limit(min(limit, 1000)).all()
