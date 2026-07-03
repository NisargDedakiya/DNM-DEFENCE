"""
Audit logging. Two ways this gets written:

  1. Explicit calls from sensitive endpoints (login, credential changes,
     finding status updates) via log_action() -- these carry meaningful
     resource_type/resource_id/detail.
  2. A catch-all middleware that logs every non-GET request automatically
     with just method/path/status, as a safety net for anything that
     doesn't call log_action() explicitly.

Both write to the same table so a single audit trail query covers
everything.
"""
from datetime import datetime

from sqlalchemy.orm import Session

from app.models.models import AuditLog


def log_action(db: Session, action: str, user=None, client_id: str | None = None,
               resource_type: str | None = None, resource_id: str | None = None,
               detail: dict | None = None, ip_address: str | None = None) -> None:
    entry = AuditLog(
        user_id=getattr(user, "id", None),
        user_email=getattr(user, "email", None),
        client_id=client_id,
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
        ip_address=ip_address,
        detail=detail or {},
        created_at=datetime.utcnow(),
    )
    db.add(entry)
    db.commit()
