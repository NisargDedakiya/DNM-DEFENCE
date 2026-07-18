from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import require_client_access
from app.core.database import get_db
from app.models.models import Client
from app.services.security_posture import compute_posture, generate_posture_summary

router = APIRouter(prefix="/api/clients/{client_id}/posture", tags=["posture"],
                   dependencies=[Depends(require_client_access)])


@router.get("")
def get_posture(client_id: str, include_summary: bool = True, db: Session = Depends(get_db)):
    """
    The startup security scorecard: overall grade, domain breakdown, a
    prioritised action plan with step-by-step fixes, and SOC 2 readiness.
    Client-visible -- this is the report a founder reads. Works fully without
    AI; the plain-English summary is added only if an Anthropic key is
    configured (and is simply omitted otherwise, never an error).
    """
    if not db.query(Client).get(client_id):
        raise HTTPException(404, "Client not found")
    posture = compute_posture(db, client_id)
    if include_summary:
        posture["summary"] = generate_posture_summary(posture)
    return posture
