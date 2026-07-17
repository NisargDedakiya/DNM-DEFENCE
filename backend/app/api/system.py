from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import require_staff
from app.core.database import get_db
from app.services.system_diagnostics import run_diagnostics, operator_overview

router = APIRouter(prefix="/api/system", tags=["system"], dependencies=[Depends(require_staff)])


@router.get("/diagnostics")
def get_diagnostics(db: Session = Depends(get_db)):
    """
    Staff-only: is the platform actually able to do work right now? Separate
    from the unauthenticated /health liveness probe (which only checks the
    database and must stay fast) -- this does the slower checks (Celery
    worker ping, tool-on-PATH checks) that explain *why* scans might be
    silently going nowhere.
    """
    return run_diagnostics(db)


@router.get("/operator-overview")
def get_operator_overview(db: Session = Depends(get_db)):
    """
    Staff-only 'whole book of business' rollup for the operator delivering
    managed security to multiple clients: client counts, open findings by
    severity across every client, scan activity/failures, a per-client risk
    leaderboard, and the system-health status in one payload.
    """
    return operator_overview(db)
