from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.auth import require_staff
from app.core.database import get_db
from app.services.system_diagnostics import run_diagnostics

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
