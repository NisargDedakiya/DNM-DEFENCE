from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import require_client_access
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.models import Client, Asset, ScanRun
from app.schemas.schemas import AssetOut, ScanRunOut, ScanTriggerResponse
from app.workers.tasks import run_subdomain_enum_for_client, run_port_scan_for_client

router = APIRouter(prefix="/api/clients/{client_id}", tags=["assets"], dependencies=[Depends(require_client_access)])


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@router.get("/assets", response_model=list[AssetOut])
def list_assets(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(Asset).filter_by(client_id=client_id).all()


@router.post("/scans/subdomain-enum", response_model=ScanTriggerResponse)
def trigger_subdomain_enum(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    task = run_subdomain_enum_for_client.delay(client_id)
    return ScanTriggerResponse(message="Subdomain enumeration queued", task_id=task.id)


@router.post("/scans/port-scan", response_model=ScanTriggerResponse)
def trigger_port_scan(client_id: str, full_range: bool = False, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    task = run_port_scan_for_client.delay(client_id, full_range)
    return ScanTriggerResponse(message="Port scan queued", task_id=task.id)


@router.get("/scans", response_model=list[ScanRunOut])
def list_scans(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(ScanRun).filter_by(client_id=client_id).order_by(ScanRun.started_at.desc()).limit(50).all()
