import os
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_client_access
from app.core.database import get_db
from app.models.models import Client, MobileAppScan, MobileScanStatus, MobileTrafficImport
from app.services.mobile_sast import run_static_analysis, generate_executive_summary
from app.services.mobile_traffic import analyze_har_import

router = APIRouter(prefix="/api/clients/{client_id}/mobile-scans", tags=["mobile-security"], dependencies=[Depends(require_client_access)])

_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "mobile-app-uploads")
os.makedirs(_UPLOAD_DIR, exist_ok=True)
_ALLOWED_EXTENSIONS = {".apk": "android", ".ipa": "ios"}


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    platform: str
    original_filename: str | None
    status: str
    app_label: str | None
    findings: list
    masvs_score: int | None
    executive_summary: str | None
    error_message: str | None
    created_at: datetime


class TrafficImportOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    discovered_endpoints: list
    sensitive_data_hits: list
    auth_classification: dict
    openapi_lite: dict
    created_at: datetime


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_scan(client_id: str, scan_id: str, db: Session) -> MobileAppScan:
    scan = db.query(MobileAppScan).filter_by(id=scan_id, client_id=client_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.post("", response_model=ScanOut, status_code=201)
def upload_app(client_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """MOB-1 — upload an .apk/.ipa. UUID-derived storage filename, same path-traversal-safe pattern as other uploads in this codebase."""
    _require_client(client_id, db)
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in _ALLOWED_EXTENSIONS:
        raise HTTPException(422, f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(_ALLOWED_EXTENSIONS))}")

    stored_name = f"{uuid.uuid4().hex}{ext}"
    dest_path = os.path.join(_UPLOAD_DIR, stored_name)
    with open(dest_path, "wb") as f:
        f.write(file.file.read())

    scan = MobileAppScan(client_id=client_id, platform=_ALLOWED_EXTENSIONS[ext], original_filename=file.filename,
                          file_path=dest_path, status=MobileScanStatus.queued, findings=[])
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(MobileAppScan).filter_by(client_id=client_id).order_by(MobileAppScan.created_at.desc()).all()


@router.post("/{scan_id}/analyze", response_model=ScanOut)
def analyze_scan(client_id: str, scan_id: str, db: Session = Depends(get_db)):
    """MOB-1 — runs the static analysis + MASVS checklist evaluation, then a Claude executive summary."""
    scan = _require_scan(client_id, scan_id, db)
    try:
        result = run_static_analysis(scan.file_path, scan.platform.value)
    except Exception as e:
        scan.status = MobileScanStatus.failed
        scan.error_message = str(e)[:1000]
        db.commit()
        db.refresh(scan)
        return scan

    scan.findings = result["findings"]
    scan.masvs_score = result["masvs_score"]
    scan.app_label = result["analysis"].get("package_name")
    scan.status = MobileScanStatus.completed
    try:
        scan.executive_summary = generate_executive_summary(scan.app_label or scan.original_filename, result["findings"], result["masvs_score"])
    except RuntimeError:
        scan.executive_summary = None
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/{scan_id}/traffic-import", response_model=TrafficImportOut, status_code=201)
def import_traffic(client_id: str, scan_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    """MOB-2 — HAR-file import + analysis (endpoint discovery, sensitive-data detection, auth classification, OpenAPI-lite doc)."""
    _require_scan(client_id, scan_id, db)
    content = file.file.read().decode("utf-8", errors="ignore")
    try:
        result = analyze_har_import(content)
    except (ValueError, KeyError) as e:
        raise HTTPException(422, f"Could not parse HAR file: {e}")

    record = MobileTrafficImport(
        client_id=client_id, mobile_app_scan_id=scan_id,
        discovered_endpoints=result["discovered_endpoints"], sensitive_data_hits=result["sensitive_data_hits"],
        auth_classification=result["auth_classification"], openapi_lite=result["openapi_lite"],
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.get("/{scan_id}/traffic-imports", response_model=list[TrafficImportOut])
def list_traffic_imports(client_id: str, scan_id: str, db: Session = Depends(get_db)):
    _require_scan(client_id, scan_id, db)
    return db.query(MobileTrafficImport).filter_by(mobile_app_scan_id=scan_id).order_by(MobileTrafficImport.created_at.desc()).all()
