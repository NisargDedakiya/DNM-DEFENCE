import os
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_staff
from app.core.database import get_db
from app.models.models import Client, FirmwareAnalysisJob, FirmwareScanStatus
from app.services.firmware_analysis import (
    run_binwalk_extraction, scan_extracted_files_for_secrets, identify_components, extract_printable_strings,
    check_library_cves, run_checksec, generate_firmware_summary,
)
from app.services.mobile_sast import SECRET_PATTERNS

# IOT-1 is analyst-only tooling per the doc's "Analyst UI" labeling.
router = APIRouter(prefix="/api/clients/{client_id}/firmware-scans", tags=["firmware"], dependencies=[Depends(require_staff)])

_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "firmware-uploads")
_EXTRACT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "firmware-extracted")
os.makedirs(_UPLOAD_DIR, exist_ok=True)
os.makedirs(_EXTRACT_DIR, exist_ok=True)

_MAX_RAW_READ_BYTES = 10_000_000  # bounded read for identify_components when extraction is unavailable
_MAX_CHECKSEC_BINARIES = 5


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_id: str
    original_filename: str | None
    status: str
    component_summary: dict
    findings: dict
    executive_summary: str | None
    error_message: str | None
    created_at: datetime


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_scan(client_id: str, scan_id: str, db: Session) -> FirmwareAnalysisJob:
    scan = db.query(FirmwareAnalysisJob).filter_by(id=scan_id, client_id=client_id).first()
    if not scan:
        raise HTTPException(404, "Firmware scan not found")
    return scan


def _find_elf_binaries(directory: str, limit: int) -> list[str]:
    found = []
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if len(found) >= limit:
                return found
            path = os.path.join(root, fname)
            try:
                with open(path, "rb") as f:
                    if f.read(4) == b"\x7fELF":
                        found.append(path)
            except OSError:
                continue
    return found


@router.post("", response_model=ScanOut, status_code=201)
def upload_firmware(client_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    _require_client(client_id, db)
    stored_name = f"{uuid.uuid4().hex}_{file.filename or 'firmware.bin'}"
    dest_path = os.path.join(_UPLOAD_DIR, stored_name)
    with open(dest_path, "wb") as f:
        f.write(file.file.read())

    scan = FirmwareAnalysisJob(client_id=client_id, original_filename=file.filename, file_path=dest_path,
                                status=FirmwareScanStatus.queued, component_summary={}, findings={})
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.get("", response_model=list[ScanOut])
def list_scans(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(FirmwareAnalysisJob).filter_by(client_id=client_id).order_by(FirmwareAnalysisJob.created_at.desc()).all()


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(client_id: str, scan_id: str, db: Session = Depends(get_db)):
    return _require_scan(client_id, scan_id, db)


@router.post("/{scan_id}/analyze", response_model=ScanOut)
def analyze_scan(client_id: str, scan_id: str, db: Session = Depends(get_db)):
    """IOT-1 — binwalk extraction, component identification, secret scanning, NVD CVE matching, then a Claude executive summary."""
    scan = _require_scan(client_id, scan_id, db)
    try:
        extraction_dir = os.path.join(_EXTRACT_DIR, scan.id)
        extraction = run_binwalk_extraction(scan.file_path, extraction_dir)

        if extraction["extracted"]:
            secrets = scan_extracted_files_for_secrets(extraction_dir)
            text_blob_parts = []
            for root, _dirs, files in os.walk(extraction_dir):
                for fname in files[:200]:
                    try:
                        with open(os.path.join(root, fname), "rb") as f:
                            text_blob_parts.append(extract_printable_strings(f.read(500_000)))
                    except OSError:
                        continue
            text_blob = "\n".join(text_blob_parts)
            checksec_results = [
                {"binary": os.path.relpath(b, extraction_dir), "result": r}
                for b in _find_elf_binaries(extraction_dir, _MAX_CHECKSEC_BINARIES)
                if (r := run_checksec(b)) is not None
            ]
        else:
            with open(scan.file_path, "rb") as f:
                raw = f.read(_MAX_RAW_READ_BYTES)
            text_blob = extract_printable_strings(raw)
            secrets = [{"type": name, "file": scan.original_filename, "excerpt": m.group(0)[:120]}
                       for name, pattern in SECRET_PATTERNS.items()
                       if (m := pattern.search(text_blob))]
            checksec_results = []

        components = identify_components(text_blob)
        cves = check_library_cves(components)

        scan.component_summary = components
        scan.findings = {"extracted": extraction["extracted"], "components": components, "secrets": secrets,
                          "cves": cves, "checksec": checksec_results}
        scan.status = FirmwareScanStatus.completed
        try:
            scan.executive_summary = generate_firmware_summary(scan.findings)
        except RuntimeError:
            scan.executive_summary = None
    except Exception as e:
        scan.status = FirmwareScanStatus.failed
        scan.error_message = str(e)[:1000]

    db.commit()
    db.refresh(scan)
    return scan
