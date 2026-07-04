import os
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from fastapi.responses import PlainTextResponse, JSONResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_staff
from app.core.database import get_db
from app.models.models import (
    Client, DfirCase, DfirCaseStatus, Severity, DfirEvidence, DfirIoc, DfirTimelineEntry, IrRetainer,
    DfirLogAnalysisJob,
)
from app.services.dfir import (
    compute_file_hashes, append_custody_entry, generate_executive_report, generate_technical_report,
    export_iocs_stix, export_iocs_sigma, export_iocs_csv,
)
from app.services.dfir_log_analysis import (
    parse_cloudtrail_json, parse_azure_activity_log, parse_gcp_audit_log,
    parse_syslog, parse_web_access_log, parse_palo_alto_log, parse_evtx,
    detect_auth_anomalies, extract_iocs, generate_log_narrative,
)

# DFIR-1/DFIR-2 are analyst/admin only, per the doc's [ANALYST] labeling —
# clients never see raw case notes about their own live incident directly.
router = APIRouter(prefix="/api/clients/{client_id}/dfir", tags=["dfir"], dependencies=[Depends(require_staff)])

_EVIDENCE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "dfir-evidence")
_LOG_UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "dfir-log-uploads")
os.makedirs(_EVIDENCE_DIR, exist_ok=True)
os.makedirs(_LOG_UPLOAD_DIR, exist_ok=True)

_JSON_PARSERS = {"cloudtrail": parse_cloudtrail_json, "azure": parse_azure_activity_log, "gcp": parse_gcp_audit_log}
_TEXT_PARSERS = {"syslog": parse_syslog, "web_access": parse_web_access_log, "paloalto": parse_palo_alto_log}


class CaseCreate(BaseModel):
    case_number: str
    incident_type: str | None = None
    severity: Severity = Severity.medium
    status: DfirCaseStatus = DfirCaseStatus.active
    discovered_at: datetime | None = None
    initial_vector: str | None = None
    affected_systems: list[str] = []
    data_exfiltrated: bool = False


class CaseUpdate(BaseModel):
    incident_type: str | None = None
    severity: Severity | None = None
    status: DfirCaseStatus | None = None
    contained_at: datetime | None = None
    closed_at: datetime | None = None
    initial_vector: str | None = None
    affected_systems: list[str] | None = None
    data_exfiltrated: bool | None = None
    retainer_hours_used: int | None = None


class CaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_id: str
    case_number: str
    incident_type: str | None
    severity: str
    status: str
    discovered_at: datetime | None
    contained_at: datetime | None
    closed_at: datetime | None
    initial_vector: str | None
    affected_systems: list
    data_exfiltrated: bool
    retainer_hours_used: int
    created_at: datetime


class EvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    case_id: str
    evidence_type: str | None
    source_host: str | None
    acquisition_tool: str | None
    md5_hash: str | None
    sha256_hash: str | None
    file_size_bytes: int | None
    acquired_at: datetime
    chain_of_custody: list


class CustodyEntryCreate(BaseModel):
    custodian: str
    action: str


class IocCreate(BaseModel):
    ioc_type: str
    value: str
    confidence: str = "medium"
    context: str | None = None
    attack_technique_id: str | None = None


class IocOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    case_id: str
    ioc_type: str
    value: str
    confidence: str
    first_seen: datetime | None
    last_seen: datetime | None
    context: str | None
    attack_technique_id: str | None


class TimelineEntryCreate(BaseModel):
    timestamp: datetime
    event_description: str
    source: str | None = None
    host: str | None = None
    attack_technique_id: str | None = None


class TimelineEntryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    case_id: str
    timestamp: datetime
    event_description: str
    source: str | None
    host: str | None
    attack_technique_id: str | None


class RetainerUpsert(BaseModel):
    tier: str | None = None
    hours_included_per_year: int = 0
    hours_used: int = 0
    response_sla_hours: int | None = None
    last_tabletop_at: datetime | None = None


class RetainerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_id: str
    tier: str | None
    hours_included_per_year: int
    hours_used: int
    response_sla_hours: int | None
    last_tabletop_at: datetime | None


class LogAnalysisJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    case_id: str
    original_filename: str | None
    log_type: str | None
    events_count: int
    anomalies: list
    iocs: list
    narrative: str | None
    error_message: str | None
    created_at: datetime


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_case(client_id: str, case_id: str, db: Session) -> DfirCase:
    case = db.query(DfirCase).filter_by(id=case_id, client_id=client_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.post("/cases", response_model=CaseOut, status_code=201)
def create_case(client_id: str, payload: CaseCreate, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    if db.query(DfirCase).filter_by(case_number=payload.case_number).first():
        raise HTTPException(422, f"Case number '{payload.case_number}' already exists")
    case = DfirCase(client_id=client_id, **payload.model_dump())
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


@router.get("/cases", response_model=list[CaseOut])
def list_cases(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(DfirCase).filter_by(client_id=client_id).order_by(DfirCase.created_at.desc()).all()


@router.get("/cases/{case_id}", response_model=CaseOut)
def get_case(client_id: str, case_id: str, db: Session = Depends(get_db)):
    return _require_case(client_id, case_id, db)


@router.patch("/cases/{case_id}", response_model=CaseOut)
def update_case(client_id: str, case_id: str, payload: CaseUpdate, db: Session = Depends(get_db)):
    case = _require_case(client_id, case_id, db)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(case, field, value)
    db.commit()
    db.refresh(case)
    return case


@router.post("/cases/{case_id}/evidence", response_model=EvidenceOut, status_code=201)
def upload_evidence(client_id: str, case_id: str, evidence_type: str = Form(...), source_host: str = Form(""),
                     acquisition_tool: str = Form(""), acquired_by_name: str = Form("analyst"),
                     file: UploadFile = File(...), db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    data = file.file.read()
    hashes = compute_file_hashes(data)

    stored_name = uuid.uuid4().hex
    dest_path = os.path.join(_EVIDENCE_DIR, stored_name)
    with open(dest_path, "wb") as f:
        f.write(data)

    evidence = DfirEvidence(
        case_id=case_id, evidence_type=evidence_type, source_host=source_host or None,
        acquisition_tool=acquisition_tool or None, storage_path=dest_path, **hashes,
    )
    evidence.chain_of_custody = append_custody_entry(evidence, acquired_by_name, "acquired and hashed on upload")
    db.add(evidence)
    db.commit()
    db.refresh(evidence)
    return evidence


@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceOut])
def list_evidence(client_id: str, case_id: str, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    return db.query(DfirEvidence).filter_by(case_id=case_id).order_by(DfirEvidence.acquired_at.desc()).all()


@router.post("/cases/{case_id}/evidence/{evidence_id}/custody", response_model=EvidenceOut)
def add_custody_entry(client_id: str, case_id: str, evidence_id: str, payload: CustodyEntryCreate,
                       db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    evidence = db.query(DfirEvidence).filter_by(id=evidence_id, case_id=case_id).first()
    if not evidence:
        raise HTTPException(404, "Evidence not found")
    evidence.chain_of_custody = append_custody_entry(evidence, payload.custodian, payload.action)
    db.commit()
    db.refresh(evidence)
    return evidence


@router.post("/cases/{case_id}/iocs", response_model=IocOut, status_code=201)
def add_ioc(client_id: str, case_id: str, payload: IocCreate, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    now = datetime.utcnow()
    ioc = DfirIoc(case_id=case_id, first_seen=now, last_seen=now, **payload.model_dump())
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


@router.get("/cases/{case_id}/iocs", response_model=list[IocOut])
def list_iocs(client_id: str, case_id: str, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    return db.query(DfirIoc).filter_by(case_id=case_id).all()


@router.get("/cases/{case_id}/iocs/export/stix")
def export_iocs_stix_endpoint(client_id: str, case_id: str, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    iocs = db.query(DfirIoc).filter_by(case_id=case_id).all()
    return JSONResponse(export_iocs_stix(iocs))


@router.get("/cases/{case_id}/iocs/export/sigma", response_class=PlainTextResponse)
def export_iocs_sigma_endpoint(client_id: str, case_id: str, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    iocs = db.query(DfirIoc).filter_by(case_id=case_id).all()
    return export_iocs_sigma(iocs)


@router.get("/cases/{case_id}/iocs/export/csv", response_class=PlainTextResponse)
def export_iocs_csv_endpoint(client_id: str, case_id: str, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    iocs = db.query(DfirIoc).filter_by(case_id=case_id).all()
    return export_iocs_csv(iocs)


@router.post("/cases/{case_id}/timeline", response_model=TimelineEntryOut, status_code=201)
def add_timeline_entry(client_id: str, case_id: str, payload: TimelineEntryCreate, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    entry = DfirTimelineEntry(case_id=case_id, **payload.model_dump())
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.get("/cases/{case_id}/timeline", response_model=list[TimelineEntryOut])
def list_timeline(client_id: str, case_id: str, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    return db.query(DfirTimelineEntry).filter_by(case_id=case_id).order_by(DfirTimelineEntry.timestamp).all()


@router.get("/cases/{case_id}/reports/executive", response_class=PlainTextResponse)
def get_executive_report(client_id: str, case_id: str, db: Session = Depends(get_db)):
    case = _require_case(client_id, case_id, db)
    return generate_executive_report(case)


@router.get("/cases/{case_id}/reports/technical", response_class=PlainTextResponse)
def get_technical_report(client_id: str, case_id: str, db: Session = Depends(get_db)):
    case = _require_case(client_id, case_id, db)
    evidence = db.query(DfirEvidence).filter_by(case_id=case_id).all()
    iocs = db.query(DfirIoc).filter_by(case_id=case_id).all()
    timeline = db.query(DfirTimelineEntry).filter_by(case_id=case_id).all()
    return generate_technical_report(case, evidence, iocs, timeline)


@router.get("/retainer", response_model=RetainerOut)
def get_retainer(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    retainer = db.query(IrRetainer).filter_by(client_id=client_id).first()
    if not retainer:
        raise HTTPException(404, "No retainer configured for this client")
    return retainer


@router.put("/retainer", response_model=RetainerOut)
def upsert_retainer(client_id: str, payload: RetainerUpsert, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    retainer = db.query(IrRetainer).filter_by(client_id=client_id).first()
    if not retainer:
        retainer = IrRetainer(client_id=client_id, **payload.model_dump())
        db.add(retainer)
    else:
        for field, value in payload.model_dump().items():
            setattr(retainer, field, value)
    db.commit()
    db.refresh(retainer)
    return retainer


@router.post("/cases/{case_id}/log-analysis/upload", response_model=LogAnalysisJobOut, status_code=201)
def upload_log_for_analysis(client_id: str, case_id: str, log_type: str = Form(...),
                             file: UploadFile = File(...), db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    if log_type not in {**_JSON_PARSERS, **_TEXT_PARSERS, "evtx": None}:
        raise HTTPException(422, f"Unsupported log_type '{log_type}'. Choose from: "
                                 f"{', '.join(list(_JSON_PARSERS) + list(_TEXT_PARSERS) + ['evtx'])}")

    data = file.file.read()
    job = DfirLogAnalysisJob(case_id=case_id, original_filename=file.filename, log_type=log_type)

    try:
        if log_type in _JSON_PARSERS:
            import json
            events = _JSON_PARSERS[log_type](json.loads(data.decode("utf-8")))
        elif log_type in _TEXT_PARSERS:
            events = _TEXT_PARSERS[log_type](data.decode("utf-8", errors="replace"))
        else:  # evtx
            stored_path = os.path.join(_LOG_UPLOAD_DIR, f"{uuid.uuid4().hex}.evtx")
            with open(stored_path, "wb") as f:
                f.write(data)
            events = parse_evtx(stored_path)

        anomalies = detect_auth_anomalies(events)
        iocs = extract_iocs(events)
        job.events_count = len(events)
        job.anomalies = anomalies
        job.iocs = iocs
        job.narrative = generate_log_narrative(events, anomalies)
    except Exception as e:
        job.error_message = str(e)

    db.add(job)
    db.commit()
    db.refresh(job)
    return job


@router.get("/cases/{case_id}/log-analysis/{job_id}/results", response_model=LogAnalysisJobOut)
def get_log_analysis_results(client_id: str, case_id: str, job_id: str, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    job = db.query(DfirLogAnalysisJob).filter_by(id=job_id, case_id=case_id).first()
    if not job:
        raise HTTPException(404, "Log analysis job not found")
    return job


@router.get("/cases/{case_id}/log-analysis", response_model=list[LogAnalysisJobOut])
def list_log_analysis_jobs(client_id: str, case_id: str, db: Session = Depends(get_db)):
    _require_case(client_id, case_id, db)
    return db.query(DfirLogAnalysisJob).filter_by(case_id=case_id).order_by(DfirLogAnalysisJob.created_at.desc()).all()
