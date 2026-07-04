import os
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_staff
from app.core.database import get_db
from app.models.models import (
    ResearchTarget, ResearchStatus, ResearchFinding, ResearchFindingStatus, Severity,
    FuzzingJob, FuzzingJobStatus,
)
from app.services.zero_day import (
    lookup_cve, check_cve_exists, days_until_disclosure_deadline,
    submit_to_hackerone, submit_to_bugcrowd, publish_github_security_advisory, generate_disclosure_advisory,
)

# ZD-1 targets aren't necessarily tied to a client (client_id is nullable —
# null means independent Track-A research), so this is a top-level router
# rather than nested under /clients/{client_id}, unlike most other tools.
# Analyst/admin only, same as every Advanced Services router in this phase.
router = APIRouter(prefix="/api/zero-day", tags=["zero-day"], dependencies=[Depends(require_staff)])

_POC_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "zero-day-pocs")
os.makedirs(_POC_DIR, exist_ok=True)


class TargetCreate(BaseModel):
    name: str
    client_id: str | None = None
    vendor: str | None = None
    version: str | None = None
    language: str | None = None
    source_url: str | None = None
    bug_bounty_url: str | None = None
    max_bounty: int | None = None
    priority: str = "medium"
    status: ResearchStatus = ResearchStatus.identified
    notes: str | None = None


class TargetUpdate(BaseModel):
    status: ResearchStatus | None = None
    priority: str | None = None
    total_hours: int | None = None
    total_earned: int | None = None
    notes: str | None = None


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_id: str | None
    name: str
    vendor: str | None
    version: str | None
    language: str | None
    source_url: str | None
    bug_bounty_url: str | None
    max_bounty: int | None
    priority: str
    status: str
    total_hours: int
    total_earned: int
    notes: str | None
    created_at: datetime


class FindingCreate(BaseModel):
    title: str
    cve_id: str | None = None
    cvss_score: float | None = None
    severity: Severity | None = None
    vuln_class: str | None = None
    description: str | None = None


class FindingUpdate(BaseModel):
    status: ResearchFindingStatus | None = None
    vendor_notified: datetime | None = None
    patch_released: datetime | None = None
    published_at: datetime | None = None
    bounty_amount: int | None = None
    bounty_platform: str | None = None
    cve_id: str | None = None
    cvss_score: float | None = None
    severity: Severity | None = None


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target_id: str
    title: str
    cve_id: str | None
    cvss_score: float | None
    severity: str | None
    vuln_class: str | None
    description: str | None
    poc_path: str | None
    status: str
    vendor_notified: datetime | None
    patch_released: datetime | None
    published_at: datetime | None
    bounty_amount: int | None
    bounty_platform: str | None
    created_at: datetime
    days_until_deadline: int | None = None


class FuzzingJobCreate(BaseModel):
    fuzzer: str
    target_binary_path: str | None = None
    corpus_path: str | None = None
    status: FuzzingJobStatus = FuzzingJobStatus.queued


class FuzzingJobUpdate(BaseModel):
    status: FuzzingJobStatus | None = None
    crashes_found: int | None = None
    execs_per_sec: int | None = None
    started_at: datetime | None = None
    ended_at: datetime | None = None


class FuzzingJobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target_id: str
    fuzzer: str
    target_binary_path: str | None
    corpus_path: str | None
    status: str
    crashes_found: int
    execs_per_sec: int | None
    started_at: datetime | None
    ended_at: datetime | None


class HackerOneSubmit(BaseModel):
    program_handle: str
    api_identifier: str


class BugcrowdSubmit(BaseModel):
    program_code: str


class GithubAdvisoryPublish(BaseModel):
    repo_full_name: str


def _require_target(target_id: str, db: Session) -> ResearchTarget:
    target = db.query(ResearchTarget).get(target_id)
    if not target:
        raise HTTPException(404, "Research target not found")
    return target


def _require_finding(target_id: str, finding_id: str, db: Session) -> ResearchFinding:
    finding = db.query(ResearchFinding).filter_by(id=finding_id, target_id=target_id).first()
    if not finding:
        raise HTTPException(404, "Finding not found")
    return finding


def _finding_out(finding: ResearchFinding) -> dict:
    out = FindingOut.model_validate(finding).model_dump()
    out["days_until_deadline"] = days_until_disclosure_deadline(finding.vendor_notified)
    return out


@router.post("/targets", response_model=TargetOut, status_code=201)
def create_target(payload: TargetCreate, db: Session = Depends(get_db)):
    target = ResearchTarget(**payload.model_dump())
    db.add(target)
    db.commit()
    db.refresh(target)
    return target


@router.get("/targets", response_model=list[TargetOut])
def list_targets(db: Session = Depends(get_db)):
    return db.query(ResearchTarget).order_by(ResearchTarget.created_at.desc()).all()


@router.get("/targets/{target_id}", response_model=TargetOut)
def get_target(target_id: str, db: Session = Depends(get_db)):
    return _require_target(target_id, db)


@router.patch("/targets/{target_id}", response_model=TargetOut)
def update_target(target_id: str, payload: TargetUpdate, db: Session = Depends(get_db)):
    target = _require_target(target_id, db)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(target, field, value)
    db.commit()
    db.refresh(target)
    return target


@router.delete("/targets/{target_id}", status_code=204)
def delete_target(target_id: str, db: Session = Depends(get_db)):
    target = _require_target(target_id, db)
    db.delete(target)
    db.commit()


@router.post("/targets/{target_id}/findings", response_model=FindingOut, status_code=201)
def create_finding(target_id: str, payload: FindingCreate, db: Session = Depends(get_db)):
    _require_target(target_id, db)
    finding = ResearchFinding(target_id=target_id, **payload.model_dump())
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return _finding_out(finding)


@router.get("/targets/{target_id}/findings", response_model=list[FindingOut])
def list_findings(target_id: str, db: Session = Depends(get_db)):
    _require_target(target_id, db)
    findings = db.query(ResearchFinding).filter_by(target_id=target_id).order_by(ResearchFinding.created_at.desc()).all()
    return [_finding_out(f) for f in findings]


@router.patch("/targets/{target_id}/findings/{finding_id}", response_model=FindingOut)
def update_finding(target_id: str, finding_id: str, payload: FindingUpdate, db: Session = Depends(get_db)):
    finding = _require_finding(target_id, finding_id, db)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(finding, field, value)
    db.commit()
    db.refresh(finding)
    return _finding_out(finding)


@router.post("/targets/{target_id}/findings/{finding_id}/poc", response_model=FindingOut)
def upload_poc(target_id: str, finding_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    finding = _require_finding(target_id, finding_id, db)
    ext = os.path.splitext(file.filename or "")[1].lower()
    stored_name = f"{uuid.uuid4().hex}{ext}"
    dest_path = os.path.join(_POC_DIR, stored_name)
    with open(dest_path, "wb") as f:
        f.write(file.file.read())
    finding.poc_path = dest_path
    db.commit()
    db.refresh(finding)
    return _finding_out(finding)


@router.get("/findings/{finding_id}/lookup-cve")
def lookup_finding_cve(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(ResearchFinding).get(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    if not finding.cve_id:
        raise HTTPException(422, "Finding has no CVE ID set yet")
    if not check_cve_exists(finding.cve_id):
        return {"exists": False, "detail": None}
    return {"exists": True, "detail": lookup_cve(finding.cve_id)}


@router.get("/findings/{finding_id}/advisory", response_class=PlainTextResponse)
def get_advisory(finding_id: str, db: Session = Depends(get_db)):
    finding = db.query(ResearchFinding).get(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    return generate_disclosure_advisory(finding)


@router.post("/findings/{finding_id}/submit/hackerone")
def submit_finding_hackerone(finding_id: str, payload: HackerOneSubmit, db: Session = Depends(get_db)):
    finding = db.query(ResearchFinding).get(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    result = submit_to_hackerone(finding, payload.program_handle, payload.api_identifier)
    if result is None:
        raise HTTPException(422, "HackerOne submission not configured or failed — check HACKERONE_API_TOKEN")
    return result


@router.post("/findings/{finding_id}/submit/bugcrowd")
def submit_finding_bugcrowd(finding_id: str, payload: BugcrowdSubmit, db: Session = Depends(get_db)):
    finding = db.query(ResearchFinding).get(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    result = submit_to_bugcrowd(finding, payload.program_code)
    if result is None:
        raise HTTPException(422, "Bugcrowd submission not configured or failed — check BUGCROWD_API_KEY")
    return result


@router.post("/findings/{finding_id}/publish-advisory")
def publish_advisory(finding_id: str, payload: GithubAdvisoryPublish, db: Session = Depends(get_db)):
    finding = db.query(ResearchFinding).get(finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    try:
        return publish_github_security_advisory(payload.repo_full_name, finding)
    except Exception as e:
        raise HTTPException(422, f"Failed to publish GitHub Security Advisory: {e}")


@router.post("/targets/{target_id}/fuzzing-jobs", response_model=FuzzingJobOut, status_code=201)
def create_fuzzing_job(target_id: str, payload: FuzzingJobCreate, db: Session = Depends(get_db)):
    _require_target(target_id, db)
    job = FuzzingJob(target_id=target_id, **payload.model_dump())
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


@router.get("/targets/{target_id}/fuzzing-jobs", response_model=list[FuzzingJobOut])
def list_fuzzing_jobs(target_id: str, db: Session = Depends(get_db)):
    _require_target(target_id, db)
    return db.query(FuzzingJob).filter_by(target_id=target_id).all()


@router.patch("/targets/{target_id}/fuzzing-jobs/{job_id}", response_model=FuzzingJobOut)
def update_fuzzing_job(target_id: str, job_id: str, payload: FuzzingJobUpdate, db: Session = Depends(get_db)):
    job = db.query(FuzzingJob).filter_by(id=job_id, target_id=target_id).first()
    if not job:
        raise HTTPException(404, "Fuzzing job not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(job, field, value)
    db.commit()
    db.refresh(job)
    return job
