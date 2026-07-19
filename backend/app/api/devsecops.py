import os
import tempfile
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_client_access
from app.core.entitlements import require_feature
from app.core.database import get_db
from app.models.models import Client, PipelineIntegration, DeveloperScorecardSnapshot
from app.services.devsecops import (
    GATE_TEMPLATES, deploy_gate_workflow, poll_pipeline_runs, sync_pipeline_findings_to_db,
)
from app.services.triage import (
    parse_sarif, parse_trivy_json, parse_owasp_dependency_check_xml, triage_findings, sync_triage_findings_to_db,
)
from app.services.scorecard import compute_scorecard_metrics, snapshot_scorecard, generate_scorecard_narrative, export_scorecard_pdf
from app.services.iac_scan import run_checkov, sync_iac_findings_to_db

router = APIRouter(prefix="/api/clients/{client_id}/devsecops", tags=["devsecops"], dependencies=[Depends(require_client_access), Depends(require_feature("devsecops"))])

_EXPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "generated_reports")
os.makedirs(_EXPORT_DIR, exist_ok=True)


class PipelineCreate(BaseModel):
    repo_full_name: str
    template: str
    block_on_severity: str = "high"


class PipelineOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    provider: str
    repo_full_name: str
    gate_config: dict
    is_active: bool
    last_synced_at: datetime | None
    created_at: datetime


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_pipeline(client_id: str, pipeline_id: str, db: Session) -> PipelineIntegration:
    p = db.query(PipelineIntegration).filter_by(id=pipeline_id, client_id=client_id).first()
    if not p:
        raise HTTPException(404, "Pipeline not found")
    return p


# --- DSO-1: Pipeline Security Orchestrator ---

@router.post("/pipelines", response_model=PipelineOut, status_code=201)
def register_pipeline(client_id: str, payload: PipelineCreate, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    if payload.template not in GATE_TEMPLATES:
        raise HTTPException(422, f"Unknown template '{payload.template}'. Choose from: {', '.join(GATE_TEMPLATES)}")
    pipeline = PipelineIntegration(
        client_id=client_id, repo_full_name=payload.repo_full_name,
        gate_config={"template": payload.template, "block_on_severity": payload.block_on_severity},
    )
    db.add(pipeline)
    db.commit()
    db.refresh(pipeline)
    return pipeline


@router.get("/pipelines", response_model=list[PipelineOut])
def list_pipelines(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(PipelineIntegration).filter_by(client_id=client_id).order_by(PipelineIntegration.created_at.desc()).all()


@router.post("/pipelines/{pipeline_id}/deploy-gate")
def deploy_gate(client_id: str, pipeline_id: str, db: Session = Depends(get_db)):
    pipeline = _require_pipeline(client_id, pipeline_id, db)
    gate_config = pipeline.gate_config or {}
    try:
        result = deploy_gate_workflow(pipeline.repo_full_name, gate_config.get("template", "python_fastapi"),
                                       gate_config.get("block_on_severity", "high"))
    except RuntimeError as e:
        raise HTTPException(422, str(e))
    return result


@router.post("/pipelines/{pipeline_id}/poll")
def poll_pipeline(client_id: str, pipeline_id: str, db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    pipeline = _require_pipeline(client_id, pipeline_id, db)
    try:
        runs = poll_pipeline_runs(pipeline.repo_full_name)
    except RuntimeError as e:
        raise HTTPException(422, str(e))
    new_count = sync_pipeline_findings_to_db(db, client, pipeline.repo_full_name, runs)
    pipeline.last_synced_at = datetime.utcnow()
    db.commit()
    return {"runs_seen": len(runs), "new_findings": new_count}


# --- DSO-2: Security Finding Triage Assistant ---

@router.post("/triage/sarif")
def triage_sarif(client_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    import json
    try:
        data = json.loads(file.file.read())
    except json.JSONDecodeError as e:
        raise HTTPException(422, f"Invalid SARIF JSON: {e}")
    findings = parse_sarif(data)
    return _triage_and_sync(db, client, findings)


@router.post("/triage/trivy")
def triage_trivy(client_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    import json
    try:
        data = json.loads(file.file.read())
    except json.JSONDecodeError as e:
        raise HTTPException(422, f"Invalid Trivy JSON: {e}")
    findings = parse_trivy_json(data)
    return _triage_and_sync(db, client, findings)


@router.post("/triage/owasp-dependency-check")
def triage_owasp_dc(client_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    content = file.file.read().decode("utf-8", errors="ignore")
    findings = parse_owasp_dependency_check_xml(content)
    return _triage_and_sync(db, client, findings)


def _triage_and_sync(db: Session, client: Client, findings: list[dict]) -> dict:
    if not findings:
        return {"parsed": 0, "new_findings": 0, "findings": []}
    try:
        findings = triage_findings(findings)
    except RuntimeError:
        pass  # ANTHROPIC_API_KEY unset -- findings sync unfiltered/unannotated, the safe default
    new_count = sync_triage_findings_to_db(db, client, findings)
    return {"parsed": len(findings), "new_findings": new_count, "findings": findings}


# --- DSO-3: Developer Security Scorecard ---

@router.get("/scorecard")
def get_scorecard(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return compute_scorecard_metrics(db, client_id)


@router.post("/scorecard/snapshot")
def snapshot(client_id: str, db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    snap = snapshot_scorecard(db, client)
    return {"id": snap.id, "snapshot_date": snap.snapshot_date, "metrics": snap.metrics}


@router.get("/scorecard/trend")
def scorecard_trend(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    snaps = db.query(DeveloperScorecardSnapshot).filter_by(client_id=client_id).order_by(DeveloperScorecardSnapshot.snapshot_date).all()
    return [{"date": s.snapshot_date.isoformat(), **s.metrics} for s in snaps]


@router.get("/scorecard/export/pdf")
def export_scorecard(client_id: str, db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    metrics = compute_scorecard_metrics(db, client_id)
    narrative = generate_scorecard_narrative(client.name, metrics)
    safe_name = client.name.replace(" ", "_").replace("/", "-")
    output_path = os.path.join(_EXPORT_DIR, f"{safe_name}_scorecard_{datetime.utcnow().strftime('%Y-%m-%d')}.pdf")
    export_scorecard_pdf(client.name, metrics, narrative, output_path)
    return FileResponse(output_path, media_type="application/pdf", filename=os.path.basename(output_path))


# --- DSO-4: IaC Security Scanner ---

@router.post("/iac-scan")
def iac_scan(client_id: str, file: UploadFile = File(...), db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    content = file.file.read()
    with tempfile.TemporaryDirectory() as tmp_dir:
        dest_path = os.path.join(tmp_dir, file.filename or "iac_file")
        with open(dest_path, "wb") as f:
            f.write(content)
        findings = run_checkov(tmp_dir)

    new_count = sync_iac_findings_to_db(db, client, findings)
    return {"parsed": len(findings), "new_findings": new_count, "findings": findings}
