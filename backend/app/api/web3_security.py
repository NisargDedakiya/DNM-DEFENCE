import os
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_client_access
from app.core.database import get_db
from app.models.models import Client, SmartContractAudit, ContractAuditStatus, OnChainMonitor
from app.services.web3_scan import run_contract_scan
from app.services.web3_report import render_web3_audit_html, export_pdf, render_web3_audit_markdown

router = APIRouter(prefix="/api/clients/{client_id}/web3", tags=["web3-security"], dependencies=[Depends(require_client_access)])

_EXPORT_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "generated_reports")
os.makedirs(_EXPORT_DIR, exist_ok=True)


class AuditCreate(BaseModel):
    contract_name: str
    contract_source: str
    network: str = "ethereum"


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    contract_name: str | None
    network: str
    status: str
    solc_version_hint: str | None
    findings: list
    error_message: str | None
    created_at: datetime


class MonitorCreate(BaseModel):
    contract_address: str
    network: str = "ethereum"
    alert_thresholds: dict = {}
    telegram_chat_id: str | None = None


class MonitorOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    contract_address: str
    network: str
    alert_thresholds: dict
    telegram_chat_id: str | None
    last_checked_block: int | None
    is_active: bool
    last_alerts: list
    created_at: datetime


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_audit(client_id: str, audit_id: str, db: Session) -> SmartContractAudit:
    audit = db.query(SmartContractAudit).filter_by(id=audit_id, client_id=client_id).first()
    if not audit:
        raise HTTPException(404, "Audit not found")
    return audit


@router.post("/contract-audits", response_model=AuditOut, status_code=201)
def create_audit(client_id: str, payload: AuditCreate, db: Session = Depends(get_db)):
    """WEB3-1 — submits Solidity source for scanning; runs Slither + Semgrep (+ optional Mythril) synchronously and stores deduped findings."""
    _require_client(client_id, db)
    audit = SmartContractAudit(client_id=client_id, contract_name=payload.contract_name,
                                contract_source=payload.contract_source, network=payload.network,
                                status=ContractAuditStatus.queued, findings=[])
    db.add(audit)
    db.commit()
    db.refresh(audit)

    try:
        result = run_contract_scan(payload.contract_source)
    except Exception as e:
        audit.status = ContractAuditStatus.failed
        audit.error_message = str(e)[:1000]
        db.commit()
        db.refresh(audit)
        return audit

    audit.findings = result["findings"]
    audit.solc_version_hint = result["solc_version_hint"]
    audit.status = ContractAuditStatus.completed
    db.commit()
    db.refresh(audit)
    return audit


@router.get("/contract-audits", response_model=list[AuditOut])
def list_audits(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(SmartContractAudit).filter_by(client_id=client_id).order_by(SmartContractAudit.created_at.desc()).all()


@router.get("/contract-audits/{audit_id}/export/pdf")
def export_audit_pdf(client_id: str, audit_id: str, public: bool = False, db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    audit = _require_audit(client_id, audit_id, db)
    html = render_web3_audit_html(client.name, audit.contract_name or "Contract", audit.network, audit.findings, public_mode=public)
    safe_name = (audit.contract_name or "contract").replace(" ", "_").replace("/", "-")
    output_path = os.path.join(_EXPORT_DIR, f"{safe_name}_audit_{audit.id}.pdf")
    export_pdf(html, output_path)
    return FileResponse(output_path, media_type="application/pdf", filename=os.path.basename(output_path))


@router.get("/contract-audits/{audit_id}/export/markdown", response_class=PlainTextResponse)
def export_audit_markdown(client_id: str, audit_id: str, db: Session = Depends(get_db)):
    client = _require_client(client_id, db)
    audit = _require_audit(client_id, audit_id, db)
    return render_web3_audit_markdown(client.name, audit.contract_name or "Contract", audit.network, audit.findings)


@router.post("/onchain-monitors", response_model=MonitorOut, status_code=201)
def create_monitor(client_id: str, payload: MonitorCreate, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    monitor = OnChainMonitor(client_id=client_id, contract_address=payload.contract_address, network=payload.network,
                              alert_thresholds=payload.alert_thresholds, telegram_chat_id=payload.telegram_chat_id,
                              last_alerts=[])
    db.add(monitor)
    db.commit()
    db.refresh(monitor)
    return monitor


@router.get("/onchain-monitors", response_model=list[MonitorOut])
def list_monitors(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(OnChainMonitor).filter_by(client_id=client_id).order_by(OnChainMonitor.created_at.desc()).all()


@router.patch("/onchain-monitors/{monitor_id}", response_model=MonitorOut)
def update_monitor(client_id: str, monitor_id: str, is_active: bool, db: Session = Depends(get_db)):
    monitor = db.query(OnChainMonitor).filter_by(id=monitor_id, client_id=client_id).first()
    if not monitor:
        raise HTTPException(404, "Monitor not found")
    monitor.is_active = is_active
    db.commit()
    db.refresh(monitor)
    return monitor
