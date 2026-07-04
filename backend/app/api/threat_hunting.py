from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_staff
from app.core.crypto import encrypt_credentials
from app.core.database import get_db
from app.models.models import (
    Client, HuntHypothesis, HuntHypothesisSource, HuntOperation, HuntOperationStatus, HuntOutcome, HuntFinding,
    Severity, SiemConnection, SiemProvider,
)
from app.services.threat_hunting import (
    seed_hypothesis_library, generate_hypothesis, enrich_ioc, generate_hunt_report, compute_attck_coverage,
    query_elastic, query_splunk, query_crowdstrike,
)

# Hypothesis library isn't client-scoped (a shared reusable library), so it
# gets its own top-level router; hunt operations/SIEM connections/IoC
# enrichment are client-scoped. Both require_staff only.
hypothesis_router = APIRouter(prefix="/api/threat-hunting/hypotheses", tags=["threat-hunting"],
                               dependencies=[Depends(require_staff)])
router = APIRouter(prefix="/api/clients/{client_id}/threat-hunting", tags=["threat-hunting"],
                    dependencies=[Depends(require_staff)])


class HypothesisCreate(BaseModel):
    title: str
    description: str | None = None
    attack_technique: str | None = None
    data_sources: list[str] = []
    industries: list[str] = []


class HypothesisOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    title: str
    description: str | None
    attack_technique: str | None
    data_sources: list
    industries: list
    priority: str
    hunt_count: int
    last_positive_at: datetime | None
    source: str
    created_at: datetime


class HypothesisGenerateRequest(BaseModel):
    client_industry: str
    recent_cti: list[str] = []


class HuntCreate(BaseModel):
    hypothesis_id: str
    status: HuntOperationStatus = HuntOperationStatus.planned


class HuntUpdate(BaseModel):
    status: HuntOperationStatus | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    outcome: HuntOutcome | None = None
    hours_spent: int | None = None


class HuntOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_id: str
    hypothesis_id: str
    status: str
    started_at: datetime | None
    completed_at: datetime | None
    outcome: str | None
    hours_spent: int


class FindingCreate(BaseModel):
    title: str
    severity: Severity = Severity.medium
    description: str | None = None
    evidence: dict = {}
    iocs: list = []
    attack_technique_id: str | None = None
    confirmed: bool = False
    escalated_to_ir: bool = False


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    hunt_id: str
    severity: str
    title: str
    description: str | None
    evidence: dict
    iocs: list
    attack_technique_id: str | None
    confirmed: bool
    escalated_to_ir: bool


class SiemConnectionCreate(BaseModel):
    provider: SiemProvider
    base_url: str | None = None
    api_key: str | None = None  # elastic
    username: str | None = None  # splunk
    password: str | None = None  # splunk
    client_id_cred: str | None = None  # crowdstrike
    client_secret: str | None = None  # crowdstrike


class SiemConnectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    client_id: str
    provider: str
    base_url: str | None
    is_active: bool
    created_at: datetime


class SiemQueryRequest(BaseModel):
    query: str


class IocEnrichRequest(BaseModel):
    ioc_value: str
    ioc_type: str


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_hunt(client_id: str, hunt_id: str, db: Session) -> HuntOperation:
    hunt = db.query(HuntOperation).filter_by(id=hunt_id, client_id=client_id).first()
    if not hunt:
        raise HTTPException(404, "Hunt operation not found")
    return hunt


@hypothesis_router.post("/seed")
def seed_library(db: Session = Depends(get_db)):
    created = seed_hypothesis_library(db)
    return {"created": created}


@hypothesis_router.get("", response_model=list[HypothesisOut])
def list_hypotheses(db: Session = Depends(get_db)):
    return db.query(HuntHypothesis).order_by(HuntHypothesis.priority.desc(), HuntHypothesis.created_at.desc()).all()


@hypothesis_router.post("", response_model=HypothesisOut, status_code=201)
def create_hypothesis(payload: HypothesisCreate, db: Session = Depends(get_db)):
    hypothesis = HuntHypothesis(**payload.model_dump(), source=HuntHypothesisSource.manual)
    db.add(hypothesis)
    db.commit()
    db.refresh(hypothesis)
    return hypothesis


@hypothesis_router.post("/generate", response_model=HypothesisOut, status_code=201)
def generate_hypothesis_endpoint(payload: HypothesisGenerateRequest, db: Session = Depends(get_db)):
    result = generate_hypothesis(payload.client_industry, payload.recent_cti)
    hypothesis = HuntHypothesis(
        title=result.get("title", "AI-generated hypothesis"), description=result.get("description"),
        attack_technique=result.get("attack_technique"), data_sources=result.get("data_sources", []),
        source=HuntHypothesisSource.ai_generated,
    )
    db.add(hypothesis)
    db.commit()
    db.refresh(hypothesis)
    return hypothesis


@router.post("/hunts", response_model=HuntOut, status_code=201)
def create_hunt(client_id: str, payload: HuntCreate, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    hypothesis = db.query(HuntHypothesis).get(payload.hypothesis_id)
    if not hypothesis:
        raise HTTPException(422, "Unknown hypothesis_id")
    hunt = HuntOperation(client_id=client_id, **payload.model_dump())
    db.add(hunt)
    hypothesis.hunt_count = (hypothesis.hunt_count or 0) + 1
    db.commit()
    db.refresh(hunt)
    return hunt


@router.get("/hunts", response_model=list[HuntOut])
def list_hunts(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(HuntOperation).filter_by(client_id=client_id).all()


@router.patch("/hunts/{hunt_id}", response_model=HuntOut)
def update_hunt(client_id: str, hunt_id: str, payload: HuntUpdate, db: Session = Depends(get_db)):
    hunt = _require_hunt(client_id, hunt_id, db)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(hunt, field, value)
    if hunt.outcome == HuntOutcome.threat_found and hunt.hypothesis:
        hunt.hypothesis.last_positive_at = datetime.utcnow()
    db.commit()
    db.refresh(hunt)
    return hunt


@router.post("/hunts/{hunt_id}/findings", response_model=FindingOut, status_code=201)
def add_finding(client_id: str, hunt_id: str, payload: FindingCreate, db: Session = Depends(get_db)):
    _require_hunt(client_id, hunt_id, db)
    finding = HuntFinding(hunt_id=hunt_id, **payload.model_dump())
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


@router.get("/hunts/{hunt_id}/findings", response_model=list[FindingOut])
def list_findings(client_id: str, hunt_id: str, db: Session = Depends(get_db)):
    _require_hunt(client_id, hunt_id, db)
    return db.query(HuntFinding).filter_by(hunt_id=hunt_id).all()


@router.get("/hunts/{hunt_id}/report", response_class=PlainTextResponse)
def get_hunt_report(client_id: str, hunt_id: str, db: Session = Depends(get_db)):
    hunt = _require_hunt(client_id, hunt_id, db)
    findings = db.query(HuntFinding).filter_by(hunt_id=hunt_id).all()
    return generate_hunt_report(hunt, findings)


@router.get("/coverage")
def get_coverage(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    hunts = db.query(HuntOperation).filter_by(client_id=client_id, status=HuntOperationStatus.complete).all()
    return compute_attck_coverage(hunts)


@router.post("/enrich-ioc")
def enrich_ioc_endpoint(client_id: str, payload: IocEnrichRequest, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return enrich_ioc(payload.ioc_value, payload.ioc_type)


@router.post("/siem-connections", response_model=SiemConnectionOut, status_code=201)
def register_siem_connection(client_id: str, payload: SiemConnectionCreate, db: Session = Depends(get_db)):
    _require_client(client_id, db)

    if payload.provider == SiemProvider.elastic:
        if not payload.api_key:
            raise HTTPException(400, "Elastic connections require api_key")
        creds = {"api_key": payload.api_key}
    elif payload.provider == SiemProvider.splunk:
        if not (payload.username and payload.password):
            raise HTTPException(400, "Splunk connections require username and password")
        creds = {"username": payload.username, "password": payload.password}
    elif payload.provider == SiemProvider.crowdstrike:
        if not (payload.client_id_cred and payload.client_secret):
            raise HTTPException(400, "CrowdStrike connections require client_id_cred and client_secret")
        creds = {"client_id": payload.client_id_cred, "client_secret": payload.client_secret}
    else:
        creds = {}

    connection = SiemConnection(client_id=client_id, provider=payload.provider, base_url=payload.base_url,
                                 encrypted_credentials=encrypt_credentials(creds))
    db.add(connection)
    db.commit()
    db.refresh(connection)
    return connection


@router.get("/siem-connections", response_model=list[SiemConnectionOut])
def list_siem_connections(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(SiemConnection).filter_by(client_id=client_id).all()


@router.post("/siem-connections/{connection_id}/query")
def query_siem_connection(client_id: str, connection_id: str, payload: SiemQueryRequest, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    connection = db.query(SiemConnection).filter_by(id=connection_id, client_id=client_id).first()
    if not connection:
        raise HTTPException(404, "SIEM connection not found")

    if connection.provider == SiemProvider.elastic:
        results = query_elastic(connection, payload.query)
    elif connection.provider == SiemProvider.splunk:
        results = query_splunk(connection, payload.query)
    elif connection.provider == SiemProvider.crowdstrike:
        results = query_crowdstrike(connection, payload.query)
    else:
        raise HTTPException(422, f"Live querying isn't supported yet for provider '{connection.provider.value}'")
    return {"results": results}
