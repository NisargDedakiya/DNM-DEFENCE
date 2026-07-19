from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.auth import require_client_access
from app.core.entitlements import require_feature
from app.core.database import get_db
from app.models.models import Client, PromptInjectionTest, AIFeatureInventory
from app.services.ai_security_testing import run_and_classify, sync_prompt_injection_findings_to_db
from app.services.ai_posture import check_ai_library_cves, generate_ai_security_brief
from app.services.compliance import get_compliance_summary

router = APIRouter(prefix="/api/clients/{client_id}/ai-security", tags=["ai-security"], dependencies=[Depends(require_client_access), Depends(require_feature("ai_security"))])


class PromptInjectionTestCreate(BaseModel):
    target_url: str
    headers: dict = {}


class PromptInjectionTestOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    target_url: str
    results: list
    success_count: int
    created_at: datetime


class FeatureInventoryCreate(BaseModel):
    feature_name: str
    feature_type: str | None = None
    library_stack: dict = {}


class FeatureInventoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    feature_name: str
    feature_type: str | None
    library_stack: dict
    created_at: datetime
    updated_at: datetime


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@router.post("/prompt-injection-tests", response_model=PromptInjectionTestOut, status_code=201)
def create_prompt_injection_test(client_id: str, payload: PromptInjectionTestCreate, db: Session = Depends(get_db)):
    """AI-1 — runs the full curated payload library against the client's target endpoint and syncs successful attacks into Finding."""
    client = _require_client(client_id, db)
    classified = run_and_classify(payload.target_url, payload.headers or None)
    success_count = sum(1 for r in classified if r["classification"]["success"])

    test = PromptInjectionTest(client_id=client_id, target_url=payload.target_url, results=classified, success_count=success_count)
    db.add(test)
    sync_prompt_injection_findings_to_db(db, client, payload.target_url, classified)
    db.commit()
    db.refresh(test)
    return test


@router.get("/prompt-injection-tests", response_model=list[PromptInjectionTestOut])
def list_prompt_injection_tests(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(PromptInjectionTest).filter_by(client_id=client_id).order_by(PromptInjectionTest.created_at.desc()).all()


@router.post("/feature-inventory", response_model=FeatureInventoryOut, status_code=201)
def create_feature_inventory(client_id: str, payload: FeatureInventoryCreate, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    feature = AIFeatureInventory(client_id=client_id, **payload.model_dump())
    db.add(feature)
    db.commit()
    db.refresh(feature)
    return feature


@router.get("/feature-inventory", response_model=list[FeatureInventoryOut])
def list_feature_inventory(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(AIFeatureInventory).filter_by(client_id=client_id).order_by(AIFeatureInventory.created_at.desc()).all()


@router.get("/cve-check")
def run_cve_check(client_id: str, db: Session = Depends(get_db)):
    """AI-2 — checks every declared library across every AI feature against the free CIRCL CVE index."""
    _require_client(client_id, db)
    features = db.query(AIFeatureInventory).filter_by(client_id=client_id).all()
    combined_libraries: dict = {}
    for f in features:
        combined_libraries.update(f.library_stack or {})
    return {"hits": check_ai_library_cves(combined_libraries)}


@router.get("/posture-brief")
def posture_brief(client_id: str, db: Session = Depends(get_db)):
    """AI-2 — Claude monthly AI security brief grounded in real inventory/CVE/OWASP-checklist data."""
    client = _require_client(client_id, db)
    features = db.query(AIFeatureInventory).filter_by(client_id=client_id).all()
    combined_libraries: dict = {}
    for f in features:
        combined_libraries.update(f.library_stack or {})
    cve_hits = check_ai_library_cves(combined_libraries)
    owasp_summary = get_compliance_summary(db, client_id).get("owasp_llm", {})
    return {"brief": generate_ai_security_brief(client.name, len(features), cve_hits, owasp_summary)}
