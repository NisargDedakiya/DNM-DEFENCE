from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from sqlalchemy.orm import Session

from app.core.audit import log_action
from app.core.auth import hash_password, require_staff, require_client_access
from app.core.database import get_db
from app.models.models import Client, User, UserRole
from app.schemas.schemas import ClientCreate, ClientOut
from app.services.compliance import seed_compliance_controls
from app.workers.tasks import run_subdomain_enum_for_client

router = APIRouter(prefix="/api/clients", tags=["clients"])


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


class ClientUserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=72)


class ClientUserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    email: str
    is_active: bool
    mfa_enabled: bool
    created_at: datetime


class ClientUserUpdate(BaseModel):
    is_active: bool


@router.post("", response_model=ClientOut, status_code=201)
def onboard_client(payload: ClientCreate, db: Session = Depends(get_db), _staff: User = Depends(require_staff)):
    """
    Staff-only. Client onboarding workflow (Module 7): creating a client
    automatically triggers the baseline subdomain enumeration scan so the
    asset inventory isn't empty on day one.
    """
    client = Client(**payload.model_dump())
    db.add(client)
    db.commit()
    db.refresh(client)

    seed_compliance_controls(db, client)
    run_subdomain_enum_for_client.delay(client.id)

    return client


@router.get("", response_model=list[ClientOut])
def list_clients(db: Session = Depends(get_db), _staff: User = Depends(require_staff)):
    """Staff-only — a client-role user has no reason to see the full client roster."""
    return db.query(Client).all()


@router.get("/{client_id}", response_model=ClientOut)
def get_client(client_id: str, db: Session = Depends(get_db), _access: User = Depends(require_client_access)):
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@router.get("/{client_id}/users", response_model=list[ClientUserOut])
def list_client_users(client_id: str, db: Session = Depends(get_db), _staff: User = Depends(require_staff)):
    """
    Staff-only. Connects the dots between "a client record exists" and "someone
    can actually log into the portal for it" -- every login that can see this
    client's data, in one place.
    """
    _require_client(client_id, db)
    return db.query(User).filter_by(client_id=client_id, role=UserRole.client).order_by(User.created_at).all()


@router.post("/{client_id}/users", response_model=ClientUserOut, status_code=201)
def create_client_user(client_id: str, payload: ClientUserCreate, request: Request,
                        db: Session = Depends(get_db), staff: User = Depends(require_staff)):
    """Staff-only — provisions a portal login scoped to this client_id, the write side of the list above."""
    _require_client(client_id, db)
    if db.query(User).filter_by(email=payload.email).first():
        raise HTTPException(400, "Email already registered")

    user = User(email=payload.email, hashed_password=hash_password(payload.password),
                role=UserRole.client, client_id=client_id)
    db.add(user)
    db.commit()
    db.refresh(user)
    log_action(db, action="user.create_client_user", user=staff, client_id=client_id,
               resource_type="user", resource_id=user.id, detail={"created_email": user.email},
               ip_address=_client_ip(request))
    return user


@router.patch("/{client_id}/users/{user_id}", response_model=ClientUserOut)
def update_client_user(client_id: str, user_id: str, payload: ClientUserUpdate, request: Request,
                        db: Session = Depends(get_db), staff: User = Depends(require_staff)):
    """Staff-only — revoke or restore a client portal login without deleting the account (preserves its audit trail)."""
    _require_client(client_id, db)
    user = db.query(User).filter_by(id=user_id, client_id=client_id, role=UserRole.client).first()
    if not user:
        raise HTTPException(404, "Client user not found")

    user.is_active = payload.is_active
    db.commit()
    db.refresh(user)
    log_action(db, action="user.set_active", user=staff, client_id=client_id,
               resource_type="user", resource_id=user.id, detail={"is_active": payload.is_active},
               ip_address=_client_ip(request))
    return user
