from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.auth import require_staff, require_client_access
from app.core.database import get_db
from app.models.models import Client, User
from app.schemas.schemas import ClientCreate, ClientOut
from app.services.compliance import seed_compliance_controls
from app.workers.tasks import run_subdomain_enum_for_client

router = APIRouter(prefix="/api/clients", tags=["clients"])


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
