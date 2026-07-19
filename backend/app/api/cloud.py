from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from app.core.auth import require_client_access
from app.core.entitlements import require_feature
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from app.core.crypto import encrypt_credentials
from app.core.database import get_db
from app.models.models import Client, CloudAccount, CloudProvider
from app.schemas.schemas import ScanTriggerResponse
from app.workers.tasks import run_cloud_audit_for_client

router = APIRouter(prefix="/api/clients/{client_id}/cloud-accounts", tags=["cloud"], dependencies=[Depends(require_client_access), Depends(require_feature("cloud_security"))])


class CloudAccountCreate(BaseModel):
    provider: CloudProvider
    account_identifier: str  # AWS account ID / GCP project ID / Azure subscription ID

    # AWS
    access_key_id: str | None = None
    secret_access_key: str | None = None
    region: str = "us-east-1"

    # GCP — paste the full service-account JSON key as a dict
    service_account_json: dict | None = None

    # Azure
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


class CloudAccountOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: str
    provider: str
    account_identifier: str
    is_active: bool
    last_audited_at: datetime | None = None


def _require_client(client_id: str, db: Session) -> Client:
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return client


@router.post("", response_model=CloudAccountOut, status_code=201)
def register_cloud_account(client_id: str, payload: CloudAccountCreate, db: Session = Depends(get_db)):
    """
    Registers a client's cloud account for auditing. Credentials must be a
    READ-ONLY IAM user/role (AWS managed policy: SecurityAudit or
    ReadOnlyAccess). Never request or accept write-capable credentials.
    """
    _require_client(client_id, db)

    if payload.provider == CloudProvider.aws:
        if not (payload.access_key_id and payload.secret_access_key):
            raise HTTPException(400, "AWS accounts require access_key_id and secret_access_key")
        creds = {"access_key_id": payload.access_key_id, "secret_access_key": payload.secret_access_key, "region": payload.region}
    elif payload.provider == CloudProvider.gcp:
        if not payload.service_account_json:
            raise HTTPException(400, "GCP accounts require service_account_json")
        creds = {"service_account_json": payload.service_account_json}
    elif payload.provider == CloudProvider.azure:
        if not (payload.tenant_id and payload.client_id and payload.client_secret):
            raise HTTPException(400, "Azure accounts require tenant_id, client_id, and client_secret")
        creds = {"tenant_id": payload.tenant_id, "client_id": payload.client_id, "client_secret": payload.client_secret}
    else:
        raise HTTPException(400, "Unsupported provider")

    encrypted = encrypt_credentials(creds)

    account = CloudAccount(
        client_id=client_id, provider=payload.provider,
        account_identifier=payload.account_identifier,
        encrypted_credentials=encrypted,
    )
    db.add(account)
    db.commit()
    db.refresh(account)
    return account


@router.get("", response_model=list[CloudAccountOut])
def list_cloud_accounts(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    return db.query(CloudAccount).filter_by(client_id=client_id).all()


@router.post("/audit", response_model=ScanTriggerResponse)
def trigger_cloud_audit(client_id: str, db: Session = Depends(get_db)):
    _require_client(client_id, db)
    task = run_cloud_audit_for_client.delay(client_id)
    return ScanTriggerResponse(message="Cloud security audit queued", task_id=task.id)


@router.post("/{account_id}/rotate-credentials", response_model=CloudAccountOut)
def rotate_credentials(client_id: str, account_id: str, payload: CloudAccountCreate, db: Session = Depends(get_db)):
    """
    API key rotation. Same payload shape as registration -- the analyst
    generates fresh read-only credentials in the cloud console, then
    calls this to replace the stored (encrypted) ones and reset the
    rotation clock that check_cloud_credential_rotation watches.
    """
    _require_client(client_id, db)
    account = db.query(CloudAccount).filter_by(id=account_id, client_id=client_id).first()
    if not account:
        raise HTTPException(404, "Cloud account not found")

    if payload.provider == CloudProvider.aws:
        creds = {"access_key_id": payload.access_key_id, "secret_access_key": payload.secret_access_key, "region": payload.region}
    elif payload.provider == CloudProvider.gcp:
        creds = {"service_account_json": payload.service_account_json}
    elif payload.provider == CloudProvider.azure:
        creds = {"tenant_id": payload.tenant_id, "client_id": payload.client_id, "client_secret": payload.client_secret}
    else:
        raise HTTPException(400, "Unsupported provider")

    account.encrypted_credentials = encrypt_credentials(creds)
    account.credentials_rotated_at = datetime.utcnow()
    db.commit()
    db.refresh(account)
    return account
