from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.auth import require_client_access, require_staff
from app.core.database import get_db
from app.core.plans import PLANS, PlanTier, public_plans, plan_features, FEATURES
from app.models.models import Client

# Public catalogue — no client scope, any authenticated user can read the tiers.
catalogue_router = APIRouter(prefix="/api/plans", tags=["plans"])

# Per-client subscription — tenant-scoped.
router = APIRouter(prefix="/api/clients/{client_id}/subscription", tags=["plans"],
                   dependencies=[Depends(require_client_access)])


@catalogue_router.get("")
def list_plans():
    """The three subscription tiers with pricing, cadence, SLAs, and per-feature inclusion."""
    return public_plans()


def _subscription_payload(client: Client) -> dict:
    tier = PlanTier(client.plan) if client.plan in [t.value for t in PlanTier] else PlanTier.enterprise
    plan = PLANS[tier]
    features = plan_features(tier)
    return {
        "client_id": client.id,
        "plan": plan["tier"],
        "plan_name": plan["name"],
        "price_monthly_usd": plan["price_monthly_usd"],
        "scan_cadence": plan["scan_cadence"],
        "sla_hours_critical": plan["sla_hours_critical"],
        "sla_hours_high": plan["sla_hours_high"],
        "entitlements": {key: (key in features) for key in FEATURES},
    }


@router.get("")
def get_subscription(client_id: str, db: Session = Depends(get_db)):
    """The client's current plan and exactly which capabilities it entitles them to."""
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return _subscription_payload(client)


class SubscriptionUpdate(BaseModel):
    plan: str


@router.put("", dependencies=[Depends(require_staff)])
def set_subscription(client_id: str, payload: SubscriptionUpdate, db: Session = Depends(get_db)):
    """
    Staff-only: change a client's subscription tier. Also applies the plan's
    SLA targets to the client so alerting/escalation reflect the tier they pay
    for (a higher tier buys tighter response SLAs, not just more features).
    """
    client = db.query(Client).get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    valid = [t.value for t in PlanTier]
    if payload.plan not in valid:
        raise HTTPException(422, f"Invalid plan '{payload.plan}'. Must be one of: {', '.join(valid)}")

    plan = PLANS[PlanTier(payload.plan)]
    client.plan = payload.plan
    client.sla_hours_critical = plan["sla_hours_critical"]
    client.sla_hours_high = plan["sla_hours_high"]
    db.commit()
    db.refresh(client)
    return _subscription_payload(client)
