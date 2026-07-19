"""
Subscription entitlement gating.

`require_feature("cloud_security")` used as a router dependency returns HTTP
402 (Payment Required) with an upgrade message when a *client-role* user's
plan doesn't include that capability. Staff (admin/analyst) always pass —
they deliver the service on the client's behalf regardless of tier, and
gating them would break internal delivery.

Because staff bypass and new clients default to the top tier, adding these
gates never removes access from anyone who has it today; a capability is only
withheld once a client is explicitly placed on a lower tier.
"""
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.auth import get_current_user
from app.core.database import get_db
from app.core.plans import PLANS, PlanTier, plan_has_feature, FEATURES
from app.models.models import Client, User, UserRole


def _min_tier_for(feature: str) -> str:
    for tier in (PlanTier.essential, PlanTier.growth, PlanTier.enterprise):
        if feature in PLANS[tier]["features"]:
            return PLANS[tier]["name"]
    return PLANS[PlanTier.enterprise]["name"]


def require_feature(feature: str):
    """Build a FastAPI dependency that enforces plan entitlement for `feature`."""

    def _dependency(client_id: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> None:
        # Staff are never plan-gated.
        if user.role in (UserRole.admin, UserRole.analyst):
            return
        client = db.query(Client).get(client_id)
        if not client:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Client not found")
        if not plan_has_feature(client.plan, feature):
            label = FEATURES.get(feature, feature)
            raise HTTPException(
                status.HTTP_402_PAYMENT_REQUIRED,
                f"'{label}' is not included in your current plan. "
                f"Upgrade to {_min_tier_for(feature)} or higher to enable it.",
            )

    return _dependency
