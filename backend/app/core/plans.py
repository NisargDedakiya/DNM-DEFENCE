"""
Subscription tiers — the single source of truth for what each plan includes.

Three paid tiers, no free tier. Higher tiers unlock more security services
and run scans more often. Everything that reads "what is this client entitled
to" — API gating, the automatic scan scheduler, the frontend nav, the Plans
page — reads from here so tiers can never drift between enforcement points.

Design notes:
- Features are coarse, client-facing capabilities (what the *client* sees and
  self-serves), not internal analyst tools. Staff/analysts are never gated by
  plan — they deliver the service on the client's behalf regardless of tier.
- New clients default to the ENTERPRISE tier at the data layer so nothing is
  accidentally locked out; the real tier is chosen explicitly at onboarding
  and can be changed any time via the subscription API.
"""
from enum import Enum


class PlanTier(str, Enum):
    essential = "essential"
    growth = "growth"
    enterprise = "enterprise"


# Client-facing capability keys. Each maps to one or more API routers and a
# nav entry. Kept as plain strings (not an enum) so adding a capability is a
# one-line change here and in the plan membership below.
FEATURES = {
    "asset_discovery": "Continuous asset & subdomain discovery",
    "vulnerability_management": "Vulnerability detection & tracking",
    "security_scorecard": "Security report card (grade + action plan)",
    "reports": "Scheduled security reports",
    "compliance": "Compliance center (SOC 2 / ISO 27001 readiness)",
    "alerts": "Real-time finding & SLA alerts",
    "threat_intel": "Dark-web & threat-intelligence monitoring",
    "cloud_security": "Cloud security posture (CSPM)",
    "phishing_simulations": "Phishing / social-engineering simulations",
    "mobile_security": "Mobile app security testing",
    "web3_security": "Blockchain & Web3 security",
    "ai_security": "AI/ML model security",
    "devsecops": "DevSecOps pipeline & IaC security",
    "penetration_testing": "Scheduled penetration testing",
}

# Which scan types the automatic scheduler runs for each capability. The
# all-clients beat tasks consult this so a client is only ever scanned for the
# services their tier includes -- the "automatic bundling" of the subscription.
FEATURE_SCANS = {
    "threat_intel": {"dark_web_scan"},
    "cloud_security": {"cloud_audit"},
}

_ESSENTIAL = {
    "asset_discovery", "vulnerability_management", "security_scorecard",
    "reports", "compliance", "alerts",
}
_GROWTH = _ESSENTIAL | {"threat_intel", "cloud_security", "phishing_simulations"}
_ENTERPRISE = _GROWTH | {
    "mobile_security", "web3_security", "ai_security", "devsecops", "penetration_testing",
}

PLANS = {
    PlanTier.essential: {
        "tier": PlanTier.essential.value,
        "name": "Essential",
        "price_monthly_usd": 499,
        "tagline": "Core security monitoring for a small team with no security staff.",
        "features": _ESSENTIAL,
        "scan_cadence": "Weekly asset & vulnerability scans, monthly report.",
        "sla_hours_critical": 48,
        "sla_hours_high": 120,
    },
    PlanTier.growth: {
        "tier": PlanTier.growth.value,
        "name": "Growth",
        "price_monthly_usd": 1499,
        "tagline": "Proactive managed security as you start selling to bigger customers.",
        "features": _GROWTH,
        "scan_cadence": "Daily asset scans, weekly vuln + cloud audits, weekly threat digest.",
        "sla_hours_critical": 24,
        "sla_hours_high": 72,
    },
    PlanTier.enterprise: {
        "tier": PlanTier.enterprise.value,
        "name": "Enterprise",
        "price_monthly_usd": 4999,
        "tagline": "A full-scope security program: every service, tightest SLAs.",
        "features": _ENTERPRISE,
        "scan_cadence": "Daily asset + vuln + cloud scans, continuous threat hunting.",
        "sla_hours_critical": 8,
        "sla_hours_high": 24,
    },
}

DEFAULT_TIER = PlanTier.enterprise


def _coerce(tier) -> PlanTier:
    if isinstance(tier, PlanTier):
        return tier
    try:
        return PlanTier(str(tier))
    except ValueError:
        return DEFAULT_TIER


def plan_features(tier) -> set[str]:
    return set(PLANS[_coerce(tier)]["features"])


def plan_has_feature(tier, feature: str) -> bool:
    return feature in plan_features(tier)


def plan_allows_scan(tier, scan_type: str) -> bool:
    """
    Does this tier's bundle include the given scan type? Scans not tied to any
    gated feature (asset discovery, core vuln scans) are available on every
    paid tier and always return True here.
    """
    feats = plan_features(tier)
    for feature, scans in FEATURE_SCANS.items():
        if scan_type in scans:
            return feature in feats
    return True


def public_plans() -> list[dict]:
    """Plan catalogue for the Plans page / API — features expanded to labels, cheapest first."""
    out = []
    for tier in (PlanTier.essential, PlanTier.growth, PlanTier.enterprise):
        p = PLANS[tier]
        out.append({
            "tier": p["tier"],
            "name": p["name"],
            "price_monthly_usd": p["price_monthly_usd"],
            "tagline": p["tagline"],
            "scan_cadence": p["scan_cadence"],
            "sla_hours_critical": p["sla_hours_critical"],
            "sla_hours_high": p["sla_hours_high"],
            "features": [{"key": k, "label": FEATURES[k], "included": k in p["features"]} for k in FEATURES],
        })
    return out
