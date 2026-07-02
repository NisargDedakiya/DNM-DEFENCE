"""
Shared risk-score calculation. Single source of truth so the dashboard,
reports, and trend snapshots never drift from each other -- this logic
used to be duplicated between ai_reports.py and the frontend.
"""


def compute_risk_score(counts: dict[str, int]) -> int:
    """
    Simple weighted risk score, 0 (best) to 100 (worst). Not meant to be
    a rigorous model -- it's a directional indicator, calibrated so a
    handful of open criticals dominates the score.
    """
    raw = counts.get("critical", 0) * 25 + counts.get("high", 0) * 10 + counts.get("medium", 0) * 3 + counts.get("low", 0) * 1
    return min(100, raw)


def risk_band(score: int) -> str:
    if score >= 60:
        return "critical"
    if score >= 35:
        return "high"
    if score >= 15:
        return "medium"
    return "good"
