from app.services.risk_score import compute_risk_score, risk_band


def test_compute_risk_score_weights_severity():
    assert compute_risk_score({"critical": 0, "high": 0, "medium": 0, "low": 0}) == 0
    assert compute_risk_score({"critical": 1, "high": 0, "medium": 0, "low": 0}) == 25
    assert compute_risk_score({"critical": 1, "high": 1, "medium": 0, "low": 0}) == 35


def test_compute_risk_score_caps_at_100():
    assert compute_risk_score({"critical": 10, "high": 0, "medium": 0, "low": 0}) == 100


def test_compute_risk_score_missing_keys_default_to_zero():
    assert compute_risk_score({}) == 0
    assert compute_risk_score({"critical": 2}) == 50


def test_risk_band_thresholds():
    assert risk_band(0) == "good"
    assert risk_band(14) == "good"
    assert risk_band(15) == "medium"
    assert risk_band(34) == "medium"
    assert risk_band(35) == "high"
    assert risk_band(59) == "high"
    assert risk_band(60) == "critical"
    assert risk_band(100) == "critical"
