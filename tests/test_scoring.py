from analyzer.scoring import compute_risk_score, classify_risk_band, BAND_LOWER_RISK, BAND_SUSPICIOUS, BAND_HIGH_RISK


def test_classify_risk_band():
    assert classify_risk_band(0) == BAND_LOWER_RISK
    assert classify_risk_band(30) == BAND_LOWER_RISK
    assert classify_risk_band(31) == BAND_SUSPICIOUS
    assert classify_risk_band(50) == BAND_SUSPICIOUS
    assert classify_risk_band(70) == BAND_SUSPICIOUS
    assert classify_risk_band(71) == BAND_HIGH_RISK
    assert classify_risk_band(100) == BAND_HIGH_RISK


def test_compute_risk_score_empty():
    res = compute_risk_score([])
    assert res["score"] == 0
    assert res["risk_band"] == BAND_LOWER_RISK
    assert res["signals"] == []


def test_compute_risk_score_clamping():
    signals = [
        {"id": "SIG_1", "points": 40, "name": "Flag 1"},
        {"id": "SIG_2", "points": 50, "name": "Flag 2"},
        {"id": "SIG_3", "points": 30, "name": "Flag 3"},
    ]
    res = compute_risk_score(signals)
    assert res["score"] == 100
    assert res["total_points"] == 120
    assert res["risk_band"] == BAND_HIGH_RISK
    assert len(res["signals"]) == 3


def test_compute_risk_score_deduplication():
    signals = [
        {"id": "SIG_DUP", "points": 20, "name": "Flag Dup"},
        {"id": "SIG_DUP", "points": 20, "name": "Flag Dup"},
    ]
    res = compute_risk_score(signals)
    assert res["score"] == 20
    assert len(res["signals"]) == 1
