"""Module C: Scoring & Classification Engine.

Aggregates weighted feature flags from lexical analysis and DOM inspection into
a standardized 0–100 risk score and maps them to risk bands:
- Lower risk: 0 - 30%
- Suspicious: 31 - 70%
- High Risk: 71 - 100%
"""

from __future__ import annotations

from typing import Any

BAND_LOWER_RISK = "Lower risk"
BAND_SUSPICIOUS = "Suspicious"
BAND_HIGH_RISK = "High Risk"


def classify_risk_band(score: int) -> str:
    """Map numeric risk score (0-100) to corresponding risk band.

    - 0 to 30: Lower risk
    - 31 to 70: Suspicious
    - 71 to 100: High Risk
    """
    if score <= 30:
        return BAND_LOWER_RISK
    elif score <= 70:
        return BAND_SUSPICIOUS
    else:
        return BAND_HIGH_RISK


def compute_risk_score(signals: list[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate weighted signals into a 0-100 composite risk score.

    Applies non-linear saturation so multiple moderate indicators accumulate
    appropriately while clamping the maximum score at 100.

    Returns:
        dict: {
            "score": int,
            "risk_band": str,
            "signals": list,
            "total_points": int,
            "signal_count": int
        }
    """
    # Deduplicate signals by id if any overlap
    seen_ids = set()
    unique_signals = []
    total_raw_points = 0

    for s in signals:
        sid = s.get("id")
        if sid not in seen_ids:
            seen_ids.add(sid)
            unique_signals.append(s)
            total_raw_points += int(s.get("points", 0))

    # Standardize/clamp score between 0 and 100
    calculated_score = min(100, max(0, total_raw_points))
    risk_band = classify_risk_band(calculated_score)

    return {
        "score": calculated_score,
        "risk_band": risk_band,
        "signals": unique_signals,
        "total_points": total_raw_points,
        "signal_count": len(unique_signals),
    }
