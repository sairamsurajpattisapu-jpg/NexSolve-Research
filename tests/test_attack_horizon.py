"""Comprehensive test suite for NexSolve Attack Horizon engine."""
from __future__ import annotations

from datetime import datetime, timezone
import pytest

from ml.forecasting.attack_horizon import (
    AttackHorizonResult,
    AttackHorizonState,
    compute_attack_horizon,
    parse_timestamp,
)


def _make_forecasts(probabilities: list[float | None], confidences: list[float | None] | None = None) -> list[dict]:
    forecasts = []
    for i, p in enumerate(probabilities, start=1):
        c = confidences[i - 1] if confidences else (None if p is None else abs(p - 0.5) * 2)
        forecasts.append({
            "horizon": i,
            "attack_probability": p,
            "confidence": c,
            "predicted_stage": "Reconnaissance" if p and p >= 0.5 else None,
            "abstained": p is None,
        })
    return forecasts


# Scenario 1: No attack forecast
def test_scenario_1_no_attack_forecast():
    forecasts = _make_forecasts([0.1, 0.15, 0.2, 0.18, 0.12])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    assert res.state == AttackHorizonState.NO_ATTACK_FORECAST
    assert res.horizon_windows == 0
    assert res.horizon_seconds == 0
    assert res.onset_horizon is None
    assert res.onset_timestamp is None
    assert res.lead_time_seconds is None
    assert res.end_horizon is None
    assert res.end_timestamp is None
    assert res.temporal_consistency == 1.0
    assert "No attack forecast" in res.summary


# Scenario 2: Early signal (T+1 only)
def test_scenario_2_early_signal_t1_only():
    forecasts = _make_forecasts([0.75, 0.2, 0.15, 0.1, 0.05])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    assert res.state == AttackHorizonState.EARLY_SIGNAL
    assert res.horizon_windows == 1
    assert res.horizon_seconds == 60
    assert res.onset_horizon == 1
    assert res.onset_timestamp == "2026-01-01T00:01:00Z"
    assert res.lead_time_seconds == 60
    assert res.end_horizon == 1
    assert res.end_timestamp == "2026-01-01T00:01:00Z"
    assert "Early attack signal" in res.summary


# Scenario 3: Sustained attack T+1..T+3
def test_scenario_3_sustained_attack_t1_to_t3():
    forecasts = _make_forecasts([0.80, 0.85, 0.82, 0.3, 0.1])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    assert res.state == AttackHorizonState.SUSTAINED_ATTACK_FORECAST
    assert res.horizon_windows == 3
    assert res.horizon_seconds == 180
    assert res.onset_horizon == 1
    assert res.onset_timestamp == "2026-01-01T00:01:00Z"
    assert res.lead_time_seconds == 60
    assert res.end_horizon == 3
    assert res.end_timestamp == "2026-01-01T00:03:00Z"
    assert "Sustained attack forecast spanning 3 windows" in res.summary


# Scenario 4: Sustained attack T+1..T+5
def test_scenario_4_sustained_attack_full_horizon():
    forecasts = _make_forecasts([0.70, 0.75, 0.80, 0.85, 0.90])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    assert res.state == AttackHorizonState.SUSTAINED_ATTACK_FORECAST
    assert res.horizon_windows == 5
    assert res.horizon_seconds == 300
    assert res.onset_horizon == 1
    assert res.onset_timestamp == "2026-01-01T00:01:00Z"
    assert res.lead_time_seconds == 60
    assert res.end_horizon == 5
    assert res.end_timestamp == "2026-01-01T00:05:00Z"


# Scenario 5: Isolated attack at T+3
def test_scenario_5_isolated_attack_at_t3():
    forecasts = _make_forecasts([0.1, 0.2, 0.85, 0.15, 0.1])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    assert res.state == AttackHorizonState.EARLY_SIGNAL
    assert res.horizon_windows == 1
    assert res.horizon_seconds == 60
    assert res.onset_horizon == 3
    assert res.onset_timestamp == "2026-01-01T00:03:00Z"
    assert res.lead_time_seconds == 180
    assert res.end_horizon == 3
    assert res.end_timestamp == "2026-01-01T00:03:00Z"


# Scenario 6: Delayed sustained attack T+2..T+4
def test_scenario_6_delayed_sustained_attack():
    forecasts = _make_forecasts([0.15, 0.75, 0.85, 0.80, 0.2])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    assert res.state == AttackHorizonState.SUSTAINED_ATTACK_FORECAST
    assert res.horizon_windows == 3
    assert res.horizon_seconds == 180
    assert res.onset_horizon == 2
    assert res.onset_timestamp == "2026-01-01T00:02:00Z"
    assert res.lead_time_seconds == 120
    assert res.end_horizon == 4
    assert res.end_timestamp == "2026-01-01T00:04:00Z"


# Scenario 7: Alternating predictions (Uncertain)
def test_scenario_7_alternating_predictions():
    forecasts = _make_forecasts([0.65, 0.35, 0.70, 0.30, 0.75])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    assert res.state == AttackHorizonState.UNCERTAIN_FORECAST
    assert res.horizon_windows == 0
    assert res.horizon_seconds == 0
    assert res.onset_horizon is None
    assert res.lead_time_seconds is None


# Scenario 8: Threshold boundary hovering (Uncertain)
def test_scenario_8_threshold_boundary_hover():
    forecasts = _make_forecasts([0.51, 0.49, 0.505, 0.495, 0.502])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts, uncertainty_band=0.03)
    assert res.state == AttackHorizonState.UNCERTAIN_FORECAST
    assert res.horizon_windows == 0
    assert res.onset_horizon is None


# Scenario 9: Exact boundary condition (p = 0.5)
def test_scenario_9_exact_boundary_threshold():
    forecasts = _make_forecasts([0.5, 0.5, 0.2, 0.1, 0.1])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts, decision_threshold=0.5, uncertainty_band=0.01)
    # Both 0.5 are >= 0.5, forming a 2-window sustained sequence
    assert res.state == AttackHorizonState.SUSTAINED_ATTACK_FORECAST
    assert res.horizon_windows == 2
    assert res.horizon_seconds == 120
    assert res.onset_horizon == 1


# Scenario 10: Explicit abstention passed
def test_scenario_10_explicit_abstention_parameter():
    forecasts = _make_forecasts([0.8, 0.85, 0.9, 0.9, 0.9])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts, abstention_reason="INSUFFICIENT_HISTORY")
    assert res.state == AttackHorizonState.ABSTAINED
    assert res.abstention_reason == "INSUFFICIENT_HISTORY"
    assert res.horizon_windows == 0
    assert res.horizon_seconds == 0
    assert res.onset_horizon is None
    assert res.lead_time_seconds is None


# Scenario 11: Explicit abstention in point forecast dicts
def test_scenario_11_point_forecast_abstention():
    forecasts = _make_forecasts([None, None, None, None, None])
    res = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    assert res.state == AttackHorizonState.ABSTAINED
    assert res.horizon_windows == 0
    assert res.onset_horizon is None
    assert all(e["abstained"] for e in res.evidence_chain)


# Scenario 12: Missing required features / gapped history
def test_scenario_12_gapped_history_abstention():
    res = compute_attack_horizon("2026-01-01T00:00:00Z", [], abstention_reason="GAPPED_HISTORY")
    assert res.state == AttackHorizonState.ABSTAINED
    assert res.abstention_reason == "GAPPED_HISTORY"


# Scenario 13: Timestamps - ISO-8601 string input
def test_scenario_13_iso_timestamp_parsing():
    forecasts = _make_forecasts([0.8, 0.8, 0.1, 0.1, 0.1])
    res = compute_attack_horizon("2026-05-15T10:30:00Z", forecasts)
    assert res.onset_timestamp == "2026-05-15T10:31:00Z"
    assert res.end_timestamp == "2026-05-15T10:32:00Z"


# Scenario 14: Timestamps - Epoch integer input
def test_scenario_14_epoch_integer_parsing():
    epoch = 1700000000
    expected_iso_t0 = datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    expected_iso_t1 = datetime.fromtimestamp(epoch + 60, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    forecasts = _make_forecasts([0.8, 0.1, 0.1, 0.1, 0.1])
    res = compute_attack_horizon(epoch, forecasts)
    assert res.onset_timestamp == expected_iso_t1
    assert res.evidence_chain[0]["predicted_timestamp"] == expected_iso_t1


# Scenario 15: Lead time calculation
def test_scenario_15_lead_time_calculation():
    # Onset at T+4
    forecasts = _make_forecasts([0.1, 0.2, 0.3, 0.9, 0.85])
    res = compute_attack_horizon(0, forecasts, window_seconds=60)
    assert res.onset_horizon == 4
    assert res.lead_time_seconds == 240  # 4 * 60s
    assert res.horizon_windows == 2
    assert res.horizon_seconds == 120   # 2 * 60s


# Scenario 16: Temporal decay detection
def test_scenario_16_temporal_decay_detection():
    # Decaying sequence from peak
    decaying = _make_forecasts([0.9, 0.8, 0.7, 0.6, 0.5])
    res_decay = compute_attack_horizon(0, decaying)
    assert res_decay.state == AttackHorizonState.SUSTAINED_ATTACK_FORECAST
    assert res_decay.decay_observed is True

    # Rising sequence
    rising = _make_forecasts([0.55, 0.65, 0.75, 0.85, 0.95])
    res_rising = compute_attack_horizon(0, rising)
    assert res_rising.state == AttackHorizonState.SUSTAINED_ATTACK_FORECAST
    assert res_rising.decay_observed is False


# Scenario 17: Confidence vs horizon distinction
def test_scenario_17_confidence_vs_horizon_distinction():
    forecasts = _make_forecasts([0.8, 0.85, 0.9, 0.1, 0.1], confidences=[0.6, 0.7, 0.8, 0.8, 0.8])
    res = compute_attack_horizon(0, forecasts, calibration_status="UNSUPPORTED")
    # Horizon is in windows (integer) and seconds (integer)
    assert isinstance(res.horizon_windows, int)
    assert isinstance(res.horizon_seconds, int)
    assert res.horizon_windows == 3
    assert res.horizon_seconds == 180

    # Confidence is statistical summary with explicit calibration status
    assert res.confidence_summary["calibration_status"] == "UNSUPPORTED"
    assert 0.0 <= res.confidence_summary["mean_confidence"] <= 1.0
    assert res.confidence_summary["min_confidence"] == 0.6
    assert res.confidence_summary["max_confidence"] == 0.8


# Scenario 18: Deterministic repeatability
def test_scenario_18_deterministic_repeatability():
    forecasts = _make_forecasts([0.7, 0.75, 0.8, 0.2, 0.1])
    res1 = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    res2 = compute_attack_horizon("2026-01-01T00:00:00Z", forecasts)
    assert res1.to_dict() == res2.to_dict()


# Scenario 19: Object-based (camelCase / snake_case) input compatibility
def test_scenario_19_object_and_camelcase_input():
    class MockForecastPoint:
        def __init__(self, horizon, attackProbability, confidence, predictedStage):
            self.horizon = horizon
            self.attackProbability = attackProbability
            self.confidence = confidence
            self.predictedStage = predictedStage

    points = [
        MockForecastPoint(1, 0.85, 0.7, "Reconnaissance"),
        MockForecastPoint(2, 0.80, 0.6, "Lateral Movement"),
        MockForecastPoint(3, 0.20, 0.6, None),
    ]
    res = compute_attack_horizon("2026-01-01T00:00:00Z", points)
    assert res.state == AttackHorizonState.SUSTAINED_ATTACK_FORECAST
    assert res.horizon_windows == 2
    assert res.onset_horizon == 1
