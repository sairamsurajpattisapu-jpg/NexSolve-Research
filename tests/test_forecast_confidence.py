"""Unit tests for NexSolve Forecast Confidence, Calibration, and Uncertainty engine."""
from __future__ import annotations

import pytest

from ml.forecasting.attack_horizon import compute_attack_horizon
from ml.forecasting.evidence_intelligence import (
    EvidenceChain,
    EvidenceQuality,
)
from ml.forecasting.forecast_confidence import (
    CalibrationStatus,
    ConfidenceState,
    ForecastConfidenceResult,
    UncertaintyLevel,
    evaluate_forecast_confidence,
)


def _make_chain(strength: float = 0.5, quality: EvidenceQuality = EvidenceQuality.HIGH, contra_count: int = 0) -> EvidenceChain:
    return EvidenceChain(
        current_window_id="w-0",
        current_timestamp="2026-09-10T06:00:00Z",
        forecast_horizon=3,
        supporting=[],
        contradictory=[{"explanation": f"contra-{i}"} for i in range(contra_count)],
        evidence_strength=strength,
        evidence_quality=quality,
        supporting_feature_count=2,
        contradictory_feature_count=contra_count,
        provenance_complete=True,
        explanation="Test chain",
        limitations=[],
    )


# 1. Uncalibrated representation: confidence_value MUST be None
def test_uncalibrated_representation_withholds_confidence_value():
    chain = _make_chain(strength=0.75)
    res = evaluate_forecast_confidence(
        forecast_score=0.82,
        evidence_chain=chain,
        calibration_status=CalibrationStatus.UNSUPPORTED,
    )
    assert res.forecast_score == 0.82
    assert res.confidence_value is None  # MUST be None!
    assert res.calibration_status == CalibrationStatus.UNSUPPORTED
    assert res.confidence_state == ConfidenceState.UNCALIBRATED
    assert "score reflects raw model margin" in res.explanation


# 2. Score vs Confidence Distinction: score 0.82 is NOT 82% confidence
def test_score_is_not_treated_as_confidence_percentage():
    chain = _make_chain(strength=0.75)
    res = evaluate_forecast_confidence(
        forecast_score=0.82,
        evidence_chain=chain,
        calibration_status="UNSUPPORTED",
    )
    assert res.confidence_value is None
    # evidence strength is also separate
    assert res.evidence_strength == 0.75


# 3. High uncertainty condition: boundary hover
def test_high_uncertainty_boundary_hover():
    chain = _make_chain(strength=0.50, contra_count=4)
    # Score 0.51 hovering right on the decision boundary
    res = evaluate_forecast_confidence(
        forecast_score=0.51,
        evidence_chain=chain,
        calibration_status="UNSUPPORTED",
    )
    assert res.uncertainty_level == UncertaintyLevel.HIGH
    assert res.confidence_state == ConfidenceState.HIGH_UNCERTAINTY


# 4. Low evidence condition: high score with weak evidence
def test_low_evidence_condition():
    chain = _make_chain(strength=0.15)  # Very weak evidence
    res = evaluate_forecast_confidence(
        forecast_score=0.88,
        evidence_chain=chain,
        calibration_status="UNSUPPORTED",
    )
    assert res.confidence_state == ConfidenceState.LOW_SUPPORT
    assert "evidence support is weak" in res.explanation


# 5. Missing / NaN score
def test_missing_or_nan_score():
    chain = _make_chain()
    res_none = evaluate_forecast_confidence(forecast_score=None, evidence_chain=chain)
    assert res_none.confidence_state == ConfidenceState.UNKNOWN
    assert res_none.uncertainty_level == UncertaintyLevel.HIGH

    res_nan = evaluate_forecast_confidence(forecast_score=float("nan"), evidence_chain=chain)
    assert res_nan.confidence_state == ConfidenceState.UNKNOWN


# 6. Calibrated mode
def test_calibrated_mode():
    chain = _make_chain(strength=0.80)
    res = evaluate_forecast_confidence(
        forecast_score=0.75,
        evidence_chain=chain,
        calibration_status=CalibrationStatus.CALIBRATED,
    )
    assert res.confidence_value == 0.75
    assert res.confidence_state == ConfidenceState.CALIBRATED
    assert res.calibration_status == CalibrationStatus.CALIBRATED
    assert res.uncertainty_level == UncertaintyLevel.LOW


# 7. Deterministic output
def test_deterministic_confidence_output():
    chain = _make_chain(strength=0.60)
    r1 = evaluate_forecast_confidence(0.70, chain).to_dict()
    r2 = evaluate_forecast_confidence(0.70, chain).to_dict()
    assert r1 == r2
