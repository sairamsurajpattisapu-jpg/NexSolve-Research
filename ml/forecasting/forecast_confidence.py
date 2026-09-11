"""Forecast Confidence, Calibration, and Uncertainty representation for NexSolve.

Strictly separates:
1. forecast_score (raw model output)
2. confidence (statistical calibrated probability, or None if uncalibrated)
3. evidence_strength (explainability/consistency metric)
4. calibration_status (UNSUPPORTED / UNCALIBRATED / CALIBRATED)
5. uncertainty (LOW / MEDIUM / HIGH)
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any

from ml.forecasting.attack_horizon import AttackHorizonResult, AttackHorizonState
from ml.forecasting.evidence_intelligence import EvidenceChain, EvidenceQuality


class ConfidenceState(str, Enum):
    CALIBRATED = "CALIBRATED"
    UNCALIBRATED = "UNCALIBRATED"
    LOW_SUPPORT = "LOW_SUPPORT"
    HIGH_UNCERTAINTY = "HIGH_UNCERTAINTY"
    UNKNOWN = "UNKNOWN"


class UncertaintyLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CalibrationStatus(str, Enum):
    UNSUPPORTED = "UNSUPPORTED"
    UNCALIBRATED = "UNCALIBRATED"
    CALIBRATED = "CALIBRATED"


@dataclass(frozen=True)
class ForecastConfidenceResult:
    """Rigorous breakdown of model score vs statistical confidence vs uncertainty."""
    forecast_score: float | None
    confidence_value: float | None  # None when calibration is unsupported
    confidence_state: ConfidenceState
    evidence_strength: float
    calibration_status: CalibrationStatus
    uncertainty_level: UncertaintyLevel
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        res["confidence_state"] = self.confidence_state.value
        res["calibration_status"] = self.calibration_status.value
        res["uncertainty_level"] = self.uncertainty_level.value
        return res


def evaluate_forecast_confidence(
    forecast_score: float | None,
    evidence_chain: EvidenceChain,
    attack_horizon: AttackHorizonResult | None = None,
    calibration_status: CalibrationStatus | str = CalibrationStatus.UNSUPPORTED,
) -> ForecastConfidenceResult:
    """Evaluate confidence and uncertainty without confusing raw score with confidence.

    Parameters
    ----------
    forecast_score : float | None
        Raw point forecast probability for the primary window.
    evidence_chain : EvidenceChain
        Synthesized evidence chain containing evidence_strength and quality.
    attack_horizon : AttackHorizonResult | None, optional
        Precomputed Attack Horizon result.
    calibration_status : CalibrationStatus | str, default UNSUPPORTED
        Whether calibration is proven or unsupported.
    """
    if isinstance(calibration_status, str):
        try:
            cal_status = CalibrationStatus(calibration_status)
        except ValueError:
            cal_status = CalibrationStatus.UNSUPPORTED
    else:
        cal_status = calibration_status

    # 1. Missing score or abstained state
    if forecast_score is None or not math.isfinite(forecast_score):
        return ForecastConfidenceResult(
            forecast_score=None,
            confidence_value=None,
            confidence_state=ConfidenceState.UNKNOWN,
            evidence_strength=evidence_chain.evidence_strength,
            calibration_status=cal_status,
            uncertainty_level=UncertaintyLevel.HIGH,
            explanation="No forecast score available; confidence state is UNKNOWN.",
        )

    # 2. Determine Uncertainty Level
    # High uncertainty if:
    # - Attack horizon state is UNCERTAIN_FORECAST
    # - Score hovers within 0.05 of 0.50
    # - Evidence quality is DEGRADED or INSUFFICIENT
    # - Contradictory evidence outweighs supporting
    is_uncertain_horizon = attack_horizon is not None and attack_horizon.state == AttackHorizonState.UNCERTAIN_FORECAST
    is_boundary_hover = abs(forecast_score - 0.50) <= 0.04
    is_degraded_quality = evidence_chain.evidence_quality in (EvidenceQuality.DEGRADED, EvidenceQuality.INSUFFICIENT)
    is_high_contradiction = evidence_chain.contradictory_feature_count > evidence_chain.supporting_feature_count

    if is_uncertain_horizon or (is_boundary_hover and is_high_contradiction) or is_degraded_quality:
        uncertainty = UncertaintyLevel.HIGH
    elif is_boundary_hover or is_high_contradiction or evidence_chain.evidence_strength < 0.35:
        uncertainty = UncertaintyLevel.MEDIUM
    else:
        uncertainty = UncertaintyLevel.LOW

    # 3. Determine Confidence State and Value
    # If calibration is UNSUPPORTED or UNCALIBRATED:
    # confidence_value MUST BE None! We do NOT pretend raw score is confidence.
    if cal_status in (CalibrationStatus.UNSUPPORTED, CalibrationStatus.UNCALIBRATED):
        conf_val = None
        if uncertainty == UncertaintyLevel.HIGH:
            conf_state = ConfidenceState.HIGH_UNCERTAINTY
            explanation = (
                f"Raw forecast score is {forecast_score:.2f}, but calibration is UNSUPPORTED and uncertainty is HIGH "
                f"(boundary hover / degraded capture). Confidence value withheld."
            )
        elif evidence_chain.evidence_strength < 0.25 and forecast_score >= 0.50:
            conf_state = ConfidenceState.LOW_SUPPORT
            explanation = (
                f"Raw forecast score is {forecast_score:.2f}, but evidence support is weak "
                f"(evidence strength {evidence_chain.evidence_strength:.2f}). Confidence value withheld."
            )
        else:
            conf_state = ConfidenceState.UNCALIBRATED
            explanation = (
                f"Raw forecast score is {forecast_score:.2f}. Model calibration is {cal_status.value}; "
                f"score reflects raw model margin, NOT calibrated posterior confidence."
            )
    else:
        # CALIBRATED mode
        conf_val = round(forecast_score, 4)
        if uncertainty == UncertaintyLevel.HIGH:
            conf_state = ConfidenceState.HIGH_UNCERTAINTY
            explanation = f"Calibrated probability is {conf_val:.2f}, but uncertainty is elevated."
        elif evidence_chain.evidence_strength < 0.25:
            conf_state = ConfidenceState.LOW_SUPPORT
            explanation = f"Calibrated probability is {conf_val:.2f}, but corroborating evidence is minimal."
        else:
            conf_state = ConfidenceState.CALIBRATED
            explanation = f"Calibrated probability is {conf_val:.2f} with {uncertainty.value.lower()} uncertainty."

    return ForecastConfidenceResult(
        forecast_score=round(forecast_score, 4),
        confidence_value=conf_val,
        confidence_state=conf_state,
        evidence_strength=evidence_chain.evidence_strength,
        calibration_status=cal_status,
        uncertainty_level=uncertainty,
        explanation=explanation,
    )
