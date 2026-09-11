"""Unified Forecast Intelligence orchestration for NexSolve.

Orchestrates:
1. Multi-step forecast rollout
2. Attack Horizon calculation
3. Evidence Intelligence extraction (supporting vs contradictory)
4. Forecast Confidence & Uncertainty representation
5. Unknown Behavior classification
6. Explicit Forecast Abstention evaluation
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from ml.forecasting.attack_horizon import AttackHorizonResult, compute_attack_horizon
from ml.forecasting.evidence_intelligence import EvidenceChain, build_evidence_chain
from ml.forecasting.forecast_abstention import (
    AbstentionSeverity,
    ForecastAbstentionResult,
    ForecastAvailabilityStatus,
    evaluate_forecast_abstention,
)
from ml.forecasting.forecast_confidence import (
    CalibrationStatus,
    ForecastConfidenceResult,
    evaluate_forecast_confidence,
)
from ml.forecasting.unknown_behavior import (
    BehaviorClassification,
    UnknownBehaviorResult,
    classify_unknown_behavior,
)


@dataclass(frozen=True)
class ForecastIntelligenceResult:
    """Unified, end-to-end forecast intelligence and trust layer product."""
    forecasts: list[dict[str, Any]]
    attack_horizon: dict[str, Any]
    evidence_chain: dict[str, Any]
    confidence: dict[str, Any]
    unknown_behavior: dict[str, Any]
    abstention: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "forecasts": self.forecasts,
            "attack_horizon": self.attack_horizon,
            "evidence_chain": self.evidence_chain,
            "confidence": self.confidence,
            "unknown_behavior": self.unknown_behavior,
            "abstention": self.abstention,
        }


def assemble_forecast_intelligence(
    sequence: Sequence[Any],
    forecast_points: Sequence[Any],
    capture_quality: Any = None,
    provenance_info: Mapping[str, Any] | None = None,
    min_sequence_length: int = 8,
    required_features: Sequence[str] | None = None,
    calibration_status: str = "UNSUPPORTED",
    decision_threshold: float = 0.50,
    window_seconds: int = 60,
) -> ForecastIntelligenceResult:
    """Run full intelligence pipeline server-side and assemble the unified response.

    Parameters
    ----------
    sequence : Sequence[Any]
        Input sequence of NetworkStates or state dicts up to current time T_0.
    forecast_points : Sequence[Any]
        Raw rollout points from world model.
    capture_quality : Any, optional
        Capture quality assessment.
    provenance_info : Mapping[str, Any] | None, optional
        Metadata on capture source and transformations.
    min_sequence_length : int, default 8
        Minimum required lookback windows.
    required_features : Sequence[str] | None, optional
        Required schema features.
    calibration_status : str, default "UNSUPPORTED"
        Calibration validity status.
    decision_threshold : float, default 0.50
        Binary classification threshold.
    window_seconds : int, default 60
        Window interval duration in seconds.
    """
    # 1. Evaluate Pre-Rollout Abstention Check
    abstention_check = evaluate_forecast_abstention(
        sequence=sequence,
        capture_quality=capture_quality,
        min_sequence_length=min_sequence_length,
        required_features=required_features,
    )

    # Determine current timestamp
    curr_state = sequence[-1] if sequence else None
    curr_ts = getattr(curr_state, "timestamp", 0) if curr_state else 0
    if isinstance(curr_state, Mapping) and "timestamp" in curr_state:
        curr_ts = curr_state["timestamp"]

    # 2. Compute Attack Horizon
    horizon_res = compute_attack_horizon(
        current_timestamp=curr_ts,
        forecasts=forecast_points,
        decision_threshold=decision_threshold,
        window_seconds=window_seconds,
        abstention_reason=abstention_check.reason if abstention_check.abstained else None,
        calibration_status=calibration_status,
    )

    # 3. Extract Evidence Intelligence
    evidence_chain = build_evidence_chain(
        sequence=sequence,
        forecast_horizon_result=horizon_res,
        capture_quality=capture_quality,
        provenance_info=provenance_info,
    )

    # 4. Extract Primary Forecast Score
    primary_score = None
    if forecast_points:
        first_pt = forecast_points[0]
        if isinstance(first_pt, Mapping):
            primary_score = first_pt.get("attack_probability") or first_pt.get("attackProbability")
        elif hasattr(first_pt, "attack_probability"):
            primary_score = first_pt.attack_probability
        elif hasattr(first_pt, "attackProbability"):
            primary_score = first_pt.attackProbability

    # 5. Evaluate Confidence & Uncertainty
    confidence_res = evaluate_forecast_confidence(
        forecast_score=primary_score if not abstention_check.abstained else None,
        evidence_chain=evidence_chain,
        attack_horizon=horizon_res,
        calibration_status=calibration_status,
    )

    # 6. Classify Unknown Behavior
    unknown_behavior_res = classify_unknown_behavior(
        evidence_chain=evidence_chain,
        attack_horizon=horizon_res,
        current_state=curr_state,
    )

    # 7. Final Abstention Decision Synthesis with all trust layer signals
    if not abstention_check.abstained:
        abstention_check = evaluate_forecast_abstention(
            sequence=sequence,
            evidence_chain=evidence_chain,
            confidence_result=confidence_res,
            unknown_behavior=unknown_behavior_res,
            capture_quality=capture_quality,
            min_sequence_length=min_sequence_length,
            required_features=required_features,
        )

    # Convert forecast points to standard dicts
    formatted_forecasts: list[dict[str, Any]] = []
    for pt in forecast_points:
        if isinstance(pt, Mapping):
            formatted_forecasts.append(dict(pt))
        elif hasattr(pt, "model_dump"):
            formatted_forecasts.append(pt.model_dump())
        elif hasattr(pt, "__dict__"):
            formatted_forecasts.append(dict(pt.__dict__))
        else:
            formatted_forecasts.append({"raw": str(pt)})

    return ForecastIntelligenceResult(
        forecasts=formatted_forecasts,
        attack_horizon=horizon_res.to_dict(),
        evidence_chain=evidence_chain.to_dict(),
        confidence=confidence_res.to_dict(),
        unknown_behavior=unknown_behavior_res.to_dict(),
        abstention=abstention_check.to_dict(),
    )
