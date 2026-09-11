"""Forecast Abstention Integration for NexSolve.

Deterministically determines whether the system must abstain from forecasting.
Distinguishes between hard blockers (FORECAST_UNAVAILABLE) such as insufficient history,
gaps, or missing features, versus non-blocking qualifiers
(FORECAST_AVAILABLE_BUT_UNCALIBRATED).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from ml.forecasting.attack_horizon import parse_timestamp
from ml.forecasting.evidence_intelligence import EvidenceChain, EvidenceQuality
from ml.forecasting.forecast_confidence import CalibrationStatus, ForecastConfidenceResult
from ml.forecasting.unknown_behavior import BehaviorClassification, UnknownBehaviorResult


class AbstentionSeverity(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ForecastAvailabilityStatus(str, Enum):
    FORECAST_AVAILABLE = "FORECAST_AVAILABLE"
    FORECAST_AVAILABLE_BUT_UNCALIBRATED = "FORECAST_AVAILABLE_BUT_UNCALIBRATED"
    FORECAST_UNAVAILABLE = "FORECAST_UNAVAILABLE"


@dataclass(frozen=True)
class ForecastAbstentionResult:
    """Deterministic abstention decision with explicit requirement checks."""
    abstained: bool
    reason: str | None
    severity: AbstentionSeverity
    status: ForecastAvailabilityStatus
    missing_requirements: list[str]
    explanation: str
    observed_windows: int | None = None
    required_windows: int | None = None
    capture_duration_seconds: float | None = None
    gap_seconds: int | None = None

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        res["severity"] = self.severity.value
        res["status"] = self.status.value
        return res


def evaluate_forecast_abstention(
    sequence: Sequence[Any],
    evidence_chain: EvidenceChain | None = None,
    confidence_result: ForecastConfidenceResult | None = None,
    unknown_behavior: UnknownBehaviorResult | None = None,
    capture_quality: Any = None,
    min_sequence_length: int = 8,
    required_features: Sequence[str] | None = None,
) -> ForecastAbstentionResult:
    """Evaluate whether the forecasting pipeline must abstain or can proceed.

    Parameters
    ----------
    sequence : Sequence[Any]
        Chronological observation sequence of network states up to T_0.
    evidence_chain : EvidenceChain | None, optional
        Synthesized evidence chain.
    confidence_result : ForecastConfidenceResult | None, optional
        Confidence and uncertainty breakdown.
    unknown_behavior : UnknownBehaviorResult | None, optional
        Unknown behavior classification.
    capture_quality : Any, optional
        Capture quality assessment.
    min_sequence_length : int, default 8
        Minimum contiguous lookback windows required.
    required_features : Sequence[str] | None, optional
        Specific flow features required by the forecasting architecture.
    """
    missing_requirements: list[str] = []

    timestamps: list[int] = []
    for s in sequence:
        raw_ts = getattr(s, "timestamp", None)
        if raw_ts is None and isinstance(s, Mapping):
            raw_ts = s.get("timestamp")
        if raw_ts is not None:
            epoch, _ = parse_timestamp(raw_ts)
            timestamps.append(epoch)
    duration_s = (max(timestamps) - min(timestamps) + 60) if timestamps else 0

    # 1. Check Contiguity & Timestamp Gaps (Gapped History)
    for i in range(len(timestamps) - 1):
        dt = timestamps[i + 1] - timestamps[i]
        if dt != 60:
            gap_duration = dt - 60
            missing_requirements.append(
                f"gapped history: window interval between step {i} and {i+1} is {dt}s (expected 60s)"
            )
            return ForecastAbstentionResult(
                abstained=True,
                reason="GAPPED_HISTORY",
                severity=AbstentionSeverity.HIGH,
                status=ForecastAvailabilityStatus.FORECAST_UNAVAILABLE,
                missing_requirements=missing_requirements,
                explanation=f"Forecasting abstained: non-contiguous timestamp gap of {gap_duration}s detected in history.",
                observed_windows=len(timestamps),
                required_windows=min_sequence_length,
                gap_seconds=gap_duration,
            )

    # 2. Check Sequence Length (Insufficient History)
    seq_len = len(sequence) if sequence else 0
    if seq_len < min_sequence_length:
        missing_requirements.append(
            f"insufficient history: sequence length {seq_len} is less than required {min_sequence_length} windows"
        )
        return ForecastAbstentionResult(
            abstained=True,
            reason="INSUFFICIENT_HISTORY",
            severity=AbstentionSeverity.CRITICAL,
            status=ForecastAvailabilityStatus.FORECAST_UNAVAILABLE,
            missing_requirements=missing_requirements,
            explanation=(
                f"Forecasting abstained: insufficient history for the selected sequence length "
                f"({seq_len} / {min_sequence_length} windows observed, {duration_s}s duration). "
                f"Requires at least {min_sequence_length} contiguous windows ({min_sequence_length * 60}s) "
                f"to prevent hallucinatory rollouts."
            ),
            observed_windows=seq_len,
            required_windows=min_sequence_length,
            capture_duration_seconds=float(duration_s),
        )

    # 3. Check Required Features
    if required_features and sequence:
        curr = sequence[-1]
        flow_feats = getattr(curr, "flow_features", None)
        if flow_feats is None and isinstance(curr, Mapping):
            flow_feats = curr.get("flow_features") or curr.get("flowFeatures")
        if not flow_feats:
            missing_requirements.append("missing required flow feature dictionary")
        else:
            for req in required_features:
                if req not in flow_feats:
                    missing_requirements.append(f"missing required feature: {req}")

        if missing_requirements:
            return ForecastAbstentionResult(
                abstained=True,
                reason="MISSING_REQUIRED_FEATURES",
                severity=AbstentionSeverity.HIGH,
                status=ForecastAvailabilityStatus.FORECAST_UNAVAILABLE,
                missing_requirements=missing_requirements,
                explanation=f"Forecasting abstained: required feature schema incomplete ({len(missing_requirements)} missing).",
                observed_windows=seq_len,
                required_windows=min_sequence_length,
                capture_duration_seconds=float(duration_s),
            )

    # 4. Check Capture Quality
    if capture_quality is not None:
        c_status = getattr(capture_quality, "status", None)
        if isinstance(c_status, Enum):
            c_status = c_status.value
        elif isinstance(capture_quality, Mapping):
            c_status = capture_quality.get("status")

        if c_status == "INSUFFICIENT":
            missing_requirements.append("capture quality is INSUFFICIENT")
            return ForecastAbstentionResult(
                abstained=True,
                reason="POOR_CAPTURE_QUALITY",
                severity=AbstentionSeverity.CRITICAL,
                status=ForecastAvailabilityStatus.FORECAST_UNAVAILABLE,
                missing_requirements=missing_requirements,
                explanation="Forecasting abstained: underlying capture quality is INSUFFICIENT to produce reliable forecasts.",
                observed_windows=seq_len,
                required_windows=min_sequence_length,
                capture_duration_seconds=float(duration_s),
            )

    # 5. Check Unknown Behavior Recommended Abstention
    if unknown_behavior is not None and unknown_behavior.abstain_recommended:
        missing_requirements.append(f"unknown behavior unmappable: {unknown_behavior.reason}")
        return ForecastAbstentionResult(
            abstained=True,
            reason="UNKNOWN_BEHAVIOR",
            severity=AbstentionSeverity.HIGH,
            status=ForecastAvailabilityStatus.FORECAST_UNAVAILABLE,
            missing_requirements=missing_requirements,
            explanation=f"Forecasting abstained due to unmappable unknown behavior: {unknown_behavior.reason}",
            observed_windows=seq_len,
            required_windows=min_sequence_length,
            capture_duration_seconds=float(duration_s),
        )

    # 6. Non-Blocking Qualifier: Uncalibrated Model Support
    # Deterministic baseline forecast is STILL AVAILABLE, but flagged as uncalibrated.
    is_uncalibrated = (
        confidence_result is not None
        and confidence_result.calibration_status in (CalibrationStatus.UNSUPPORTED, CalibrationStatus.UNCALIBRATED)
    )

    if is_uncalibrated:
        return ForecastAbstentionResult(
            abstained=False,
            reason=None,
            severity=AbstentionSeverity.LOW,
            status=ForecastAvailabilityStatus.FORECAST_AVAILABLE_BUT_UNCALIBRATED,
            missing_requirements=[],
            explanation=(
                "Forecast is available and supported by lookback history, but model calibration is UNSUPPORTED. "
                "Raw scores should not be treated as calibrated probabilities."
            ),
            observed_windows=seq_len,
            required_windows=min_sequence_length,
            capture_duration_seconds=float(duration_s),
        )

    # 7. Clean Available State
    return ForecastAbstentionResult(
        abstained=False,
        reason=None,
        severity=AbstentionSeverity.NONE,
        status=ForecastAvailabilityStatus.FORECAST_AVAILABLE,
        missing_requirements=[],
        explanation="Forecast requirements satisfied with contiguous observation history.",
        observed_windows=seq_len,
        required_windows=min_sequence_length,
        capture_duration_seconds=float(duration_s),
    )
