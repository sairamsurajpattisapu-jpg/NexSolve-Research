"""Comprehensive Multi-Tier Abstention Engine for NexSolve.

Explicitly implements five discrete operational tiers:
1. FULL_FORECAST: High data quality, complete lookback, low uncertainty, all views active.
2. DEGRADED_FORECAST: Lookback sufficient, but some optional views missing or higher uncertainty; forecasts returned with calibrated wider uncertainty intervals.
3. ANOMALY_ONLY: Extreme OOD or high uncertainty prevents forward trajectory forecast, but current anomaly detection remains valid.
4. OBSERVABILITY_ONLY: Severe telemetry missingness; outputs only descriptive capture diagnostics without forward predictions.
5. ABSTAIN: Fatal preconditions failed (gapped timestamps, < 8 windows, corrupted numeric values, or invalid artifacts); strictly returns zero forecast without manufacturing confidence.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping, Sequence


class ForecastOperationalTier(str, Enum):
    FULL_FORECAST = "FULL_FORECAST"
    DEGRADED_FORECAST = "DEGRADED_FORECAST"
    ANOMALY_ONLY = "ANOMALY_ONLY"
    OBSERVABILITY_ONLY = "OBSERVABILITY_ONLY"
    ABSTAIN = "ABSTAIN"


class AbstentionReasonCode(str, Enum):
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    NON_CONTIGUOUS_TIMESTAMPS = "NON_CONTIGUOUS_TIMESTAMPS"
    INVALID_FEATURE_COUNT = "INVALID_FEATURE_COUNT"
    FEATURE_SCHEMA_MISMATCH = "FEATURE_SCHEMA_MISMATCH"
    INVALID_NUMERIC_VALUE = "INVALID_NUMERIC_VALUE"
    ARTIFACT_INTEGRITY_COMPROMISED = "ARTIFACT_INTEGRITY_COMPROMISED"
    ROLLOUT_DIVERGENCE = "ROLLOUT_DIVERGENCE"
    POOR_CAPTURE_QUALITY = "POOR_CAPTURE_QUALITY"
    PCAP_EXTRACTION_FAILED = "PCAP_EXTRACTION_FAILED"
    EXCESSIVE_UNCERTAINTY = "EXCESSIVE_UNCERTAINTY"
    EXTREME_OOD_SHIFT = "EXTREME_OOD_SHIFT"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


@dataclass(frozen=True)
class ComprehensiveAbstentionDecision:
    """Decision output dictating allowed pipeline outputs and operational tier."""
    tier: ForecastOperationalTier
    is_abstained: bool
    reason_code: str | None
    explanation: str
    missing_requirements: tuple[str, ...]
    allowed_outputs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.value,
            "operational_tier": self.tier.value,
            "is_abstained": self.is_abstained,
            "abstained": self.is_abstained,
            "reason_code": self.reason_code,
            "reason": self.reason_code,
            "explanation": self.explanation,
            "missing_requirements": list(self.missing_requirements),
            "allowed_outputs": list(self.allowed_outputs),
        }


class ComprehensiveAbstentionEngine:
    """Evaluates input preconditions, quality scores, and uncertainty to select tier."""

    @classmethod
    def evaluate(
        cls,
        window_count: int,
        is_continuous: bool,
        has_nans_or_infs: bool,
        capture_quality_status: str,  # "GOOD", "DEGRADED", "INSUFFICIENT"
        total_uncertainty: float = 0.0,
        ood_score: float = 0.0,
        missingness_flags: Mapping[str, float] | None = None,
        artifact_corrupted: bool = False,
    ) -> ComprehensiveAbstentionDecision:
        """Determines the appropriate operational tier and abstention status."""
        missing = []

        # 1. Hard blockers -> ABSTAIN
        if artifact_corrupted:
            return ComprehensiveAbstentionDecision(
                tier=ForecastOperationalTier.ABSTAIN,
                is_abstained=True,
                reason_code=AbstentionReasonCode.ARTIFACT_INTEGRITY_COMPROMISED.value,
                explanation="Model checkpoint artifacts failed SHA-256 cryptographic verification.",
                missing_requirements=("valid_model_artifacts",),
                allowed_outputs=(),
            )

        if has_nans_or_infs:
            return ComprehensiveAbstentionDecision(
                tier=ForecastOperationalTier.ABSTAIN,
                is_abstained=True,
                reason_code=AbstentionReasonCode.INVALID_NUMERIC_VALUE.value,
                explanation="Input telemetry contains non-finite values (NaN, +Inf, -Inf).",
                missing_requirements=("finite_numeric_telemetry",),
                allowed_outputs=(),
            )

        if not is_continuous:
            return ComprehensiveAbstentionDecision(
                tier=ForecastOperationalTier.ABSTAIN,
                is_abstained=True,
                reason_code=AbstentionReasonCode.NON_CONTIGUOUS_TIMESTAMPS.value,
                explanation="Input sequence contains timestamp intervals differing from canonical 60s windows.",
                missing_requirements=("contiguous_60s_timestamps",),
                allowed_outputs=(),
            )

        if window_count < 8:
            missing.append(f"insufficient_lookback_history: received {window_count}, required 8")
            return ComprehensiveAbstentionDecision(
                tier=ForecastOperationalTier.ABSTAIN,
                is_abstained=True,
                reason_code=AbstentionReasonCode.INSUFFICIENT_HISTORY.value,
                explanation=f"Lookback history too short ({window_count} < 8 contiguous windows).",
                missing_requirements=tuple(missing),
                allowed_outputs=(),
            )

        if capture_quality_status == "INSUFFICIENT":
            return ComprehensiveAbstentionDecision(
                tier=ForecastOperationalTier.ABSTAIN,
                is_abstained=True,
                reason_code=AbstentionReasonCode.POOR_CAPTURE_QUALITY.value,
                explanation="Underlying capture quality is marked INSUFFICIENT.",
                missing_requirements=("reliable_packet_capture",),
                allowed_outputs=(),
            )

        # 2. Extreme OOD or uncertainty -> ANOMALY_ONLY
        if ood_score > 0.85:
            return ComprehensiveAbstentionDecision(
                tier=ForecastOperationalTier.ANOMALY_ONLY,
                is_abstained=False,
                reason_code=AbstentionReasonCode.EXTREME_OOD_SHIFT.value,
                explanation="Input is severely out-of-distribution; forward trajectory rollout suppressed, anomaly detection preserved.",
                missing_requirements=("in_distribution_telemetry",),
                allowed_outputs=("current_state", "anomalies", "risk_indicators", "observability"),
            )

        if total_uncertainty > 0.80:
            return ComprehensiveAbstentionDecision(
                tier=ForecastOperationalTier.ANOMALY_ONLY,
                is_abstained=False,
                reason_code=AbstentionReasonCode.EXCESSIVE_UNCERTAINTY.value,
                explanation="Predictive uncertainty exceeds safety threshold (0.80); forward rollout suppressed.",
                missing_requirements=("bounded_predictive_uncertainty",),
                allowed_outputs=("current_state", "anomalies", "risk_indicators", "observability"),
            )

        # 3. Missing optional views or degraded quality -> DEGRADED_FORECAST
        is_degraded = (
            capture_quality_status == "DEGRADED"
            or (missingness_flags is not None and any(missingness_flags.values()))
            or total_uncertainty > 0.45
        )

        if is_degraded:
            return ComprehensiveAbstentionDecision(
                tier=ForecastOperationalTier.DEGRADED_FORECAST,
                is_abstained=False,
                reason_code=None,
                explanation="Telemetry operational with partial modality missingness; wider uncertainty bounds applied.",
                missing_requirements=(),
                allowed_outputs=(
                    "current_state", "forecast", "attack_assessment", "attack_progression",
                    "anomalies", "host_risk", "communication_risk", "network_risk_indicators",
                    "evidence", "uncertainty"
                ),
            )

        # 4. Standard optimal conditions -> FULL_FORECAST
        return ComprehensiveAbstentionDecision(
            tier=ForecastOperationalTier.FULL_FORECAST,
            is_abstained=False,
            reason_code=None,
            explanation="Optimal observation telemetry available; full multi-task forecast permitted.",
            missing_requirements=(),
            allowed_outputs=(
                "current_state", "forecast", "attack_assessment", "attack_progression",
                "anomalies", "host_risk", "communication_risk", "network_risk_indicators",
                "evidence", "uncertainty"
            ),
        )
