"""NexSolve Forecast Validation Engine: Evaluates Observed -> Forecast -> Actual Subsequent Telemetry.

Truthfully compares:
- OBSERVED STATE (Window T0)
- FORECAST TRAJECTORY (T+1 .. T+5 rollouts)
- ACTUAL SUBSEQUENT TELEMETRY (Windows T+1 .. T+5 when captured in the PCAP)

ZERO-FABRICATION CONTRACT:
When subsequent capture telemetry is unavailable (capture ends before horizon),
or when forecast is withheld (insufficient history), validation status is recorded
strictly as 'VALIDATION NOT AVAILABLE'. Never invent or hallucinate ground truth.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Sequence


@dataclass(slots=True, frozen=True)
class HorizonValidationRecord:
    horizon: int
    lookahead_seconds: int
    observed_state_t0: str
    predicted_probability: float | None
    predicted_stage: str | None
    actual_subsequent_state: str | None
    actual_threat_score: float | None
    actual_packet_count: int | None
    actual_flow_count: int | None
    relationship: str  # "CONSISTENT", "DIVERGENT", "VALIDATION NOT AVAILABLE"
    validation_status: str  # "VALIDATED", "VALIDATION NOT AVAILABLE"
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True, frozen=True)
class ForecastValidationResult:
    status: str  # "VALIDATED", "PARTIALLY_VALIDATED", "VALIDATION NOT AVAILABLE"
    summary: str
    evaluated_horizons: int
    unvalidated_horizons: int
    points: list[HorizonValidationRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "summary": self.summary,
            "evaluated_horizons": self.evaluated_horizons,
            "unvalidated_horizons": self.unvalidated_horizons,
            "points": [p.to_dict() for p in self.points],
            "metadata": self.metadata,
        }


def evaluate_forecast_validation(
    candidates: Sequence[Any],
    forecast_points: Sequence[dict[str, Any]],
    is_forecast_available: bool,
    observed_stage: str = "BENIGN",
    abstention_reason: str | None = None,
    history_window_count: int = 8,
) -> ForecastValidationResult:
    """Evaluate run-time validation comparing forecast rollouts with subsequent capture windows."""
    total_windows = len(candidates)

    if not is_forecast_available or total_windows < history_window_count:
        reason_msg = abstention_reason or f"Insufficient historical sequence ({total_windows} < {history_window_count} windows)"
        points = [
            HorizonValidationRecord(
                horizon=h,
                lookahead_seconds=h * 60,
                observed_state_t0=observed_stage,
                predicted_probability=None,
                predicted_stage=None,
                actual_subsequent_state=None,
                actual_threat_score=None,
                actual_packet_count=None,
                actual_flow_count=None,
                relationship="VALIDATION NOT AVAILABLE",
                validation_status="VALIDATION NOT AVAILABLE",
                explanation=f"Validation not available: forecasting withheld ({reason_msg}).",
            )
            for h in range(1, 6)
        ]
        return ForecastValidationResult(
            status="VALIDATION NOT AVAILABLE",
            summary=f"Forecasting withheld ({reason_msg}). No forward trajectories available for empirical validation.",
            evaluated_horizons=0,
            unvalidated_horizons=5,
            points=points,
            metadata={
                "total_windows": total_windows,
                "history_window_count": history_window_count,
                "reason": reason_msg,
            },
        )

    # T0 is the end of the history sequence used for forecasting (e.g. index 7 for 8 windows)
    t0_index = history_window_count - 1
    fp_map = {int(p.get("horizon", idx + 1)): p for idx, p in enumerate(forecast_points)}

    points: list[HorizonValidationRecord] = []
    evaluated_count = 0
    unvalidated_count = 0

    for h in range(1, 6):
        fp = fp_map.get(h, {})
        pred_prob = fp.get("attackProbability") if fp.get("attackProbability") is not None else fp.get("stepAttackProbability")
        pred_stage = fp.get("predictedStage") or fp.get("predicted_stage") or "BENIGN"

        target_index = t0_index + h
        if target_index < total_windows:
            # Subsequent window exists in the capture!
            target_candidate = candidates[target_index]
            pkt_features = getattr(target_candidate, "packet_features", {}) or {}
            flow_features = getattr(target_candidate, "flow_features", {}) or {}

            # Determine actual telemetry state of this subsequent window
            pkt_count = int(pkt_features.get("packet_count", 0))
            flow_count = int(flow_features.get("flow_count", 0))
            syn_count = int(pkt_features.get("syn_count", 0))
            rst_count = int(pkt_features.get("rst_count", 0))

            # Heuristic assessment of actual subsequent window
            if syn_count >= 50 or flow_count >= 100:
                actual_state = "RECONNAISSANCE"
                actual_score = min(100.0, 50.0 + (flow_count / 10.0))
            elif rst_count >= 20:
                actual_state = "SCAN_OR_RESET"
                actual_score = 45.0
            elif pkt_count > 500:
                actual_state = "ELEVATED_TRAFFIC"
                actual_score = 35.0
            else:
                actual_state = "BENIGN"
                actual_score = 15.0

            # Compare forecast vs actual
            pred_is_attack = (pred_prob is not None and pred_prob >= 0.5)
            actual_is_attack = (actual_state in ("RECONNAISSANCE", "SCAN_OR_RESET", "COMMAND_AND_CONTROL", "IMPACT"))
            prob_str = f"{pred_prob:.1%}" if pred_prob is not None else "N/A"

            if pred_is_attack == actual_is_attack or (pred_stage == actual_state):
                relationship = "CONSISTENT"
                expl = (
                    f"Subsequent capture window w_{target_index} confirms projected trajectory: "
                    f"predicted {pred_stage} ({prob_str}) aligned with "
                    f"observed {actual_state} telemetry ({pkt_count} pkts, {flow_count} flows)."
                )
            else:
                relationship = "DIVERGENT"
                expl = (
                    f"Subsequent capture window w_{target_index} shows divergent trajectory: "
                    f"predicted {pred_stage} ({prob_str}), "
                    f"actual observed {actual_state} ({pkt_count} pkts, {flow_count} flows)."
                )

            val_status = "VALIDATED"
            evaluated_count += 1
        else:
            # Beyond capture duration
            actual_state = None
            actual_score = None
            pkt_count = None
            flow_count = None
            relationship = "VALIDATION NOT AVAILABLE"
            val_status = "VALIDATION NOT AVAILABLE"
            expl = (
                f"Capture concludes after {total_windows} windows ({total_windows * 60}s). "
                f"No subsequent physical telemetry recorded for horizon T+{h} (+{h * 60}s)."
            )
            unvalidated_count += 1

        points.append(
            HorizonValidationRecord(
                horizon=h,
                lookahead_seconds=h * 60,
                observed_state_t0=observed_stage,
                predicted_probability=pred_prob,
                predicted_stage=pred_stage,
                actual_subsequent_state=actual_state,
                actual_threat_score=actual_score,
                actual_packet_count=pkt_count,
                actual_flow_count=flow_count,
                relationship=relationship,
                validation_status=val_status,
                explanation=expl,
            )
        )

    if evaluated_count == 5:
        overall_status = "VALIDATED"
        summary = "All 5 forecast horizons empirically validated against subsequent capture observation windows."
    elif evaluated_count > 0:
        overall_status = "PARTIALLY_VALIDATED"
        summary = (
            f"{evaluated_count} of 5 forecast horizons validated against subsequent capture observation windows. "
            f"{unvalidated_count} horizon(s) extend beyond capture duration."
        )
    else:
        overall_status = "VALIDATION NOT AVAILABLE"
        summary = "Capture terminates at T0 (no subsequent observation windows available in capture)."

    return ForecastValidationResult(
        status=overall_status,
        summary=summary,
        evaluated_horizons=evaluated_count,
        unvalidated_horizons=unvalidated_count,
        points=points,
        metadata={
            "total_windows": total_windows,
            "t0_window_index": t0_index,
            "lookback_windows": history_window_count,
        },
    )
