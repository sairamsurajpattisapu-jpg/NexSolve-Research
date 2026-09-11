"""Attack Horizon forecasting engine for NexSolve.

Computes the temporal attack horizon, lead time, sustained attack span,
and temporal consistency from multi-step network state forecasts.
Distinguishes between temporal span (horizon in windows/seconds) and
confidence/calibration status.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Sequence


class AttackHorizonState(str, Enum):
    """Exhaustive states for attack horizon determination."""
    NO_ATTACK_FORECAST = "NO_ATTACK_FORECAST"
    EARLY_SIGNAL = "EARLY_SIGNAL"
    SUSTAINED_ATTACK_FORECAST = "SUSTAINED_ATTACK_FORECAST"
    UNCERTAIN_FORECAST = "UNCERTAIN_FORECAST"
    ABSTAINED = "ABSTAINED"


@dataclass(frozen=True)
class HorizonEvidence:
    """Individual horizon step evidence record."""
    horizon: int
    horizon_seconds: int
    predicted_timestamp: str
    attack_probability: float | None
    confidence: float | None
    predicted_stage: str | None
    above_threshold: bool
    abstained: bool
    reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ConfidenceSummary:
    """Statistical support and calibration indicators (separate from temporal horizon)."""
    mean_confidence: float | None
    min_confidence: float | None
    max_confidence: float | None
    calibration_status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AttackHorizonResult:
    """Synthesized attack horizon intelligence product."""
    state: AttackHorizonState
    onset_horizon: int | None
    onset_timestamp: str | None
    lead_time_seconds: int | None
    horizon_windows: int
    horizon_seconds: int
    end_horizon: int | None
    end_timestamp: str | None
    decision_threshold: float
    temporal_consistency: float
    decay_observed: bool
    confidence_summary: dict[str, Any]
    evidence_chain: list[dict[str, Any]]
    abstention_reason: str | None
    summary: str

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["state"] = self.state.value
        return result


def parse_timestamp(timestamp: int | float | str | datetime) -> tuple[int, str]:
    """Normalize input timestamp into UTC epoch seconds and ISO-8601 string."""
    if isinstance(timestamp, (int, float)):
        epoch = int(timestamp)
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
        return epoch, dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(timestamp, datetime):
        dt = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
        dt_utc = dt.astimezone(timezone.utc)
        return int(dt_utc.timestamp()), dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(timestamp, str):
        clean = timestamp.strip()
        try:
            val = float(clean)
            epoch = int(val)
            dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
            return epoch, dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            pass
        # ISO string parsing
        iso_str = clean.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso_str)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        dt_utc = dt.astimezone(timezone.utc)
        return int(dt_utc.timestamp()), dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    raise TypeError(f"Unsupported timestamp type: {type(timestamp)}")


def epoch_to_iso(epoch: int) -> str:
    """Convert UTC epoch seconds to standard ISO-8601 string."""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _extract_forecast_field(point: Any, name: str, default: Any = None) -> Any:
    """Helper to extract field from either dict or object."""
    if isinstance(point, dict):
        if name in point:
            return point[name]
        camel = "".join(part.capitalize() if i > 0 else part for i, part in enumerate(name.split("_")))
        return point.get(camel, default)
    if hasattr(point, name):
        return getattr(point, name)
    camel = "".join(part.capitalize() if i > 0 else part for i, part in enumerate(name.split("_")))
    return getattr(point, camel, default)


def compute_attack_horizon(
    current_timestamp: int | float | str | datetime,
    forecasts: Sequence[Any],
    decision_threshold: float = 0.5,
    window_seconds: int = 60,
    abstention_reason: str | None = None,
    calibration_status: str = "UNSUPPORTED",
    uncertainty_band: float = 0.03,
) -> AttackHorizonResult:
    """Compute attack horizon, lead time, and temporal persistence.

    Parameters
    ----------
    current_timestamp : int | float | str | datetime
        Base observation time T_0.
    forecasts : Sequence[Any]
        Ordered sequence of multi-step forecast points (T+1 .. T+K).
    decision_threshold : float, default 0.5
        Threshold above which a forecast is classified as attack.
    window_seconds : int, default 60
        Duration in seconds of each temporal window step.
    abstention_reason : str | None, default None
        Explicit abstention reason if pipeline halted (e.g. INSUFFICIENT_HISTORY).
    calibration_status : str, default "UNSUPPORTED"
        Calibration evaluation status of forecasting model.
    uncertainty_band : float, default 0.03
        Score proximity to threshold considered hovering uncertainty.
    """
    epoch_0, iso_0 = parse_timestamp(current_timestamp)

    # 1. Pipeline-level abstention check
    if abstention_reason is not None:
        return _build_abstained_result(
            reason=abstention_reason,
            decision_threshold=decision_threshold,
            calibration_status=calibration_status,
            forecasts=forecasts,
            epoch_0=epoch_0,
            window_seconds=window_seconds,
        )

    if not forecasts:
        return _build_abstained_result(
            reason="EMPTY_FORECASTS",
            decision_threshold=decision_threshold,
            calibration_status=calibration_status,
            forecasts=[],
            epoch_0=epoch_0,
            window_seconds=window_seconds,
        )

    # 2. Inspect point forecasts
    parsed_evidence: list[HorizonEvidence] = []
    probabilities: list[float] = []
    confidences: list[float] = []
    stages: list[str | None] = []
    horizons: list[int] = []

    for idx, pt in enumerate(forecasts, start=1):
        h = int(_extract_forecast_field(pt, "horizon", idx))
        prob = _extract_forecast_field(pt, "attack_probability", None)
        conf = _extract_forecast_field(pt, "confidence", None)
        stg = _extract_forecast_field(pt, "predicted_stage", None)
        abstained = bool(_extract_forecast_field(pt, "abstained", False))
        reason = _extract_forecast_field(pt, "reason", None)
        if not reason:
            explanations = _extract_forecast_field(pt, "explanation", []) or []
            for exp in explanations:
                if isinstance(exp, str) and ("abstained" in exp.lower() or "insufficient" in exp.lower() or "gapped" in exp.lower()):
                    reason = exp
                    break

        if prob is None or abstained or not math.isfinite(prob):
            point_reason = reason or "MISSING_FORECAST_SCORE"
            return _build_abstained_result(
                reason=point_reason,
                decision_threshold=decision_threshold,
                calibration_status=calibration_status,
                forecasts=forecasts,
                epoch_0=epoch_0,
                window_seconds=window_seconds,
            )

        prob = float(prob)
        conf = float(conf) if conf is not None and math.isfinite(conf) else None
        above = prob >= decision_threshold
        pt_epoch = epoch_0 + (h * window_seconds)
        pt_iso = epoch_to_iso(pt_epoch)

        ev = HorizonEvidence(
            horizon=h,
            horizon_seconds=h * window_seconds,
            predicted_timestamp=pt_iso,
            attack_probability=round(prob, 4),
            confidence=round(conf, 4) if conf is not None else None,
            predicted_stage=stg,
            above_threshold=above,
            abstained=False,
            reason=None,
        )
        parsed_evidence.append(ev)
        horizons.append(h)
        probabilities.append(prob)
        if conf is not None:
            confidences.append(conf)
        stages.append(stg)

    # 3. Confidence Summary (distinct from temporal horizon)
    conf_summary = ConfidenceSummary(
        mean_confidence=round(sum(confidences) / len(confidences), 4) if confidences else None,
        min_confidence=round(min(confidences), 4) if confidences else None,
        max_confidence=round(max(confidences), 4) if confidences else None,
        calibration_status=calibration_status,
    ).to_dict()

    above_flags = [p >= decision_threshold for p in probabilities]
    n_points = len(probabilities)

    flips = sum(1 for i in range(n_points - 1) if above_flags[i] != above_flags[i + 1])
    in_band_count = sum(1 for p in probabilities if abs(p - decision_threshold) <= uncertainty_band)
    boundary_hovering = in_band_count >= (n_points // 2 + 1)
    total_pos = sum(1 for a in above_flags if a)
    alternating = total_pos >= 2 and flips >= 3 and not (any(above_flags[i] and above_flags[i+1] for i in range(n_points-1)))

    if alternating or (boundary_hovering and flips >= 1):
        # High uncertainty / contradictory alternation across horizon
        consistency = max(0.0, round(1.0 - (flips / max(1, n_points - 1)), 4))
        return AttackHorizonResult(
            state=AttackHorizonState.UNCERTAIN_FORECAST,
            onset_horizon=None,
            onset_timestamp=None,
            lead_time_seconds=None,
            horizon_windows=0,
            horizon_seconds=0,
            end_horizon=None,
            end_timestamp=None,
            decision_threshold=decision_threshold,
            temporal_consistency=consistency,
            decay_observed=False,
            confidence_summary=conf_summary,
            evidence_chain=[e.to_dict() for e in parsed_evidence],
            abstention_reason=None,
            summary=(
                f"Uncertain attack forecast; predictions oscillate or hover near decision boundary "
                f"({decision_threshold:.2f} ± {uncertainty_band:.2f}) across {n_points} horizons. "
                f"Temporal consistency: {consistency:.2f}."
            ),
        )

    # 5. No Attack Forecast
    if not any(above_flags):
        return AttackHorizonResult(
            state=AttackHorizonState.NO_ATTACK_FORECAST,
            onset_horizon=None,
            onset_timestamp=None,
            lead_time_seconds=None,
            horizon_windows=0,
            horizon_seconds=0,
            end_horizon=None,
            end_timestamp=None,
            decision_threshold=decision_threshold,
            temporal_consistency=1.0,
            decay_observed=False,
            confidence_summary=conf_summary,
            evidence_chain=[e.to_dict() for e in parsed_evidence],
            abstention_reason=None,
            summary=f"No attack forecast across the {n_points}-window horizon ({n_points * window_seconds}s). Baseline traffic expected.",
        )

    # 6. Attack Detected: Determine Onset & Sustained Span
    onset_idx = min(i for i, a in enumerate(above_flags) if a)
    onset_h = horizons[onset_idx]
    onset_epoch = epoch_0 + (onset_h * window_seconds)
    onset_iso = epoch_to_iso(onset_epoch)
    lead_time_sec = onset_h * window_seconds

    # Count consecutive run starting from onset
    run_len = 0
    for flag in above_flags[onset_idx:]:
        if flag:
            run_len += 1
        else:
            break

    end_idx = onset_idx + run_len - 1
    end_h = horizons[end_idx]
    end_epoch = epoch_0 + (end_h * window_seconds)
    end_iso = epoch_to_iso(end_epoch)
    horizon_sec = run_len * window_seconds

    # Temporal consistency: ratio of consecutive run to total positive flags
    total_positive = sum(1 for a in above_flags if a)
    consistency = round(run_len / total_positive, 4)

    # Temporal decay: from onset_idx onward, are probabilities non-increasing?
    decay_observed = False
    if run_len > 1 and onset_idx < n_points - 1:
        tail = probabilities[onset_idx:]
        decay_observed = all(tail[i] >= tail[i + 1] - 1e-6 for i in range(len(tail) - 1))

    if run_len >= 2:
        state = AttackHorizonState.SUSTAINED_ATTACK_FORECAST
        summary = (
            f"Sustained attack forecast spanning {run_len} windows ({horizon_sec}s) "
            f"starting at horizon T+{onset_h} (lead time {lead_time_sec}s) "
            f"through T+{end_h}. Temporal consistency: {consistency:.2f}."
        )
    else:
        state = AttackHorizonState.EARLY_SIGNAL
        summary = (
            f"Early attack signal detected at horizon T+{onset_h} (lead time {lead_time_sec}s); "
            f"duration isolated to {horizon_sec}s (1 window). Temporal consistency: {consistency:.2f}."
        )

    return AttackHorizonResult(
        state=state,
        onset_horizon=onset_h,
        onset_timestamp=onset_iso,
        lead_time_seconds=lead_time_sec,
        horizon_windows=run_len,
        horizon_seconds=horizon_sec,
        end_horizon=end_h,
        end_timestamp=end_iso,
        decision_threshold=decision_threshold,
        temporal_consistency=consistency,
        decay_observed=decay_observed,
        confidence_summary=conf_summary,
        evidence_chain=[e.to_dict() for e in parsed_evidence],
        abstention_reason=None,
        summary=summary,
    )


def _build_abstained_result(
    reason: str,
    decision_threshold: float,
    calibration_status: str,
    forecasts: Sequence[Any],
    epoch_0: int,
    window_seconds: int,
) -> AttackHorizonResult:
    """Construct deterministic abstained result."""
    evidence_chain = []
    for idx, pt in enumerate(forecasts, start=1):
        h = int(_extract_forecast_field(pt, "horizon", idx))
        pt_epoch = epoch_0 + (h * window_seconds)
        pt_iso = epoch_to_iso(pt_epoch)
        evidence_chain.append(
            HorizonEvidence(
                horizon=h,
                horizon_seconds=h * window_seconds,
                predicted_timestamp=pt_iso,
                attack_probability=None,
                confidence=None,
                predicted_stage=None,
                above_threshold=False,
                abstained=True,
                reason=reason,
            ).to_dict()
        )

    return AttackHorizonResult(
        state=AttackHorizonState.ABSTAINED,
        onset_horizon=None,
        onset_timestamp=None,
        lead_time_seconds=None,
        horizon_windows=0,
        horizon_seconds=0,
        end_horizon=None,
        end_timestamp=None,
        decision_threshold=decision_threshold,
        temporal_consistency=0.0,
        decay_observed=False,
        confidence_summary=ConfidenceSummary(
            mean_confidence=None,
            min_confidence=None,
            max_confidence=None,
            calibration_status=calibration_status,
        ).to_dict(),
        evidence_chain=evidence_chain,
        abstention_reason=reason,
        summary=f"Attack horizon evaluation abstained: {reason}.",
    )
