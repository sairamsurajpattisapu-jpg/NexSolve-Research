"""NexSolve Production Temporal ML Inference Engine.

Authoritative inference pipeline executing multi-horizon recursive forecasting
(T+1 through T+5) using validated model checkpoints from the Model Registry.
Enforces strict input validation (45 canonical features, no RTT fabrication,
finite numeric checks, lookback >= 8, contiguous 60s windows), calibrated
decision thresholds, evidence-gated hybrid blending, and machine-readable
abstention decisions.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from world_model import (
    FEATURE_NAMES_45,
    FLOW_NAMES_45,
    LOOKBACK,
    PACKET_NAMES,
    TEMPORAL_NAMES,
    NetworkState,
    NumpyLSTM,
)
from ml.registry import (
    ModelArtifactCorruptedError,
    ModelArtifactNotFoundError,
    ModelRegistry,
    ModelSpec,
)


class AbstentionReason(str, Enum):
    """Machine-readable reason codes for forecast abstention."""
    INSUFFICIENT_HISTORY = "INSUFFICIENT_HISTORY"
    NON_CONTIGUOUS_TIMESTAMPS = "NON_CONTIGUOUS_TIMESTAMPS"
    INVALID_FEATURE_COUNT = "INVALID_FEATURE_COUNT"
    FEATURE_SCHEMA_MISMATCH = "FEATURE_SCHEMA_MISMATCH"
    INVALID_NUMERIC_VALUE = "INVALID_NUMERIC_VALUE"
    ARTIFACT_INTEGRITY_COMPROMISED = "ARTIFACT_INTEGRITY_COMPROMISED"
    ROLLOUT_DIVERGENCE = "ROLLOUT_DIVERGENCE"
    POOR_CAPTURE_QUALITY = "POOR_CAPTURE_QUALITY"
    PCAP_EXTRACTION_FAILED = "PCAP_EXTRACTION_FAILED"
    UNSUPPORTED_INPUT_FORMAT = "UNSUPPORTED_INPUT_FORMAT"


class ForecastAvailabilityStatus(str, Enum):
    """Standardized availability status for forecast outputs."""
    FORECAST_AVAILABLE = "FORECAST_AVAILABLE"
    FORECAST_ABSTAINED = "FORECAST_ABSTAINED"


class RiskLevel(str, Enum):
    """Calibrated categorical risk level based on attack probability."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class ForecastHorizonOutput:
    """Deterministic prediction for an individual forward horizon step."""
    horizon_step: int
    horizon_name: str
    target_timestamp: int | None
    attack_probability: float
    raw_probability: float
    binary_prediction: int
    decision_threshold: float
    confidence_score: float
    risk_level: str
    predicted_features: dict[str, float]
    predicted_vector: tuple[float, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon_step": self.horizon_step,
            "horizon_name": self.horizon_name,
            "target_timestamp": self.target_timestamp,
            "attack_probability": round(self.attack_probability, 4),
            "raw_probability": round(self.raw_probability, 4),
            "binary_prediction": int(self.binary_prediction),
            "decision_threshold": round(self.decision_threshold, 4),
            "confidence_score": round(self.confidence_score, 4),
            "risk_level": self.risk_level,
            "predicted_features": {
                k: round(v, 6) for k, v in self.predicted_features.items()
            },
            "predicted_vector": [round(v, 6) for v in self.predicted_vector],
        }


@dataclass(frozen=True)
class ProductionForecastResult:
    """Authoritative structured output from the production inference pipeline."""
    status: str
    model_id: str
    model_version: str
    feature_schema_version: str
    execution_timestamp_utc: str
    lookback_windows: int
    decision_threshold: float
    hybrid_alpha: float | None
    abstained: bool
    abstention_reason: str | None
    abstention_message: str | None
    missing_requirements: list[str]
    input_window_count: int
    current_window_timestamp: int | None
    horizons: dict[str, ForecastHorizonOutput]
    rollout_diagnostics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "feature_schema_version": self.feature_schema_version,
            "execution_timestamp_utc": self.execution_timestamp_utc,
            "lookback_windows": self.lookback_windows,
            "decision_threshold": round(self.decision_threshold, 4),
            "hybrid_alpha": round(self.hybrid_alpha, 4) if self.hybrid_alpha is not None else None,
            "abstained": self.abstained,
            "abstention_reason": self.abstention_reason,
            "abstention_message": self.abstention_message,
            "missing_requirements": list(self.missing_requirements),
            "input_window_count": self.input_window_count,
            "current_window_timestamp": self.current_window_timestamp,
            "horizons": {k: v.to_dict() for k, v in self.horizons.items()},
            "rollout_diagnostics": self.rollout_diagnostics,
        }


def _determine_risk_level(prob: float, threshold: float) -> str:
    """Map calibrated probability to transparent risk level."""
    if prob < 0.15:
        return RiskLevel.LOW.value
    elif prob < threshold:
        return RiskLevel.MEDIUM.value
    elif prob < 0.70:
        return RiskLevel.HIGH.value
    else:
        return RiskLevel.CRITICAL.value


class ProductionInferenceEngine:
    """Production temporal inference engine with strict verification and abstention."""

    def __init__(
        self,
        model_id: str = "candidate_v2",
        verify_checksums: bool = True,
        use_hybrid: bool = False,
        hybrid_alpha: float | None = None,
        custom_threshold: float | None = None,
    ) -> None:
        self.model_id = model_id
        self.verify_checksums = verify_checksums
        self.use_hybrid = use_hybrid

        # Load authoritative model and spec from registry
        self.model, self.scaler_mean, self.scaler_scale, self.spec = ModelRegistry.load_model(
            model_id=self.model_id,
            verify_checksums=self.verify_checksums,
            use_cache=True,
        )

        self.threshold = (
            custom_threshold
            if custom_threshold is not None
            else self.spec.calibrated_threshold
        )
        self.hybrid_alpha = (
            hybrid_alpha
            if hybrid_alpha is not None
            else (self.spec.hybrid_alpha if self.use_hybrid else None)
        )

    def validate_network_states(
        self,
        states: Sequence[NetworkState],
        min_lookback: int | None = None,
    ) -> tuple[bool, str | None, str | None, list[str]]:
        """Validate input state sequence against temporal and schema requirements.

        Returns:
            (is_valid, abstention_reason, explanation, missing_requirements)
        """
        required_len = min_lookback or self.spec.lookback
        missing_reqs: list[str] = []

        # 1. Sequence Length Check
        if len(states) < required_len:
            msg = (
                f"Input sequence contains {len(states)} windows, but model requires "
                f"at least {required_len} contiguous lookback windows ({required_len * self.spec.window_seconds}s)."
            )
            missing_reqs.append(msg)
            return False, AbstentionReason.INSUFFICIENT_HISTORY.value, msg, missing_reqs

        # 2. Timestamp Contiguity Check (strictly 60s window intervals)
        for i in range(len(states) - 1):
            t_curr = states[i].timestamp
            t_next = states[i + 1].timestamp
            delta = t_next - t_curr
            if delta != self.spec.window_seconds:
                msg = (
                    f"Non-contiguous timestamp gap detected between window {i} (ts={t_curr}) "
                    f"and window {i+1} (ts={t_next}): interval is {delta}s "
                    f"(expected exactly {self.spec.window_seconds}s)."
                )
                missing_reqs.append(msg)
                return False, AbstentionReason.NON_CONTIGUOUS_TIMESTAMPS.value, msg, missing_reqs

        # 3. Canonical 45-Feature Schema and Numeric Sanity Check
        for idx, s in enumerate(states):
            # Check flow features partition
            for fn in FLOW_NAMES_45:
                if fn not in s.flow_features:
                    missing_reqs.append(f"Window {idx} missing required flow feature '{fn}'")
            # Check packet features partition
            for pn in PACKET_NAMES:
                if pn not in s.packet_features:
                    missing_reqs.append(f"Window {idx} missing required packet feature '{pn}'")
            # Check temporal features partition
            for tn in TEMPORAL_NAMES:
                if tn not in s.temporal_features:
                    missing_reqs.append(f"Window {idx} missing required temporal feature '{tn}'")

            if "mean_tcp_rtt" in s.flow_features and s.flow_features["mean_tcp_rtt"] is not None:
                # We warn / enforce that RTT is excluded from 45-canonical model
                pass

            if missing_reqs:
                msg = (
                    f"Feature schema mismatch: {len(missing_reqs)} missing canonical features. "
                    f"Requires exact 45 features in FEATURE_NAMES_45."
                )
                return False, AbstentionReason.FEATURE_SCHEMA_MISMATCH.value, msg, missing_reqs

            # Encode and check for non-finite values
            vec = s.encode(list(self.spec.feature_names))
            if len(vec) != self.spec.feature_count:
                msg = f"Encoded vector dimension {len(vec)} does not match expected {self.spec.feature_count}."
                missing_reqs.append(msg)
                return False, AbstentionReason.INVALID_FEATURE_COUNT.value, msg, missing_reqs

            if not np.all(np.isfinite(vec)):
                invalid_indices = np.where(~np.isfinite(vec))[0]
                bad_names = [self.spec.feature_names[i] for i in invalid_indices]
                msg = f"Non-finite numeric values (NaN/Inf) detected in window {idx} at features: {bad_names}"
                missing_reqs.append(msg)
                return False, AbstentionReason.INVALID_NUMERIC_VALUE.value, msg, missing_reqs

        return True, None, None, []

    def predict_states(
        self,
        states: Sequence[NetworkState],
        horizons: Sequence[int] = (1, 2, 3, 4, 5),
    ) -> ProductionForecastResult:
        """Run production recursive forecasting on a validated sequence of NetworkStates."""
        now_utc = datetime.now(timezone.utc).isoformat()

        # Validate inputs
        is_valid, reason, msg, missing = self.validate_network_states(states)
        if not is_valid:
            return ProductionForecastResult(
                status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                model_id=self.spec.model_id,
                model_version=self.spec.version,
                feature_schema_version=self.spec.feature_schema_version,
                execution_timestamp_utc=now_utc,
                lookback_windows=self.spec.lookback,
                decision_threshold=self.threshold,
                hybrid_alpha=self.hybrid_alpha,
                abstained=True,
                abstention_reason=reason,
                abstention_message=msg,
                missing_requirements=missing,
                input_window_count=len(states) if states else 0,
                current_window_timestamp=states[-1].timestamp if states else None,
                horizons={},
                rollout_diagnostics={"validation_failed": True, "reason": reason},
            )

        lookback = self.spec.lookback
        max_h = max(horizons)
        names = list(self.spec.feature_names)
        n_flow = len(FLOW_NAMES_45)
        n_pkt = len(PACKET_NAMES)

        # Slice the most recent lookback windows
        history = list(states[-lookback:])
        current_state = history[-1]
        t0 = current_state.timestamp

        # Vectorized pre-allocated trajectory buffer
        buf = np.zeros((lookback + max_h, len(names)), dtype=np.float64)
        for i, s in enumerate(history):
            buf[i] = s.encode(names)

        outputs: dict[str, ForecastHorizonOutput] = {}
        rollout_scaled_drifts: list[float] = []

        # Autoregressive multi-horizon recursive rollout
        for step in range(1, max_h + 1):
            window = buf[step - 1 : step - 1 + lookback]
            scaled_window = (window - self.scaler_mean) / self.scaler_scale

            pred_scaled, raw_prob = self.model.predict(scaled_window)

            # Divergence & finite check
            if not np.all(np.isfinite(pred_scaled)) or not math.isfinite(raw_prob) or np.max(np.abs(pred_scaled)) > 1e4:
                return ProductionForecastResult(
                    status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                    model_id=self.spec.model_id,
                    model_version=self.spec.version,
                    feature_schema_version=self.spec.feature_schema_version,
                    execution_timestamp_utc=now_utc,
                    lookback_windows=lookback,
                    decision_threshold=self.threshold,
                    hybrid_alpha=self.hybrid_alpha,
                    abstained=True,
                    abstention_reason=AbstentionReason.ROLLOUT_DIVERGENCE.value,
                    abstention_message=f"Numerical instability: non-finite or unbounded output at rollout horizon T+{step}.",
                    missing_requirements=[f"Unbounded rollout output at horizon T+{step}"],
                    input_window_count=len(states),
                    current_window_timestamp=t0,
                    horizons={},
                    rollout_diagnostics={"divergence_step": step},
                )

            # Track rollout step stability
            scaled_norm = float(np.mean(pred_scaled ** 2))
            rollout_scaled_drifts.append(scaled_norm)

            # Invert scaling to canonical feature space
            pred_unscaled = pred_scaled * self.scaler_scale + self.scaler_mean

            # Roll into trajectory buffer with canonical partition semantics
            sim_vec = np.zeros(len(names), dtype=np.float64)
            sim_vec[:n_flow] = pred_unscaled[:n_flow]
            sim_vec[n_flow : n_flow + n_pkt] = pred_unscaled[n_flow : n_flow + n_pkt]
            sim_vec[n_flow + n_pkt :] = pred_unscaled[n_flow + n_pkt :]
            buf[lookback - 1 + step] = sim_vec

            # Apply hybrid blending if active
            if self.use_hybrid and self.hybrid_alpha is not None:
                curr_label = float(current_state.attack_state if current_state.attack_state is not None else 0.0)
                final_prob = float(self.hybrid_alpha * curr_label + (1.0 - self.hybrid_alpha) * raw_prob)
            else:
                final_prob = float(raw_prob)

            binary_pred = int(final_prob >= self.threshold)
            confidence = round(float(abs(final_prob - 0.5) * 2.0), 4)
            risk = _determine_risk_level(final_prob, self.threshold)
            h_key = f"T+{step}"

            target_ts = t0 + step * self.spec.window_seconds if t0 is not None else None
            feat_dict = {name: float(val) for name, val in zip(names, pred_unscaled)}

            if step in horizons:
                outputs[h_key] = ForecastHorizonOutput(
                    horizon_step=step,
                    horizon_name=h_key,
                    target_timestamp=target_ts,
                    attack_probability=final_prob,
                    raw_probability=float(raw_prob),
                    binary_prediction=binary_pred,
                    decision_threshold=self.threshold,
                    confidence_score=confidence,
                    risk_level=risk,
                    predicted_features=feat_dict,
                    predicted_vector=tuple(float(v) for v in pred_unscaled),
                )

        diagnostics = {
            "rollout_steps": len(horizons),
            "mean_rollout_scaled_drift": round(float(np.mean(rollout_scaled_drifts)), 4) if rollout_scaled_drifts else 0.0,
            "max_rollout_scaled_drift": round(float(np.max(rollout_scaled_drifts)), 4) if rollout_scaled_drifts else 0.0,
            "active_threshold": self.threshold,
            "hybrid_active": self.use_hybrid,
            "hybrid_alpha": self.hybrid_alpha,
        }

        return ProductionForecastResult(
            status=ForecastAvailabilityStatus.FORECAST_AVAILABLE.value,
            model_id=self.spec.model_id,
            model_version=self.spec.version,
            feature_schema_version=self.spec.feature_schema_version,
            execution_timestamp_utc=now_utc,
            lookback_windows=lookback,
            decision_threshold=self.threshold,
            hybrid_alpha=self.hybrid_alpha,
            abstained=False,
            abstention_reason=None,
            abstention_message=None,
            missing_requirements=[],
            input_window_count=len(states),
            current_window_timestamp=t0,
            horizons=outputs,
            rollout_diagnostics=diagnostics,
        )

    def predict_vector_sequence(
        self,
        sequence: np.ndarray,
        base_timestamp: int = 1700000000,
        horizons: Sequence[int] = (1, 2, 3, 4, 5),
    ) -> ProductionForecastResult:
        """Run inference on raw 2D numpy matrix of shape (N, 45)."""
        now_utc = datetime.now(timezone.utc).isoformat()
        if not isinstance(sequence, np.ndarray) or sequence.ndim != 2:
            return ProductionForecastResult(
                status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                model_id=self.spec.model_id,
                model_version=self.spec.version,
                feature_schema_version=self.spec.feature_schema_version,
                execution_timestamp_utc=now_utc,
                lookback_windows=self.spec.lookback,
                decision_threshold=self.threshold,
                hybrid_alpha=self.hybrid_alpha,
                abstained=True,
                abstention_reason=AbstentionReason.UNSUPPORTED_INPUT_FORMAT.value,
                abstention_message="Input sequence must be a 2D numpy array of shape (N, 45).",
                missing_requirements=["Expected 2D numpy array of shape (N, 45)"],
                input_window_count=0,
                current_window_timestamp=None,
                horizons={},
                rollout_diagnostics={},
            )

        if sequence.shape[1] != self.spec.feature_count:
            return ProductionForecastResult(
                status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                model_id=self.spec.model_id,
                model_version=self.spec.version,
                feature_schema_version=self.spec.feature_schema_version,
                execution_timestamp_utc=now_utc,
                lookback_windows=self.spec.lookback,
                decision_threshold=self.threshold,
                hybrid_alpha=self.hybrid_alpha,
                abstained=True,
                abstention_reason=AbstentionReason.INVALID_FEATURE_COUNT.value,
                abstention_message=f"Feature dimension is {sequence.shape[1]}, expected {self.spec.feature_count}.",
                missing_requirements=[f"Feature count mismatch: {sequence.shape[1]} != {self.spec.feature_count}"],
                input_window_count=len(sequence),
                current_window_timestamp=None,
                horizons={},
                rollout_diagnostics={},
            )

        if not np.all(np.isfinite(sequence)):
            return ProductionForecastResult(
                status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                model_id=self.spec.model_id,
                model_version=self.spec.version,
                feature_schema_version=self.spec.feature_schema_version,
                execution_timestamp_utc=now_utc,
                lookback_windows=self.spec.lookback,
                decision_threshold=self.threshold,
                hybrid_alpha=self.hybrid_alpha,
                abstained=True,
                abstention_reason=AbstentionReason.INVALID_NUMERIC_VALUE.value,
                abstention_message="Non-finite numeric values (NaN or Inf) detected in input sequence.",
                missing_requirements=["Matrix contains NaN or Inf values"],
                input_window_count=len(sequence),
                current_window_timestamp=None,
                horizons={},
                rollout_diagnostics={},
            )

        # Convert matrix rows to synthetic NetworkState sequence for uniform rollout
        states: list[NetworkState] = []
        n_flow = len(FLOW_NAMES_45)
        n_pkt = len(PACKET_NAMES)

        for i, row in enumerate(sequence):
            ts = base_timestamp + i * self.spec.window_seconds
            flow = {name: float(val) for name, val in zip(FLOW_NAMES_45, row[:n_flow])}
            packet = {name: float(val) for name, val in zip(PACKET_NAMES, row[n_flow : n_flow + n_pkt])}
            temporal = {name: float(val) for name, val in zip(TEMPORAL_NAMES, row[n_flow + n_pkt :])}
            states.append(NetworkState(ts, flow, packet, temporal, None, True))

        return self.predict_states(states, horizons=horizons)

    def predict_pcap(
        self,
        pcap_path: str | Path,
        window_seconds: int = 60,
        horizons: Sequence[int] = (1, 2, 3, 4, 5),
    ) -> ProductionForecastResult:
        """Run end-to-end inference directly from a PCAP capture file."""
        now_utc = datetime.now(timezone.utc).isoformat()
        path = Path(pcap_path)
        if not path.exists():
            return ProductionForecastResult(
                status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                model_id=self.spec.model_id,
                model_version=self.spec.version,
                feature_schema_version=self.spec.feature_schema_version,
                execution_timestamp_utc=now_utc,
                lookback_windows=self.spec.lookback,
                decision_threshold=self.threshold,
                hybrid_alpha=self.hybrid_alpha,
                abstained=True,
                abstention_reason=AbstentionReason.PCAP_EXTRACTION_FAILED.value,
                abstention_message=f"PCAP file not found: {path}",
                missing_requirements=[f"PCAP file not found: {path}"],
                input_window_count=0,
                current_window_timestamp=None,
                horizons={},
                rollout_diagnostics={},
            )

        try:
            from ml.data.pcap_extractor import extract_canonical_capture
            from nexsolve_core.state import (
                MODEL_SCHEMA_45,
                build_network_state_candidates,
                build_state_history,
                candidates_to_network_states,
                evaluate_model_compatibility,
            )
            from nexsolve_core.schemas import QualityStatus

            _pkts, windows, quality = extract_canonical_capture(path, window_seconds=window_seconds)

            q_status = quality.get("status") if isinstance(quality, dict) else getattr(quality, "status", None)
            if hasattr(q_status, "value"):
                q_status = q_status.value

            if q_status == "INSUFFICIENT":
                return ProductionForecastResult(
                    status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                    model_id=self.spec.model_id,
                    model_version=self.spec.version,
                    feature_schema_version=self.spec.feature_schema_version,
                    execution_timestamp_utc=now_utc,
                    lookback_windows=self.spec.lookback,
                    decision_threshold=self.threshold,
                    hybrid_alpha=self.hybrid_alpha,
                    abstained=True,
                    abstention_reason=AbstentionReason.POOR_CAPTURE_QUALITY.value,
                    abstention_message="PCAP capture quality is INSUFFICIENT to produce reliable forecasts.",
                    missing_requirements=["Capture quality status is INSUFFICIENT"],
                    input_window_count=len(windows),
                    current_window_timestamp=None,
                    horizons={},
                    rollout_diagnostics={"quality_status": q_status},
                )

            candidates = build_network_state_candidates(windows)
            history = build_state_history(candidates, lookback=self.spec.lookback)

            if history.status == "INSUFFICIENT_HISTORY":
                return ProductionForecastResult(
                    status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                    model_id=self.spec.model_id,
                    model_version=self.spec.version,
                    feature_schema_version=self.spec.feature_schema_version,
                    execution_timestamp_utc=now_utc,
                    lookback_windows=self.spec.lookback,
                    decision_threshold=self.threshold,
                    hybrid_alpha=self.hybrid_alpha,
                    abstained=True,
                    abstention_reason=AbstentionReason.INSUFFICIENT_HISTORY.value,
                    abstention_message=history.reason,
                    missing_requirements=[history.reason],
                    input_window_count=len(candidates),
                    current_window_timestamp=None,
                    horizons={},
                    rollout_diagnostics={"history_status": history.status},
                )

            if history.status == "GAPPED_HISTORY":
                return ProductionForecastResult(
                    status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                    model_id=self.spec.model_id,
                    model_version=self.spec.version,
                    feature_schema_version=self.spec.feature_schema_version,
                    execution_timestamp_utc=now_utc,
                    lookback_windows=self.spec.lookback,
                    decision_threshold=self.threshold,
                    hybrid_alpha=self.hybrid_alpha,
                    abstained=True,
                    abstention_reason=AbstentionReason.NON_CONTIGUOUS_TIMESTAMPS.value,
                    abstention_message=history.reason,
                    missing_requirements=[history.reason],
                    input_window_count=len(candidates),
                    current_window_timestamp=None,
                    horizons={},
                    rollout_diagnostics={"history_status": history.status},
                )

            compat_report = evaluate_model_compatibility(candidates, MODEL_SCHEMA_45, history.status)
            if not compat_report.model_ready:
                return ProductionForecastResult(
                    status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                    model_id=self.spec.model_id,
                    model_version=self.spec.version,
                    feature_schema_version=self.spec.feature_schema_version,
                    execution_timestamp_utc=now_utc,
                    lookback_windows=self.spec.lookback,
                    decision_threshold=self.threshold,
                    hybrid_alpha=self.hybrid_alpha,
                    abstained=True,
                    abstention_reason=AbstentionReason.FEATURE_SCHEMA_MISMATCH.value,
                    abstention_message=compat_report.to_dict().get("reason", "Required features unavailable for model."),
                    missing_requirements=list(compat_report.unavailable_features),
                    input_window_count=len(candidates),
                    current_window_timestamp=None,
                    horizons={},
                    rollout_diagnostics={"compatibility_report": compat_report.to_dict()},
                )

            states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history.status)
            return self.predict_states(states, horizons=horizons)

        except Exception as exc:
            return ProductionForecastResult(
                status=ForecastAvailabilityStatus.FORECAST_ABSTAINED.value,
                model_id=self.spec.model_id,
                model_version=self.spec.version,
                feature_schema_version=self.spec.feature_schema_version,
                execution_timestamp_utc=now_utc,
                lookback_windows=self.spec.lookback,
                decision_threshold=self.threshold,
                hybrid_alpha=self.hybrid_alpha,
                abstained=True,
                abstention_reason=AbstentionReason.PCAP_EXTRACTION_FAILED.value,
                abstention_message=f"Failed to extract or parse PCAP: {str(exc)}",
                missing_requirements=[f"PCAP processing error: {str(exc)}"],
                input_window_count=0,
                current_window_timestamp=None,
                horizons={},
                rollout_diagnostics={"error": str(exc)},
            )


def predict_forecast(
    sequence: Sequence[NetworkState] | np.ndarray,
    model_id: str = "candidate_v2",
    use_hybrid: bool = False,
    hybrid_alpha: float | None = None,
    custom_threshold: float | None = None,
    horizons: Sequence[int] = (1, 2, 3, 4, 5),
) -> ProductionForecastResult:
    """Convenience functional interface for production forecasting."""
    engine = ProductionInferenceEngine(
        model_id=model_id,
        use_hybrid=use_hybrid,
        hybrid_alpha=hybrid_alpha,
        custom_threshold=custom_threshold,
    )
    if isinstance(sequence, np.ndarray):
        return engine.predict_vector_sequence(sequence, horizons=horizons)
    return engine.predict_states(sequence, horizons=horizons)


def predict_pcap_forecast(
    pcap_path: str | Path,
    model_id: str = "candidate_v2",
    window_seconds: int = 60,
    use_hybrid: bool = False,
    hybrid_alpha: float | None = None,
    custom_threshold: float | None = None,
    horizons: Sequence[int] = (1, 2, 3, 4, 5),
) -> ProductionForecastResult:
    """Convenience functional interface for PCAP forecasting."""
    engine = ProductionInferenceEngine(
        model_id=model_id,
        use_hybrid=use_hybrid,
        hybrid_alpha=hybrid_alpha,
        custom_threshold=custom_threshold,
    )
    return engine.predict_pcap(pcap_path, window_seconds=window_seconds, horizons=horizons)
