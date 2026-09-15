r"""Comprehensive Production Multi-Horizon Forecasting Engine.

Implements the unified forecasting pipeline:
1. Multi-Horizon Autoregressive Rollout (H in {1, 2, 3, 5, 10})
2. Separation of P(Attack at T+H) and Cumulative Infiltration Risk:
   Risk(H) = 1 - \prod_{h=1}^H (1 - p_h)
3. Transparent Risk Levels: LOW, MEDIUM, HIGH, CRITICAL with UNCALIBRATED probability disclosure
4. Deep Behavioral Attack Progression & MITRE mapping grounded in predicted state dynamics
5. Mathematical Early Warning Score (0-100) combining current probability, cumulative risk,
   trajectory acceleration, persistence divergence, and progression severity
6. Rich Driver Explainability: Top 5 drivers per horizon with current vs predicted values,
   relative change, direction, and domain interpretation
7. Safe Model Fallback when history is insufficient or model is unavailable.
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
    PACKET_NAMES,
    TEMPORAL_NAMES,
    NetworkState,
    NumpyLSTM,
    load_model,
)

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL_DIR = ROOT / "models" / "nexsolve_world_model_45"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EarlyWarningLevel(str, Enum):
    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class FeatureDriver:
    feature: str
    current_value: float
    predicted_value: float
    direction: str  # "increasing", "decreasing", "stable"
    relative_change: float
    importance: str  # "HIGH", "MEDIUM", "LOW"
    interpretation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ProgressionFinding:
    stage: str
    mitre_techniques: list[str]
    horizon: str
    evidence: list[str]
    supporting_features: list[str]
    confidence_status: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class HorizonForecastPoint:
    horizon: int
    lookahead_seconds: int
    predicted_timestamp: str
    predicted_state: dict[str, float]
    attack_probability: float | None
    cumulative_risk: float | None
    risk_level: RiskLevel
    probability_status: str
    confidence: float | None
    uncertainty: float | None
    predicted_stage: str
    top_drivers: list[FeatureDriver]
    behavioral_interpretation: str

    def to_dict(self) -> dict[str, Any]:
        res = asdict(self)
        res["risk_level"] = self.risk_level.value
        res["top_drivers"] = [d.to_dict() for d in self.top_drivers]
        return res


@dataclass(frozen=True)
class EarlyWarningAssessment:
    early_warning_score: int  # 0 - 100
    early_warning_level: EarlyWarningLevel
    drivers: list[str]
    score_components: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return {
            "early_warning_score": self.early_warning_score,
            "early_warning_level": self.early_warning_level.value,
            "drivers": self.drivers,
            "score_components": self.score_components,
        }


@dataclass(frozen=True)
class ForecastTrajectoryResult:
    origin_timestamp: str
    lookback_windows: int
    supported_horizons: list[int]
    forecast_status: str
    current_state: dict[str, Any]
    forecasts: list[HorizonForecastPoint]
    progression: list[ProgressionFinding]
    mitre_mapping: dict[str, str]
    early_warning: EarlyWarningAssessment
    is_fallback: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin_timestamp": self.origin_timestamp,
            "lookback_windows": self.lookback_windows,
            "supported_horizons": self.supported_horizons,
            "forecast_status": self.forecast_status,
            "current_state": self.current_state,
            "forecasts": [f.to_dict() for f in self.forecasts],
            "progression": [p.to_dict() for p in self.progression],
            "mitre_mapping": self.mitre_mapping,
            "early_warning": self.early_warning.to_dict(),
            "is_fallback": self.is_fallback,
        }


def _determine_risk_level(prob: float | None) -> RiskLevel:
    if prob is None:
        return RiskLevel.LOW
    if prob >= 0.75:
        return RiskLevel.CRITICAL
    if prob >= 0.50:
        return RiskLevel.HIGH
    if prob >= 0.25:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _explain_feature_change(feature: str, curr: float, pred: float) -> tuple[str, float, str, str]:
    delta = pred - curr
    rel = delta / max(abs(curr), 1e-4)
    if abs(rel) < 0.05:
        direction = "stable"
    elif rel > 0:
        direction = "increasing"
    else:
        direction = "decreasing"

    importance = "HIGH" if abs(rel) > 0.5 else "MEDIUM" if abs(rel) > 0.15 else "LOW"

    # Domain interpretations grounded in network telemetry semantics
    if "port" in feature:
        interp = f"Port cardinality {direction} ({curr:.0f} -> {pred:.0f}) indicates {'broad scanning or service discovery activity' if direction == 'increasing' else 'consolidation of traffic to specific target services'}."
    elif "byte" in feature or "packet" in feature:
        interp = f"Volumetric flow {direction} ({curr:.1f} -> {pred:.1f}) represents {'traffic surge or data movement pressure' if direction == 'increasing' else 'traffic attenuation'}."
    elif "iat" in feature:
        interp = f"Inter-arrival time {direction} ({curr:.2f}s -> {pred:.2f}s) indicates {'irregular pacing or command-and-control interval changes' if direction == 'increasing' else 'rapid automated transmission burst'}."
    elif "syn" in feature or "rst" in feature:
        interp = f"TCP flag pressure {direction} ({curr:.0f} -> {pred:.0f}) reflects {'connection exhaustion attempts or failed handshakes' if direction == 'increasing' else 'normalizing connection tear-downs'}."
    elif "swin" in feature or "dwin" in feature:
        interp = f"TCP window dynamics {direction} ({curr:.0f} -> {pred:.0f}) reflects {'client/server buffer modulation or exfiltration flow adjustments' if direction == 'increasing' else 'window shrinking or transmission constraints'}."
    else:
        interp = f"Feature '{feature}' {direction} by {abs(rel)*100:.1f}% relative to current state."

    return direction, rel, importance, interp


class ForecastingPipeline:
    """Production Multi-Horizon World Model Forecasting Engine."""

    def __init__(self, model_dir: Path | None = None):
        self.model_dir = Path(model_dir or DEFAULT_MODEL_DIR)
        self.feature_names = FEATURE_NAMES_45
        self._model: NumpyLSTM | None = None
        self._mean: np.ndarray | None = None
        self._scale: np.ndarray | None = None

        if self.model_dir.exists() and (self.model_dir / "model.npz").exists():
            try:
                self._model, self._mean, self._scale = load_model(self.model_dir)
            except Exception:
                self._model = None

    @property
    def is_available(self) -> bool:
        return self._model is not None and self._mean is not None and self._scale is not None

    def execute_forecast(
        self,
        history: Sequence[NetworkState],
        horizons: Sequence[int] = (1, 2, 3, 5, 10),
    ) -> ForecastTrajectoryResult:
        """Runs multi-step forecasting with explicit fallback guardrails."""
        if not history:
            return self._build_empty_fallback(0)

        current_s = history[-1]
        origin_ts = datetime.fromtimestamp(current_s.timestamp, timezone.utc).isoformat()
        lookback_count = len(history)

        # Insufficient history guardrail: minimum 8 windows required
        if lookback_count < 8:
            return self._build_insufficient_history_fallback(current_s, lookback_count, list(horizons))

        if self._model is None or self._mean is None or self._scale is None:
            return self._build_model_unavailable_fallback(current_s, lookback_count, list(horizons))

        # 1. Rollout inference
        max_h = max(horizons)
        rolling_states = list(history[-8:])
        simulated_states: dict[int, dict[str, float]] = {}
        step_probabilities: dict[int, float] = {}

        flow_names = [n for n in self.feature_names if n in set(FLOW_NAMES_45)]
        packet_names = [n for n in self.feature_names if n in set(PACKET_NAMES)]
        temporal_names = [n for n in self.feature_names if n in set(TEMPORAL_NAMES)]

        for step in range(1, max_h + 1):
            matrix = np.asarray([s.encode(self.feature_names) for s in rolling_states[-8:]])
            scaled = (matrix - self._mean) / self._scale
            pred_scaled, prob = self._model.predict(scaled)
            pred_vector = pred_scaled * self._scale + self._mean
            pred_dict = {name: float(val) for name, val in zip(self.feature_names, pred_vector)}

            simulated_states[step] = pred_dict
            step_probabilities[step] = float(prob)

            # Roll prediction forward without future ground truth
            sim_state = NetworkState(
                current_s.timestamp + step * 60,
                {n: pred_dict.get(n, 0.0) for n in flow_names},
                {n: pred_dict.get(n, 0.0) for n in packet_names},
                {n: pred_dict.get(n, 0.0) for n in temporal_names},
                int(prob >= 0.5),
                current_s.packet_features_available,
            )
            rolling_states.append(sim_state)

        # 2. Build horizon points with cumulative risk
        forecast_points: list[HorizonForecastPoint] = []
        cum_survival = 1.0
        current_encoded = current_s.encode(self.feature_names)
        current_dict = {name: float(val) for name, val in zip(self.feature_names, current_encoded)}

        # Evaluate drivers against current state
        for h in horizons:
            prob_h = step_probabilities.get(h, 0.0)
            # Cumulative risk: 1 - \prod_{step=1}^h (1 - p_step)
            h_probs = [step_probabilities.get(s, 0.0) for s in range(1, h + 1)]
            cum_risk = float(1.0 - np.prod([1.0 - p for p in h_probs]))

            pred_state_h = simulated_states.get(h, {})
            risk_level = _determine_risk_level(cum_risk)

            # Feature driver ranking for horizon h
            feat_deltas = []
            for name in self.feature_names:
                c_val = current_dict.get(name, 0.0)
                p_val = pred_state_h.get(name, 0.0)
                direction, rel, importance, interp = _explain_feature_change(name, c_val, p_val)
                feat_deltas.append(FeatureDriver(
                    feature=name,
                    current_value=round(c_val, 4),
                    predicted_value=round(p_val, 4),
                    direction=direction,
                    relative_change=round(rel, 4),
                    importance=importance,
                    interpretation=interp,
                ))

            # Rank top 5 drivers by absolute relative change
            top_drivers = sorted(feat_deltas, key=lambda d: abs(d.relative_change), reverse=True)[:5]

            # Behavioral stage determination
            pred_stage = self._infer_stage_from_state(pred_state_h, prob_h)
            h_ts = datetime.fromtimestamp(current_s.timestamp + h * 60, timezone.utc).isoformat()
            interp_summary = f"At T+{h} (+{h*60}s), forecasted attack risk is {prob_h*100:.1f}%, with cumulative multi-window threat risk of {cum_risk*100:.1f}%."

            forecast_points.append(HorizonForecastPoint(
                horizon=h,
                lookahead_seconds=h * 60,
                predicted_timestamp=h_ts,
                predicted_state=pred_state_h,
                attack_probability=round(prob_h, 4),
                cumulative_risk=round(cum_risk, 4),
                risk_level=risk_level,
                probability_status="UNCALIBRATED",
                confidence=round(float(abs(prob_h - 0.5) * 2), 4),
                uncertainty=round(float(1.0 - abs(prob_h - 0.5) * 2), 4),
                predicted_stage=pred_stage,
                top_drivers=top_drivers,
                behavioral_interpretation=interp_summary,
            ))

        # 3. Progression Analysis across predicted trajectory
        progression_findings = self._analyze_progression_trajectory(simulated_states, step_probabilities, horizons)

        # 4. Early Warning Score (0-100)
        early_warning = self._compute_early_warning_score(current_s, simulated_states, step_probabilities, horizons)

        mitre_map = {
            "RECONNAISSANCE": "T1046: Network Service Discovery",
            "COMMAND_AND_CONTROL": "T1071: Application Layer Protocol",
            "EXPLOITATION": "T1190: Exploit Public-Facing Application",
            "DENIAL_OF_SERVICE": "T1498: Network Denial of Service",
            "STABLE_BENIGN": "N/A: Normal Traffic Equilibrium",
        }

        return ForecastTrajectoryResult(
            origin_timestamp=origin_ts,
            lookback_windows=lookback_count,
            supported_horizons=list(horizons),
            forecast_status="SUCCESSFUL_ROLLOUT",
            current_state={
                "timestamp": origin_ts,
                "flow_count": current_s.flow_features.get("flow_count", 0.0),
                "total_packets": current_s.flow_features.get("total_packets", 0.0),
                "total_bytes": current_s.flow_features.get("total_src_bytes", 0.0) + current_s.flow_features.get("total_dst_bytes", 0.0),
                "unique_dst_ports": current_s.flow_features.get("unique_dst_ports", 0.0),
            },
            forecasts=forecast_points,
            progression=progression_findings,
            mitre_mapping=mitre_map,
            early_warning=early_warning,
            is_fallback=False,
        )

    def _infer_stage_from_state(self, state: dict[str, float], prob: float) -> str:
        if prob < 0.40:
            return "STABLE_BENIGN"
        ports = state.get("unique_dst_ports", 0.0)
        udp_count = state.get("proto_udp_count", 0.0)
        tcp_count = state.get("proto_tcp_count", 0.0)
        packets = state.get("total_packets", 1.0)
        syn_count = state.get("tcp_syn_count", 0.0)

        if syn_count > 50 or (packets > 1000 and tcp_count > 0.8 * packets):
            return "DENIAL_OF_SERVICE"
        if ports > 15:
            return "RECONNAISSANCE"
        if state.get("total_dst_bytes", 0.0) > state.get("total_src_bytes", 0.0) * 4:
            return "COMMAND_AND_CONTROL"
        if prob >= 0.70:
            return "EXPLOITATION"
        return "ATTACK_IMMINENT"

    def _analyze_progression_trajectory(
        self,
        simulated_states: dict[int, dict[str, float]],
        step_probs: dict[int, float],
        horizons: Sequence[int],
    ) -> list[ProgressionFinding]:
        findings: list[ProgressionFinding] = []

        # Check for scanning / reconnaissance acceleration
        ports_h1 = simulated_states.get(1, {}).get("unique_dst_ports", 0.0)
        ports_h3 = simulated_states.get(3, {}).get("unique_dst_ports", 0.0)
        if ports_h3 > ports_h1 * 1.5 and ports_h3 >= 10:
            findings.append(ProgressionFinding(
                stage="RECONNAISSANCE",
                mitre_techniques=["T1046"],
                horizon="T+3",
                evidence=[
                    f"Destination port diversity expands from {ports_h1:.0f} to {ports_h3:.0f}",
                    "Flow dispersion across distinct target ports indicates scanning pattern",
                ],
                supporting_features=["unique_dst_ports", "flow_count"],
                confidence_status="BEHAVIORAL_INFERENCE",
            ))

        # Check for volumetric or SYN surge
        packets_h1 = simulated_states.get(1, {}).get("total_packets", 0.0)
        packets_h5 = simulated_states.get(5, {}).get("total_packets", 0.0)
        if packets_h5 > packets_h1 * 2.0 and packets_h5 > 500:
            findings.append(ProgressionFinding(
                stage="DENIAL_OF_SERVICE",
                mitre_techniques=["T1498"],
                horizon="T+5",
                evidence=[
                    f"Packet volume doubles over rollout horizon ({packets_h1:.0f} -> {packets_h5:.0f})",
                    "Volumetric flow surge consistent with flood onset",
                ],
                supporting_features=["total_packets", "delta_total_packets"],
                confidence_status="BEHAVIORAL_INFERENCE",
            ))

        # Check for sustained high threat risk
        high_prob_horizons = [h for h in horizons if step_probs.get(h, 0.0) >= 0.65]
        if len(high_prob_horizons) >= 2:
            findings.append(ProgressionFinding(
                stage="SUSTAINED_ATTACK_PROGRESSION",
                mitre_techniques=["T1190", "T1071"],
                horizon=f"T+{high_prob_horizons[0]}..T+{high_prob_horizons[-1]}",
                evidence=[
                    f"Impending attack probability remains elevated across horizons: {high_prob_horizons}",
                    "Continuous state dynamics diverge from benign equilibrium",
                ],
                supporting_features=["proto_tcp_count", "rolling_total_bytes"],
                confidence_status="BEHAVIORAL_INFERENCE",
            ))

        if not findings:
            findings.append(ProgressionFinding(
                stage="STABLE_BENIGN",
                mitre_techniques=[],
                horizon="T+1..T+5",
                evidence=["Trajectory remains in equilibrium with no anomalous behavioral transitions observed"],
                supporting_features=["flow_count", "total_bytes"],
                confidence_status="BASELINE_EQUILIBRIUM",
            ))

        return findings

    def _compute_early_warning_score(
        self,
        current_s: NetworkState,
        simulated_states: dict[int, dict[str, float]],
        step_probs: dict[int, float],
        horizons: Sequence[int],
    ) -> EarlyWarningAssessment:
        """Computes transparent Early Warning Score (0-100) combining:
        1. Base probability at T+1 (35% weight)
        2. Cumulative 5-window risk (35% weight)
        3. Trajectory acceleration / delta (15% weight)
        4. State dispersion / divergence (15% weight)
        """
        p1 = step_probs.get(1, 0.0)
        h5_probs = [step_probs.get(s, 0.0) for s in range(1, min(6, max(horizons) + 1))]
        cum_5 = float(1.0 - np.prod([1.0 - p for p in h5_probs])) if h5_probs else p1

        # Trajectory acceleration: p(T+3) - p(T+1)
        p3 = step_probs.get(3, p1)
        accel = max(0.0, p3 - p1)

        # State dispersion: relative change in ports or packets
        curr_ports = current_s.flow_features.get("unique_dst_ports", 1.0)
        pred_ports = simulated_states.get(3, {}).get("unique_dst_ports", curr_ports)
        port_growth = max(0.0, min(1.0, (pred_ports - curr_ports) / max(curr_ports, 1.0)))

        c_p1 = p1 * 35.0
        c_cum = cum_5 * 35.0
        c_acc = accel * 15.0
        c_disp = port_growth * 15.0

        raw_score = c_p1 + c_cum + c_acc + c_disp
        score = int(round(min(100.0, max(0.0, raw_score))))

        drivers = []
        if cum_5 >= 0.5:
            drivers.append(f"Cumulative 5-window attack risk accumulates to {cum_5*100:.1f}%.")
        if p1 >= 0.5:
            drivers.append(f"Immediate T+1 onset risk is elevated ({p1*100:.1f}%).")
        if accel > 0.15:
            drivers.append(f"Forward trajectory exhibits accelerating risk (+{accel*100:.1f}% by T+3).")
        if port_growth > 0.2:
            drivers.append(f"Projected target port dispersion increases by {port_growth*100:.1f}%.")
        if not drivers:
            drivers.append("Network state remains in stable equilibrium with baseline metrics.")

        if score >= 75:
            level = EarlyWarningLevel.CRITICAL
        elif score >= 50:
            level = EarlyWarningLevel.HIGH
        elif score >= 25:
            level = EarlyWarningLevel.ELEVATED
        else:
            level = EarlyWarningLevel.NORMAL

        return EarlyWarningAssessment(
            early_warning_score=score,
            early_warning_level=level,
            drivers=drivers,
            score_components={
                "t1_probability_component": round(c_p1, 2),
                "cumulative_risk_component": round(c_cum, 2),
                "acceleration_component": round(c_acc, 2),
                "state_divergence_component": round(c_disp, 2),
            },
        )

    def _build_insufficient_history_fallback(
        self,
        current_s: NetworkState,
        lookback_count: int,
        horizons: list[int],
    ) -> ForecastTrajectoryResult:
        origin_ts = datetime.fromtimestamp(current_s.timestamp, timezone.utc).isoformat()
        current_dict = {name: float(current_s.flow_features.get(name, 0.0)) for name in FLOW_NAMES_45}

        points = [
            HorizonForecastPoint(
                horizon=h,
                lookahead_seconds=h * 60,
                predicted_timestamp=datetime.fromtimestamp(current_s.timestamp + h * 60, timezone.utc).isoformat(),
                predicted_state=current_dict,
                attack_probability=None,
                cumulative_risk=None,
                risk_level=RiskLevel.LOW,
                probability_status="ABSTAINED_INSUFFICIENT_HISTORY",
                confidence=None,
                uncertainty=None,
                predicted_stage="PERSISTENCE_REFERENCE",
                top_drivers=[],
                behavioral_interpretation=f"Forecast abstained: {lookback_count} of 8 required historical observation windows available.",
            )
            for h in horizons
        ]

        return ForecastTrajectoryResult(
            origin_timestamp=origin_ts,
            lookback_windows=lookback_count,
            supported_horizons=horizons,
            forecast_status="ABSTAINED_INSUFFICIENT_HISTORY",
            current_state={"timestamp": origin_ts, "flow_count": current_s.flow_features.get("flow_count", 0.0)},
            forecasts=points,
            progression=[],
            mitre_mapping={},
            early_warning=EarlyWarningAssessment(
                early_warning_score=0,
                early_warning_level=EarlyWarningLevel.NORMAL,
                drivers=["Forecasting abstained due to insufficient telemetry history."],
                score_components={},
            ),
            is_fallback=True,
        )

    def _build_model_unavailable_fallback(
        self,
        current_s: NetworkState,
        lookback_count: int,
        horizons: list[int],
    ) -> ForecastTrajectoryResult:
        origin_ts = datetime.fromtimestamp(current_s.timestamp, timezone.utc).isoformat()
        current_dict = {name: float(current_s.flow_features.get(name, 0.0)) for name in FLOW_NAMES_45}

        points = [
            HorizonForecastPoint(
                horizon=h,
                lookahead_seconds=h * 60,
                predicted_timestamp=datetime.fromtimestamp(current_s.timestamp + h * 60, timezone.utc).isoformat(),
                predicted_state=current_dict,
                attack_probability=None,
                cumulative_risk=None,
                risk_level=RiskLevel.LOW,
                probability_status="MODEL_UNAVAILABLE",
                confidence=None,
                uncertainty=None,
                predicted_stage="PERSISTENCE_REFERENCE",
                top_drivers=[],
                behavioral_interpretation="Forecast unavailable: model checkpoint not loaded.",
            )
            for h in horizons
        ]

        return ForecastTrajectoryResult(
            origin_timestamp=origin_ts,
            lookback_windows=lookback_count,
            supported_horizons=horizons,
            forecast_status="MODEL_UNAVAILABLE",
            current_state={"timestamp": origin_ts},
            forecasts=points,
            progression=[],
            mitre_mapping={},
            early_warning=EarlyWarningAssessment(
                early_warning_score=0,
                early_warning_level=EarlyWarningLevel.NORMAL,
                drivers=["Model unavailable."],
                score_components={},
            ),
            is_fallback=True,
        )

    def _build_empty_fallback(self, lookback_count: int) -> ForecastTrajectoryResult:
        now_ts = datetime.now(timezone.utc).isoformat()
        return ForecastTrajectoryResult(
            origin_timestamp=now_ts,
            lookback_windows=lookback_count,
            supported_horizons=[],
            forecast_status="NO_DATA",
            current_state={},
            forecasts=[],
            progression=[],
            mitre_mapping={},
            early_warning=EarlyWarningAssessment(
                early_warning_score=0,
                early_warning_level=EarlyWarningLevel.NORMAL,
                drivers=["No telemetry observed."],
                score_components={},
            ),
            is_fallback=True,
        )
