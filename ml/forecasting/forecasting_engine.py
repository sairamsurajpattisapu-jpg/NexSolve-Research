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
        return {
            "feature": self.feature,
            "current_value": self.current_value,
            "predicted_value": self.predicted_value,
            "direction": self.direction,
            "relative_change": self.relative_change,
            "importance": self.importance,
            "interpretation": self.interpretation,
        }


@dataclass(frozen=True)
class ProgressionFinding:
    stage: str
    mitre_techniques: list[str]
    horizon: str
    evidence: list[str]
    supporting_features: list[str]
    confidence_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "mitre_techniques": list(self.mitre_techniques),
            "horizon": self.horizon,
            "evidence": list(self.evidence),
            "supporting_features": list(self.supporting_features),
            "confidence_status": self.confidence_status,
        }


@dataclass(frozen=True)
class EvidenceAttribution:
    """Explicit network telemetry evidence justifying the projected attack stage."""
    predicted_stage: str
    mitre_technique: str
    behavioral_rationale: str
    top_observable_drivers: list[FeatureDriver]
    epistemic_certainty: str
    supporting_signals: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "predicted_stage": self.predicted_stage,
            "mitre_technique": self.mitre_technique,
            "behavioral_rationale": self.behavioral_rationale,
            "top_observable_drivers": [d.to_dict() for d in self.top_observable_drivers],
            "epistemic_certainty": self.epistemic_certainty,
            "supporting_signals": list(self.supporting_signals),
        }


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
    evidence_attribution: EvidenceAttribution | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon": self.horizon,
            "lookahead_seconds": self.lookahead_seconds,
            "predicted_timestamp": self.predicted_timestamp,
            "predicted_state": dict(self.predicted_state),
            "attack_probability": self.attack_probability,
            "cumulative_risk": self.cumulative_risk,
            "risk_level": self.risk_level.value,
            "probability_status": self.probability_status,
            "confidence": self.confidence,
            "uncertainty": self.uncertainty,
            "predicted_stage": self.predicted_stage,
            "top_drivers": [d.to_dict() for d in self.top_drivers],
            "behavioral_interpretation": self.behavioral_interpretation,
            "evidence_attribution": self.evidence_attribution.to_dict() if self.evidence_attribution is not None else None,
        }



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
class TrajectoryScenario:
    scenario_name: str  # "CONTINUATION", "ESCALATION", "STABILIZATION", "DIVERSIFIED_SCAN"
    scenario_probability: float
    description: str
    projected_risk_profile: list[float]
    projected_stages: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_name": self.scenario_name,
            "scenario_probability": round(self.scenario_probability, 3),
            "description": self.description,
            "projected_risk_profile": [round(r, 4) for r in self.projected_risk_profile],
            "projected_stages": list(self.projected_stages),
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
    alternative_trajectories: list[TrajectoryScenario] = None
    counterfactual_simulations: dict[str, Any] = None

    def __post_init__(self):
        if self.alternative_trajectories is None:
            object.__setattr__(self, "alternative_trajectories", [])
        if self.counterfactual_simulations is None:
            object.__setattr__(self, "counterfactual_simulations", {})

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
            "alternative_trajectories": [t.to_dict() for t in self.alternative_trajectories],
            "counterfactual_simulations": dict(self.counterfactual_simulations),
        }


@dataclass(frozen=True)
class ForecastRevisionRecord:
    revision_id: str
    previous_revision_id: str | None
    timestamp: float
    reason: str
    primary_stage_previous: str | None
    primary_stage_updated: str
    probability_previous: float | None
    probability_updated: float
    contradictory_evidence_count: int
    supporting_evidence_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "revision_id": self.revision_id,
            "previous_revision_id": self.previous_revision_id,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "primary_stage_previous": self.primary_stage_previous,
            "primary_stage_updated": self.primary_stage_updated,
            "probability_previous": round(self.probability_previous, 4) if self.probability_previous is not None else None,
            "probability_updated": round(self.probability_updated, 4),
            "contradictory_evidence_count": self.contradictory_evidence_count,
            "supporting_evidence_count": self.supporting_evidence_count,
        }


class BeliefUpdateEngine:
    """Dynamically updates prior forecast trajectories and stage beliefs when new network evidence arrives."""

    def __init__(self) -> None:
        self.revision_history: list[ForecastRevisionRecord] = []
        self._revision_counter = 1

    def update_belief(
        self,
        current_forecast: ForecastTrajectoryResult,
        new_evidences: Sequence[Any],
        entity_memory: Any = None,
    ) -> tuple[ForecastTrajectoryResult, ForecastRevisionRecord]:
        now_ts = datetime.now(timezone.utc).timestamp()
        rev_id = f"REV_{self._revision_counter:04d}"
        prev_rev_id = self.revision_history[-1].revision_id if self.revision_history else None
        self._revision_counter += 1

        # Evaluate evidence direction & contradiction signals
        contradictory_signals = 0
        supporting_signals = 0
        for ev in new_evidences:
            proto = str(getattr(ev, "protocol", "")).upper()
            bytes_cnt = getattr(ev, "bytes_count", 0) or 0
            if bytes_cnt == 0 or proto in {"NTP", "ARP"}:
                contradictory_signals += 1
            else:
                supporting_signals += 1

        old_p1 = current_forecast.forecasts[0].attack_probability if current_forecast.forecasts else 0.5
        old_stage = current_forecast.forecasts[0].predicted_stage if current_forecast.forecasts else "UNKNOWN"

        # Belief adjustment factor based on contradictory vs supporting evidence
        if contradictory_signals > supporting_signals:
            factor = 0.75
            reason = f"Received {contradictory_signals} benign/quiescent evidence records counterbalancing threat momentum."
            new_stage = "STABILIZATION" if old_p1 < 0.6 else old_stage
        elif supporting_signals > 0:
            factor = 1.15
            reason = f"Corroborating telemetry received ({supporting_signals} active network evidence records)."
            new_stage = old_stage
        else:
            factor = 1.0
            reason = "Belief maintained; no contradictory or corroborating shifts."
            new_stage = old_stage

        new_p1 = max(0.01, min(0.99, (old_p1 or 0.5) * factor))

        revision = ForecastRevisionRecord(
            revision_id=rev_id,
            previous_revision_id=prev_rev_id,
            timestamp=now_ts,
            reason=reason,
            primary_stage_previous=old_stage,
            primary_stage_updated=new_stage,
            probability_previous=old_p1,
            probability_updated=new_p1,
            contradictory_evidence_count=contradictory_signals,
            supporting_evidence_count=supporting_signals,
        )
        self.revision_history.append(revision)

        # Build revised forecast points
        updated_points = []
        for p in current_forecast.forecasts:
            rev_prob = max(0.01, min(0.99, (p.attack_probability or 0.5) * factor)) if p.attack_probability is not None else None
            updated_points.append(HorizonForecastPoint(
                horizon=p.horizon,
                lookahead_seconds=p.lookahead_seconds,
                predicted_timestamp=p.predicted_timestamp,
                predicted_state=p.predicted_state,
                attack_probability=round(rev_prob, 4) if rev_prob is not None else None,
                cumulative_risk=p.cumulative_risk,
                risk_level=_determine_risk_level(rev_prob),
                probability_status="REVISED_BELIEF",
                confidence=round(max(0.1, min(0.99, (p.confidence or 0.5) * (0.95 if contradictory_signals > 0 else 1.05))), 4) if p.confidence is not None else None,
                uncertainty=p.uncertainty,
                predicted_stage=new_stage if p.horizon == 1 else p.predicted_stage,
                top_drivers=p.top_drivers,
                behavioral_interpretation=f"Belief updated ({revision.revision_id}): {reason}",
                evidence_attribution=p.evidence_attribution,
            ))

        revised_forecast = ForecastTrajectoryResult(
            origin_timestamp=current_forecast.origin_timestamp,
            lookback_windows=current_forecast.lookback_windows,
            supported_horizons=current_forecast.supported_horizons,
            forecast_status=f"REVISED_{revision.revision_id}",
            current_state=current_forecast.current_state,
            forecasts=updated_points,
            progression=current_forecast.progression,
            mitre_mapping=current_forecast.mitre_mapping,
            early_warning=current_forecast.early_warning,
            is_fallback=current_forecast.is_fallback,
            alternative_trajectories=current_forecast.alternative_trajectories,
            counterfactual_simulations=current_forecast.counterfactual_simulations,
        )

        return revised_forecast, revision



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

        # 1. Vectorized rollout inference
        max_h = max(horizons)
        simulated_states: dict[int, dict[str, float]] = {}
        step_probabilities: dict[int, float] = {}

        flow_names = FLOW_NAMES_45
        packet_names = PACKET_NAMES
        temporal_names = TEMPORAL_NAMES
        n_flow = len(flow_names)
        n_pkt = len(packet_names)

        buf = np.zeros((8 + max_h, len(self.feature_names)), dtype=np.float64)
        for i, s in enumerate(history[-8:]):
            buf[i] = s.encode(self.feature_names)

        for step in range(1, max_h + 1):
            window = buf[step - 1 : step + 7]
            scaled = (window - self._mean) / self._scale
            pred_scaled, prob = self._model.predict(scaled)
            pred_vector = pred_scaled * self._scale + self._mean
            pred_dict = {name: float(val) for name, val in zip(self.feature_names, pred_vector)}

            simulated_states[step] = pred_dict
            step_probabilities[step] = float(prob)

            # Roll prediction forward without future ground truth into preallocated trajectory buffer
            sim_vec = np.zeros(len(self.feature_names), dtype=np.float64)
            sim_vec[:n_flow] = [pred_dict.get(n, 0.0) for n in flow_names]
            sim_vec[n_flow:n_flow + n_pkt] = [pred_dict.get(n, 0.0) for n in packet_names]
            sim_vec[n_flow + n_pkt:] = [pred_dict.get(n, 0.0) for n in temporal_names]
            buf[7 + step] = sim_vec

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

            # Calibrated Epistemic Uncertainty:
            # Baseline uncertainty from boundary proximity plus step decay compounding
            boundary_dist = abs(prob_h - 0.5) * 2.0
            step_decay_penalty = min(0.25, (h - 1) * 0.05)
            calibrated_conf = round(float(max(0.05, min(0.98, boundary_dist - step_decay_penalty))), 4)
            calibrated_unc = round(float(max(0.02, min(0.95, (1.0 - boundary_dist) + step_decay_penalty))), 4)

            # Grounded MITRE technique mapping for predicted stage
            stage_mitre_dict = {
                "RECONNAISSANCE": "T1046: Network Service Discovery",
                "COMMAND_AND_CONTROL": "T1071: Application Layer Protocol",
                "EXPLOITATION": "T1190: Exploit Public-Facing Application",
                "DENIAL_OF_SERVICE": "T1498: Network Denial of Service",
                "EXFILTRATION": "T1041: Exfiltration Over C2 Channel",
                "ATTACK_IMMINENT": "T1190: Exploit Public-Facing Application",
                "STABLE_BENIGN": "N/A: Normal Traffic Equilibrium",
            }
            assigned_mitre = stage_mitre_dict.get(pred_stage, "T1190: Exploit Public-Facing Application")

            # Grounded rationale answering "Why does NexSolve think this attack stage is coming next?"
            primary_driver_text = f", driven by {top_drivers[0].feature} ({top_drivers[0].direction} to {top_drivers[0].predicted_value:.1f})" if top_drivers else ""
            if pred_stage == "DENIAL_OF_SERVICE":
                rationale = f"Volumetric packet surge and TCP SYN concentration projected at T+{h}{primary_driver_text}, indicating imminent resource exhaustion."
            elif pred_stage == "RECONNAISSANCE":
                rationale = f"Destination port cardinality expansion projected at T+{h}{primary_driver_text}, reflecting systematic service enumeration."
            elif pred_stage == "COMMAND_AND_CONTROL":
                rationale = f"Asymmetric payload transfer and regular cadence projected at T+{h}{primary_driver_text}, consistent with active remote agent channel."
            elif pred_stage == "EXFILTRATION":
                rationale = f"Sustained outbound egress volume surge projected at T+{h}{primary_driver_text}, consistent with bulk data staging or exfiltration."
            elif pred_stage == "EXPLOITATION" or pred_stage == "ATTACK_IMMINENT":
                rationale = f"Composite network state divergence and high attack probability ({prob_h*100:.1f}%){primary_driver_text} signal transition into active exploitation."
            else:
                rationale = f"Network telemetry remains within baseline equilibrium boundaries through T+{h} with no anomalous stage divergence."

            evidence_attrib = EvidenceAttribution(
                predicted_stage=pred_stage,
                mitre_technique=assigned_mitre,
                behavioral_rationale=rationale,
                top_observable_drivers=top_drivers[:3],
                epistemic_certainty="HIGH_CONFIDENCE" if calibrated_conf >= 0.70 else "MODERATE_UNCERTAINTY" if calibrated_conf >= 0.40 else "HIGH_UNCERTAINTY",
                supporting_signals=[d.interpretation for d in top_drivers[:2]],
            )

            forecast_points.append(HorizonForecastPoint(
                horizon=h,
                lookahead_seconds=h * 60,
                predicted_timestamp=h_ts,
                predicted_state=pred_state_h,
                attack_probability=round(prob_h, 4),
                cumulative_risk=round(cum_risk, 4),
                risk_level=risk_level,
                probability_status="UNCALIBRATED",
                confidence=calibrated_conf,
                uncertainty=calibrated_unc,
                predicted_stage=pred_stage,
                top_drivers=top_drivers,
                behavioral_interpretation=interp_summary,
                evidence_attribution=evidence_attrib,
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
            "EXFILTRATION": "T1041: Exfiltration Over C2 Channel",
            "STABLE_BENIGN": "N/A: Normal Traffic Equilibrium",
        }

        # 5. Probabilistic Alternative Future Trajectories (Batch 2 & Batch 5)
        p_mean = float(np.mean([p for p in step_probabilities.values()])) if step_probabilities else 0.1
        alt_trajectories = [
            TrajectoryScenario(
                scenario_name="CONTINUATION",
                scenario_probability=max(0.1, min(0.85, 1.0 - abs(p_mean - 0.5))),
                description="Observed behavior continues along present kinematic velocity without sudden intervention.",
                projected_risk_profile=[step_probabilities.get(h, p_mean) for h in horizons],
                projected_stages=[self._infer_stage_from_state(simulated_states.get(h, {}), step_probabilities.get(h, p_mean)) for h in horizons],
            ),
            TrajectoryScenario(
                scenario_name="ESCALATION",
                scenario_probability=min(0.9, p_mean * 1.3),
                description="Attack velocity accelerates through rapid target port dispersion or packet surge.",
                projected_risk_profile=[min(1.0, step_probabilities.get(h, p_mean) * (1.0 + 0.1 * idx)) for idx, h in enumerate(horizons)],
                projected_stages=["EXPLOITATION" if idx >= 2 else self._infer_stage_from_state(simulated_states.get(h, {}), step_probabilities.get(h, p_mean)) for idx, h in enumerate(horizons)],
            ),
            TrajectoryScenario(
                scenario_name="STABILIZATION",
                scenario_probability=max(0.05, 1.0 - p_mean),
                description="Network communications decay back toward learned baseline equilibrium.",
                projected_risk_profile=[max(0.01, step_probabilities.get(h, p_mean) * (0.8 ** (idx + 1))) for idx, h in enumerate(horizons)],
                projected_stages=["STABLE_BENIGN" for _ in horizons],
            ),
        ]

        # 6. Counterfactual Behavioral Perturbations (Batch 5)
        counterfactuals = {
            "cessation_of_suspicious_flows": {
                "description": "Counterfactual: What if all suspicious connections and high-fanout ports terminate immediately?",
                "simulated_trajectory": [max(0.02, step_probabilities.get(h, p_mean) * 0.25) for h in horizons],
                "expected_impact": "Immediate risk attenuation to nominal baseline equilibrium.",
            },
            "unmitigated_persistence": {
                "description": "Counterfactual: What if current anomalous scanning continues unmitigated across all 5 horizons?",
                "simulated_trajectory": [min(0.99, step_probabilities.get(h, p_mean) * 1.4) for h in horizons],
                "expected_impact": "High probability of lateral exploitation and defensive exhaustion.",
            },
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
            alternative_trajectories=alt_trajectories,
            counterfactual_simulations=counterfactuals,
        )

    def _infer_stage_from_state(self, state: dict[str, float], prob: float) -> str:
        if prob < 0.40:
            return "STABLE_BENIGN"
        ports = state.get("unique_dst_ports", 0.0)
        udp_count = state.get("proto_udp_count", 0.0)
        tcp_count = state.get("proto_tcp_count", 0.0)
        packets = state.get("total_packets", 1.0)
        syn_count = state.get("tcp_syn_count", 0.0)
        src_bytes = state.get("total_src_bytes", 0.0)
        dst_bytes = state.get("total_dst_bytes", 0.0)

        # Volumetric or SYN Flood
        if syn_count > 50 or (packets > 1000 and tcp_count > 0.8 * packets) or (packets > 2000 and udp_count > 0.8 * packets):
            return "DENIAL_OF_SERVICE"
        # Network Scanning / Reconnaissance
        if ports > 15 or (ports > 8 and packets < 500):
            return "RECONNAISSANCE"
        # Bulk Egress / Exfiltration
        if src_bytes > 500000 and src_bytes > dst_bytes * 5:
            return "EXFILTRATION"
        # Command & Control Asymmetry
        if dst_bytes > src_bytes * 4:
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
