"""Deterministic, evidence-bounded interpretation of NexSolve forecasts.

This module interprets model output; it does not change model weights, use labels
as inference features, or turn flow aggregates into packet observations.
"""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from world_model import NetworkState, explain, forecast_k_steps

ROOT = Path(__file__).resolve().parents[1]
MITRE_BUNDLE = ROOT / "MITRE" / "enterprise-attack-19.2.json"
STAGES = ("BENIGN", "RECONNAISSANCE", "INITIAL_ACCESS", "EXECUTION", "PERSISTENCE", "PRIVILEGE_ESCALATION", "DEFENSE_EVASION", "CREDENTIAL_ACCESS", "DISCOVERY", "LATERAL_MOVEMENT", "COMMAND_AND_CONTROL", "EXFILTRATION", "IMPACT", "UNKNOWN")


@dataclass(frozen=True)
class TrendThresholds:
    """Documented thresholds applied to adjacent forecast probabilities."""

    low_probability: float = 0.35
    high_probability: float = 0.65
    rising_delta: float = 0.10
    rapid_rising_delta: float = 0.25
    uncertainty_margin: float = 0.10

    def __post_init__(self) -> None:
        if not 0 <= self.low_probability < self.high_probability <= 1:
            raise ValueError("probability thresholds must satisfy 0 <= low < high <= 1")
        if not 0 < self.rising_delta <= self.rapid_rising_delta:
            raise ValueError("delta thresholds must be positive and ordered")


def _finite(value: Any) -> bool:
    return isinstance(value, (int, float)) and math.isfinite(float(value))


def load_attack_technique(technique_id: str, bundle_path: Path = MITRE_BUNDLE) -> dict[str, Any] | None:
    """Return validated ATT&CK metadata, or None for an invalid/unknown ID."""
    if not isinstance(technique_id, str) or not technique_id.startswith("T"):
        return None
    bundle = json.loads(bundle_path.read_text(encoding="utf-8"))
    for item in bundle.get("objects", []):
        references = item.get("external_references", [])
        if item.get("type") != "attack-pattern":
            continue
        reference = next((ref for ref in references if ref.get("source_name") == "mitre-attack" and ref.get("external_id") == technique_id), None)
        if reference is None:
            continue
        return {"technique_id": technique_id, "technique_name": item.get("name"), "tactics": [phase.get("phase_name") for phase in item.get("kill_chain_phases", [])], "description": item.get("description"), "reference": reference.get("url"), "status": "CONTEXTUAL_TECHNIQUE"}
    return None


def _flow_value(state_or_flow: NetworkState | dict[str, Any], name: str) -> float | None:
    flow = state_or_flow.flow_features if isinstance(state_or_flow, NetworkState) else state_or_flow.get("flow_features", state_or_flow)
    value = flow.get(name)
    return float(value) if _finite(value) else None


def _scan_signal(state: NetworkState | dict[str, Any]) -> dict[str, Any] | None:
    ports = _flow_value(state, "unique_dst_ports")
    flows = _flow_value(state, "flow_count")
    duration = _flow_value(state, "mean_duration")
    if ports is None or flows is None or flows <= 0:
        return None
    diversity = ports / flows
    if ports < 10 and diversity < 0.50:
        return None
    evidence = [{"feature": "unique_dst_ports", "direction": "elevated_destination_port_diversity", "contribution": "supports", "value": ports, "evidence_source": "observed_flow_aggregate"}, {"feature": "flow_count", "direction": "fan_out_context", "contribution": "supports", "value": flows, "evidence_source": "observed_flow_aggregate"}]
    if duration is not None and duration <= 1000000:
        evidence.append({"feature": "mean_duration", "direction": "short_flow_context", "contribution": "supports", "value": duration, "evidence_source": "observed_flow_aggregate"})
    return {"behavioral_signal": "PORT_SCAN_LIKE_ACTIVITY", "evidence": evidence, "confidence": min(0.95, 0.55 + min(0.35, diversity) + (0.05 if duration is not None and duration <= 1000000 else 0.0))}


def infer_stage(state: NetworkState | dict[str, Any], *, forecast: bool = False, mitre_bundle: Path = MITRE_BUNDLE) -> dict[str, Any]:
    """Infer one contextual stage without reading attack_state or future data."""
    signal = _scan_signal(state)
    if signal is None:
        return {"stage": "UNKNOWN", "confidence": 0.0, "status": "INSUFFICIENT_EVIDENCE", "evidence": [], "evidence_source": "available_flow_features", "techniques": []}
    technique = load_attack_technique("T1046", mitre_bundle)
    techniques = []
    if technique is not None:
        techniques.append({**technique, "status": "FORECAST_CONTEXT" if forecast else "CONTEXTUAL_TECHNIQUE", "confidence": signal["confidence"]})
    return {"stage": "RECONNAISSANCE", "confidence": signal["confidence"], "status": "CONTEXTUAL_HYPOTHESIS", "evidence": signal["evidence"], "evidence_source": "observed_flow_aggregate" if not forecast else "predicted_flow_state", "behavioral_signal": signal["behavioral_signal"], "techniques": techniques}


def probability_trend(probabilities: Iterable[float | None], thresholds: TrendThresholds = TrendThresholds()) -> list[str]:
    values = list(probabilities)
    result = ["INSUFFICIENT_EVIDENCE"]
    for index, current in enumerate(values):
        if not _finite(current):
            result.append("INSUFFICIENT_EVIDENCE")
            continue
        current = float(current)
        if index == 0 or not _finite(values[index - 1]):
            result.append("STABLE_LOW" if current < thresholds.low_probability else "STABLE_HIGH" if current >= thresholds.high_probability else "UNCERTAIN")
            continue
        delta = current - float(values[index - 1])
        if delta >= thresholds.rapid_rising_delta:
            result.append("RAPIDLY_RISING")
        elif delta >= thresholds.rising_delta:
            result.append("RISING")
        elif delta <= -thresholds.rising_delta:
            result.append("FALLING")
        elif abs(current - 0.5) < thresholds.uncertainty_margin:
            result.append("UNCERTAIN")
        elif current < thresholds.low_probability:
            result.append("STABLE_LOW")
        elif current >= thresholds.high_probability:
            result.append("STABLE_HIGH")
        else:
            result.append("UNCERTAIN")
    return result[1:]


def defender_guidance(trend: str, confidence: float | None, abstained: bool = False) -> dict[str, str]:
    if abstained or trend == "INSUFFICIENT_EVIDENCE":
        return {"priority": "LOW", "recommendation": "Insufficient evidence for reliable attack progression forecast."}
    if trend in {"RAPIDLY_RISING", "STABLE_HIGH"} and confidence is not None and confidence >= 0.65:
        return {"priority": "HIGH", "recommendation": "Investigate hosts associated with the forecast behavior."}
    if trend in {"RISING", "RAPIDLY_RISING"}:
        return {"priority": "MEDIUM", "recommendation": "Increase monitoring of affected flows."}
    return {"priority": "LOW", "recommendation": "Continue monitoring."}


def analyze_forecast(states: list[NetworkState], forecast_points: list[dict[str, Any]], *, thresholds: TrendThresholds = TrendThresholds(), explanations: list[dict[str, Any]] | None = None, mitre_bundle: Path = MITRE_BUNDLE) -> dict[str, Any]:
    """Compose a stable API-ready intelligence result from existing model output."""
    probabilities = [point.get("attack_probability") for point in forecast_points]
    trends = probability_trend(probabilities, thresholds)
    current = infer_stage(states[-1], mitre_bundle=mitre_bundle) if states else {"stage": "UNKNOWN", "confidence": 0.0, "status": "INSUFFICIENT_EVIDENCE", "evidence": [], "evidence_source": "none", "techniques": []}
    timeline = []
    for point, trend in zip(forecast_points, trends):
        predicted = point.get("predicted_state")
        stage = infer_stage({"flow_features": {key: predicted[key] for key in ("flow_count", "unique_dst_ports", "mean_duration") if key in predicted}} if predicted else {}, forecast=True, mitre_bundle=mitre_bundle)
        confidence = point.get("confidence")
        abstained = bool(point.get("abstained", predicted is None)) or predicted is None
        if abstained:
            stage = {"stage": "UNKNOWN", "confidence": 0.0, "status": "INSUFFICIENT_EVIDENCE", "evidence": [], "evidence_source": "model_abstention", "techniques": []}
        timeline.append({"horizon": point.get("horizon"), "window_offset_seconds": int(point.get("horizon", 0)) * 60, "attack_probability": point.get("attack_probability"), "probability_delta": None if len(timeline) == 0 or point.get("attack_probability") is None or probabilities[len(timeline) - 1] is None else point.get("attack_probability") - probabilities[len(timeline) - 1], "trend": trend, "confidence": confidence, "uncertainty": None if confidence is None else 1.0 - confidence, "stage": stage, "status": "INSUFFICIENT_EVIDENCE" if abstained else "MODEL_PREDICTION"})
    evidence = current.get("evidence", [])
    return {"current_state": {"status": "OBSERVATION", "attack_probability": None, "risk_trend": "INSUFFICIENT_EVIDENCE", "stage": current}, "forecast": timeline, "evidence": evidence, "defender_guidance": defender_guidance(timeline[0]["trend"], timeline[0]["confidence"], not timeline or timeline[0]["status"] == "INSUFFICIENT_EVIDENCE"), "explanation": explanations or [], "limitations": ["Stage outputs are CONTEXTUAL_HYPOTHESIS, not dataset-confirmed ATT&CK stages.", "Forecast probabilities are uncalibrated model outputs.", "LSTM model-level feature attribution unavailable for this forecast; existing ablation explanations are associations, not causes.", "CIC flow CSVs have no event timestamps or packet observations.", "Observed labels are excluded from inference and are evaluation metadata only."], "thresholds": asdict(thresholds)}


def run_model_intelligence(states: list[NetworkState], *, thresholds: TrendThresholds = TrendThresholds(), package_dir: Path | None = None) -> dict[str, Any]:
    result = forecast_k_steps(states, 5, package_dir)
    explanations = []
    if len(states) >= 8:
        from world_model import load_model
        model, mean, scale = load_model(package_dir)
        explanations = explain(states, model, mean, scale)
    return analyze_forecast(states, result["forecasts"], thresholds=thresholds, explanations=explanations)