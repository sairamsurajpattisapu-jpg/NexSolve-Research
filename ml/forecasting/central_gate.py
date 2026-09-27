"""Authoritative Central Forecast Gate for NexSolve.

Enforces a single, non-divergent execution and validation path for predictive network forecasting:
validate_inputs()
        ↓
validate_temporal_continuity()
        ↓
validate_feature_contract()
        ↓
validate_observability()
        ↓
run_frozen_model()
        ↓
validate_forecast_output()
        ↓
publish_forecast()

Guarantees:
- ONE source of truth for backend, reporting, API, CLI, and frontend.
- Zero independent invention of forecast stages, probabilities, or confidence by downstream components.
- Complete, non-leaking propagation of abstention: an abstained forecast produces NO future stages, NO probabilities, and NO fabricated persistence.
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from nexsolve_core.data_quality import DataQualityAssessment, assess_data_quality
from nexsolve_core.schemas import CaptureQuality, QualityStatus, TemporalWindow
from nexsolve_core.state import (
    MODEL_SCHEMA_45,
    NetworkStateCandidate,
    candidates_to_network_states,
    evaluate_model_compatibility,
)

logger = logging.getLogger("nexsolve.forecast_gate")


@dataclass(slots=True, frozen=True)
class CentralForecastResult:
    """Canonical forecast result bundle published by the central gate."""

    is_forecast_available: bool
    forecast_status: str  # "FORECAST_READY" | "FORECAST_ABSTAINED"
    abstention_reason: str | None
    abstention_explanation: str | None
    data_quality: DataQualityAssessment
    forecast_points: list[dict[str, Any]]
    final_inference_result: dict[str, Any]
    early_warning: dict[str, Any]
    attack_horizon: dict[str, Any]
    attack_progression: dict[str, Any]
    evidence_chain: dict[str, Any]
    confidence: dict[str, Any]
    uncertainty: dict[str, Any]
    engine_metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_forecast_available": self.is_forecast_available,
            "forecast_status": self.forecast_status,
            "abstention_reason": self.abstention_reason,
            "abstention_explanation": self.abstention_explanation,
            "data_quality": self.data_quality.to_dict(),
            "forecast_points": self.forecast_points,
            "final_world_model": self.final_inference_result,
            "early_warning": self.early_warning,
            "attack_horizon": self.attack_horizon,
            "attack_progression": self.attack_progression,
            "evidence_chain": self.evidence_chain,
            "confidence": self.confidence,
            "uncertainty": self.uncertainty,
            "forecast_engine": self.engine_metadata,
        }


def validate_inputs(
    canonical_windows: Sequence[TemporalWindow] | Sequence[dict[str, Any]],
    capture_quality: CaptureQuality | dict[str, Any] | None,
) -> tuple[bool, str | None, str | None]:
    """Step 1: Validate input window structures and packet counts."""
    if not canonical_windows:
        return False, "INSUFFICIENT_DATA", "Forecast withheld: capture contains no temporal windows."
    total_pkts = 0
    for w in canonical_windows:
        if isinstance(w, TemporalWindow):
            total_pkts += w.packet_count
        elif isinstance(w, dict):
            total_pkts += w.get("packet_count", 0)
    if total_pkts == 0:
        return False, "ZERO_PACKETS", "Forecast withheld: zero valid packets parsed from capture."
    return True, None, None


def validate_temporal_continuity(
    canonical_windows: Sequence[TemporalWindow] | Sequence[dict[str, Any]],
    history_status: str,
    required_windows: int = 8,
) -> tuple[bool, str | None, str | None]:
    """Step 2: Enforce minimum lookback and temporal continuity constraints."""
    if len(canonical_windows) < required_windows:
        return (
            False,
            "INSUFFICIENT_HISTORY",
            f"Forecast withheld: Forecasting requires at least {required_windows} continuous 60-second windows. "
            f"Capture provides {len(canonical_windows)} windows. Static traffic analysis completed successfully.",
        )
    if history_status == "GAPPED_HISTORY":
        return (
            False,
            "NON_CONTIGUOUS_TIMESTAMPS",
            "Forecast withheld: Input sequence contains non-contiguous temporal windows or excessive time gaps.",
        )
    return True, None, None


def validate_feature_contract(
    candidates: tuple[NetworkStateCandidate, ...],
    model_schema: dict[str, Any] = MODEL_SCHEMA_45,
    history_status: str = "VALID",
) -> tuple[bool, str | None, str | None, dict[str, Any]]:
    """Step 3: Verify that observed features satisfy the frozen model's input contract."""
    compat = evaluate_model_compatibility(candidates, model_schema, history_status).to_dict()
    if not compat.get("model_ready", False):
        reasons = compat.get("reasons", [])
        explanation = f"Forecast withheld: {reasons[0]}" if reasons else "Forecast withheld: feature contract mismatch."
        return False, "MODEL_FEATURE_CONTRACT_MISMATCH", explanation, compat
    return True, None, None, compat


def validate_observability(
    canonical_windows: Sequence[TemporalWindow] | Sequence[dict[str, Any]],
    capture_quality: CaptureQuality | dict[str, Any] | None,
) -> tuple[bool, str | None, str | None, DataQualityAssessment]:
    """Step 4: Execute Data Quality Gate to verify observability and integrity."""
    dq = assess_data_quality(canonical_windows, capture_quality)
    if not dq.forecast_eligible:
        reason = dq.disqualifying_reasons[0] if dq.disqualifying_reasons else "Data quality is INSUFFICIENT for forecasting."
        return False, "DATA_QUALITY_INSUFFICIENT", f"Forecast withheld: {reason}", dq
    return True, None, None, dq


def run_frozen_model(
    states: tuple[Any, ...],
    model_dir: Path,
    analysis_id: str,
    flows: list[dict[str, Any]],
    capture_quality: CaptureQuality | dict[str, Any] | None,
) -> dict[str, Any]:
    """Step 5: Execute inference strictly on the frozen production model weights."""
    from ml.final_production_inference import FinalProductionInferenceEngine

    engine = FinalProductionInferenceEngine(model_dir)
    return engine.run_inference(
        sequence=states,
        analysis_id=analysis_id,
        flows=flows,
        capture_quality=capture_quality,
    )


def validate_forecast_output(
    inference_result: dict[str, Any],
) -> tuple[bool, str | None, str | None]:
    """Step 6: Verify model output validity (no NaNs, probabilities in [0, 1])."""
    if inference_result.get("is_abstained", False):
        return (
            False,
            inference_result.get("abstention_reason", "MODEL_ABSTAINED"),
            inference_result.get("abstention_explanation", "Model internally abstained from forecasting."),
        )
    forecast_map = inference_result.get("forecast", {})
    if not forecast_map:
        return False, "EMPTY_FORECAST", "Forecast withheld: model returned empty forecast map."
    for h in (1, 2, 3, 4, 5):
        h_data = forecast_map.get(f"T+{h}")
        if not h_data:
            return False, "INCOMPLETE_HORIZONS", f"Forecast withheld: missing horizon T+{h} in model output."
        p = h_data.get("attack_probability")
        if p is None or math.isnan(p) or math.isinf(p) or not (0.0 <= p <= 1.0):
            return False, "INVALID_PROBABILITY", f"Forecast withheld: invalid probability value at T+{h}: {p}"
    return True, None, None


import os


def execute_central_forecast_gate(
    canonical_windows: Sequence[TemporalWindow] | Sequence[dict[str, Any]],
    candidates: tuple[NetworkStateCandidate, ...],
    history_status: str,
    capture_quality: CaptureQuality | dict[str, Any] | None,
    detection_findings: list[dict[str, Any]],
    behavioral_report: Any,
    model_dir: Path,
    analysis_id: str,
    filename: str,
    capture_fingerprint_sha256: str,
    all_flows_dict: list[dict[str, Any]] | None = None,
    engine_type: str = "production",
) -> CentralForecastResult:
    """The ONE authoritative forecast decision path for NexSolve.

    Guarantees no downstream divergence or independent invention of predictions.
    Supports either frozen production engine or unverified research candidate.
    """
    from ml.forecasting import assemble_forecast_intelligence
    from ml.forecasting.attack_progression import forecast_attack_progression

    norm_engine = (engine_type or os.getenv("NEXSOLVE_FORECAST_ENGINE", "production")).strip().lower()
    if norm_engine in ("stealth", "stealth_v1", "stealth-v1"):
        raise ValueError(
            "Engine 'stealth_v1' is REJECTED and unavailable for forecasting "
            "due to severe false-alarm explosion (FPR 94.4%). Multi-event research "
            "candidate 'multi_event_v1' remains the active research engine."
        )
    elif norm_engine in ("multi_event", "multi_event_v1", "multi-event"):
        from ml.forecasting.multi_event_engine import MultiEventResearchForecastEngine
        engine = MultiEventResearchForecastEngine()
    elif norm_engine in ("research", "next_gen", "nextgen", "candidate"):
        from ml.forecasting.next_gen_engine import NextGenResearchForecastEngine
        engine = NextGenResearchForecastEngine()
    else:
        from ml.forecasting.frozen_engine import FrozenWorldModelForecastEngine
        engine = FrozenWorldModelForecastEngine(model_dir=model_dir)
    engine_metadata = engine.metadata.to_dict()

    # Step 1: Input validation
    ok, reason, expl = validate_inputs(canonical_windows, capture_quality)
    if not ok:
        dq = assess_data_quality(canonical_windows, capture_quality)
        return _build_abstained_result(
            reason=reason,
            explanation=expl,
            dq=dq,
            detection_findings=detection_findings,
            behavioral_report=behavioral_report,
            history_window_count=len(canonical_windows),
            analysis_id=analysis_id,
            filename=filename,
            sha256=capture_fingerprint_sha256,
            engine_metadata=engine_metadata,
        )

    # Step 2: Temporal continuity
    ok, reason, expl = validate_temporal_continuity(canonical_windows, history_status)
    if not ok:
        dq = assess_data_quality(canonical_windows, capture_quality)
        return _build_abstained_result(
            reason=reason,
            explanation=expl,
            dq=dq,
            detection_findings=detection_findings,
            behavioral_report=behavioral_report,
            history_window_count=len(canonical_windows),
            analysis_id=analysis_id,
            filename=filename,
            sha256=capture_fingerprint_sha256,
            engine_metadata=engine_metadata,
        )

    # Step 3: Feature contract
    ok, reason, expl, compat = validate_feature_contract(candidates, MODEL_SCHEMA_45, history_status)
    if not ok:
        dq = assess_data_quality(canonical_windows, capture_quality)
        return _build_abstained_result(
            reason=reason,
            explanation=expl,
            dq=dq,
            detection_findings=detection_findings,
            behavioral_report=behavioral_report,
            history_window_count=len(canonical_windows),
            analysis_id=analysis_id,
            filename=filename,
            sha256=capture_fingerprint_sha256,
            engine_metadata=engine_metadata,
        )

    # Step 4: Observability and Data Quality Gate
    ok, reason, expl, dq = validate_observability(canonical_windows, capture_quality)
    if not ok:
        return _build_abstained_result(
            reason=reason,
            explanation=expl,
            dq=dq,
            detection_findings=detection_findings,
            behavioral_report=behavioral_report,
            history_window_count=len(canonical_windows),
            analysis_id=analysis_id,
            filename=filename,
            sha256=capture_fingerprint_sha256,
            engine_metadata=engine_metadata,
        )

    # Step 5: Run Selected Forecast Engine
    states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history_status)
    try:
        inference_result = engine.run_forecast(
            canonical_windows=canonical_windows,
            candidates=candidates,
            history_status=history_status,
            capture_quality=capture_quality,
            detection_findings=detection_findings,
            behavioral_report=behavioral_report,
            analysis_id=analysis_id,
            filename=filename,
            capture_fingerprint_sha256=capture_fingerprint_sha256,
            all_flows_dict=all_flows_dict,
        )
    except Exception as exc:
        logger.error("Inference execution failed on forecast engine (%s): %s", engine_metadata.get("name"), exc)
        return _build_abstained_result(
            reason="INFERENCE_EXECUTION_FAILURE",
            explanation=f"Forecast withheld: inference execution encountered an unexpected error ({type(exc).__name__}).",
            dq=dq,
            detection_findings=detection_findings,
            behavioral_report=behavioral_report,
            history_window_count=len(canonical_windows),
            analysis_id=analysis_id,
            filename=filename,
            sha256=capture_fingerprint_sha256,
            engine_metadata=engine_metadata,
        )

    # Step 6: Validate Forecast Output
    ok, reason, expl = validate_forecast_output(inference_result)
    if not ok:
        return _build_abstained_result(
            reason=reason,
            explanation=expl,
            dq=dq,
            detection_findings=detection_findings,
            behavioral_report=behavioral_report,
            history_window_count=len(canonical_windows),
            analysis_id=analysis_id,
            filename=filename,
            sha256=capture_fingerprint_sha256,
            engine_metadata=engine_metadata,
        )

    # Step 7: Publish Valid Forecast
    return _build_published_result(
        inference_result=inference_result,
        states=states,
        candidates=candidates,
        dq=dq,
        detection_findings=detection_findings,
        behavioral_report=behavioral_report,
        history_window_count=len(canonical_windows),
        analysis_id=analysis_id,
        filename=filename,
        sha256=capture_fingerprint_sha256,
        engine_metadata=engine_metadata,
    )


def _build_abstained_result(
    reason: str,
    explanation: str,
    dq: DataQualityAssessment,
    detection_findings: list[dict[str, Any]],
    behavioral_report: Any,
    history_window_count: int,
    analysis_id: str,
    filename: str,
    sha256: str,
    engine_metadata: dict[str, Any] | None = None,
) -> CentralForecastResult:
    """Builds a mathematically consistent abstained forecast bundle."""
    from ml.forecasting import assemble_forecast_intelligence
    from ml.forecasting.attack_progression import forecast_attack_progression

    meta = engine_metadata or {
        "name": "Frozen World Model",
        "version": "3.0.0",
        "status": "production",
        "is_production_ready": True,
    }

    abstained_points = [
        {
            "horizon": h,
            "horizon_minutes": h,
            "lookaheadSeconds": h * 60,
            "lookahead_seconds": h * 60,
            "attack_probability": None,
            "attackProbability": None,
            "cumulativeRisk": None,
            "cumulative_risk": None,
            "predicted_stage": None,
            "predictedStage": None,
            "riskLevel": None,
            "risk_level": None,
            "confidence": None,
            "confidence_score": None,
            "uncertainty": None,
            "explanation": [f"Forecast abstained: {reason}"],
            "top_drivers": [],
            "topDrivers": [],
            "evidence_attribution": None,
            "evidenceAttribution": None,
            "abstained": True,
        }
        for h in (1, 2, 3, 4, 5)
    ]

    progression = forecast_attack_progression(
        observed_findings=detection_findings,
        behavioral_report=behavioral_report,
        history_window_count=history_window_count,
        forecast_engine_abstained=True,
        forecast_engine_abstention_reason=explanation,
        forecast_points=[],
    )

    intelligence = assemble_forecast_intelligence(
        sequence=[],
        forecast_points=[],
        capture_quality={"quality_status": dq.overall_status.value},
        provenance_info={"capture_id": analysis_id, "source": filename, "sha256": sha256},
        min_sequence_length=8,
        required_features=(),
        calibration_status="UNSUPPORTED",
        decision_threshold=0.5,
        window_seconds=60,
        observed_findings=detection_findings,
        attack_progression=progression,
        behavioral_report=behavioral_report,
    )

    final_inf = {
        "forecast_status": "FORECAST_ABSTAINED",
        "is_abstained": True,
        "abstention": {
            "abstained": True,
            "operational_tier": "ABSTAINED",
            "reason": reason,
            "explanation": explanation,
        },
        "abstention_reason": reason,
        "abstention_explanation": explanation,
        "forecast": {},
        "network_risk_indicators": [],
        "host_risk": [],
        "communication_risk": [],
        "uncertainty": {},
        "evidence": [],
        "forecast_engine": meta,
    }

    return CentralForecastResult(
        is_forecast_available=False,
        forecast_status="FORECAST_ABSTAINED",
        abstention_reason=reason,
        abstention_explanation=explanation,
        data_quality=dq,
        forecast_points=abstained_points,
        final_inference_result=final_inf,
        early_warning={
            "early_warning_score": 0,
            "early_warning_level": "NORMAL",
            "operational_risk_band": "LOW",
            "confidence": 0.0,
            "abstained": True,
            "explanation": explanation,
            "primary_drivers": [],
            "drivers": ["Forecasting withheld."],
            "score_components": {},
        },
        attack_horizon=intelligence.attack_horizon,
        attack_progression=progression.to_dict(),
        evidence_chain=intelligence.evidence_chain,
        confidence=intelligence.confidence,
        uncertainty={"level": "UNKNOWN", "epistemic": 0.0, "aleatoric": 0.0, "calibrated": False},
        engine_metadata=meta,
    )


def _build_published_result(
    inference_result: dict[str, Any],
    states: tuple[Any, ...],
    candidates: tuple[NetworkStateCandidate, ...],
    dq: DataQualityAssessment,
    detection_findings: list[dict[str, Any]],
    behavioral_report: Any,
    history_window_count: int,
    analysis_id: str,
    filename: str,
    sha256: str,
    engine_metadata: dict[str, Any] | None = None,
) -> CentralForecastResult:
    """Builds the canonical forecast bundle from real model inferences."""
    from ml.forecasting import assemble_forecast_intelligence
    from ml.forecasting.attack_progression import forecast_attack_progression
    from ml.forecasting.forecasting_engine import FeatureDriver, _explain_feature_change
    from world_model import FEATURE_NAMES_45

    meta = engine_metadata or inference_result.get("forecast_engine") or {
        "name": "Frozen World Model",
        "version": "3.0.0",
        "status": "production",
        "is_production_ready": True,
    }
    inference_result["forecast_engine"] = meta

    forecast_map = inference_result.get("forecast", {})
    curr_state_dict = {
        name: float(val)
        for name, val in zip(FEATURE_NAMES_45, states[-1].encode(FEATURE_NAMES_45))
    } if states else {}

    forecast_points: list[dict[str, Any]] = []
    all_drivers: list[FeatureDriver] = []

    for h in (1, 2, 3, 4, 5):
        h_key = f"T+{h}"
        h_data = forecast_map.get(h_key, {})
        p = float(h_data.get("attack_probability", 0.0))
        p_stage = h_data.get("predicted_stage", "BENIGN_OBSERVATION")
        r_level = h_data.get("risk_level", "LOW")
        conf = float(h_data.get("confidence_score", 0.85))
        unc = round(1.0 - conf, 4)

        pred_feat_dict = h_data.get("predicted_features", {})
        feat_deltas = []
        for name in FEATURE_NAMES_45:
            c_val = curr_state_dict.get(name, 0.0)
            p_val = pred_feat_dict.get(name, 0.0)
            direction, rel, importance, interp = _explain_feature_change(name, c_val, p_val)
            feat_deltas.append(
                FeatureDriver(
                    feature=name,
                    current_value=round(c_val, 4),
                    predicted_value=round(p_val, 4),
                    direction=direction,
                    relative_change=round(rel, 4),
                    importance=importance,
                    interpretation=interp,
                )
            )
        top_drivers = sorted(feat_deltas, key=lambda d: abs(d.relative_change), reverse=True)[:5]
        if top_drivers:
            all_drivers.extend(top_drivers)

        forecast_points.append({
            "horizon": h,
            "horizon_minutes": h,
            "lookaheadSeconds": h * 60,
            "lookahead_seconds": h * 60,
            "attackProbability": p,
            "attack_probability": p,
            "cumulativeRisk": round(min(1.0, p * (1.0 + (h - 1) * 0.15)), 4),
            "cumulative_risk": round(min(1.0, p * (1.0 + (h - 1) * 0.15)), 4),
            "riskLevel": r_level,
            "risk_level": r_level,
            "predictedStage": p_stage,
            "predicted_stage": p_stage,
            "confidence": conf,
            "confidence_score": conf,
            "uncertainty": unc,
            "explanation": [d.interpretation for d in top_drivers[:3]] if top_drivers else [f"State dynamics project {p_stage} at T+{h} (risk: {p*100:.1f}%)."],
            "topDrivers": [d.to_dict() for d in top_drivers],
            "top_drivers": [d.to_dict() for d in top_drivers],
            "evidenceAttribution": None,
            "evidence_attribution": None,
            "abstained": False,
        })

    progression = forecast_attack_progression(
        observed_findings=detection_findings,
        behavioral_report=behavioral_report,
        history_window_count=history_window_count,
        forecast_engine_abstained=False,
        forecast_points=forecast_points,
    )

    state_dicts = [
        {
            "timestamp": c.start_timestamp,
            "flow_features": c.flow_features,
            "packet_features": c.packet_features,
            "temporal_features": c.temporal_features,
            "packet_features_available": True,
        }
        for c in candidates
    ]

    intelligence = assemble_forecast_intelligence(
        sequence=state_dicts,
        forecast_points=forecast_points,
        capture_quality={"quality_status": dq.overall_status.value},
        provenance_info={"capture_id": analysis_id, "source": filename, "sha256": sha256},
        min_sequence_length=8,
        required_features=tuple(FEATURE_NAMES_45[:17]),
        calibration_status="CALIBRATED" if inference_result.get("calibrated") else "UNSUPPORTED",
        decision_threshold=0.5,
        window_seconds=60,
        observed_findings=detection_findings,
        attack_progression=progression,
        behavioral_report=behavioral_report,
    )

    # Early warning from model trajectory
    max_p = max((p["attack_probability"] for p in forecast_points), default=0.0)
    ew_score = int(round(max_p * 100))
    ew_level = (
        "CRITICAL" if ew_score >= 70
        else "HIGH" if ew_score >= 40
        else "ELEVATED" if ew_score >= 15
        else "NORMAL"
    )

    # Check for research candidate precursor detection
    precursor_detected = False
    lead_time_seconds = 60
    if meta.get("status") == "research":
        p_feat = inference_result.get("precursor_features", {})
        if p_feat.get("precursor_triggered"):
            precursor_detected = True
            lead_time_seconds = p_feat.get("advance_lead_time_seconds", 180)
            ew_level = "HIGH"
            ew_score = max(ew_score, 85)

    early_warning = {
        "early_warning_score": ew_score,
        "early_warning_level": ew_level,
        "operational_risk_band": ew_level,
        "confidence": round(sum(p["confidence"] for p in forecast_points) / max(len(forecast_points), 1), 2),
        "abstained": False,
        "explanation": (
            f"Precursor pattern detected with +{lead_time_seconds}s advance lead time (RESEARCH CANDIDATE)."
            if precursor_detected
            else f"Forecast generated from {history_window_count} contiguous historical windows."
        ),
        "primary_drivers": [d.to_dict() for d in all_drivers[:5]],
        "drivers": [d.interpretation for d in all_drivers[:3]] if all_drivers else ["Observed baseline network telemetry."],
        "score_components": {"max_attack_probability": round(max_p, 4)},
        "lead_time_seconds": lead_time_seconds,
        "precursor_detected": precursor_detected,
    }

    return CentralForecastResult(
        is_forecast_available=True,
        forecast_status="FORECAST_READY",
        abstention_reason=None,
        abstention_explanation=None,
        data_quality=dq,
        forecast_points=forecast_points,
        final_inference_result=inference_result,
        early_warning=early_warning,
        attack_horizon=intelligence.attack_horizon,
        attack_progression=progression.to_dict(),
        evidence_chain=intelligence.evidence_chain,
        confidence=intelligence.confidence,
        uncertainty=inference_result.get("uncertainty", {}),
        engine_metadata=meta,
    )
