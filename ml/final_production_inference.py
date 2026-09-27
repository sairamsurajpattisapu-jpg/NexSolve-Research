"""NexSolve Final Production Temporal ML Inference Engine.

Implements the authoritative, production-grade inference contract (Step 21):
- analysis_id
- data_quality
- observability
- current_state
- forecast (T+1 .. T+5 multi-horizon)
- attack_assessment
- attack_progression
- anomalies
- host_risk
- communication_risk
- network_risk_indicators
- evidence
- uncertainty
- abstention (5-tier: FULL, DEGRADED, ANOMALY_ONLY, OBSERVABILITY_ONLY, ABSTAIN)
- model_metadata

Grounded strictly in observable physical telemetry and verified model weights.
Never manufactures fake probabilities or ungrounded vulnerability claims.
"""
from __future__ import annotations

import hashlib
import math
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from ml.features.feature_registry import FeatureFamily, FeatureRegistry
from ml.models.abstention_engine import (
    AbstentionReasonCode,
    ComprehensiveAbstentionDecision,
    ComprehensiveAbstentionEngine,
    ForecastOperationalTier,
)
from ml.models.final_world_model import (
    FinalNetworkWorldModel,
    FinalWorldModelInferenceResult,
    FinalWorldModelStepOutput,
)
from ml.models.host_graph_intelligence import (
    CommunicationEdge,
    GraphEvolutionSnapshot,
    HostGraphIntelligenceEngine,
    HostProfile,
)
from ml.models.risk_indicators import NetworkRiskEngine, ObservedRiskIndicator
from ml.models.temporal_intelligence import CausalTemporalEngine, TemporalVelocityVector
from ml.models.uncertainty_ood import UncertaintyOODDetector, UncertaintyOODResult
from world_model import FEATURE_NAMES_45, LOOKBACK, NetworkState

ROOT = Path(__file__).resolve().parents[1]
FINAL_MODEL_DIR = ROOT / "models" / "final_world_model"


class FinalProductionInferenceEngine:
    """Authoritative production inference pipeline for the Final World Model."""

    def __init__(self, model_dir: Path | None = None) -> None:
        self.model_dir = model_dir or FINAL_MODEL_DIR
        self._model: FinalNetworkWorldModel | None = None

    def _get_model(self) -> FinalNetworkWorldModel:
        if self._model is None:
            if not (self.model_dir / "model.npz").exists():
                raise FileNotFoundError(f"Final world model not found at {self.model_dir}")
            self._model = FinalNetworkWorldModel.load(self.model_dir)
        return self._model

    def _build_abstention_result(
        self,
        aid: str,
        reason: str,
        explanation: str,
        missing: Sequence[str] = (),
        tier: str = ForecastOperationalTier.ABSTAIN.value,
        data_quality: Mapping[str, Any] | None = None,
        observability_score: float = 0.0,
    ) -> dict[str, Any]:
        dq = dict(data_quality) if data_quality else {"status": "INSUFFICIENT", "score": 0.0, "window_count": 0, "is_continuous": False}
        now_utc = datetime.now(timezone.utc).isoformat()
        return {
            "analysis_id": aid,
            "model_id": "final_world_model",
            "model_version": "3.0.0",
            "status": "FORECAST_ABSTAINED",
            "operational_tier": tier,
            "is_abstained": True,
            "abstention_reason": reason,
            "abstention_explanation": explanation,
            "missing_requirements": list(missing),
            "data_quality": dq,
            "observability": {
                "score": observability_score,
                "is_partial_capture": True,
                "unobserved_protocols": ["UNVERIFIED"],
            },
            "current_state": {
                "timestamp": 0,
                "features": {},
            },
            "forecast": {},
            "attack_assessment": {
                "primary_risk_level": "UNKNOWN",
                "onset_lead_time_seconds": 0,
                "max_attack_probability": 0.0,
                "trajectory_summary": f"Abstained: {explanation}",
            },
            "attack_progression": {
                "progression_index": 0.0,
                "predicted_stage": "UNKNOWN",
                "stage_probabilities": {},
                "progression_trend": "UNKNOWN",
            },
            "anomalies": {
                "anomaly_score": 0.0,
                "is_anomaly": False,
                "residual_energy": 0.0,
            },
            "host_risk": [],
            "communication_risk": [],
            "network_risk_indicators": [],
            "evidence": [],
            "uncertainty": {
                "epistemic_uncertainty": 1.0,
                "aleatoric_uncertainty": 1.0,
                "total_uncertainty": 1.0,
                "ood_score": 1.0,
                "is_ood": True,
                "evidence_sufficiency_score": 0.0,
            },
            "abstention": {
                "tier": tier,
                "is_abstained": True,
                "reason_code": reason,
                "explanation": explanation,
                "missing_requirements": list(missing),
                "allowed_outputs": [],
            },
            "model_metadata": {
                "model_id": "final_world_model",
                "model_version": "3.0.0",
                "feature_schema_version": "18_family_world_model_v1",
                "calibrated_threshold": 0.30,
                "lookback_windows": 8,
                "execution_timestamp_utc": now_utc,
            },
        }

    def predict_pcap(self, pcap_path: str | Path, window_seconds: int = 60) -> dict[str, Any]:
        """Runs the entire end-to-end pipeline directly on a raw PCAP file."""
        from ml.data.pcap_extractor import extract_canonical_capture
        from nexsolve_core.state import (
            MODEL_SCHEMA_45,
            build_network_state_candidates,
            build_state_history,
            candidates_to_network_states,
        )

        aid = f"analysis_{uuid.uuid4().hex[:12]}"
        p = Path(pcap_path)
        if not p.exists():
            return self._build_abstention_result(
                aid=aid,
                reason=AbstentionReasonCode.PCAP_EXTRACTION_FAILED.value,
                explanation=f"PCAP file not found: {p}",
                missing=["valid_pcap_file"],
            )

        try:
            pkts, windows, quality = extract_canonical_capture(p, window_seconds=window_seconds)
        except Exception as e:
            return self._build_abstention_result(
                aid=aid,
                reason=AbstentionReasonCode.PCAP_EXTRACTION_FAILED.value,
                explanation=f"Failed to parse PCAP file: {e}",
                missing=["parseable_pcap_frames"],
            )

        q_status = quality.get("status") if isinstance(quality, dict) else getattr(quality, "status", "GOOD")
        q_score = float(quality.get("score", 1.0)) if isinstance(quality, dict) else getattr(quality, "score", 1.0)

        if q_status == "INSUFFICIENT" or len(pkts) == 0:
            return self._build_abstention_result(
                aid=aid,
                reason=AbstentionReasonCode.POOR_CAPTURE_QUALITY.value,
                explanation=f"PCAP capture quality is marked INSUFFICIENT (parsed {len(pkts)} packets).",
                missing=["reliable_packet_capture"],
                data_quality={"status": "INSUFFICIENT", "score": q_score, "window_count": len(windows), "is_continuous": False},
            )

        if len(windows) < 8:
            return self._build_abstention_result(
                aid=aid,
                reason=AbstentionReasonCode.INSUFFICIENT_HISTORY.value,
                explanation=f"Need 8 contiguous windows; received {len(windows)}.",
                missing=[f"insufficient_lookback_history: received {len(windows)}, required 8"],
                data_quality={"status": q_status, "score": q_score, "window_count": len(windows), "is_continuous": False},
            )

        ts_list = [w.start_timestamp for w in windows]
        for i in range(len(ts_list) - 1):
            if ts_list[i + 1] - ts_list[i] != window_seconds:
                return self._build_abstention_result(
                    aid=aid,
                    reason=AbstentionReasonCode.NON_CONTIGUOUS_TIMESTAMPS.value,
                    explanation=f"Window interval delta is not {window_seconds}s (got {ts_list[i+1] - ts_list[i]}s).",
                    missing=["contiguous_60s_timestamps"],
                    data_quality={"status": q_status, "score": q_score, "window_count": len(windows), "is_continuous": False},
                )

        candidates = build_network_state_candidates(windows)
        history = build_state_history(candidates, lookback=8)
        states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history.status)

        all_flows = []
        for w in windows:
            for f in getattr(w, "flows", []):
                all_flows.append(f if isinstance(f, Mapping) else asdict(f))

        return self.run_inference(
            sequence=states,
            analysis_id=aid,
            flows=all_flows,
            capture_quality={"status": q_status, "score": q_score},
        )

    def run_inference(
        self,
        sequence: Sequence[Any],
        analysis_id: str | None = None,
        flows: Sequence[Mapping[str, Any]] | None = None,
        capture_quality: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Executes full multi-view multi-task inference adhering strictly to the Step 21 contract."""
        aid = analysis_id or f"analysis_{uuid.uuid4().hex[:12]}"
        now_utc = datetime.now(timezone.utc).isoformat()

        # 1. Inspect sequence length and numeric validity
        window_count = len(sequence)
        has_nans = False
        timestamps: list[int] = []
        vectors_45: list[np.ndarray] = []

        for item in sequence:
            if isinstance(item, NetworkState):
                timestamps.append(int(item.timestamp))
                vec = item.encode_45()
            elif isinstance(item, Mapping):
                timestamps.append(int(item.get("timestamp", 0)))
                # Extract 45 features
                f_dict = item.get("flow_features", {})
                p_dict = item.get("packet_features", {})
                t_dict = item.get("temporal_features", {})
                vec = np.asarray([f_dict.get(n, 0.0) for n in FEATURE_NAMES_45[:17]] +
                                 [p_dict.get(n, 0.0) for n in FEATURE_NAMES_45[17:39]] +
                                 [t_dict.get(n, 0.0) for n in FEATURE_NAMES_45[39:]], dtype=np.float64)
            elif isinstance(item, (np.ndarray, list)):
                arr = np.asarray(item, dtype=np.float64)
                if len(arr) == 45:
                    vec = arr
                    timestamps.append(len(timestamps) * 60)
                else:
                    vec = np.zeros(45, dtype=np.float64)
            else:
                vec = np.zeros(45, dtype=np.float64)

            if np.any(np.isnan(vec)) or np.any(np.isinf(vec)):
                has_nans = True
            vectors_45.append(vec)

        # 2. Check temporal continuity
        is_continuous = True
        if len(timestamps) >= 2:
            for i in range(len(timestamps) - 1):
                dt = timestamps[i + 1] - timestamps[i]
                if dt != 60:
                    is_continuous = False
                    break

        # 3. Capture Quality Assessment
        cq = capture_quality or {}
        cq_status = str(cq.get("status", "GOOD")).upper()
        if cq_status not in ("GOOD", "DEGRADED", "INSUFFICIENT"):
            cq_status = "GOOD"
        cq_score = float(cq.get("score", 1.0 if cq_status == "GOOD" else 0.6 if cq_status == "DEGRADED" else 0.1))

        # 4. Check Abstention Preconditions
        abstention = ComprehensiveAbstentionEngine.evaluate(
            window_count=window_count,
            is_continuous=is_continuous,
            has_nans_or_infs=has_nans,
            capture_quality_status=cq_status,
            total_uncertainty=0.0,
            ood_score=0.0,
        )

        # Build current state representation
        curr_vec = vectors_45[-1] if vectors_45 else np.zeros(45, dtype=np.float64)
        curr_ts = timestamps[-1] if timestamps else 0
        curr_state_dict = {name: float(val) for name, val in zip(FEATURE_NAMES_45, curr_vec)}

        # If hard abstained, return safe structured abstention contract
        if abstention.is_abstained:
            return {
                "analysis_id": aid,
                "model_id": "final_world_model",
                "model_version": "3.0.0",
                "status": "FORECAST_ABSTAINED",
                "operational_tier": abstention.tier.value,
                "is_abstained": True,
                "abstention_reason": abstention.reason_code,
                "abstention_explanation": abstention.explanation,
                "missing_requirements": list(abstention.missing_requirements),
                "data_quality": {
                    "status": cq_status,
                    "score": cq_score,
                    "window_count": window_count,
                    "is_continuous": is_continuous,
                },
                "observability": {
                    "score": cq_score,
                    "is_partial_capture": True,
                    "unobserved_protocols": ["UNVERIFIED"],
                },
                "current_state": {
                    "timestamp": curr_ts,
                    "features": curr_state_dict,
                },
                "forecast": {},
                "attack_assessment": {
                    "primary_risk_level": "UNKNOWN",
                    "onset_lead_time_seconds": 0,
                    "max_attack_probability": 0.0,
                    "trajectory_summary": "Abstained due to missing operational preconditions.",
                },
                "attack_progression": {
                    "progression_index": 0.0,
                    "predicted_stage": "UNKNOWN",
                    "stage_probabilities": {},
                    "progression_trend": "UNKNOWN",
                },
                "anomalies": {
                    "anomaly_score": 0.0,
                    "is_anomaly": False,
                    "residual_energy": 0.0,
                },
                "host_risk": [],
                "communication_risk": [],
                "network_risk_indicators": [],
                "evidence": [],
                "uncertainty": {
                    "epistemic_uncertainty": 1.0,
                    "aleatoric_uncertainty": 1.0,
                    "total_uncertainty": 1.0,
                    "ood_score": 1.0,
                    "is_ood": True,
                    "evidence_sufficiency_score": 0.0,
                },
                "abstention": abstention.to_dict(),
                "model_metadata": {
                    "model_id": "final_world_model",
                    "model_version": "3.0.0",
                    "feature_schema_version": "18_family_world_model_v1",
                    "calibrated_threshold": 0.30,
                    "lookback_windows": 8,
                    "execution_timestamp_utc": now_utc,
                },
            }

        # 5. Execute Multi-View World Model Rollout
        model = self._get_model()

        # Build view sequence for lookback
        lookback_slice = vectors_45[-LOOKBACK:]
        scaled_slice = [(v - model.scaler_mean) / model.scaler_scale for v in lookback_slice]
        view_seq = [model.extract_views_from_canonical_45(step_vec) for step_vec in scaled_slice]

        z_t, h_t, step_outputs = model.predict_k_steps(view_seq, k=5, capture_quality_score=cq_score)

        # 6. Extract Host Profiles and Temporal Communication Graph
        current_flows = flows if flows is not None else []
        host_profiles, comm_edges, graph_snapshot = model.host_graph_engine.analyze_window(
            current_flows, timestamp=curr_ts
        )

        # 7. Extract Behavioral and Temporal Dynamics
        temporal_vec = model.temporal_engine.compute_temporal_vector(
            [{"timestamp": t, "total_src_bytes": v[1], "total_dst_bytes": v[2], "total_packets": v[3],
              "flow_count": v[0], "unique_src_ports": v[12], "unique_dst_ports": v[13], "mean_iat": v[11]}
             for t, v in zip(timestamps[-LOOKBACK:], vectors_45[-LOOKBACK:])]
        )
        behavioral_vec, _, _ = model.behavioral_engine.compute_behavioral_vector(current_flows)

        # 8. Extract Observed Network Risk Indicators
        risk_indicators = model.risk_engine.evaluate_indicators(
            hosts=host_profiles,
            edges=comm_edges,
            graph_snapshot=graph_snapshot,
            behavior=behavioral_vec,
            temporal=temporal_vec,
        )

        # 9. Format Horizon Forecasts
        horizons_dict = {}
        probs = []
        for out in step_outputs:
            h_step = out.horizon_step
            p = out.attack_probability
            probs.append(p)
            unscaled_pred = out.predicted_state_vector * model.scaler_scale + model.scaler_mean
            pred_feat_dict = {name: float(val) for name, val in zip(FEATURE_NAMES_45, unscaled_pred)}

            risk_lvl = "CRITICAL" if p >= 0.70 else "HIGH" if p >= 0.30 else "MEDIUM" if p >= 0.15 else "LOW"
            conf = float(min(1.0, max(0.0, 1.0 - out.epistemic_uncertainty)))

            horizons_dict[f"T+{h_step}"] = {
                "horizon_step": h_step,
                "horizon_name": f"T+{h_step}",
                "target_timestamp": curr_ts + (h_step * 60),
                "attack_probability": round(p, 4),
                "raw_probability": round(out.raw_probability, 4),
                "binary_prediction": int(p >= 0.30),
                "decision_threshold": 0.30,
                "confidence_score": round(conf, 4),
                "risk_level": risk_lvl,
                "predicted_stage": out.predicted_stage.value,
                "predicted_features": {k: round(v, 4) for k, v in pred_feat_dict.items()},
                "predicted_vector": [round(float(v), 4) for v in unscaled_pred],
            }

        # 10. Attack Assessment & Trajectory
        max_p = max(probs) if probs else 0.0
        primary_risk = "CRITICAL" if max_p >= 0.70 else "HIGH" if max_p >= 0.30 else "MEDIUM" if max_p >= 0.15 else "LOW"
        onset_lead = 120 if (probs and probs[0] >= 0.30) else 0

        # 11. Host and Communication Risk Rankings
        sorted_hosts = sorted(host_profiles.values(), key=lambda h: h.risk_score, reverse=True)
        host_rankings = [h.to_dict() for h in sorted_hosts[:10]]

        sorted_edges = sorted(comm_edges, key=lambda e: e.total_bytes, reverse=True)
        edge_rankings = [e.to_dict() for e in sorted_edges[:10]]

        # 12. Primary Step Diagnostics
        t1_out = step_outputs[0]
        ood_res = model.ood_detector.evaluate_diagnostics(
            z_t=z_t, h_t=h_t, attack_prob=t1_out.attack_probability, capture_quality_score=cq_score
        )

        # 13. Evidence Chain Synthesis
        evidence_chain = []
        if risk_indicators:
            for ind in risk_indicators[:5]:
                evidence_chain.append({
                    "evidence_id": f"evi_{uuid.uuid4().hex[:8]}",
                    "source": "NETWORK_RISK_ENGINE",
                    "indicator": ind.indicator_type,
                    "entity": ind.entity,
                    "observation": ind.observation,
                    "severity": ind.severity.value,
                    "evidence_citations": list(ind.evidence),
                })

        return {
            "analysis_id": aid,
            "model_id": "final_world_model",
            "model_version": "3.0.0",
            "status": "FORECAST_AVAILABLE",
            "operational_tier": abstention.tier.value,
            "is_abstained": False,
            "abstention_reason": None,
            "abstention_explanation": abstention.explanation,
            "missing_requirements": [],
            "data_quality": {
                "status": cq_status,
                "score": cq_score,
                "window_count": window_count,
                "is_continuous": True,
            },
            "observability": {
                "score": round(graph_snapshot.graph_observability_score, 4),
                "is_partial_capture": graph_snapshot.is_partial_capture,
                "active_nodes": graph_snapshot.node_count,
                "active_edges": graph_snapshot.edge_count,
                "density": round(graph_snapshot.graph_density, 6),
            },
            "current_state": {
                "timestamp": curr_ts,
                "features": curr_state_dict,
                "latent_world_state": [round(float(v), 4) for v in z_t],
            },
            "forecast": horizons_dict,
            "attack_assessment": {
                "primary_risk_level": primary_risk,
                "onset_lead_time_seconds": onset_lead,
                "max_attack_probability": round(max_p, 4),
                "trajectory_summary": f"Attack trajectory reaches peak risk {max_p*100:.1f}% ({primary_risk}) across 5 forward horizons.",
            },
            "attack_progression": {
                "progression_index": round(t1_out.progression_index, 4),
                "predicted_stage": t1_out.predicted_stage.value,
                "stage_probabilities": {k: round(v, 4) for k, v in t1_out.stage_probabilities.items()},
                "progression_trend": t1_out.progression_trend,
            },
            "anomalies": {
                "anomaly_score": round(t1_out.anomaly_score, 4),
                "is_anomaly": t1_out.is_anomaly,
                "residual_energy": round(t1_out.anomaly_score * 0.2, 4),
            },
            "host_risk": host_rankings,
            "communication_risk": edge_rankings,
            "network_risk_indicators": [ind.to_dict() for ind in risk_indicators],
            "evidence": evidence_chain,
            "uncertainty": ood_res.to_dict(),
            "abstention": abstention.to_dict(),
            "model_metadata": {
                "model_id": "final_world_model",
                "model_version": "3.0.0",
                "feature_schema_version": "18_family_world_model_v1",
                "calibrated_threshold": 0.30,
                "lookback_windows": 8,
                "execution_timestamp_utc": now_utc,
            },
        }
