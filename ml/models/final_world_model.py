"""NexSolve Final Network World Model Architecture.

Unifies representation learning, temporal dynamics, dynamic graph topologies,
multi-task forecasting, calibrated uncertainty, risk indicators, and abstention:

RAW TELEMETRY / PCAP
        |
INGESTION + QUALITY ASSESSMENT
        |
PACKET / FLOW / PROTOCOL / HOST / TEMPORAL / GRAPH / OBSERVABILITY VIEWS
        |
MULTI-VIEW ENCODERS
        |
CROSS-VIEW FUSION
        |
NETWORK WORLD STATE Z_t
        |
RECURRENT TEMPORAL ACCUMULATOR h_t
        |
+-----------------------------------------------------------+
|                                                           |
|-- Future State Forecast (T+1 .. T+5 continuous state)    |
|-- Forward Attack Probability (calibrated sigmoid)        |
|-- Attack Stage Estimation (MITRE 6-stage taxonomy)       |
|-- Attack Progression Trajectory                          |
|-- Anomaly Detection (latent reconstruction residual)     |
|-- Novelty / OOD Detection (Mahalanobis envelope)         |
|-- Host Risk & Edge Risk                                  |
|-- Observed Network Risk Indicators                       |
|-- Uncertainty & Observability Decomposition              |
+-----------------------------------------------------------+
        |
EVIDENCE SYNTHESIS ENGINE
        |
5-TIER ABSTENTION ENGINE (FULL, DEGRADED, ANOMALY, OBS, ABSTAIN)
        |
FINAL STRUCTURED NETWORK INTELLIGENCE
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from ml.features.feature_registry import FeatureFamily, FeatureRegistry
from ml.models.abstention_engine import (
    ComprehensiveAbstentionDecision,
    ComprehensiveAbstentionEngine,
    ForecastOperationalTier,
)
from ml.models.behavioral_intelligence import BehavioralEngine, BehavioralVector
from ml.models.host_graph_intelligence import (
    CommunicationEdge,
    GraphEvolutionSnapshot,
    HostGraphIntelligenceEngine,
    HostProfile,
)
from ml.models.multi_task_heads import (
    AttackStageName,
    MultiTaskDecoders,
    MultiTaskPredictionOutput,
)
from ml.models.risk_indicators import NetworkRiskEngine, ObservedRiskIndicator
from ml.models.temporal_intelligence import CausalTemporalEngine, TemporalVelocityVector
from ml.models.uncertainty_ood import UncertaintyOODDetector, UncertaintyOODResult


@dataclass(frozen=True)
class FinalWorldModelStepOutput:
    """Full structured intelligence for an individual forward forecast horizon."""
    horizon_step: int
    attack_probability: float
    raw_probability: float
    predicted_state: dict[str, float]
    predicted_vector: tuple[float, ...]
    predicted_stage: str
    stage_probabilities: dict[str, float]
    progression_index: float
    progression_trend: str
    anomaly_score: float
    is_anomaly: bool
    ood_score: float
    is_ood: bool
    epistemic_uncertainty: float
    aleatoric_uncertainty: float
    confidence_score: float
    risk_level: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon_step": self.horizon_step,
            "attack_probability": round(self.attack_probability, 4),
            "raw_probability": round(self.raw_probability, 4),
            "predicted_state": {k: round(v, 4) for k, v in self.predicted_state.items()},
            "predicted_vector": [round(v, 4) for v in self.predicted_vector],
            "predicted_stage": self.predicted_stage,
            "stage_probabilities": {k: round(v, 4) for k, v in self.stage_probabilities.items()},
            "progression_index": round(self.progression_index, 4),
            "progression_trend": self.progression_trend,
            "anomaly_score": round(self.anomaly_score, 4),
            "is_anomaly": self.is_anomaly,
            "ood_score": round(self.ood_score, 4),
            "is_ood": self.is_ood,
            "epistemic_uncertainty": round(self.epistemic_uncertainty, 4),
            "aleatoric_uncertainty": round(self.aleatoric_uncertainty, 4),
            "confidence_score": round(self.confidence_score, 4),
            "risk_level": self.risk_level,
        }


@dataclass(frozen=True)
class FinalWorldModelInferenceResult:
    """Authoritative structured output from the Final Network World Model."""
    analysis_id: str
    model_id: str
    model_version: str
    status: str
    operational_tier: str
    is_abstained: bool
    abstention_reason: str | None
    abstention_explanation: str
    missing_requirements: tuple[str, ...]
    data_quality_score: float
    observability_score: float
    evidence_sufficiency_score: float
    current_world_state: tuple[float, ...]
    horizons: dict[str, FinalWorldModelStepOutput]
    host_risk_rankings: tuple[dict[str, Any], ...]
    edge_risk_rankings: tuple[dict[str, Any], ...]
    observed_risk_indicators: tuple[dict[str, Any], ...]
    evidence_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "model_id": self.model_id,
            "model_version": self.model_version,
            "status": self.status,
            "operational_tier": self.operational_tier,
            "is_abstained": self.is_abstained,
            "abstention_reason": self.abstention_reason,
            "abstention_explanation": self.abstention_explanation,
            "missing_requirements": list(self.missing_requirements),
            "data_quality_score": round(self.data_quality_score, 4),
            "observability_score": round(self.observability_score, 4),
            "evidence_sufficiency_score": round(self.evidence_sufficiency_score, 4),
            "current_world_state": [round(v, 4) for v in self.current_world_state],
            "horizons": {k: v.to_dict() for k, v in self.horizons.items()},
            "host_risk_rankings": list(self.host_risk_rankings),
            "edge_risk_rankings": list(self.edge_risk_rankings),
            "observed_risk_indicators": list(self.observed_risk_indicators),
            "evidence_summary": self.evidence_summary,
        }


class FinalNetworkWorldModel:
    """Unified Final Network World Model implementing multi-view encoders and multi-task heads."""

    def __init__(
        self,
        d_z: int = 32,
        hidden_dim: int = 32,
        state_dim: int = 45,
        seed: int = 42,
        enabled_views: set[str] | None = None,
    ) -> None:
        from ml.models.world_model_encoders import MultiViewEncoders, RecurrentWorldStateAccumulator

        self.d_z = d_z
        self.hidden_dim = hidden_dim
        self.state_dim = state_dim
        self.seed = seed

        # Submodules
        self.encoders = MultiViewEncoders(d_z=d_z, seed=seed, enabled_views=enabled_views)
        self.accumulator = RecurrentWorldStateAccumulator(input_dim=d_z, hidden_dim=hidden_dim, seed=seed)
        self.decoders = MultiTaskDecoders(hidden_dim=hidden_dim, state_dim=state_dim, seed=seed)
        self.temporal_engine = CausalTemporalEngine()
        self.behavioral_engine = BehavioralEngine()
        self.host_graph_engine = HostGraphIntelligenceEngine()
        self.risk_engine = NetworkRiskEngine()
        self.ood_detector = UncertaintyOODDetector(feature_dim=d_z)

        # Canonical 45-feature schema names
        from world_model import FEATURE_NAMES_45
        self.feature_names_45 = list(FEATURE_NAMES_45)

        # Scaler
        self.scaler_mean = np.zeros(state_dim, dtype=np.float64)
        self.scaler_scale = np.ones(state_dim, dtype=np.float64)

    def extract_views_from_canonical_45(
        self,
        vector_45: np.ndarray,
        temporal_velocity: np.ndarray | None = None,
    ) -> dict[str, np.ndarray]:
        """Maps canonical 45-feature vector into structured multi-view inputs with explicit missingness."""
        flow_vec = vector_45[:17]
        pkt_vec = vector_45[17:39]
        temp_vec_base = vector_45[39:45]

        # Combine with temporal velocity if provided
        if temporal_velocity is not None and len(temporal_velocity) >= 10:
            temp_vec = temporal_velocity[:10]
        else:
            temp_vec = np.pad(temp_vec_base, (0, max(0, 10 - len(temp_vec_base))))

        # Derived protocol metrics from flow/packet features (16 dims)
        tcp_cnt = float(flow_vec[14])
        udp_cnt = float(flow_vec[15])
        other_cnt = float(flow_vec[16])
        n_flows = max(1.0, float(flow_vec[0]))
        n_pkts = max(1.0, float(pkt_vec[0]))

        proto_vec = np.zeros(16, dtype=np.float64)
        proto_vec[0] = pkt_vec[9] / max(1.0, pkt_vec[10])   # syn/ack ratio
        proto_vec[1] = pkt_vec[12] / n_flows                # rst ratio
        proto_vec[2] = pkt_vec[11] / n_flows                # fin ratio
        proto_vec[3] = (pkt_vec[13] + pkt_vec[14]) / n_pkts # psh/urg ratio
        proto_vec[4] = udp_cnt
        proto_vec[5] = udp_cnt / max(1.0, flow_vec[3])      # udp packet ratio
        proto_vec[6] = tcp_cnt / n_flows                    # tcp flow fraction
        proto_vec[7] = udp_cnt / n_flows                    # udp flow fraction
        proto_vec[8] = other_cnt / n_flows                  # other proto fraction

        # Observability and explicit missingness flags (10 dims)
        obs_vec = np.zeros(10, dtype=np.float64)
        obs_vec[0] = 1.0  # complete canonical
        obs_vec[1] = 0.0  # no truncation
        obs_vec[2] = 1.0  # sensor coverage
        obs_vec[3] = 0.0 if tcp_cnt > 0 else 1.0    # is tcp missing
        obs_vec[4] = 0.0 if udp_cnt > 0 else 1.0    # is udp missing
        obs_vec[5] = 1.0  # is dns unobserved (missing)
        obs_vec[6] = 1.0  # is tls unobserved (missing)
        obs_vec[7] = 1.0  # is http unobserved (missing)
        obs_vec[8] = 1.0  # is raw graph unobserved (missing)
        obs_vec[9] = 0.0 if np.any(pkt_vec > 0) else 1.0 # is packet missing

        # Host view (5 dims): derived directly from port and flow cardinality
        u_src = float(flow_vec[12])
        u_dst = float(flow_vec[13])
        host_vec = np.array([
            u_src + u_dst,                                   # active endpoints lower bound
            u_src,                                           # unique source ports
            u_dst,                                           # unique destination ports
            u_src / max(1.0, u_dst),                         # port asymmetry ratio
            n_flows / max(1.0, u_dst),                       # concentration per server port
        ], dtype=np.float64)

        # Graph view (11 dims): when graph is unobserved from vector_45 alone,
        # emit exact cardinality projections with is_graph_unobserved=1.0 in obs_vec
        # (Zero arbitrary constant padding)
        graph_vec = np.zeros(11, dtype=np.float64)
        graph_vec[0] = u_src + u_dst                        # estimated active nodes
        graph_vec[1] = n_flows                              # active communication edges
        graph_vec[2] = min(1.0, n_flows / max(1.0, (u_src + u_dst) ** 2)) # estimated graph density
        graph_vec[3] = n_flows / max(1.0, u_src + u_dst)    # mean degree estimate
        # Dims [4..10] (betweenness, edge churn, node churn) are unobserved and kept at 0.0
        # with obs_vec[8]=1.0 (is_graph_unobserved)

        # Behavioral view (12 dims): derived from verifiable flow/packet ratios
        # (Zero arbitrary constant padding)
        tot_bytes = float(flow_vec[1]) + float(flow_vec[2])
        beh_vec = np.zeros(12, dtype=np.float64)
        beh_vec[0] = u_src / n_flows                        # src port diversity
        beh_vec[1] = u_dst / n_flows                        # dst port diversity
        beh_vec[2] = float(flow_vec[1]) / max(1.0, float(flow_vec[2])) # src/dst byte asymmetry
        beh_vec[3] = tot_bytes / max(1.0, float(flow_vec[3])) # bytes per packet
        beh_vec[4] = float(pkt_vec[1]) / max(1.0, float(pkt_vec[0])) # packet size variance ratio
        beh_vec[5] = float(pkt_vec[19]) / max(1.0, float(pkt_vec[18])) # IAT variance ratio
        beh_vec[6] = float(flow_vec[4])                     # mean flow duration
        beh_vec[7] = float(pkt_vec[9]) / n_flows            # syn to flow ratio
        beh_vec[8] = float(pkt_vec[12]) / n_flows           # rst to flow ratio

        return {
            "flow": flow_vec,
            "packet": pkt_vec,
            "protocol": proto_vec,
            "temporal": temp_vec,
            "host": host_vec,
            "graph": graph_vec,
            "behavior": beh_vec,
            "observability": obs_vec,
        }

    def forward_sequence(
        self,
        sequence_of_views: Sequence[Mapping[str, np.ndarray]],
    ) -> tuple[np.ndarray, np.ndarray, list[np.ndarray]]:
        """Processes lookback sequence of multi-view windows -> final (Z_t, h_t, z_trajectory)."""
        z_seq = []
        for views in sequence_of_views:
            z_t = self.encoders.encode_and_fuse(views)
            z_seq.append(z_t)

        z_matrix = np.asarray(z_seq)
        h_final, c_final, _ = self.accumulator.forward_sequence(z_matrix)
        return z_matrix[-1], h_final, z_seq

    def predict_k_steps(
        self,
        sequence_of_views: Sequence[Mapping[str, np.ndarray]],
        k: int = 5,
        capture_quality_score: float = 1.0,
    ) -> tuple[np.ndarray, np.ndarray, list[MultiTaskPredictionOutput]]:
        """Performs recursive or direct multi-step forecasting across K forward horizons."""
        z_t, h_t, _ = self.forward_sequence(sequence_of_views)

        outputs: list[MultiTaskPredictionOutput] = []
        curr_h = h_t.copy()
        curr_z = z_t.copy()

        for step in range(1, k + 1):
            out = self.decoders.predict_single_step(
                curr_h,
                horizon_step=step,
                observability_score=capture_quality_score,
            )
            outputs.append(out)

            # Roll recurrent state forward for step + 1
            # Unscale predicted state to derive projected next latent state
            pred_unscaled = out.predicted_state_vector * self.scaler_scale + self.scaler_mean
            next_views = self.extract_views_from_canonical_45(pred_unscaled)
            next_z = self.encoders.encode_and_fuse(next_views)
            curr_h, _ = self.accumulator.forward_step(next_z, curr_h, np.zeros_like(curr_h))

        return z_t, h_t, outputs

    def save(self, checkpoint_dir: Path) -> None:
        """Saves model weights, matrices, and parameters."""
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        # Weights archive
        weights_dict = {
            "d_z": np.array([self.d_z]),
            "hidden_dim": np.array([self.hidden_dim]),
            "state_dim": np.array([self.state_dim]),
            "W_fuse": self.encoders.W_fuse,
            "b_fuse": self.encoders.b_fuse,
            "W_gate": self.encoders.W_gate,
            "b_gate": self.encoders.b_gate,
            "W_acc": self.accumulator.W,
            "b_acc": self.accumulator.b,
            "W_state": self.decoders.W_state,
            "b_state": self.decoders.b_state,
            "W_attack": self.decoders.W_attack,
            "b_attack": self.decoders.b_attack,
            "W_stage": self.decoders.W_stage,
            "b_stage": self.decoders.b_stage,
            "W_prog": self.decoders.W_prog,
            "b_prog": self.decoders.b_prog,
            "W_recon": self.decoders.W_recon,
            "b_recon": self.decoders.b_recon,
            "W_unc": self.decoders.W_unc,
            "b_unc": self.decoders.b_unc,
            "temperature": np.array([self.decoders.temperature]),
            "threshold": np.array([self.decoders.threshold]),
        }
        # Add encoder linear weights
        for vname, enc in self.encoders.encoders.items():
            weights_dict[f"enc_{vname}_W"] = enc.W
            weights_dict[f"enc_{vname}_b"] = enc.b

        np.savez_compressed(checkpoint_dir / "model.npz", **weights_dict)

        # Scaler parameters
        np.savez_compressed(
            checkpoint_dir / "preprocessing.npz",
            mean=self.scaler_mean,
            scale=self.scaler_scale,
        )

    @classmethod
    def load(cls, checkpoint_dir: Path) -> "FinalNetworkWorldModel":
        """Loads model checkpoint from disk."""
        data = np.load(checkpoint_dir / "model.npz")
        prep = np.load(checkpoint_dir / "preprocessing.npz")

        d_z = int(data["d_z"][0])
        h_dim = int(data["hidden_dim"][0])
        s_dim = int(data["state_dim"][0])

        model = cls(d_z=d_z, hidden_dim=h_dim, state_dim=s_dim)
        model.encoders.W_fuse = data["W_fuse"]
        model.encoders.b_fuse = data["b_fuse"]
        model.encoders.W_gate = data["W_gate"]
        model.encoders.b_gate = data["b_gate"]

        for vname, enc in model.encoders.encoders.items():
            if f"enc_{vname}_W" in data:
                enc.W = data[f"enc_{vname}_W"]
                enc.b = data[f"enc_{vname}_b"]

        model.accumulator.W = data["W_acc"]
        model.accumulator.b = data["b_acc"]

        model.decoders.W_state = data["W_state"]
        model.decoders.b_state = data["b_state"]
        model.decoders.W_attack = data["W_attack"]
        model.decoders.b_attack = data["b_attack"]
        model.decoders.W_stage = data["W_stage"]
        model.decoders.b_stage = data["b_stage"]
        model.decoders.W_prog = data["W_prog"]
        model.decoders.b_prog = data["b_prog"]
        model.decoders.W_recon = data["W_recon"]
        model.decoders.b_recon = data["b_recon"]
        model.decoders.W_unc = data["W_unc"]
        model.decoders.b_unc = data["b_unc"]
        model.decoders.temperature = float(data["temperature"][0])
        model.decoders.threshold = float(data["threshold"][0])

        model.scaler_mean = prep["mean"]
        model.scaler_scale = prep["scale"]

        return model
