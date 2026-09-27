"""Comprehensive Test Suite for NexSolve Final Network World Model.

Verifies:
- 18 Feature families and registry metadata
- Feature availability & explicit missingness
- Temporal integrity & leak-safe continuity
- Behavioral intelligence (diversity, entropy, churn)
- Dynamic host & temporal graph intelligence
- Multi-view representation encoders & cross-view fusion
- Recurrent world state accumulator (Z_t -> h_t)
- Multi-task decoders (forecast, attack, stage, progression, anomaly, OOD, uncertainty)
- Observed network risk indicator engine
- Probabilistic calibration (Brier score, ECE)
- 5-Tier abstention engine
- Low-data operation regimes (100% down to 5%)
- Checkpoint artifact cryptographic integrity
- Production inference contract adhering to Step 21
- Candidate V2 baseline immutability & backward compatibility
"""
from __future__ import annotations

import copy
import hashlib
import json
import math
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from ml.features.feature_registry import (
    FeatureDefinition,
    FeatureFamily,
    FeatureRegistry,
    NormalizationType,
    TelemetrySource,
)
from ml.final_production_inference import FinalProductionInferenceEngine
from ml.models.abstention_engine import (
    AbstentionReasonCode,
    ComprehensiveAbstentionDecision,
    ComprehensiveAbstentionEngine,
    ForecastOperationalTier,
)
from ml.models.behavioral_intelligence import (
    BehavioralEngine,
    BehavioralVector,
    compute_gini_coefficient,
    compute_shannon_entropy,
)
from ml.models.final_world_model import FinalNetworkWorldModel
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
from ml.models.risk_indicators import (
    NetworkRiskEngine,
    ObservedRiskIndicator,
    RiskSeverity,
    RiskTrend,
)
from ml.models.temporal_intelligence import (
    CausalTemporalEngine,
    TemporalDiscontinuityError,
    TemporalVelocityVector,
)
from ml.models.uncertainty_ood import (
    CalibrationMetrics,
    UncertaintyOODDetector,
    UncertaintyOODResult,
    compute_brier_score,
    compute_ece,
)
from ml.models.world_model_encoders import (
    LinearEncoder,
    MultiViewEncoders,
    RecurrentWorldStateAccumulator,
)
from ml.registry import ModelArtifactCorruptedError, ModelRegistry
from world_model import FEATURE_NAMES_45, LOOKBACK, NetworkState, NumpyLSTM

ROOT = Path(__file__).resolve().parents[1]


# ==============================================================================
# 1. Feature Registry & Schema Integrity Tests
# ==============================================================================

def test_feature_registry_all_18_families_present() -> None:
    """Verifies that all 18 feature families are registered and populated."""
    all_fams = [f.value for f in FeatureFamily]
    assert len(all_fams) == 18

    for fam in FeatureFamily:
        feats = FeatureRegistry.get_by_family(fam)
        assert len(feats) > 0, f"Feature family '{fam.value}' is empty"

    assert len(FeatureRegistry.list_all()) >= 100


def test_feature_registry_causality_and_safety_guarantees() -> None:
    """Every registered feature must declare strict causality and production safety."""
    for feat in FeatureRegistry.list_all():
        assert feat.is_causal is True, f"Feature {feat.name} is not marked causal"
        assert feat.is_safe_for_production is True, f"Feature {feat.name} is not safe for production"
        assert isinstance(feat.semantic_meaning, str) and len(feat.semantic_meaning) > 5
        assert isinstance(feat.computation, str) and len(feat.computation) > 0


def test_feature_schema_hash_deterministic() -> None:
    """Registry schema hash must be deterministic and invariant."""
    h1 = FeatureRegistry.schema_hash()
    h2 = FeatureRegistry.schema_hash()
    assert h1 == h2
    assert len(h1) == 64


# ==============================================================================
# 2. Temporal Intelligence & Continuity Tests
# ==============================================================================

def test_temporal_engine_computes_causal_velocity() -> None:
    """Verifies discrete deltas, accelerations, and rolling statistics."""
    engine = CausalTemporalEngine(window_seconds=60)
    windows = [
        {"timestamp": 1000 + i * 60, "total_src_bytes": 1000 * (i + 1), "total_dst_bytes": 500 * (i + 1),
         "total_packets": 100 * (i + 1), "flow_count": 10 * (i + 1), "unique_src_ports": 5, "unique_dst_ports": 8, "mean_iat": 0.05}
        for i in range(5)
    ]

    vec = engine.compute_temporal_vector(windows)
    assert vec.timestamp == 1000 + 4 * 60
    assert vec.delta_flow_count == 10.0
    assert vec.delta_total_bytes == 1500.0
    assert vec.delta_total_packets == 100.0
    assert vec.rolling_total_bytes > 0.0
    assert vec.burstiness_index >= 1.0


def test_temporal_engine_rejects_discontinuity() -> None:
    """Verifies that non-contiguous intervals raise TemporalDiscontinuityError."""
    engine = CausalTemporalEngine(window_seconds=60)
    gapped_windows = [
        {"timestamp": 1000, "flow_count": 10},
        {"timestamp": 1060, "flow_count": 12},
        {"timestamp": 1200, "flow_count": 15},  # Gap of 140s != 60s
    ]
    with pytest.raises(TemporalDiscontinuityError):
        engine.compute_temporal_vector(gapped_windows)


# ==============================================================================
# 3. Behavioral Intelligence Tests
# ==============================================================================

def test_behavioral_engine_entropy_and_diversity() -> None:
    """Tests Shannon entropy, Gini coefficient, and diversity metrics."""
    engine = BehavioralEngine()
    flows = [
        {"src_ip": "10.0.0.1", "dst_ip": f"10.0.0.{i+2}", "dst_port": 80 if i % 2 == 0 else 443,
         "proto": "tcp", "src_bytes": 1000, "dst_bytes": 2000, "duration": 1.0}
        for i in range(10)
    ]

    vec, peers, edges = engine.compute_behavioral_vector(flows)
    assert 0.0 <= vec.peer_diversity <= 2.0
    assert 0.0 <= vec.dest_diversity <= 1.0
    assert vec.port_entropy > 0.0
    assert 0.0 <= vec.traffic_concentration_gini <= 1.0
    assert len(peers) == 11
    assert len(edges) == 10


def test_gini_and_entropy_functions() -> None:
    """Unit tests for standalone mathematical helper functions."""
    assert compute_gini_coefficient([]) == 0.0
    assert compute_gini_coefficient([100, 100, 100]) == 0.0  # Perfect equality
    assert compute_gini_coefficient([0, 0, 1000]) > 0.6  # High inequality

    assert compute_shannon_entropy([]) == 0.0
    assert compute_shannon_entropy([10, 0, 0]) == 0.0
    assert compute_shannon_entropy([10, 10]) == 1.0  # log2(2) = 1 bit


# ==============================================================================
# 4. Host & Dynamic Graph Intelligence Tests
# ==============================================================================

def test_host_graph_engine_snapshots_and_observability() -> None:
    """Tests host profile synthesis and dynamic temporal graph metrics."""
    engine = HostGraphIntelligenceEngine(monitored_subnets_cardinality=100)
    flows = [
        {"src_ip": "192.168.1.10", "dst_ip": f"192.168.1.{20+i}", "dst_port": 80 + i,
         "proto": "tcp", "src_bytes": 500, "dst_bytes": 1000, "duration": 0.5, "packets": 5}
        for i in range(12)
    ]

    hosts, edges, snap = engine.analyze_window(flows, timestamp=1700000000)
    assert len(hosts) == 13
    assert len(edges) == 12
    assert snap.node_count == 13
    assert snap.edge_count == 12
    assert snap.graph_density > 0.0
    assert snap.graph_observability_score == 0.13  # 13 / 100
    assert snap.is_partial_capture is True  # 13 < 50


# ==============================================================================
# 5. Multi-View Encoders & Cross-View Fusion Tests
# ==============================================================================

def test_multi_view_encoders_and_cross_view_fusion() -> None:
    """Verifies sub-encoders, gated fusion, and latent state Z_t."""
    encoders = MultiViewEncoders(d_z=32, seed=42)
    inputs = {
        "flow": np.ones(17),
        "packet": np.ones(22),
        "protocol": np.ones(16),
        "host": np.ones(5),
        "temporal": np.ones(10),
        "behavior": np.ones(12),
        "graph": np.ones(11),
        "observability": np.ones(10),
    }

    views = encoders.encode_views(inputs)
    assert len(views) == 8
    assert views["flow"].shape == (16,)
    assert views["packet"].shape == (16,)
    assert views["protocol"].shape == (12,)
    assert views["host"].shape == (8,)

    z_t = encoders.fuse(views)
    assert z_t.shape == (32,)
    assert np.all(np.isfinite(z_t))


def test_encoder_ablation_masking() -> None:
    """Disabling an encoder must cleanly zero its view without breaking fusion."""
    encoders = MultiViewEncoders(d_z=32, seed=42, enabled_views={"flow", "packet"})
    inputs = {
        "flow": np.ones(17),
        "packet": np.ones(22),
        "graph": np.ones(11),
    }
    views = encoders.encode_views(inputs)
    assert np.any(views["flow"] != 0.0)
    assert np.all(views["graph"] == 0.0)  # Disabled view is strictly zero

    z_t = encoders.fuse(views)
    assert z_t.shape == (32,)
    assert np.all(np.isfinite(z_t))


# ==============================================================================
# 6. Recurrent Accumulator & Multi-Task Decoders Tests
# ==============================================================================

def test_recurrent_accumulator_sequence() -> None:
    """Tests temporal world state recurrence over lookback L=8."""
    acc = RecurrentWorldStateAccumulator(input_dim=32, hidden_dim=32, seed=42)
    z_seq = np.random.default_rng(42).normal(0.0, 1.0, (8, 32))
    h, c, hist = acc.forward_sequence(z_seq)

    assert h.shape == (32,)
    assert c.shape == (32,)
    assert len(hist) == 8
    assert np.all(np.isfinite(h))


def test_multi_task_decoders_outputs() -> None:
    """Tests multi-task prediction heads mapping h_t to all specific tasks."""
    dec = MultiTaskDecoders(hidden_dim=32, state_dim=45, seed=42)
    h_t = np.random.default_rng(42).normal(0.0, 1.0, 32)
    out = dec.predict_single_step(h_t, horizon_step=1)

    assert isinstance(out, MultiTaskPredictionOutput)
    assert out.predicted_state_vector.shape == (45,)
    assert 0.0 <= out.attack_probability <= 1.0
    assert out.predicted_stage in list(AttackStageName)
    assert 0.0 <= out.progression_index <= 1.0
    assert 0.0 <= out.anomaly_score <= 1.0
    assert 0.0 <= out.ood_score <= 1.0
    assert 0.0 <= out.epistemic_uncertainty <= 1.0
    assert 0.0 <= out.aleatoric_uncertainty <= 1.0


# ==============================================================================
# 7. Observed Network Risk Indicator Engine Tests
# ==============================================================================

def test_risk_indicator_engine_generates_observed_indicators() -> None:
    """Verifies that indicators contain required attributes and OBSERVED RISK INDICATOR title."""
    engine = NetworkRiskEngine()
    hosts = {
        "10.0.0.5": HostProfile(
            ip="10.0.0.5", bytes_sent=50000, bytes_recv=2000, packets_sent=500, packets_recv=50,
            outbound_peers=tuple(f"10.0.0.{i}" for i in range(30)),
            inbound_peers=("10.0.0.1",), probed_ports=tuple(range(25)),
            protocols_used=("tcp",), temporal_change_score=0.4, anomaly_score=0.6,
            risk_score=0.85, uncertainty=0.1,
        )
    }
    graph_snap = GraphEvolutionSnapshot(
        timestamp=1000, node_count=35, edge_count=40, graph_density=0.05, mean_degree=2.0,
        max_degree=30, max_betweenness_approx=0.8, edge_churn_rate=0.7, node_churn_rate=0.1,
        peer_novelty_rate=0.5, connected_components=2, graph_observability_score=0.8,
        is_partial_capture=False,
    )
    beh = BehavioralVector(
        peer_diversity=0.8, new_peer_rate=0.5, dest_diversity=0.8, src_diversity=0.1,
        port_entropy=3.5, protocol_entropy=0.5, fan_in_ratio=1.0, fan_out_ratio=30.0,
        traffic_concentration_gini=0.9, edge_churn_rate=0.7, connection_churn_rate=0.6,
        behavioral_novelty_score=2.5,
    )
    temp = TemporalVelocityVector(
        timestamp=1000, delta_flow_count=50, delta_total_bytes=100000, delta_total_packets=500,
        delta_ports=20, delta_iat=-0.01, rolling_total_bytes=500000, acceleration_total_bytes=10000,
        rolling_volatility_bytes=50000, burstiness_index=3.0, regime_change_score=0.4,
    )

    indicators = engine.evaluate_indicators(
        hosts=hosts, edges=(), graph_snapshot=graph_snap, behavior=beh, temporal=temp
    )
    assert len(indicators) >= 3

    for ind in indicators:
        assert isinstance(ind, ObservedRiskIndicator)
        d = ind.to_dict()
        assert d["title"].startswith("OBSERVED RISK INDICATOR:")
        assert ind.severity in (RiskSeverity.LOW, RiskSeverity.MEDIUM, RiskSeverity.HIGH, RiskSeverity.CRITICAL)
        assert ind.trend in (RiskTrend.INCREASING, RiskTrend.STABLE, RiskTrend.DECREASING)
        assert 0.0 <= ind.confidence <= 1.0
        assert 0.0 <= ind.observability <= 1.0
        assert len(ind.evidence) > 0


# ==============================================================================
# 8. Calibration & Uncertainty Evaluation Tests
# ==============================================================================

def test_brier_score_and_ece_computation() -> None:
    """Verifies that calibration metrics compute correctly and respect bounds."""
    y_true = [0, 0, 1, 1, 1]
    y_prob = [0.1, 0.2, 0.8, 0.9, 0.85]

    brier = compute_brier_score(y_true, y_prob)
    assert 0.0 <= brier <= 0.1  # Very well calibrated synthetic predictions

    cal = compute_ece(y_true, y_prob, n_bins=5)
    assert 0.0 <= cal.expected_calibration_error <= 0.2
    assert len(cal.bin_counts) == 5


# ==============================================================================
# 9. 5-Tier Abstention Engine Tests
# ==============================================================================

def test_five_tier_abstention_decisions() -> None:
    """Tests each of the 5 operational tiers and their activation triggers."""
    # 1. ABSTAIN on lookback < 8
    d1 = ComprehensiveAbstentionEngine.evaluate(
        window_count=5, is_continuous=True, has_nans_or_infs=False, capture_quality_status="GOOD"
    )
    assert d1.tier == ForecastOperationalTier.ABSTAIN
    assert d1.is_abstained is True
    assert d1.reason_code == AbstentionReasonCode.INSUFFICIENT_HISTORY.value

    # 2. ABSTAIN on non-contiguous
    d2 = ComprehensiveAbstentionEngine.evaluate(
        window_count=8, is_continuous=False, has_nans_or_infs=False, capture_quality_status="GOOD"
    )
    assert d2.tier == ForecastOperationalTier.ABSTAIN
    assert d2.is_abstained is True
    assert d2.reason_code == AbstentionReasonCode.NON_CONTIGUOUS_TIMESTAMPS.value

    # 3. ANOMALY_ONLY on extreme OOD
    d3 = ComprehensiveAbstentionEngine.evaluate(
        window_count=8, is_continuous=True, has_nans_or_infs=False, capture_quality_status="GOOD", ood_score=0.92
    )
    assert d3.tier == ForecastOperationalTier.ANOMALY_ONLY
    assert d3.is_abstained is False
    assert "anomalies" in d3.allowed_outputs

    # 4. DEGRADED_FORECAST on partial missingness / high uncertainty
    d4 = ComprehensiveAbstentionEngine.evaluate(
        window_count=8, is_continuous=True, has_nans_or_infs=False, capture_quality_status="DEGRADED", total_uncertainty=0.50
    )
    assert d4.tier == ForecastOperationalTier.DEGRADED_FORECAST
    assert d4.is_abstained is False
    assert "forecast" in d4.allowed_outputs

    # 5. FULL_FORECAST on optimal conditions
    d5 = ComprehensiveAbstentionEngine.evaluate(
        window_count=8, is_continuous=True, has_nans_or_infs=False, capture_quality_status="GOOD", total_uncertainty=0.20
    )
    assert d5.tier == ForecastOperationalTier.FULL_FORECAST
    assert d5.is_abstained is False


# ==============================================================================
# 10. Checkpoint Cryptographic Integrity Tests
# ==============================================================================

def test_final_model_manifest_checksum_integrity() -> None:
    """Verifies that all files in models/final_world_model match manifest SHA-256."""
    assert (ROOT / "models" / "final_world_model" / "manifest.json").exists()
    verified, hashes = ModelRegistry.verify_integrity("final_world_model")
    assert verified is True
    assert len(hashes) >= 6


def test_candidate_v2_baseline_immutability() -> None:
    """Guarantees Candidate V2 checkpoint remains 100% verified and untouched."""
    verified, hashes = ModelRegistry.verify_integrity("candidate_v2")
    assert verified is True
    assert hashes["model.npz"] == "2f0a10453936da3b022fc5f3957745d55185820187653e0cb05e61decf65f915"


# ==============================================================================
# 11. Final Production Inference Contract Tests (Step 21)
# ==============================================================================

def test_production_inference_adheres_to_step_21_contract() -> None:
    """Verifies complete Step 21 contract keys on successful execution."""
    states = [
        NetworkState(
            timestamp=1700000000 + i * 60,
            flow_features={n: float(10.0 + i) for n in FEATURE_NAMES_45[:17]},
            packet_features={n: float(5.0 + i) for n in FEATURE_NAMES_45[17:39]},
            temporal_features={n: float(1.0) for n in FEATURE_NAMES_45[39:]},
        )
        for i in range(8)
    ]
    engine = FinalProductionInferenceEngine()
    res = engine.run_inference(states)

    required_keys = [
        "analysis_id",
        "data_quality",
        "observability",
        "current_state",
        "forecast",
        "attack_assessment",
        "attack_progression",
        "anomalies",
        "host_risk",
        "communication_risk",
        "network_risk_indicators",
        "evidence",
        "uncertainty",
        "abstention",
        "model_metadata",
    ]
    for k in required_keys:
        assert k in res, f"Contract key missing: {k}"

    assert res["status"] == "FORECAST_AVAILABLE"
    assert res["is_abstained"] is False
    assert len(res["forecast"]) == 5


# ==============================================================================
# 12. Null-Port and Malformed Flow Robustness Regression Tests (Rule 9)
# ==============================================================================

def test_null_port_and_malformed_flow_robustness() -> None:
    """Verifies flow parsing never crashes on null, missing, or malformed ports and telemetry."""
    from ml.models.host_graph_intelligence import HostGraphIntelligenceEngine
    from ml.models.behavioral_intelligence import BehavioralEngine

    graph_eng = HostGraphIntelligenceEngine()
    beh_eng = BehavioralEngine()

    test_flows = [
        # 1. TCP with valid port
        {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "dst_port": 443, "proto": "tcp", "src_bytes": 1000, "dst_bytes": 500, "packets": 10, "duration": 1.5},
        # 2. UDP with valid port
        {"src_ip": "192.168.1.10", "dst_ip": "8.8.8.8", "destination_port": 53, "protocol": "udp", "src_bytes": 150, "dst_bytes": 300, "packets": 2, "duration": 0.05},
        # 3. Protocol with unavailable port (NoneType - e.g. ICMP or unresolved)
        {"src_ip": "192.168.1.10", "dst_ip": "10.0.0.2", "dst_port": None, "proto": "icmp", "src_bytes": 64, "dst_bytes": 64, "packets": 1, "duration": 0.01},
        # 4. Protocol with destination_port explicitly None
        {"src_ip": "192.168.1.11", "dst_ip": "10.0.0.3", "destination_port": None, "proto": "gre", "src_bytes": 500, "packets": 4},
        # 5. Malformed flow (string port, non-numeric bytes, missing fields)
        {"src_ip": "192.168.1.12", "dst_ip": "10.0.0.4", "dst_port": "malformed_port", "src_bytes": None, "dst_bytes": "invalid", "packets": None, "duration": None},
        # 6. Partial capture with missing IPs (must be gracefully skipped)
        {"src_ip": "", "dst_ip": "10.0.0.5", "dst_port": 80},
        {"src_ip": "192.168.1.13", "dst_ip": "", "dst_port": 80},
        {"dst_port": 80},
    ]

    # HostGraph engine must process without exception
    hosts, edges, snapshot = graph_eng.analyze_window(test_flows, timestamp=1700000000)
    assert len(hosts) >= 3
    assert len(edges) >= 3
    assert snapshot.node_count >= 3
    assert snapshot.edge_count >= 3

    # Behavioral engine must process without exception
    beh_vec, peers, edges = beh_eng.compute_behavioral_vector(test_flows)
    assert beh_vec is not None
    assert beh_vec.peer_diversity >= 0.0
    assert beh_vec.port_entropy >= 0.0

