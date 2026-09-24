"""Tests for Forecasting Baselines and Scientific Evaluation Engine."""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from ml.forecasting.baselines import LogisticRegressionBaseline, PersistenceBaseline
from ml.forecasting.evaluation import (
    MultiHorizonEvaluator,
    calculate_classification_metrics,
    evaluate_unseen_attack_generalization,
)
from world_model import FEATURE_NAMES_45, NetworkState


@pytest.fixture
def dummy_network_state() -> NetworkState:
    schema_path = Path(__file__).resolve().parents[1] / "models" / "nexsolve_world_model" / "feature_schema_45.json"
    if schema_path.exists():
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    else:
        schema = {
            "flow_features": ["flow_count", "total_packets", "total_bytes", "mean_iat", "unique_dst_ports"],
            "packet_features": ["tcp_syn_count"],
            "temporal_features": [],
        }

    flows = {k: 0.0 for k in schema.get("flow_features", ())}
    packets = {k: 0.0 for k in schema.get("packet_features", ())}
    temporals = {k: 0.0 for k in schema.get("temporal_features", ())}

    flows["flow_count"] = 100.0
    flows["total_packets"] = 2000.0
    packets["tcp_syn_count"] = 500.0
    flows["unique_dst_ports"] = 50.0

    return NetworkState(
        timestamp=1710000000,
        flow_features=flows,
        packet_features=packets,
        temporal_features=temporals,
        attack_state=None,
        packet_features_available=True,
    )


def test_persistence_baseline(dummy_network_state: NetworkState) -> None:
    baseline = PersistenceBaseline()

    # Empty history
    assert baseline.predict([]) == []

    # With non-empty history
    rollout = baseline.predict([dummy_network_state], horizons=(1, 2, 3))
    assert len(rollout) == 3
    assert rollout[0].horizon == 1
    assert rollout[0].lookahead_seconds == 60
    assert 0.0 <= rollout[0].attack_probability <= 1.0
    assert 0.0 <= rollout[0].cumulative_risk <= 1.0
    assert rollout[0].model_name == "PersistenceBaseline"


def test_logistic_regression_baseline(dummy_network_state: NetworkState) -> None:
    baseline = LogisticRegressionBaseline()

    # Empty history
    assert baseline.predict([]) == []

    # With history
    rollout = baseline.predict([dummy_network_state], horizons=(1, 2, 3, 5))
    assert len(rollout) == 4
    assert rollout[0].horizon == 1
    assert 0.0 <= rollout[0].attack_probability <= 1.0
    assert 0.0 <= rollout[0].cumulative_risk <= 1.0
    assert rollout[0].model_name == "LogisticRegressionBaseline"


def test_calculate_classification_metrics() -> None:
    y_true = [0, 0, 1, 1]
    y_prob = [0.1, 0.2, 0.8, 0.9]

    metrics = calculate_classification_metrics(y_true, y_prob, threshold=0.5)
    assert metrics.accuracy == 1.0
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.f1_score == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.false_negative_rate == 0.0
    # Brier score: mean((y_prob - y_true)^2) = ((0.1)^2 + (0.2)^2 + (-0.2)^2 + (-0.1)^2) / 4 = 0.025
    assert metrics.brier_score == pytest.approx(0.025, 0.001)

    m_dict = metrics.to_dict()
    assert m_dict["brier_score"] == pytest.approx(0.025, 0.001)


def test_multi_horizon_evaluator() -> None:
    evaluator = MultiHorizonEvaluator(horizons=(1, 2, 3))

    preds = {
        1: [0.95, 0.05, 0.90, 0.10],
        2: [0.75, 0.25, 0.70, 0.30],
        3: [0.55, 0.45, 0.50, 0.50],
    }
    truth = {
        1: [1, 0, 1, 0],
        2: [1, 0, 1, 0],
        3: [1, 0, 1, 0],
    }

    eval_report = evaluator.evaluate_model_on_trajectories(
        model_name="NexSolveWorldModel",
        predictions_by_horizon=preds,
        ground_truth_by_horizon=truth,
    )

    assert eval_report["model_name"] == "NexSolveWorldModel"
    assert 1 in eval_report["horizon_metrics"]
    assert 2 in eval_report["horizon_metrics"]
    assert 3 in eval_report["horizon_metrics"]

    m1 = eval_report["horizon_metrics"][1]
    m2 = eval_report["horizon_metrics"][2]
    m3 = eval_report["horizon_metrics"][3]

    assert m1["f1_score"] >= m2["f1_score"]
    assert m1["brier_score"] < m3["brier_score"]


def test_unseen_attack_generalization() -> None:
    # In-distribution predictions
    known_true = [0, 0, 1, 1, 1, 0, 1, 0]
    known_prob = [0.1, 0.2, 0.9, 0.85, 0.95, 0.05, 0.88, 0.15]

    # Out-of-distribution (unseen attack family)
    unseen_true = [1, 1, 1, 0]
    unseen_prob = [0.65, 0.70, 0.40, 0.30]

    gen_report = evaluate_unseen_attack_generalization(
        known_family_truths=known_true,
        known_family_probs=known_prob,
        unseen_family_truths=unseen_true,
        unseen_family_probs=unseen_prob,
        family_name="DNS_TUNNEL_EXFILTRATION",
    )

    assert gen_report["held_out_family"] == "DNS_TUNNEL_EXFILTRATION"
    assert gen_report["known_families_metrics"]["f1_score"] == 1.0
    assert 0.0 < gen_report["unseen_family_metrics"]["f1_score"] <= 1.0
    assert 0.0 < gen_report["f1_retention_ratio"] <= 1.0
    assert "verdict" in gen_report
