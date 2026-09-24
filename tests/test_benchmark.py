"""Tests for Standardized Baseline Benchmarking Engine."""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from ml.forecasting.benchmark import (
    BenchmarkRunResult,
    StandardizedBenchmarkHarness,
)
from world_model import (
    FEATURE_NAMES_45,
    FLOW_NAMES_45,
    PACKET_NAMES,
    TEMPORAL_NAMES,
    NetworkState,
)


def _make_state(idx: int, attack: int) -> NetworkState:
    flow = {n: 10.0 + idx for n in FLOW_NAMES_45}
    flow["flow_count"] = 50.0 + idx
    flow["total_packets"] = 200.0 + idx * 5
    packet = {n: 0.0 for n in PACKET_NAMES}
    packet["tcp_syn_count"] = 20.0 if attack else 1.0
    packet["tcp_ack_count"] = 100.0
    temporal = {n: 0.0 for n in TEMPORAL_NAMES}
    temporal["rolling_total_bytes"] = 5000.0

    return NetworkState(
        timestamp=1700000000 + idx * 60,
        flow_features=flow,
        packet_features=packet,
        temporal_features=temporal,
        attack_state=attack,
        packet_features_available=True,
    )


def test_standardized_benchmark_harness_execution() -> None:
    # Build 25 synthetic sequential states
    states = [_make_state(i, attack=1 if i >= 15 else 0) for i in range(25)]

    harness = StandardizedBenchmarkHarness(
        horizons=[1, 2, 3],
        lookback=8,
    )

    result = harness.run_benchmark(
        test_states=states,
        dataset_name="SyntheticTest",
        threshold=0.5,
    )

    assert result.dataset_name == "SyntheticTest"
    assert result.horizons == [1, 2, 3]
    assert "PersistenceBaseline" in result.models_evaluated
    assert "LogisticRegressionBaseline" in result.models_evaluated
    assert result.evaluated_trajectories > 0

    # Verify per-horizon metrics exist for baselines
    for m in ["PersistenceBaseline", "LogisticRegressionBaseline"]:
        assert m in result.horizon_metrics
        for h in [1, 2, 3]:
            m_res = result.horizon_metrics[m].get(h)
            assert m_res is not None
            assert 0 < m_res.sample_count <= result.evaluated_trajectories
            assert m_res.accuracy is not None
            assert m_res.brier_score is not None

    # Check serialization
    res_dict = result.to_dict()
    serialized = json.dumps(res_dict)
    assert "PersistenceBaseline" in serialized


def test_benchmark_with_holdout() -> None:
    id_states = [_make_state(i, attack=0 if i < 10 else 1) for i in range(20)]
    holdout_states = [_make_state(i + 100, attack=1) for i in range(15)]

    harness = StandardizedBenchmarkHarness(horizons=[1, 2], lookback=8)
    res = harness.run_benchmark(
        test_states=id_states,
        dataset_name="SyntheticID",
        held_out_states=holdout_states,
        held_out_family="SimulatedRansomware",
    )

    assert "status" in res.holdout_results
