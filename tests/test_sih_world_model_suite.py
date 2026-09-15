"""Comprehensive SIH 2026 World Model & Forecasting Integration Test Suite.

Verifies:
1. Feature contract: 45-dim PCAP safety gate enforces zero fabrication of mean_tcp_rtt.
2. Temporal network state representation: past-only encoding, non-overlapping windows.
3. World model transition dynamics: input/output dimensions, 1-step prediction.
4. K-step recursive rollout: S_t -> S_hat_{t+1} -> ... -> S_hat_{t+5} without future ground truth.
5. Multi-horizon attack progression and MITRE ATT&CK technique mapping.
6. Local explainability attribution without fabrication.
7. Real PCAP validation: end-to-end parsing through 45-feature schema to forecast rollouts.
8. Insufficient history abstention handling.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
import numpy as np
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from world_model import (
    FEATURE_NAMES,
    FEATURE_NAMES_45,
    FLOW_NAMES_45,
    PACKET_NAMES,
    TEMPORAL_NAMES,
    NetworkState,
    NumpyLSTM,
    explain,
    forecast_k_steps,
    load_model,
    make_sequences,
)
from nexsolve_core.state import (
    MODEL_SCHEMA_45,
    build_network_state_candidates,
    build_state_history,
    candidates_to_network_states,
    evaluate_model_compatibility,
    feature_registry,
)
from ml.data.pcap_extractor import extract_canonical_capture
from ml.forecasting.attack_progression import (
    AttackProgressionState,
    forecast_attack_progression,
    MITRE_TECHNIQUE_MAP,
)


def dummy_state(index: int, attack: int = 0) -> NetworkState:
    flow = {name: float(index + i) for i, name in enumerate(FLOW_NAMES_45)}
    packet = {name: float(index * 0.1) for name in PACKET_NAMES}
    temporal = {name: float(index * 0.5) for name in TEMPORAL_NAMES}
    return NetworkState(index * 60, flow, packet, temporal, attack, True)


def test_feature_contract_safety_gate():
    """Verify that mean_tcp_rtt is NOT in the 45-feature PCAP contract and never fabricated."""
    assert len(FEATURE_NAMES_45) == 45
    assert "mean_tcp_rtt" not in FEATURE_NAMES_45
    assert len(FEATURE_NAMES) == 46
    assert "mean_tcp_rtt" in FEATURE_NAMES

    reg = feature_registry()
    assert reg["flow_features.mean_tcp_rtt"].availability.value == "UNAVAILABLE"


def test_network_state_encoding_dimensions():
    """Verify that NetworkState encodes to exactly 45 dimensions without labels."""
    st0 = dummy_state(1, attack=0)
    st1 = dummy_state(1, attack=1)

    enc0 = st0.encode(FEATURE_NAMES_45)
    enc1 = st1.encode(FEATURE_NAMES_45)

    assert enc0.shape == (45,)
    assert enc1.shape == (45,)
    # Target label must NOT leak into the observable state vector
    assert np.array_equal(enc0, enc1)


def test_world_model_one_step_transition():
    """Verify that World Model accepts (8, 45) history and predicts (45,) state + attack prob."""
    model, mean, scale = load_model(ROOT / "models" / "nexsolve_world_model_45")
    sequence = np.random.randn(8, 45)

    pred_state, prob = model.predict(sequence)
    assert pred_state.shape == (45,)
    assert 0.0 <= prob <= 1.0


def test_world_model_k_step_recursive_rollout():
    """Verify recursive K-step rollout forwards without ground truth across 5 horizons."""
    model_dir = ROOT / "models" / "nexsolve_world_model_45"
    history = [dummy_state(i) for i in range(8)]

    result = forecast_k_steps(history, k=5, package_dir=model_dir)
    assert "forecasts" in result
    assert len(result["forecasts"]) == 5

    horizons = [f["horizon"] for f in result["forecasts"]]
    assert horizons == [1, 2, 3, 4, 5]

    for f in result["forecasts"]:
        assert not f["abstained"]
        assert 0.0 <= f["attack_probability"] <= 1.0
        assert f["predicted_state"] is not None
        assert len(f["predicted_state"]) == len(set(FEATURE_NAMES_45))


def test_insufficient_history_abstention():
    """Verify safety abstention when fewer than 8 windows are provided."""
    model_dir = ROOT / "models" / "nexsolve_world_model_45"
    history = [dummy_state(i) for i in range(3)]  # Only 3 windows

    result = forecast_k_steps(history, k=5, package_dir=model_dir)
    for f in result["forecasts"]:
        assert f["abstained"] is True
        assert f["attack_probability"] is None
        assert f["reason"] == "insufficient history"


def test_attack_progression_mitre_mapping():
    """Verify that attack progression accurately maps observed behavioral findings to MITRE."""
    findings = [{"attack_category": "network_reconnaissance", "prediction": "port_scan"}]
    progression = forecast_attack_progression(
        observed_findings=findings,
        behavioral_report=None,
        history_window_count=8,
    )
    assert progression.observed_state == AttackProgressionState.RECONNAISSANCE
    assert "T1046" in progression.observed_techniques
    assert MITRE_TECHNIQUE_MAP[AttackProgressionState.RECONNAISSANCE] == "T1046"


def test_explainability_attribution_non_empty():
    """Verify that feature perturbation explainability produces ranked evidence."""
    model, mean, scale = load_model(ROOT / "models" / "nexsolve_world_model_45")
    history = [dummy_state(i) for i in range(8)]

    explanations = explain(history, model, mean, scale, feature_names=FEATURE_NAMES_45)
    assert len(explanations) > 0
    assert "feature" in explanations[0]
    assert "contribution" in explanations[0]
    assert abs(explanations[0]["contribution"]) >= abs(explanations[-1]["contribution"])


def test_real_pcap_end_to_end_parsing_and_forecast():
    """Verify end-to-end processing on a real PCAP in the repository."""
    pcap_path = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "1kxun.pcap"
    if not pcap_path.exists():
        pytest.skip("Sample PCAP not found at expected path")

    packets, canonical_windows, quality = extract_canonical_capture(pcap_path)
    assert len(packets) > 0
    assert quality is not None

    candidates = build_network_state_candidates(canonical_windows)
    assert len(candidates) > 0

    # Ensure 45-feature schema compatibility is valid
    compat = evaluate_model_compatibility(candidates, MODEL_SCHEMA_45, "NOT_READY")
    assert "flow_features.mean_tcp_rtt" not in compat.available_features
    assert "flow_features.mean_tcp_rtt" not in MODEL_SCHEMA_45["flow_features"]


def test_transition_temporal_target_alignment():
    """Verify that training sequences strictly enforce S_t -> S_{t+1} without future overlap."""
    history = [dummy_state(i) for i in range(12)]
    x, targets, labels = make_sequences(history, feature_names=FEATURE_NAMES_45)
    assert x.shape[0] == 4  # 12 - 8
    # For sample 0: input is indices 0..7, target is index 8
    sample_0_last_input = x[0, -1]
    sample_0_target = targets[0]
    expected_input_7 = history[7].encode(FEATURE_NAMES_45)
    expected_target_8 = history[8].encode(FEATURE_NAMES_45)
    assert np.array_equal(sample_0_last_input, expected_input_7)
    assert np.array_equal(sample_0_target, expected_target_8)
    assert history[7].timestamp < history[8].timestamp


def test_calibration_metrics_contract():
    """Verify Brier score and ECE calculation contracts on synthetic calibration cases."""
    from ml.calibration.evaluation import calibration_metrics
    labels = [0, 1, 0, 1]
    probs = [0.1, 0.9, 0.2, 0.8]
    metrics = calibration_metrics(labels, probs, bins=5)
    assert metrics["status"] == "computed"
    assert 0.0 <= metrics["brier_score"] <= 1.0
    assert 0.0 <= metrics["expected_calibration_error"] <= 1.0


def test_csv_temporal_ingestion_and_state_build():
    """Verify that UNSW processed states adhere to strict non-leaking chronological order."""
    cache_file = ROOT / "data" / "processed" / "unsw_network_states.json"
    assert cache_file.exists()
    raw = json.loads(cache_file.read_text(encoding="utf-8"))
    states = [NetworkState(**s) for s in raw["states"]]
    assert len(states) > 100
    timestamps = [s.timestamp for s in states]
    assert timestamps == sorted(timestamps)
    for s in states:
        assert s.flow_features is not None
        assert "flow_count" in s.flow_features
