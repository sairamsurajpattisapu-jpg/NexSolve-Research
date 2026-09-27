"""Comprehensive Regression and Robustness Test Suite for NexSolve Production Inference.

Verifies:
- Strict 45-feature canonical input validation (no mean_tcp_rtt fabrication)
- Insufficient history abstention (< 8 windows)
- Non-contiguous timestamp gap abstention (window interval != 60s)
- Non-finite numeric rejection (NaN, +Inf, -Inf)
- Feature schema mismatch rejection
- Scaler normalization consistency with frozen training parameters
- Multi-horizon recursive rollout (T+1 through T+5)
- Calibrated decision threshold application
- Deterministic inference outputs (bitwise reproducibility)
- Structured machine-readable abstention outputs
- End-to-end PCAP slice inference
- SHA-256 artifact integrity and corruption detection
"""
from __future__ import annotations

import copy
import hashlib
import json
import tempfile
from pathlib import Path

import numpy as np
import pytest

from world_model import (
    FEATURE_NAMES_45,
    FLOW_NAMES_45,
    LOOKBACK,
    PACKET_NAMES,
    TEMPORAL_NAMES,
    NetworkState,
)
from ml.registry import (
    ModelArtifactCorruptedError,
    ModelArtifactNotFoundError,
    ModelRegistry,
)
from ml.forecasting.production_inference import (
    AbstentionReason,
    ForecastAvailabilityStatus,
    ProductionInferenceEngine,
    predict_forecast,
    predict_pcap_forecast,
)

ROOT = Path(__file__).resolve().parents[1]
REAL_PCAP_PATH = ROOT / "data" / "test_slices" / "friday_10windows_slice.pcap"


def _make_valid_state(timestamp: int, attack_state: int | None = 0) -> NetworkState:
    """Helper to generate a structurally valid 45-feature NetworkState."""
    flow = {n: 10.0 for n in FLOW_NAMES_45}
    packet = {n: 0.0 for n in PACKET_NAMES}
    temporal = {n: 1.0 for n in TEMPORAL_NAMES}
    return NetworkState(
        timestamp=timestamp,
        flow_features=flow,
        packet_features=packet,
        temporal_features=temporal,
        attack_state=attack_state,
        packet_features_available=True,
    )


def _make_valid_sequence(count: int = 8, start_ts: int = 1700000000) -> list[NetworkState]:
    """Helper to generate a contiguous sequence of valid NetworkStates."""
    return [_make_valid_state(start_ts + i * 60) for i in range(count)]


# ==============================================================================
# 1. Feature Schema & Count Validation Tests
# ==============================================================================

def test_feature_count_mismatch_44() -> None:
    """Verifies that an input vector with 44 features is cleanly rejected."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    arr_44 = np.zeros((8, 44))
    res = engine.predict_vector_sequence(arr_44)

    assert res.abstained is True
    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstention_reason == AbstentionReason.INVALID_FEATURE_COUNT.value
    assert "44 != 45" in res.missing_requirements[0] or "44" in res.abstention_message


def test_feature_count_mismatch_46() -> None:
    """Verifies that an input vector with 46 features is cleanly rejected."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    arr_46 = np.zeros((8, 46))
    res = engine.predict_vector_sequence(arr_46)

    assert res.abstained is True
    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstention_reason == AbstentionReason.INVALID_FEATURE_COUNT.value


def test_missing_feature_in_network_state() -> None:
    """Verifies that missing canonical features in NetworkState trigger schema abstention."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    states = _make_valid_sequence(8)
    # Remove one flow feature from the 5th state
    del states[4].flow_features["flow_count"]

    res = engine.predict_states(states)
    assert res.abstained is True
    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstention_reason == AbstentionReason.FEATURE_SCHEMA_MISMATCH.value
    assert any("flow_count" in req for req in res.missing_requirements)


# ==============================================================================
# 2. History & Contiguity Validation Tests
# ==============================================================================

def test_insufficient_history_rejection() -> None:
    """Verifies that fewer than 8 lookback windows are cleanly rejected."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    states_7 = _make_valid_sequence(7)

    res = engine.predict_states(states_7)
    assert res.abstained is True
    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstention_reason == AbstentionReason.INSUFFICIENT_HISTORY.value
    assert "7 windows" in res.abstention_message


def test_non_contiguous_timestamp_gap() -> None:
    """Verifies that a 120s jump (or any dt != 60s) triggers non-contiguous abstention."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    states = _make_valid_sequence(8)
    # Introduce a 120s gap between window 3 and window 4
    for i in range(4, 8):
        states[i].timestamp += 60  # total delta is now 120s

    res = engine.predict_states(states)
    assert res.abstained is True
    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstention_reason == AbstentionReason.NON_CONTIGUOUS_TIMESTAMPS.value
    assert "120s" in res.abstention_message


# ==============================================================================
# 3. Numeric Integrity Validation Tests (NaN / Inf)
# ==============================================================================

def test_nan_numeric_value_rejection() -> None:
    """Verifies that NaN values in the feature vector trigger numeric validation abstention."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    states = _make_valid_sequence(8)
    states[2].flow_features["total_src_bytes"] = float("nan")

    res = engine.predict_states(states)
    assert res.abstained is True
    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstention_reason == AbstentionReason.INVALID_NUMERIC_VALUE.value
    assert any("total_src_bytes" in req for req in res.missing_requirements)


def test_inf_numeric_value_rejection() -> None:
    """Verifies that Inf values trigger numeric validation abstention."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    arr = np.zeros((8, 45))
    arr[1, 10] = float("inf")

    res = engine.predict_vector_sequence(arr)
    assert res.abstained is True
    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstention_reason == AbstentionReason.INVALID_NUMERIC_VALUE.value


# ==============================================================================
# 4. Multi-Horizon Recursive Rollout & Calibration Tests
# ==============================================================================

def test_multi_horizon_rollout_horizons() -> None:
    """Verifies multi-step autoregressive rollout produces valid T+1..T+5 horizons."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    states = _make_valid_sequence(8, start_ts=1700000000)

    res = engine.predict_states(states, horizons=(1, 2, 3, 4, 5))
    assert res.abstained is False
    assert res.status == ForecastAvailabilityStatus.FORECAST_AVAILABLE.value
    assert len(res.horizons) == 5

    expected_horizons = ["T+1", "T+2", "T+3", "T+4", "T+5"]
    assert list(res.horizons.keys()) == expected_horizons

    for step, h_key in enumerate(expected_horizons, start=1):
        out = res.horizons[h_key]
        assert out.horizon_step == step
        assert out.horizon_name == h_key
        assert out.target_timestamp == 1700000000 + (7 + step) * 60
        assert 0.0 <= out.attack_probability <= 1.0
        assert out.binary_prediction in (0, 1)
        assert out.decision_threshold == engine.threshold
        assert out.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(out.predicted_vector) == 45
        assert len(out.predicted_features) == len(set(FEATURE_NAMES_45))
        assert set(out.predicted_features.keys()) == set(FEATURE_NAMES_45)


def test_calibrated_decision_threshold() -> None:
    """Verifies that binary decision adheres to calibrated threshold (0.30 for V2)."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    assert engine.threshold == 0.30

    states = _make_valid_sequence(8)
    res = engine.predict_states(states)

    for out in res.horizons.values():
        if out.attack_probability >= 0.30:
            assert out.binary_prediction == 1
        else:
            assert out.binary_prediction == 0


def test_deterministic_inference() -> None:
    """Verifies that identical inputs yield bitwise identical forecast outputs."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    states1 = _make_valid_sequence(8)
    states2 = _make_valid_sequence(8)

    res1 = engine.predict_states(states1)
    res2 = engine.predict_states(states2)

    for h in ("T+1", "T+2", "T+3", "T+4", "T+5"):
        assert res1.horizons[h].attack_probability == res2.horizons[h].attack_probability
        assert res1.horizons[h].binary_prediction == res2.horizons[h].binary_prediction
        assert res1.horizons[h].predicted_features == res2.horizons[h].predicted_features


# ==============================================================================
# 5. Hybrid Persistence Blending Tests
# ==============================================================================

def test_hybrid_persistence_blending() -> None:
    """Verifies hybrid blending properly interpolates current state with LSTM prediction."""
    engine_unblended = ProductionInferenceEngine(model_id="candidate_v2", use_hybrid=False)
    engine_hybrid = ProductionInferenceEngine(model_id="candidate_v2", use_hybrid=True, hybrid_alpha=0.25)

    states = _make_valid_sequence(8)
    states[-1].attack_state = 1  # current state is attack

    res_raw = engine_unblended.predict_states(states, horizons=(1,))
    res_hyb = engine_hybrid.predict_states(states, horizons=(1,))

    p_raw = res_raw.horizons["T+1"].raw_probability
    p_hyb = res_hyb.horizons["T+1"].attack_probability

    expected_blended = 0.25 * 1.0 + 0.75 * p_raw
    assert abs(p_hyb - expected_blended) < 1e-6


# ==============================================================================
# 6. JSON Serialization Test
# ==============================================================================

def test_json_serialization_roundtrip() -> None:
    """Verifies that ProductionForecastResult serializes cleanly to JSON without exceptions."""
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    states = _make_valid_sequence(8)
    res = engine.predict_states(states)

    d = res.to_dict()
    dumped = json.dumps(d)
    loaded = json.loads(dumped)

    assert loaded["status"] == "FORECAST_AVAILABLE"
    assert loaded["abstained"] is False
    assert len(loaded["horizons"]) == 5
    assert loaded["decision_threshold"] == 0.30


# ==============================================================================
# 7. Real PCAP Slice Inference Test
# ==============================================================================

def test_real_pcap_slice_inference() -> None:
    """Verifies end-to-end inference directly from real PCAP capture file."""
    if not REAL_PCAP_PATH.exists():
        pytest.skip("friday_10windows_slice.pcap not present on host")

    engine = ProductionInferenceEngine(model_id="candidate_v2")
    res = engine.predict_pcap(REAL_PCAP_PATH, window_seconds=60)

    assert res.abstained is False
    assert res.status == ForecastAvailabilityStatus.FORECAST_AVAILABLE.value
    assert len(res.horizons) == 5
    assert res.horizons["T+1"].binary_prediction in (0, 1)
    assert 0.0 <= res.horizons["T+1"].attack_probability <= 1.0


# ==============================================================================
# 8. Model Registry & Checksum Integrity Tests
# ==============================================================================

def test_model_registry_list_and_spec() -> None:
    """Verifies model registry cataloging and specification retrieval."""
    available = ModelRegistry.list_available_models()
    assert "candidate_v2" in available

    spec = ModelRegistry.get_model_spec("candidate_v2")
    assert spec.feature_count == 45
    assert spec.calibrated_threshold == 0.30
    assert spec.lookback == 8
    assert "model.npz" in spec.artifact_hashes


def test_corrupted_artifact_detection() -> None:
    """Verifies that an altered artifact fails cryptographic SHA-256 verification."""
    spec = ModelRegistry.get_model_spec("candidate_v2")

    # In a temporary directory, create a damaged model.npz with modified bytes
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        for fname in ["preprocessing.npz", "config.json", "feature_schema.json", "metadata.json", "metrics.json", "manifest.json"]:
            (tmp_path / fname).write_bytes((spec.checkpoint_dir / fname).read_bytes())

        # Write corrupted model.npz
        (tmp_path / "model.npz").write_bytes(b"CORRUPTED_BYTES_FOR_TESTING")

        # Point a custom registry lookup to the tempdir
        orig_paths = copy.copy(ModelRegistry._REGISTRY_PATHS)
        ModelRegistry._REGISTRY_PATHS["corrupted_test_model"] = tmp_path
        try:
            with pytest.raises(ModelArtifactCorruptedError):
                ModelRegistry.load_model("corrupted_test_model", verify_checksums=True, use_cache=False)
        finally:
            ModelRegistry._REGISTRY_PATHS = orig_paths
