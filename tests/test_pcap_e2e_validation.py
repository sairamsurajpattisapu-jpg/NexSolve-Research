"""Automated End-to-End Real PCAP ML Validation Suite for NexSolve.

Verifies the entire data and model pipeline using authentic PCAP captures:
- PCAP ingestion & packet extraction
- Flow reconstruction & candidate generation
- 60-second temporal windows & contiguity
- Canonical 45-feature schema (strict exclusion of mean_tcp_rtt)
- Minimum history enforcement (< 8 windows -> abstention, >= 8 windows -> forecast)
- Checkpoint loading (Candidate V2, frozen scaler, calibrated threshold)
- Multi-horizon recursive rollout (T+1..T+5)
- Honest abstention across capture failure modes (poor quality, insufficient history, gaps, schema mismatch)
- Deterministic, repeatable bitwise outputs
- Robust handling of malformed capture inputs
"""
from __future__ import annotations

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
)
from ml.data.pcap_extractor import extract_canonical_capture
from nexsolve_core.state import (
    MODEL_SCHEMA_45,
    build_network_state_candidates,
    build_state_history,
    candidates_to_network_states,
    evaluate_model_compatibility,
)
from ml.registry import ModelRegistry
from ml.forecasting.production_inference import (
    AbstentionReason,
    ForecastAvailabilityStatus,
    ProductionInferenceEngine,
    predict_pcap_forecast,
)

ROOT = Path(__file__).resolve().parents[1]
FRIDAY_PCAP = ROOT / "data" / "test_slices" / "friday_10windows_slice.pcap"
SYNSCAN_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "synscan.pcap"
SQLINJ_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "WebattackSQLinj.pcap"
SSH_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "ssh.pcap"
WIREGUARD_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "wireguard.pcap"
RAW_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "raw.pcap"


# ==============================================================================
# 1. Pipeline Trace & Transformation Integrity
# ==============================================================================

def test_pipeline_trace_transformations() -> None:
    """Traces every discrete transformation step from raw PCAP bytes to forecast."""
    assert FRIDAY_PCAP.exists(), "friday_10windows_slice.pcap must exist"

    # Step 1: Packet Ingestion
    pkts, windows, quality = extract_canonical_capture(FRIDAY_PCAP, window_seconds=60)
    assert len(pkts) == 2277
    assert len(windows) == 10
    q_status = quality.get("status") if isinstance(quality, dict) else quality.status
    assert q_status in ("GOOD", "DEGRADED")

    # Step 2: Flow Reconstruction & State Candidates
    candidates = build_network_state_candidates(windows)
    assert len(candidates) == 10

    # Step 3: Temporal History & Model Compatibility Gate
    history = build_state_history(candidates, lookback=8)
    assert history.status == "READY"
    compat = evaluate_model_compatibility(candidates, MODEL_SCHEMA_45, history.status)
    assert compat.model_ready is True
    assert len(compat.unavailable_features) == 0

    # Step 4: Conversion to Canonical 45-Feature NetworkStates
    states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history.status)
    assert len(states) == 9  # first candidate without temporal diffs safely pruned
    assert len(states) >= LOOKBACK

    # Step 5: Input Validation & Encoding
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    is_valid, reason, msg, missing = engine.validate_network_states(states)
    assert is_valid is True
    assert reason is None
    assert len(missing) == 0

    # Step 6: Inference & Multi-Horizon Recursive Rollout
    res = engine.predict_states(states)
    assert res.status == ForecastAvailabilityStatus.FORECAST_AVAILABLE.value
    assert res.abstained is False
    assert len(res.horizons) == 5


# ==============================================================================
# 2. Real PCAP Successful Inference & Forecast Sanity
# ==============================================================================

def test_real_pcap_successful_inference_friday_slice() -> None:
    """Verifies successful forecast rollout on 10-window real capture."""
    assert FRIDAY_PCAP.exists()
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    res = engine.predict_pcap(FRIDAY_PCAP, window_seconds=60)

    assert res.status == ForecastAvailabilityStatus.FORECAST_AVAILABLE.value
    assert res.abstained is False
    assert res.model_id == "candidate_v2"
    assert res.decision_threshold == 0.30
    assert len(res.horizons) == 5

    # Check each horizon
    for step in range(1, 6):
        h_key = f"T+{step}"
        assert h_key in res.horizons
        out = res.horizons[h_key]
        assert out.horizon_step == step
        assert 0.0 <= out.attack_probability <= 1.0
        assert not np.isnan(out.attack_probability)
        assert not np.isinf(out.attack_probability)
        assert out.binary_prediction in (0, 1)
        assert out.risk_level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert len(out.predicted_vector) == 45
        assert len(out.predicted_features) == len(set(FEATURE_NAMES_45))

    # T+1 elevated attack risk from scan activity
    assert res.horizons["T+1"].attack_probability > 0.50
    assert res.horizons["T+1"].binary_prediction == 1
    assert res.horizons["T+1"].risk_level == "HIGH"


# ==============================================================================
# 3. Minimum History Enforcement (< 8 Windows -> Abstention)
# ==============================================================================

def test_real_pcap_insufficient_history_synscan() -> None:
    """Verifies that synscan.pcap (1 window) triggers INSUFFICIENT_HISTORY abstention."""
    if not SYNSCAN_PCAP.exists():
        pytest.skip(f"Capture {SYNSCAN_PCAP} not found")

    engine = ProductionInferenceEngine(model_id="candidate_v2")
    res = engine.predict_pcap(SYNSCAN_PCAP, window_seconds=60)

    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstained is True
    assert res.abstention_reason == AbstentionReason.INSUFFICIENT_HISTORY.value
    assert "Need 8 contiguous windows; received 1" in res.abstention_message
    assert len(res.horizons) == 0


def test_real_pcap_insufficient_history_webattack() -> None:
    """Verifies that WebattackSQLinj.pcap (2 windows) triggers INSUFFICIENT_HISTORY abstention."""
    if not SQLINJ_PCAP.exists():
        pytest.skip(f"Capture {SQLINJ_PCAP} not found")

    engine = ProductionInferenceEngine(model_id="candidate_v2")
    res = engine.predict_pcap(SQLINJ_PCAP, window_seconds=60)

    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstained is True
    assert res.abstention_reason == AbstentionReason.INSUFFICIENT_HISTORY.value
    assert "Need 8 contiguous windows; received 2" in res.abstention_message
    assert len(res.horizons) == 0


# ==============================================================================
# 4. Gapped & Discontinuous History Abstention
# ==============================================================================

def test_real_pcap_gapped_history_ssh() -> None:
    """Verifies that ssh.pcap with temporal gaps triggers NON_CONTIGUOUS_TIMESTAMPS."""
    if not SSH_PCAP.exists():
        pytest.skip(f"Capture {SSH_PCAP} not found")

    engine = ProductionInferenceEngine(model_id="candidate_v2")
    res = engine.predict_pcap(SSH_PCAP, window_seconds=60)

    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstained is True
    assert res.abstention_reason == AbstentionReason.NON_CONTIGUOUS_TIMESTAMPS.value
    assert len(res.horizons) == 0


# ==============================================================================
# 5. Protocol Schema Compatibility (No Dense Vector Fabrication)
# ==============================================================================

def test_real_pcap_wireguard_missing_tcp_semantics() -> None:
    """Verifies wireguard.pcap (pure UDP) abstains on missing TCP window semantics without fabrication."""
    if not WIREGUARD_PCAP.exists():
        pytest.skip(f"Capture {WIREGUARD_PCAP} not found")

    engine = ProductionInferenceEngine(model_id="candidate_v2")
    res = engine.predict_pcap(WIREGUARD_PCAP, window_seconds=60)

    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstained is True
    assert res.abstention_reason == AbstentionReason.FEATURE_SCHEMA_MISMATCH.value
    assert "flow_features.mean_swin" in res.missing_requirements
    assert "packet_features.mean_tcp_window" in res.missing_requirements
    assert len(res.horizons) == 0


# ==============================================================================
# 6. Capture Quality Abstention
# ==============================================================================

def test_real_pcap_poor_quality_raw() -> None:
    """Verifies that raw.pcap (1 packet) triggers POOR_CAPTURE_QUALITY abstention."""
    if not RAW_PCAP.exists():
        pytest.skip(f"Capture {RAW_PCAP} not found")

    engine = ProductionInferenceEngine(model_id="candidate_v2")
    res = engine.predict_pcap(RAW_PCAP, window_seconds=60)

    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstained is True
    assert res.abstention_reason == AbstentionReason.POOR_CAPTURE_QUALITY.value
    assert len(res.horizons) == 0


# ==============================================================================
# 7. Feature Contract: mean_tcp_rtt is NOT Fabricated
# ==============================================================================

def test_feature_contract_mean_tcp_rtt_excluded() -> None:
    """Verifies that mean_tcp_rtt is strictly excluded from the canonical 45 features."""
    assert "mean_tcp_rtt" not in FEATURE_NAMES_45
    assert "mean_tcp_rtt" not in FLOW_NAMES_45
    assert len(FEATURE_NAMES_45) == 45

    engine = ProductionInferenceEngine(model_id="candidate_v2")
    assert engine.spec.feature_count == 45
    assert "mean_tcp_rtt" not in engine.spec.feature_names


# ==============================================================================
# 8. Deterministic Repeatability
# ==============================================================================

def test_real_pcap_repeatability_and_determinism() -> None:
    """Verifies that running the same capture multiple times produces bitwise identical forecasts."""
    assert FRIDAY_PCAP.exists()
    engine = ProductionInferenceEngine(model_id="candidate_v2")

    res1 = engine.predict_pcap(FRIDAY_PCAP, window_seconds=60)
    res2 = engine.predict_pcap(FRIDAY_PCAP, window_seconds=60)

    assert res1.abstained == res2.abstained
    assert res1.status == res2.status
    for h in ("T+1", "T+2", "T+3", "T+4", "T+5"):
        assert res1.horizons[h].attack_probability == res2.horizons[h].attack_probability
        assert res1.horizons[h].binary_prediction == res2.horizons[h].binary_prediction
        assert res1.horizons[h].confidence_score == res2.horizons[h].confidence_score
        assert res1.horizons[h].risk_level == res2.horizons[h].risk_level
        assert res1.horizons[h].predicted_vector == res2.horizons[h].predicted_vector


# ==============================================================================
# 9. Malformed Capture File Handling
# ==============================================================================

def test_malformed_capture_handling(tmp_path: Path) -> None:
    """Verifies corrupted or random bytes trigger clean abstention without crashing."""
    corrupted_pcap = tmp_path / "corrupted.pcap"
    corrupted_pcap.write_bytes(b"\xd4\xc3\xb2\xa1RANDOM_CORRUPTED_BYTES_WITHOUT_VALID_PACKETS")

    engine = ProductionInferenceEngine(model_id="candidate_v2")
    res = engine.predict_pcap(corrupted_pcap, window_seconds=60)

    assert res.status == ForecastAvailabilityStatus.FORECAST_ABSTAINED.value
    assert res.abstained is True
    assert res.abstention_reason in (
        AbstentionReason.POOR_CAPTURE_QUALITY.value,
        AbstentionReason.PCAP_EXTRACTION_FAILED.value,
    )
    assert len(res.horizons) == 0


# ==============================================================================
# 10. Forecast Sanity & Boundedness
# ==============================================================================

def test_forecast_sanity_no_numerical_explosion() -> None:
    """Verifies that predicted continuous features and probabilities remain physically bounded."""
    assert FRIDAY_PCAP.exists()
    engine = ProductionInferenceEngine(model_id="candidate_v2")
    res = engine.predict_pcap(FRIDAY_PCAP, window_seconds=60)

    for h in range(1, 6):
        out = res.horizons[f"T+{h}"]
        assert 0.0 <= out.attack_probability <= 1.0
        vec = np.array(out.predicted_vector)
        assert np.all(np.isfinite(vec))
        # Ensure predictions don't explode to astronomical values
        assert np.all(np.abs(vec) < 1e9)
