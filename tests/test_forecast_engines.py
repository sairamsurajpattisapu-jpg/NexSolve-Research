"""Authoritative Regression Tests for NexSolve Forecast Engines.

Tests:
1. Frozen Production Model immutability (golden SHA-256 digests).
2. FrozenWorldModelForecastEngine (production runtime contract).
3. NextGenResearchForecastEngine (research candidate runtime contract, 70 causal features).
4. Central Forecast Gate routing (production vs research engine selection).
5. Abstention behavior and UNKNOWN future stage enforcement.
6. End-to-end PCAP extraction and execution on real capture slice.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np
import pytest

from ml.data.pcap_extractor import extract_canonical_capture
from ml.forecasting.central_gate import execute_central_forecast_gate
from ml.forecasting.frozen_engine import FrozenWorldModelForecastEngine
from ml.forecasting.next_gen_engine import (
    NextGenResearchForecastEngine,
    extract_70_causal_features,
)
from nexsolve_core.schemas import CaptureQuality, QualityStatus
from nexsolve_core.state import (
    MODEL_SCHEMA_45,
    NetworkStateCandidate,
    build_network_state_candidates,
    build_state_history,
    candidates_to_network_states,
)
from world_model import FEATURE_NAMES_45, NetworkState

ROOT = Path(__file__).resolve().parents[1]
FROZEN_MODEL_DIR = ROOT / "models" / "final_world_model"
CANDIDATE_V2_DIR = ROOT / "models" / "research_candidates" / "next_gen_v2"
TEST_PCAP = ROOT / "data" / "test_slices" / "friday_10windows_slice.pcap"


GOLDEN_FROZEN_HASHES = {
    "config.json": "98c55f8685478286264438b07db7dca72b3a42f1a41e0a4d26366654379aa1a1",
    "feature_schema.json": "2bb8714f2da49f124c82209488e9dc1eccff3ca8f655079404ba7efb27e4454b",
    "manifest.json": "75bef97f0be8c7310a9af89d8f13046c9f7e3a12303a7a55582913996805cbf6",
    "metadata.json": "19816e54918779b1226db88a0ea7319dab7d831423b7d6a77181915f90a20093",
    "metrics.json": "8b2b395728be2f8ffd80a66a2e120d634b2206cd2abf2db5aec39fc65c4414b9",
    "model.npz": "5787b2abd68b2243f45ae1290e24b2daa5483e69405660cf3de824fd8b498ecc",
    "preprocessing.npz": "e85d998324d7f45215494ca09d1c9388667f49b7e72d0a1511a1b64b0c72c6b3",
}


def test_frozen_production_model_immutability():
    """Verify that all 7 production model files remain 100% bitwise intact."""
    for fname, expected_hash in GOLDEN_FROZEN_HASHES.items():
        fpath = FROZEN_MODEL_DIR / fname
        assert fpath.exists(), f"Missing production model artifact: {fname}"
        actual_hash = hashlib.sha256(fpath.read_bytes()).hexdigest().lower()
        assert actual_hash == expected_hash.lower(), (
            f"MUTATION DETECTED in production model file {fname}!\n"
            f"Expected: {expected_hash}\nActual:   {actual_hash}"
        )


def test_frozen_world_model_engine_metadata():
    """Verify production engine metadata."""
    engine = FrozenWorldModelForecastEngine()
    meta = engine.metadata
    assert meta.name == "Frozen World Model"
    assert meta.version == "3.0.0"
    assert meta.status == "production"
    assert meta.is_production_ready is True
    assert meta.operational_tier == "PRODUCTION"


def test_next_gen_research_engine_metadata():
    """Verify research candidate engine metadata."""
    engine = NextGenResearchForecastEngine()
    meta = engine.metadata
    assert meta.name == "Next-Gen Causal Precursor Forecaster"
    assert meta.version == "2.0.0-candidate"
    assert meta.status == "research"
    assert meta.is_production_ready is False
    assert meta.operational_tier == "RESEARCH_UNVERIFIED"
    assert "DO NOT PROMOTE TO PRODUCTION" in meta.description or "Held in research" in meta.description


@pytest.fixture(scope="module")
def real_capture_data():
    """Extract authentic windows and candidates from friday_10windows_slice.pcap once."""
    assert TEST_PCAP.exists(), f"Missing {TEST_PCAP}"
    _pkts, canonical_windows, quality = extract_canonical_capture(TEST_PCAP)
    del _pkts
    candidates = build_network_state_candidates(canonical_windows, quality)
    history = build_state_history(candidates)
    return canonical_windows, candidates, quality, history


def test_extract_70_causal_features(real_capture_data):
    """Verify 70 causal feature extraction dimensionality and properties."""
    canonical_windows, candidates, quality, history = real_capture_data
    states = candidates_to_network_states(candidates[:8], MODEL_SCHEMA_45, history.status)
    feat = extract_70_causal_features(states)
    assert isinstance(feat, np.ndarray)
    assert feat.shape == (70,)
    assert not np.isnan(feat).any()
    assert not np.isinf(feat).any()


def test_central_forecast_gate_routing_production(real_capture_data):
    """Test central gate execution with default production engine."""
    canonical_windows, candidates, quality, history = real_capture_data

    result = execute_central_forecast_gate(
        canonical_windows=canonical_windows,
        candidates=candidates,
        history_status=history.status,
        capture_quality=quality,
        detection_findings=[],
        behavioral_report=None,
        model_dir=FROZEN_MODEL_DIR,
        analysis_id="test-prod-run",
        filename=TEST_PCAP.name,
        capture_fingerprint_sha256="abc123sha256",
        engine_type="production",
    )

    assert result.is_forecast_available is True
    assert result.forecast_status == "FORECAST_READY"
    assert result.engine_metadata["name"] == "Frozen World Model"
    assert result.engine_metadata["status"] == "production"
    assert result.engine_metadata["is_production_ready"] is True
    assert len(result.forecast_points) == 5
    for p in result.forecast_points:
        assert 0.0 <= p["attack_probability"] <= 1.0
        assert p["abstained"] is False


def test_central_forecast_gate_routing_research(real_capture_data):
    """Test central gate execution with unverified research engine."""
    canonical_windows, candidates, quality, history = real_capture_data

    result = execute_central_forecast_gate(
        canonical_windows=canonical_windows,
        candidates=candidates,
        history_status=history.status,
        capture_quality=quality,
        detection_findings=[],
        behavioral_report=None,
        model_dir=FROZEN_MODEL_DIR,
        analysis_id="test-research-run",
        filename=TEST_PCAP.name,
        capture_fingerprint_sha256="abc123sha256",
        engine_type="research",
    )

    assert result.is_forecast_available is True
    assert result.forecast_status == "FORECAST_READY"
    assert result.engine_metadata["name"] == "Next-Gen Causal Precursor Forecaster"
    assert result.engine_metadata["status"] == "research"
    assert result.engine_metadata["is_production_ready"] is False
    assert len(result.forecast_points) == 5
    for p in result.forecast_points:
        assert 0.0 <= p["attack_probability"] <= 1.0


def test_central_forecast_gate_abstention_under_8_windows(real_capture_data):
    """Verify that both engines strictly abstain when history < 8 windows and set future stages to UNKNOWN."""
    canonical_windows, candidates, quality, history = real_capture_data
    sub_windows = canonical_windows[:4]
    sub_candidates = candidates[:4]

    for eng_choice in ("production", "research"):
        result = execute_central_forecast_gate(
            canonical_windows=sub_windows,
            candidates=sub_candidates,
            history_status=history.status,
            capture_quality=quality,
            detection_findings=[],
            behavioral_report=None,
            model_dir=FROZEN_MODEL_DIR,
            analysis_id=f"test-abstain-{eng_choice}",
            filename=TEST_PCAP.name,
            capture_fingerprint_sha256="abc123sha256",
            engine_type=eng_choice,
        )

        assert result.is_forecast_available is False
        assert result.forecast_status == "FORECAST_ABSTAINED"
        assert result.abstention_reason == "INSUFFICIENT_HISTORY"
        assert len(result.forecast_points) == 5

        for p in result.forecast_points:
            assert p["abstained"] is True
            assert p["attack_probability"] is None
            assert p["attackProbability"] is None
            assert p["predicted_stage"] is None
            assert p["predictedStage"] is None

        # Check attack progression timeline
        progression = result.attack_progression
        timeline = progression.get("timeline", [])
        assert len(timeline) >= 1
        # T0 is OBSERVED / EVALUATED
        assert timeline[0]["horizon_label"] == "T0"
        # T+1..T+5 must be UNKNOWN
        for ev in timeline[1:]:
            assert ev["stage"] == "UNKNOWN"
            assert ev["classification"] == "UNKNOWN"


def test_real_pcap_slice_execution():
    """Verify real PCAP extraction and pipeline execution on friday_10windows_slice.pcap."""
    from model_service.jobs import JobManager
    import time

    assert TEST_PCAP.exists(), f"Test PCAP slice not found at {TEST_PCAP}"

    manager = JobManager()
    # Test production job
    prod_job = manager.create_job(
        filename=TEST_PCAP.name,
        file_path=TEST_PCAP,
        engine_type="production",
    )
    t0 = time.time()
    while prod_job.status in ("QUEUED", "PROCESSING") and time.time() - t0 < 30:
        time.sleep(0.5)

    assert prod_job.status == "COMPLETED", f"Production job failed: {prod_job.error}"
    assert prod_job.result is not None
    assert prod_job.result["forecast_engine"]["status"] == "production"

    # Test research job
    res_job = manager.create_job(
        filename=TEST_PCAP.name,
        file_path=TEST_PCAP,
        engine_type="research",
    )
    t0 = time.time()
    while res_job.status in ("QUEUED", "PROCESSING") and time.time() - t0 < 30:
        time.sleep(0.5)

    assert res_job.status == "COMPLETED", f"Research job failed: {res_job.error}"
    assert res_job.result is not None
    assert res_job.result["forecast_engine"]["status"] == "research"
    assert res_job.result["forecast_engine"]["is_production_ready"] is False
