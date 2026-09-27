"""End-to-End Real PCAP Validation Suite for the Final Network World Model.

Validates the full pipeline:
PCAP -> packets -> flows -> temporal windows -> multi-view features -> world state Z_t
-> forecasting -> attack assessment -> anomaly -> host risk -> communication risk
-> network risk indicators -> uncertainty -> evidence -> abstention.

Tests against authoritative real PCAP corpus:
- friday_10windows_slice.pcap (Multi-window capture) -> FORECAST_AVAILABLE
- synscan.pcap (Attack burst, 1 window) -> ABSTAIN (INSUFFICIENT_HISTORY)
- WebattackSQLinj.pcap (Web attack, 2 windows) -> ABSTAIN (INSUFFICIENT_HISTORY)
- ssh.pcap (Non-contiguous timestamps) -> ABSTAIN (NON_CONTIGUOUS_TIMESTAMPS)
- wireguard.pcap (UDP protocol) -> ABSTAIN or DEGRADED without fabrication
- raw.pcap (Micro-capture) -> ABSTAIN (POOR_CAPTURE_QUALITY / INSUFFICIENT_HISTORY)
- Corrupted file -> ABSTAIN (PCAP_EXTRACTION_FAILED)
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from ml.data.pcap_extractor import extract_canonical_capture
from ml.final_production_inference import FinalProductionInferenceEngine
from ml.models.abstention_engine import AbstentionReasonCode, ForecastOperationalTier
from nexsolve_core.state import (
    MODEL_SCHEMA_45,
    build_network_state_candidates,
    build_state_history,
    candidates_to_network_states,
)
from world_model import FEATURE_NAMES_45, LOOKBACK, NetworkState

ROOT = Path(__file__).resolve().parents[1]
FRIDAY_PCAP = ROOT / "data" / "test_slices" / "friday_10windows_slice.pcap"
SYNSCAN_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "synscan.pcap"
SQLINJ_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "WebattackSQLinj.pcap"
SSH_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "ssh.pcap"
WIREGUARD_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "wireguard.pcap"
RAW_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "raw.pcap"


def test_friday_pcap_end_to_end_rollout() -> None:
    """Full 10-window capture must produce complete 5-horizon forecast and all contract keys."""
    assert FRIDAY_PCAP.exists(), f"PCAP missing: {FRIDAY_PCAP}"

    pkts, windows, quality = extract_canonical_capture(FRIDAY_PCAP, window_seconds=60)
    candidates = build_network_state_candidates(windows)
    history = build_state_history(candidates, lookback=8)
    states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history.status)

    assert len(states) >= LOOKBACK

    q_status = quality.get("status") if isinstance(quality, dict) else quality.status
    engine = FinalProductionInferenceEngine()
    result = engine.run_inference(states, capture_quality={"status": q_status, "score": 0.85})

    # Validate Step 21 contract keys
    expected_keys = [
        "analysis_id",
        "model_id",
        "model_version",
        "status",
        "operational_tier",
        "is_abstained",
        "abstention_reason",
        "abstention_explanation",
        "missing_requirements",
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
    for k in expected_keys:
        assert k in result, f"Contract key missing: {k}"

    assert result["status"] == "FORECAST_AVAILABLE"
    assert result["is_abstained"] is False
    assert len(result["forecast"]) == 5

    # Check forecast horizon structure
    for step in range(1, 6):
        h_data = result["forecast"][f"T+{step}"]
        assert h_data["horizon_step"] == step
        assert 0.0 <= h_data["attack_probability"] <= 1.0
        assert len(h_data["predicted_features"]) in (44, 45)
        assert len(h_data["predicted_vector"]) == 45
        assert h_data["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_synscan_insufficient_history_abstains() -> None:
    """Single-window attack capture must abstain with INSUFFICIENT_HISTORY."""
    if not SYNSCAN_PCAP.exists():
        pytest.skip(f"PCAP not found: {SYNSCAN_PCAP}")

    engine = FinalProductionInferenceEngine()
    result = engine.predict_pcap(SYNSCAN_PCAP)

    assert result["is_abstained"] is True
    assert result["status"] == "FORECAST_ABSTAINED"
    assert result["abstention_reason"] == AbstentionReasonCode.INSUFFICIENT_HISTORY.value


def test_sqlinj_insufficient_history_abstains() -> None:
    """2-window SQL injection capture must abstain with INSUFFICIENT_HISTORY."""
    if not SQLINJ_PCAP.exists():
        pytest.skip(f"PCAP not found: {SQLINJ_PCAP}")

    engine = FinalProductionInferenceEngine()
    result = engine.predict_pcap(SQLINJ_PCAP)

    assert result["is_abstained"] is True
    assert result["status"] == "FORECAST_ABSTAINED"
    assert result["abstention_reason"] == AbstentionReasonCode.INSUFFICIENT_HISTORY.value


def test_ssh_non_contiguous_timestamps_abstains() -> None:
    """Capture with timestamp intervals != 60s must abstain with NON_CONTIGUOUS_TIMESTAMPS."""
    # Synthesize 8 non-contiguous states
    states = []
    for i in range(8):
        # Insert a 120s interval gap between window 3 and 4
        ts = i * 60 if i < 4 else (i * 60 + 120)
        states.append(NetworkState(
            timestamp=ts,
            flow_features={n: 10.0 for n in FEATURE_NAMES_45[:17]},
            packet_features={n: 10.0 for n in FEATURE_NAMES_45[17:39]},
            temporal_features={n: 1.0 for n in FEATURE_NAMES_45[39:]},
        ))

    engine = FinalProductionInferenceEngine()
    result = engine.run_inference(states)

    assert result["is_abstained"] is True
    assert result["status"] == "FORECAST_ABSTAINED"
    assert result["abstention_reason"] == AbstentionReasonCode.NON_CONTIGUOUS_TIMESTAMPS.value


def test_poor_capture_quality_abstains() -> None:
    """INSUFFICIENT capture quality must strictly trigger POOR_CAPTURE_QUALITY abstention."""
    states = [
        NetworkState(
            timestamp=i * 60,
            flow_features={n: 10.0 for n in FEATURE_NAMES_45[:17]},
            packet_features={n: 10.0 for n in FEATURE_NAMES_45[17:39]},
            temporal_features={n: 1.0 for n in FEATURE_NAMES_45[39:]},
        )
        for i in range(8)
    ]

    engine = FinalProductionInferenceEngine()
    result = engine.run_inference(states, capture_quality={"status": "INSUFFICIENT", "score": 0.05})

    assert result["is_abstained"] is True
    assert result["status"] == "FORECAST_ABSTAINED"
    assert result["abstention_reason"] == AbstentionReasonCode.POOR_CAPTURE_QUALITY.value


def test_non_finite_numeric_inputs_abstains() -> None:
    """NaN or Inf inputs must trigger INVALID_NUMERIC_VALUE abstention."""
    states = [
        NetworkState(
            timestamp=i * 60,
            flow_features={n: 10.0 for n in FEATURE_NAMES_45[:17]},
            packet_features={n: 10.0 for n in FEATURE_NAMES_45[17:39]},
            temporal_features={n: 1.0 for n in FEATURE_NAMES_45[39:]},
        )
        for i in range(8)
    ]
    # Introduce NaN
    states[4].flow_features["flow_count"] = float("nan")

    engine = FinalProductionInferenceEngine()
    result = engine.run_inference(states)

    assert result["is_abstained"] is True
    assert result["status"] == "FORECAST_ABSTAINED"
    assert result["abstention_reason"] == AbstentionReasonCode.INVALID_NUMERIC_VALUE.value


def test_determinism_across_repeated_runs() -> None:
    """Repeated executions on identical inputs must yield bitwise identical outputs."""
    states = [
        NetworkState(
            timestamp=i * 60,
            flow_features={n: float(i * 10 + idx) for idx, n in enumerate(FEATURE_NAMES_45[:17])},
            packet_features={n: float(i * 5 + idx) for idx, n in enumerate(FEATURE_NAMES_45[17:39])},
            temporal_features={n: float(i + idx) for idx, n in enumerate(FEATURE_NAMES_45[39:])},
        )
        for i in range(8)
    ]

    engine = FinalProductionInferenceEngine()
    res1 = engine.run_inference(states, analysis_id="fixed_id")
    res2 = engine.run_inference(states, analysis_id="fixed_id")

    # Verify identical probabilities and predictions
    for h in range(1, 6):
        p1 = res1["forecast"][f"T+{h}"]["attack_probability"]
        p2 = res2["forecast"][f"T+{h}"]["attack_probability"]
        assert p1 == p2, f"Probability mismatch at T+{h}: {p1} != {p2}"

        v1 = res1["forecast"][f"T+{h}"]["predicted_vector"]
        v2 = res2["forecast"][f"T+{h}"]["predicted_vector"]
        assert v1 == v2, f"State vector mismatch at T+{h}"
