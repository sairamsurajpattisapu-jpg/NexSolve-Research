"""Phase 1 regression and validation tests for:
1. Short-PCAP analysis mode (<60s, <8 windows)
2. Analysis-state machine contracts
3. Non-fabrication & safety gates
4. Scientific forecasting evaluation harness
"""
import json
import tempfile
from pathlib import Path
import numpy as np
import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from ml.data.pcap_extractor import extract_canonical_capture
from ml.evaluation.scientific_forecasting import (
    HORIZONS,
    build_forecast_cases,
    contiguous_episodes,
    chronological_episode_split,
    persistence_predictions,
    majority_predictions,
    transition_predictions,
    logistic_predictions,
    evaluate_predictions,
    promotion_report,
    calibration_status,
)
from nexsolve_core.state import (
    build_network_state_candidates,
    build_state_history,
    evaluate_model_compatibility,
    FLOW_NAMES,
    FLOW_NAMES_45,
    PACKET_NAMES,
    TEMPORAL_NAMES,
    MODEL_SCHEMA_45,
)
from model_service.pcap_upload import analyze_uploaded_capture
from world_model import NetworkState, FEATURE_NAMES, FEATURE_NAMES_45


def _make_pcap(path: Path, num_windows: int, window_duration: float = 60.0, pkts_per_window: int = 4, base_time: float = 1700000000.0) -> None:
    """Helper to synthesize a clean, well-formed test PCAP."""
    packets = []
    for w in range(num_windows):
        for p in range(pkts_per_window):
            t_pkt = base_time + w * window_duration + p * 0.5
            pkt1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=5000 + w, dport=80, flags="S", window=64240) / b"request"
            pkt1.time = t_pkt
            packets.append(pkt1)
            pkt2 = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="192.168.1.20", dst="192.168.1.10") / TCP(sport=80, dport=5000 + w, flags="SA", window=32768) / b"response"
            pkt2.time = t_pkt + 0.05
            packets.append(pkt2)
    wrpcap(str(path), packets)


def test_30_second_short_pcap_completes_with_forecast_unavailable():
    """A 30-second capture must complete static analysis and explicitly state forecast is unavailable."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = Path(tf.name)
    try:
        # Generate 1 window of 30s duration
        _make_pcap(pcap_path, num_windows=1, window_duration=30.0, pkts_per_window=5)
        raw_bytes = pcap_path.read_bytes()
        result = analyze_uploaded_capture(pcap_path.name, raw_bytes)

        # High-level pipeline status
        assert result["status"] == "completed"
        # Machine-readable analysis state contract
        assert result["analysis_state"] == "ANALYSIS_COMPLETE_FORECAST_UNAVAILABLE"

        # Static traffic metrics must be fully populated
        assert result["traffic"]["packets"] == 10
        assert result["traffic"]["flows"] >= 1
        assert result["packet_count"] == 10
        assert result["window_count"] == 1
        assert result["findings"] is not None

        # Forecast summary contract
        assert result["forecast_summary"]["available"] is False
        assert result["forecast_summary"]["status"] == "INSUFFICIENT_HISTORY"
        assert result["forecast_summary"]["required_windows"] == 8
        assert result["forecast_summary"]["available_windows"] == 1
        assert "at least 8 continuous 60-second windows" in result["forecast_summary"]["message"]
        assert len(result["forecasts"]) == 5
        assert all(f["attackProbability"] is None for f in result["forecasts"])
        assert all(f["confidence"] is None for f in result["forecasts"])
    finally:
        pcap_path.unlink(missing_ok=True)


def test_7_window_pcap_insufficient_history():
    """A 7-window capture (420s) must produce completed static analysis but reject forecast due to lookback=8."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = Path(tf.name)
    try:
        _make_pcap(pcap_path, num_windows=7, window_duration=60.0, pkts_per_window=2)
        raw_bytes = pcap_path.read_bytes()
        result = analyze_uploaded_capture(pcap_path.name, raw_bytes)

        assert result["status"] == "completed"
        assert result["analysis_state"] == "ANALYSIS_COMPLETE_FORECAST_UNAVAILABLE"
        assert result["forecast_summary"]["available"] is False
        assert result["forecast_summary"]["status"] == "INSUFFICIENT_HISTORY"
        assert result["forecast_summary"]["available_windows"] == 7
        assert result["forecast_summary"]["required_windows"] == 8
    finally:
        pcap_path.unlink(missing_ok=True)


def test_8_window_pcap_generates_forecasts():
    """An 8-window capture (480s) satisfies lookback=8 and automatically activates the 45-feature model."""
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = Path(tf.name)
    try:
        _make_pcap(pcap_path, num_windows=8, window_duration=60.0, pkts_per_window=2)
        raw_bytes = pcap_path.read_bytes()
        result = analyze_uploaded_capture(pcap_path.name, raw_bytes)

        assert result["status"] == "completed"
        assert result["analysis_state"] == "ANALYSIS_COMPLETE_FORECAST_READY"
        assert result["forecast_summary"]["available"] is True
        assert result["forecast_summary"]["status"] == "READY"
        assert result["forecast_summary"]["available_windows"] == 8
        assert len(result["forecasts"]) == 5
        assert all(f["horizon"] in [1, 2, 3, 4, 5] for f in result["forecasts"])
    finally:
        pcap_path.unlink(missing_ok=True)


def test_canonical_45_feature_contract_and_no_zero_fill():
    """The 45-feature schema must strictly omit mean_tcp_rtt; zero-filling is forbidden."""
    assert "mean_tcp_rtt" in FLOW_NAMES
    assert "mean_tcp_rtt" not in FLOW_NAMES_45
    assert len(FLOW_NAMES_45) == 17
    assert len(PACKET_NAMES) == 22
    assert len(TEMPORAL_NAMES) == 6
    assert len(FEATURE_NAMES_45) == 45

    # Check that candidates built from passive extraction do not contain fabricated RTT
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = Path(tf.name)
    try:
        _make_pcap(pcap_path, num_windows=8, window_duration=60.0, pkts_per_window=2)
        pkts, windows, quality = extract_canonical_capture(pcap_path, window_seconds=60)
        candidates = build_network_state_candidates(windows)

        # In passive capture, mean_tcp_rtt is None or absent in raw candidates
        for c in candidates:
            assert c.flow_features.get("mean_tcp_rtt") is None or "mean_tcp_rtt" not in c.flow_features

        # 46-feature gate refuses
        history = build_state_history(candidates)
        report_46 = evaluate_model_compatibility(candidates, history_status=history.status)
        assert report_46.model_ready is False
        assert "flow_features.mean_tcp_rtt" in report_46.unavailable_features

        # 45-feature gate succeeds
        report_45 = evaluate_model_compatibility(candidates, MODEL_SCHEMA_45, history_status=history.status)
        assert report_45.model_ready is True
        assert "flow_features.mean_tcp_rtt" not in report_45.unavailable_features
    finally:
        pcap_path.unlink(missing_ok=True)


def test_scientific_evaluation_temporal_separation_and_leakage_safety():
    """Evaluation harness must enforce train_end < test_start and episode boundaries."""
    def make_dummy_state(t: int, attack: int) -> NetworkState:
        flow = {n: 1.0 for n in FLOW_NAMES_45}
        packet = {n: 0.0 for n in PACKET_NAMES}
        temporal = {n: 0.0 for n in TEMPORAL_NAMES}
        return NetworkState(t, flow, packet, temporal, attack, False)

    # 3 distinct chronological episodes
    ep1 = tuple(make_dummy_state(1000 + i * 60, 0) for i in range(15))
    ep2 = tuple(make_dummy_state(5000 + i * 60, 1) for i in range(15))
    ep3 = tuple(make_dummy_state(9000 + i * 60, 0) for i in range(15))

    splits = chronological_episode_split((ep1, ep2, ep3))
    assert splits["train"][0][-1].timestamp < splits["validation"][0][0].timestamp
    assert splits["validation"][0][-1].timestamp < splits["test"][0][0].timestamp

    # Cases must strictly enforce horizon targets > input end
    test_cases = build_forecast_cases(splits["test"][0], episode_id="test")
    assert len(test_cases) > 0
    for case in test_cases:
        assert case.input_timestamps[-1] < case.target_timestamps[0]
        assert list(case.target_timestamps) == sorted(case.target_timestamps)


def test_scientific_evaluation_reports_exist_and_are_valid():
    """Verify that reports/scientific_forecasting_evaluation.json and .md exist and contain verified metrics."""
    json_path = Path(__file__).resolve().parents[1] / "reports" / "scientific_forecasting_evaluation.json"
    md_path = Path(__file__).resolve().parents[1] / "reports" / "scientific_forecasting_evaluation.md"

    assert json_path.exists(), "scientific_forecasting_evaluation.json must exist"
    assert md_path.exists(), "scientific_forecasting_evaluation.md must exist"

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert "candidate_results" in data
    assert "Persistence" in data["candidate_results"]
    assert "Existing LSTM" in data["candidate_results"]
    assert "Majority" in data["candidate_results"]
    assert "Empirical Transition" in data["candidate_results"]
    assert "Logistic Regression" in data["candidate_results"]

    # Check 5 horizons exist for candidate results
    for h in [1, 2, 3, 4, 5]:
        assert f"T+{h}" in data["candidate_results"]["Persistence"]
        assert f"T+{h}" in data["candidate_results"]["Existing LSTM"]

    # Check honest promotion evaluation
    assert data["promotion"]["production_eligible"] is False
    assert data["promotion"]["status"] == "HOLD"
    assert "existing LSTM does not consistently beat persistence" in data["promotion"]["reasons"]
