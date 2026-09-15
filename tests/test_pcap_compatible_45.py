"""Regression and integration tests for the versioned 45-feature PCAP-compatible model and gate."""
import tempfile
from pathlib import Path
import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from ml.data.pcap_extractor import extract_canonical_capture
from nexsolve_core.state import (
    build_network_state_candidates,
    build_state_history,
    evaluate_model_compatibility,
    candidates_to_network_states,
    MODEL_SCHEMA_45,
    FLOW_NAMES,
    FLOW_NAMES_45,
    PACKET_NAMES,
    TEMPORAL_NAMES,
)
from model_service.pcap_upload import analyze_uploaded_capture


def test_45_feature_schema_definition():
    """Verify exact 45 features and omission of mean_tcp_rtt without mutation of canonical 46 features."""
    assert len(FLOW_NAMES) == 18
    assert "mean_tcp_rtt" in FLOW_NAMES
    assert len(FLOW_NAMES_45) == 17
    assert "mean_tcp_rtt" not in FLOW_NAMES_45
    assert len(PACKET_NAMES) == 22
    assert len(TEMPORAL_NAMES) == 6
    total_45 = len(FLOW_NAMES_45) + len(PACKET_NAMES) + len(TEMPORAL_NAMES)
    assert total_45 == 45


def test_dual_schema_gate_behavior():
    """Synthetic 8-window capture with bidirectional traffic: 46-gate abstains on RTT, 45-gate succeeds."""
    base_epoch = 1700000000.0
    packets = []
    for w in range(8):
        for p in range(4):
            pkt1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.1.1", dst="10.0.2.1") / TCP(sport=5000 + w, dport=80, flags="S", window=64240) / b"data"
            pkt1.time = base_epoch + w * 60.0 + p * 1.0
            packets.append(pkt1)
            pkt2 = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="10.0.2.1", dst="10.0.1.1") / TCP(sport=80, dport=5000 + w, flags="SA", window=32768) / b"resp"
            pkt2.time = base_epoch + w * 60.0 + p * 1.0 + 0.05
            packets.append(pkt2)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        pkts, windows, quality = extract_canonical_capture(temp_path, window_seconds=60)
        candidates = build_network_state_candidates(windows)
        history = build_state_history(candidates)

        assert history.status == "READY"

        # 46-feature schema: strictly refuses because mean_tcp_rtt is unavailable in passive packet contract
        report_46 = evaluate_model_compatibility(candidates, history_status=history.status)
        assert report_46.model_ready is False
        assert "flow_features.mean_tcp_rtt" in report_46.unavailable_features

        # 45-feature schema: succeeds honestly
        report_45 = evaluate_model_compatibility(candidates, MODEL_SCHEMA_45, history_status=history.status)
        assert report_45.model_ready is True
        assert len(report_45.unavailable_features) == 0

        # Candidate conversion yields valid NetworkState objects
        states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history.status)
        assert len(states) >= 7
        assert states[0].encode_45().shape == (45,)
    finally:
        temp_path.unlink(missing_ok=True)


def test_real_friday_slice_pcap_end_to_end():
    """Verify real Friday bidirectional capture runs through the entire forecast pipeline without fabrication."""
    pcap_path = Path(r"C:\Users\saira\Downloads\friday_10windows_slice.pcap")
    if not pcap_path.exists():
        pytest.skip("friday_10windows_slice.pcap not present on host")

    content = pcap_path.read_bytes()
    res = analyze_uploaded_capture("friday_10windows_slice.pcap", content)

    assert res["status"] == "completed"
    assert res["packet_count"] == 2277
    assert res["window_count"] == 10
    assert res["model_compatibility"]["model_ready"] is True
    assert res["model_compatibility"]["required_features"] == 45

    # 5-step forecast rollouts
    forecasts = res["forecasts"]
    assert len(forecasts) == 5
    for pt in forecasts:
        assert pt["attackProbability"] is not None
        assert 0.0 <= pt["attackProbability"] <= 1.0
        assert pt["confidence"] is not None
        assert len(pt["explanation"]) > 0

    # Attack horizon and evidence chain
    ah = res["attack_horizon"]
    assert ah["state"] in ("EARLY_SIGNAL", "SUSTAINED_ATTACK_FORECAST", "NO_ATTACK_FORECAST")
    assert ah["lead_time_seconds"] is not None

    ec = res["evidence_chain"]
    assert len(ec["supporting"]) > 0 or len(ec["contradictory"]) > 0


def test_insufficient_history_abstention():
    """Verify captures with fewer than 8 windows trigger explicit forecast abstention without generating predictions."""
    base_epoch = 1700000000.0
    packets = []
    # Generate only 5 windows (less than 8 requirement)
    for w in range(5):
        for p in range(2):
            pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.1.1", dst="10.0.2.1") / TCP(sport=5000 + w, dport=80, flags="S")
            pkt.time = base_epoch + w * 60.0 + p * 1.0
            packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        content = temp_path.read_bytes()
        res = analyze_uploaded_capture("short_5win.pcap", content)

        assert res["model_compatibility"]["model_ready"] is False
        assert "minimum 8 windows required" in res["model_compatibility"]["reason"].lower() or "insufficient" in res["model_compatibility"]["reason"].lower()

        for pt in res["forecasts"]:
            assert pt["attackProbability"] is None
            assert pt["predictedStage"] is None
            assert "Forecast abstained" in pt["explanation"][0]
    finally:
        temp_path.unlink(missing_ok=True)


def test_model_boundary_strict_45_shape():
    """Verify candidate state encoding produces exact 45-dimensional vectors for model input."""
    base_epoch = 1700000000.0
    packets = []
    for w in range(8):
        for p in range(2):
            pkt1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.1.1", dst="10.0.2.1") / TCP(sport=5000 + w, dport=80, flags="S", window=64240) / b"data"
            pkt1.time = base_epoch + w * 60.0 + p * 1.0
            packets.append(pkt1)
            pkt2 = Ether(src="66:77:88:99:aa:bb", dst="00:11:22:33:44:55") / IP(src="10.0.2.1", dst="10.0.1.1") / TCP(sport=80, dport=5000 + w, flags="SA", window=32768) / b"resp"
            pkt2.time = base_epoch + w * 60.0 + p * 1.0 + 0.05
            packets.append(pkt2)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        _pkts, windows, _quality = extract_canonical_capture(temp_path, window_seconds=60)
        candidates = build_network_state_candidates(windows, MODEL_SCHEMA_45)
        history = build_state_history(candidates)
        states = candidates_to_network_states(candidates, MODEL_SCHEMA_45, history.status)

        for s in states:
            vec = s.encode_45()
            assert vec.shape == (45,)
            assert vec.dtype == float or vec.dtype.kind == 'f'
    finally:
        temp_path.unlink(missing_ok=True)

