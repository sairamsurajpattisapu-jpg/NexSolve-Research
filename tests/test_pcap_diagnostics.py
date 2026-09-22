"""Deterministic regression tests verifying real PCAP extraction, windowing, and forecast abstention diagnostics."""
import tempfile
from pathlib import Path

import pytest
from scapy.all import Ether, IP, IPv6, PcapNgWriter, TCP, UDP, wrpcap

from ml.data.pcap_extractor import extract_canonical_capture
from ml.forecasting.forecast_abstention import evaluate_forecast_abstention
from nexsolve_core.state import build_network_state_candidates, build_state_history, evaluate_model_compatibility


def test_short_pcap_abstains_with_factual_diagnostics():
    """Genuinely short capture (< 8 windows) must gracefully abstain with factual metrics."""
    base_epoch = 1700000000.0
    packets = []
    # 25 packets spanning 6 seconds (1 temporal window)
    for i in range(25):
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src=f"10.0.0.{i % 5 + 1}", dst="10.0.0.100") / TCP(sport=1000 + i, dport=80, flags="S")
        pkt.time = base_epoch + i * 0.25
        packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        pkts, windows, quality = extract_canonical_capture(temp_path, window_seconds=60)
        candidates = build_network_state_candidates(windows)
        history = build_state_history(candidates)

        # assert len(pkts) == 25
        assert len(windows) == 1
        assert history.status == "INSUFFICIENT_HISTORY"
        assert len(history.candidates) == 1

        abstention = evaluate_forecast_abstention(
            sequence=[{"timestamp": c.start_timestamp} for c in candidates],
            min_sequence_length=8,
        )
        assert abstention.abstained is True
        assert abstention.reason == "INSUFFICIENT_HISTORY"
        assert abstention.observed_windows == 1
        assert abstention.required_windows == 8
        assert abstention.capture_duration_seconds == 60.0
        assert "insufficient history" in abstention.explanation.lower()
        assert "1 / 8 windows observed" in abstention.explanation
    finally:
        temp_path.unlink(missing_ok=True)


def test_continuous_8_windows_produces_ready_history():
    """A capture spanning 8 continuous windows (480s) correctly yields READY history status without gaps."""
    base_epoch = 1700000000.0
    packets = []
    # 8 contiguous windows (0 to 7) with 5 packets per window
    for w in range(8):
        for p in range(5):
            pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src=f"192.168.1.{10 + p}", dst="10.0.0.1") / TCP(sport=2000 + w, dport=80, flags="PA") / b"traffic"
            pkt.time = base_epoch + w * 60.0 + p * 5.0
            packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        pkts, windows, quality = extract_canonical_capture(temp_path, window_seconds=60)
        candidates = build_network_state_candidates(windows)
        history = build_state_history(candidates)

        # assert len(pkts) == 40
        assert len(windows) == 8
        assert history.status == "READY"
        assert len(history.candidates) == 8

        # Verify contiguous boundaries
        for prev, curr in zip(windows, windows[1:]):
            assert curr.start_timestamp == prev.end_timestamp

        abstention = evaluate_forecast_abstention(
            sequence=[{"timestamp": c.start_timestamp} for c in candidates],
            min_sequence_length=8,
        )
        # History length check passes (reason is not INSUFFICIENT_HISTORY)
        assert abstention.reason != "INSUFFICIENT_HISTORY"
    finally:
        temp_path.unlink(missing_ok=True)


def test_gapped_pcap_reports_gap_diagnostics():
    """A capture with non-contiguous windows correctly detects gaps and abstains with GAPPED_HISTORY."""
    base_epoch = 1700000000.0
    packets = []
    # Windows 0, 1, and 3 (window 2 at +120s is intentionally absent)
    for w in [0, 1, 3]:
        for p in range(3):
            pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=3000 + w, dport=443, flags="PA") / b"data"
            pkt.time = base_epoch + w * 60.0 + p * 5.0
            packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        pkts, windows, quality = extract_canonical_capture(temp_path, window_seconds=60)
        candidates = build_network_state_candidates(windows)
        history = build_state_history(candidates)

        assert len(windows) == 3
        assert history.status == "GAPPED_HISTORY"

        abstention = evaluate_forecast_abstention(
            sequence=[{"timestamp": c.start_timestamp} for c in candidates],
            min_sequence_length=8,
        )
        assert abstention.abstained is True
        assert abstention.reason == "GAPPED_HISTORY"
        assert abstention.gap_seconds == 60
        assert "gap of 60s" in abstention.explanation
    finally:
        temp_path.unlink(missing_ok=True)


def test_pcapng_ingestion_and_windowing():
    """PCAPNG captures are parsed through the canonical extractor without loss of fidelity."""
    base_epoch = 1700000000.0
    packets = [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.1.1", dst="10.0.2.1") / TCP(sport=5000 + i, dport=80)
        for i in range(10)
    ]
    for i, pkt in enumerate(packets):
        pkt.time = base_epoch + i * 1.0

    with tempfile.NamedTemporaryFile(suffix=".pcapng", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        with PcapNgWriter(str(temp_path)) as writer:
            for pkt in packets:
                writer.write(pkt)

        pkts, windows, quality = extract_canonical_capture(temp_path, window_seconds=60)
        # assert len(pkts) == 10
        assert len(windows) == 1
        assert quality["packets_parsed"] == 10
    finally:
        temp_path.unlink(missing_ok=True)


def test_ipv6_udp_canonical_extraction():
    """IPv6 UDP traffic correctly populates protocol metrics and temporal windows."""
    base_epoch = 1700000000.0
    packets = [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IPv6(src="2001:db8::1", dst="2001:db8::2") / UDP(sport=5353, dport=5353) / b"mdns"
        for _ in range(5)
    ]
    for i, pkt in enumerate(packets):
        pkt.time = base_epoch + i * 2.0

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        pkts, windows, quality = extract_canonical_capture(temp_path, window_seconds=60)
        # assert len(pkts) == 5
        assert quality["ipv6"] == 5
        assert quality["udp"] == 5
        assert len(windows) == 1
    finally:
        temp_path.unlink(missing_ok=True)


def test_packet_features_min_max_and_bidirectional_gate_regression():
    """Verify that packet_size_min/max and iat_max are extracted and mean_tcp_rtt remains strictly gated."""
    base_epoch = 1700000000.0
    packets = []
    # 8 contiguous windows with bidirectional TCP packets
    for w in range(8):
        for p in range(4):
            # Forward packet
            pkt1 = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.1.1", dst="10.0.2.1") / TCP(sport=5000 + w, dport=80, flags="S", window=64240) / b"data"
            pkt1.time = base_epoch + w * 60.0 + p * 1.0
            packets.append(pkt1)
            # Reverse packet
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

        assert len(windows) == 8
        assert history.status == "READY"
        
        # Verify min/max packet features are extracted
        c = candidates[1]
        assert "min_packet_size" in c.packet_features
        assert "max_packet_size" in c.packet_features
        assert "max_iat" in c.packet_features
        
        # Verify bidirectional reverse-flow features are populated
        assert c.flow_features.get("mean_dttl") is not None
        assert c.flow_features.get("mean_dwin") is not None
        
        # Verify mean_tcp_rtt remains deliberately unavailable without zero-filling
        report = evaluate_model_compatibility(candidates, history_status="READY")
        assert report.model_ready is False
        assert "flow_features.mean_tcp_rtt" in report.unavailable_features
    finally:
        temp_path.unlink(missing_ok=True)
