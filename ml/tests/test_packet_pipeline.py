import math

import pytest

from ml.data.flow_packet_aligner import AlignmentConfig, align_observations, validate_past_only
from ml.data.packet_features import (
    PacketRecord,
    aggregate_window_features,
    build_packet_windows,
    determine_label_alignment_status,
    normalize_packet_record,
    packet_feature_vector,
)
from ml.data.pcap_extractor import _detect_retransmission, _port_scan_score, compute_packet_window_stats


@pytest.fixture
def sample_packets():
    return [
        {
            "timestamp": 100.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": 80,
            "packet_length": 120,
            "payload_length": 40,
            "ttl": 64,
            "tcp_flags": 0x02,
            "tcp_window": 65535,
            "tcp_seq": 100,
            "tcp_ack": 200,
            "fragment_offset": 0,
            "more_fragments": False,
            "identification": 1,
        },
        {
            "timestamp": 115.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "src_port": 5000,
            "dst_port": 80,
            "packet_length": 80,
            "payload_length": 0,
            "ttl": 60,
            "tcp_flags": 0x10,
            "tcp_window": 65535,
            "tcp_seq": 140,
            "tcp_ack": 240,
            "fragment_offset": 0,
            "more_fragments": False,
            "identification": 2,
        },
        {
            "timestamp": 160.0,
            "src_ip": "10.0.0.3",
            "dst_ip": "10.0.0.9",
            "protocol": "UDP",
            "src_port": 53,
            "dst_port": 5353,
            "packet_length": 90,
            "payload_length": 20,
            "ttl": 128,
        },
    ]


def test_packet_record_normalization_and_window_aggregation(sample_packets):
    normalized = [normalize_packet_record(pkt) for pkt in sample_packets]
    assert all(isinstance(pkt, PacketRecord) for pkt in normalized)
    assert normalized[0].protocol == "TCP"
    assert normalized[2].tcp_flags is None
    windows = build_packet_windows(normalized, window_seconds=60)
    assert 1 in windows and 2 in windows
    features = aggregate_window_features(windows[1], window_start=60)
    assert features["packet_count"] == 2
    assert features["ttl_mean"] == pytest.approx(62.0)
    assert features["syn_count"] == 1
    assert features["ack_count"] == 1
    assert features["packet_size_mean"] == pytest.approx(100.0)
    assert features["fragment_count"] == 0
    assert features["protocol_counts"]["TCP"] == 2


def test_past_only_assertion_for_windowed_history():
    states = [
        {"window_start": 0, "packet_count": 5, "timestamp": 0},
        {"window_start": 60, "packet_count": 7, "timestamp": 60},
    ]
    validate_past_only(states)
    with pytest.raises(ValueError):
        validate_past_only([
            {"window_start": 60, "packet_count": 7, "timestamp": 60},
            {"window_start": 0, "packet_count": 5, "timestamp": 0},
        ])


def test_alignment_and_label_block_status():
    flow_windows = [{"window_start": 0, "timestamp": 0}, {"window_start": 120, "timestamp": 120}]
    packet_windows = [{"window_start": 0, "timestamp": 5}, {"window_start": 60, "timestamp": 65}]
    result = align_observations(flow_windows, packet_windows, AlignmentConfig(window_seconds=60))
    assert result["matched_windows"] == 1
    assert result["alignment_coverage"] == pytest.approx(1 / 3)
    assert determine_label_alignment_status({}) == "BLOCKED"


def test_packet_feature_vector_placeholder_contract_is_explicit():
    vector = packet_feature_vector({"window_start": 0, "window_end": 60, "observations": ({"timestamp": 1, "src_ip": "a", "dst_ip": "b", "protocol": "TCP"},)})
    assert vector["status"] == "PENDING_PCAP"
    assert vector["available"] is False


def test_missing_fields_are_explicit_and_not_fabricated():
    record = normalize_packet_record({"timestamp": 5.0, "src_ip": "1.1.1.1", "dst_ip": "2.2.2.2", "protocol": "TCP"})
    assert record.src_port is None
    assert record.tcp_flags is None
    assert record.ttl is None


def test_real_packet_feature_fields_cover_required_metrics(sample_packets):
    features = compute_packet_window_stats(sample_packets, retransmission_count=1)
    required = {
        "ttl_mean", "ttl_variance", "ttl_min", "ttl_max", "tcp_window_mean", "tcp_window_variance",
        "packet_size_mean", "packet_size_median", "packet_size_variance", "packet_size_p95",
        "payload_mean", "payload_median", "payload_variance", "payload_p95", "payload_zero_ratio",
        "iat_mean", "iat_median", "iat_variance", "iat_p95", "syn_count", "ack_count", "fragment_count",
        "tcp_retransmission_count", "tcp_retransmission_rate", "port_scan_score",
    }
    assert required <= features.keys()
    assert features["tcp_retransmission_count"] == 1
    assert features["port_scan_score"] is None


def test_retransmission_detector_uses_direction_and_sequence_overlap(sample_packets):
    context = {}
    assert not _detect_retransmission(sample_packets[0], context)
    duplicate = dict(sample_packets[0], timestamp=101.0)
    assert _detect_retransmission(duplicate, context)
    reverse = dict(sample_packets[0], src_ip="10.0.0.2", dst_ip="10.0.0.1", timestamp=102.0)
    assert not _detect_retransmission(reverse, context)


def test_port_scan_score_is_traffic_only_and_bounded(sample_packets):
    records = [dict(sample_packets[0], dst_port=port, tcp_flags=0x02) for port in range(1, 121)]
    score = _port_scan_score(records)
    assert 0.0 <= score <= 1.0
    assert score > 0.5
