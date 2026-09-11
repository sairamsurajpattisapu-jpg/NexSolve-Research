from __future__ import annotations

from dataclasses import replace

from nexsolve_core.schemas import PacketRecord, Provenance, build_flows, build_temporal_windows, make_capture_quality
from nexsolve_core.state import (
    FeatureAvailability,
    build_network_state_candidates,
    build_state_history,
    candidates_to_network_states,
    evaluate_model_compatibility,
    feature_registry,
)


def packet(index: int, timestamp: float, source: str = "10.0.0.1", destination: str = "10.0.0.2", protocol: str = "UDP") -> PacketRecord:
    return PacketRecord(timestamp, source, destination, 6 if ":" in source else 4, protocol, 1000, 2000, 100, 20, ttl=64, packet_index=index, provenance=Provenance("capture-a", (index,), source_timestamps=(timestamp,)))


def aggregate(packet_count: int = 1) -> dict[str, object]:
    return {
        "packet_count": packet_count, "packet_size_mean": 100.0, "packet_size_variance": 0.0, "packet_size_min": 100.0, "packet_size_max": 100.0,
        "ttl_mean": 64.0, "ttl_variance": 0.0, "ttl_min": 64.0, "ttl_max": 64.0,
        "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0, "psh_count": 0, "urg_count": 0,
        "tcp_window_mean": 0.0, "tcp_window_variance": 0.0, "fragment_count": 0, "tcp_retransmission_count": 0,
        "iat_mean": 1.0, "iat_variance": 0.0, "iat_max": 1.0, "protocol_counts": {"UDP": packet_count},
    }


def windows(count: int = 8):
    packets = tuple(packet(index, index * 60 + 1) for index in range(count))
    flows = build_flows(packets, "capture-a")
    quality = make_capture_quality(packets, capture_id="capture-a")
    raw = build_temporal_windows(packets, flows, quality)
    return tuple(replace(window, aggregate_features=aggregate(), detection_features={}) for window in raw)


def test_real_canonical_window_becomes_candidate_with_flow_packet_and_provenance():
    candidate = build_network_state_candidates(windows(1))[0]
    assert candidate.flow_features["flow_count"] == 1
    assert candidate.flow_features["total_packets"] == 1
    assert candidate.packet_features["packet_count"] == 1
    assert candidate.temporal_features == {}
    assert candidate.label == "UNKNOWN"
    assert candidate.capture_quality.capture_id == "capture-a"
    assert candidate.provenance.packet_indexes == (0,)
    assert candidate.feature_status["flow_features.flow_count"] == FeatureAvailability.CANONICAL_FLOW


def test_ipv6_canonical_window_becomes_candidate():
    ipv6_packet = packet(0, 1, "2001:db8::1", "2001:db8::2")
    flows = build_flows((ipv6_packet,), "capture-a")
    quality = make_capture_quality((ipv6_packet, packet(1, 2, "2001:db8::1", "2001:db8::2")), capture_id="capture-a")
    raw = build_temporal_windows((ipv6_packet,), flows, quality)
    candidate = build_network_state_candidates((replace(raw[0], aggregate_features=aggregate()),))[0]
    assert candidate.protocol_aggregates == {"UDP": 1}
    assert candidate.provenance.packet_indexes == (0,)


def test_flow_spanning_windows_uses_only_prefix_packets_at_each_time():
    packets = (packet(0, 1), packet(1, 61))
    flows = build_flows(packets, "capture-a")
    quality = make_capture_quality(packets, capture_id="capture-a")
    raw = build_temporal_windows(packets, flows, quality)
    candidates = build_network_state_candidates(raw)
    assert candidates[0].flow_features["total_packets"] == 1
    assert candidates[1].flow_features["total_packets"] == 2
    assert candidates[0].flow_features["mean_duration"] == 0
    assert candidates[1].flow_features["mean_duration"] == 60


def test_temporal_history_statuses_and_capture_boundaries():
    candidates = build_network_state_candidates(windows(8))
    assert build_state_history(candidates).status == "READY"
    assert build_state_history(candidates[:7]).status == "INSUFFICIENT_HISTORY"
    assert build_state_history(candidates[:3] + candidates[4:]).status == "GAPPED_HISTORY"
    other = replace(candidates[-1], provenance=replace(candidates[-1].provenance, capture_id="capture-b"))
    assert build_state_history(candidates[:-1] + (other,)).status == "GAPPED_HISTORY"


def test_compatibility_gate_reports_missing_features_without_zero_fill():
    candidates = build_network_state_candidates(windows(8))
    report = evaluate_model_compatibility(candidates, history_status="READY")
    assert report.model_ready is False
    assert report.required_features == 46
    assert "flow_features.mean_tcp_rtt" in report.unavailable_features
    assert candidates[1].feature_status["temporal_features.delta_flow_count"] == FeatureAvailability.TEMPORAL
    assert all("mean_tcp_rtt" not in candidate.flow_features for candidate in candidates)
    assert "zero" in " ".join(report.reasons).lower() or report.reasons
    try:
        candidates_to_network_states(candidates, history_status="READY")
    except ValueError as error:
        assert "zero-filled" in str(error)
    else:
        raise AssertionError("incompatible PCAP candidates must not become dense NetworkState values")


def test_registry_has_group_specific_spec_for_all_model_features():
    registry = feature_registry()
    assert len(registry) == 46
    assert registry["flow_features.mean_iat"].name == "mean_iat"
    assert registry["packet_features.mean_iat"].name == "mean_iat"
    assert registry["flow_features.mean_tcp_rtt"].availability == FeatureAvailability.UNAVAILABLE
