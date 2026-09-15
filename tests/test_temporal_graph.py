"""Unit tests for Dynamic Network Graph Intelligence and Temporal Attack Propagation."""
import pytest
from nexsolve_core.schemas import (
    CaptureQuality,
    FlowRecord,
    Provenance,
    QualityStatus,
    TemporalWindow,
)
from nexsolve_core.temporal_graph import (
    NodeRoleTag,
    build_graph_snapshot_from_flows,
    build_temporal_graph_sequence,
)
from ml.forecasting.graph_fusion import fuse_forecast_with_temporal_graph


def _make_quality() -> CaptureQuality:
    return CaptureQuality(
        total_packets_observed=100,
        parsed_packets=100,
        malformed_packets=0,
        unsupported_packets=0,
        truncated_packets=0,
        timestamp_anomalies=0,
        duplicate_packets=0,
        ipv4_count=100,
        ipv6_count=0,
        tcp_count=100,
        udp_count=0,
        icmp_count=0,
        arp_count=0,
        vlan_count=0,
        fragmented_packet_count=0,
        incomplete_flow_count=0,
        status=QualityStatus.GOOD,
        reason="nom",
        capture_id="test",
    )


def _make_flow(
    flow_id: str,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    protocol: str = "TCP",
    fwd_pkts: int = 10,
    rev_pkts: int = 5,
    fwd_bytes: int = 1000,
    rev_bytes: int = 500,
    syn: int = 1,
    rst: int = 0,
    dur: float = 1.0,
) -> FlowRecord:
    return FlowRecord(
        flow_id=flow_id,
        start_timestamp=0.0,
        end_timestamp=dur,
        duration_seconds=dur,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol=protocol,
        forward_packet_count=fwd_pkts,
        reverse_packet_count=rev_pkts,
        total_packet_count=fwd_pkts + rev_pkts,
        forward_bytes=fwd_bytes,
        reverse_bytes=rev_bytes,
        total_bytes=fwd_bytes + rev_bytes,
        packet_rate=float(fwd_pkts + rev_pkts) / max(dur, 0.001),
        byte_rate=float(fwd_bytes + rev_bytes) / max(dur, 0.001),
        syn_count=syn,
        ack_count=1,
        fin_count=0,
        rst_count=rst,
        retransmission_count=0,
        completeness="COMPLETE",
        provenance=Provenance(capture_id="test_cap"),
    )


def _make_window(window_id: str, start_t: int, end_t: int, flows: list[FlowRecord]) -> TemporalWindow:
    return TemporalWindow(
        window_id=window_id,
        start_timestamp=start_t,
        end_timestamp=end_t,
        duration_seconds=end_t - start_t,
        packet_count=sum(f.total_packet_count for f in flows),
        flow_count=len(flows),
        packets=(),
        flows=tuple(flows),
        aggregate_features={},
        detection_features={},
        quality=_make_quality(),
        ordering="ORDERED",
        provenance=Provenance(capture_id="test_cap"),
    )


def test_build_temporal_graph_sequence_empty():
    seq = build_temporal_graph_sequence(windows=None, all_flows=None)
    assert seq.status == "INSUFFICIENT_GRAPH_CONTEXT"
    assert seq.snapshot_count == 0
    assert len(seq.graph_feature_vector) == 16


def test_build_temporal_graph_from_flows():
    flows_w1 = [
        _make_flow("f1", "192.168.1.10", 44552, "10.0.0.5", 80),
        _make_flow("f2", "192.168.1.10", 44554, "10.0.0.6", 443),
    ]

    flows_w2 = flows_w1 + [
        _make_flow("f3", "192.168.1.10", 44556, "10.0.0.7", 22, rst=1),
        _make_flow("f4", "192.168.1.10", 44558, "10.0.0.8", 8080, rst=1),
        _make_flow("f5", "192.168.1.10", 44560, "10.0.0.9", 3389, rst=1),
    ]

    win1 = _make_window("0", 0, 60, flows_w1)
    win2 = _make_window("1", 60, 120, flows_w2)

    seq = build_temporal_graph_sequence(windows=[win1, win2])
    assert seq.status == "READY"
    assert seq.snapshot_count == 2
    assert len(seq.observed_snapshots) == 2
    assert len(seq.forecast_projections) == 5

    # Check that 192.168.1.10 was identified as high fan-out / lateral source
    top_node = seq.top_high_activity_nodes[0]
    assert top_node.ip == "192.168.1.10"
    assert top_node.fan_out >= 5

    # Check forecast projections T+1 to T+5
    p1 = seq.forecast_projections[0]
    assert p1.horizon_step == 1
    assert p1.predicted_node_count >= 5
    assert p1.propagation_confidence > 0.0


def test_forecast_graph_fusion():
    baseline_points = [
        {"horizon": 1, "step_attack_probability": 0.45, "cumulative_risk": 0.45, "risk_level": "MODERATE", "predicted_stage": "RECONNAISSANCE", "confidence": 0.82},
        {"horizon": 2, "step_attack_probability": 0.60, "cumulative_risk": 0.70, "risk_level": "ELEVATED", "predicted_stage": "LATERAL_MOVEMENT", "confidence": 0.78},
    ]

    # Test Mode A fallback
    res_a = fuse_forecast_with_temporal_graph(baseline_points, None, mode="MODE_A")
    assert res_a.active_mode == "MODE_A"
    assert len(res_a.fused_points) == 2
    assert res_a.fused_points[0].mode == "MODE_A_BASELINE"

    # Test Mode B with valid graph
    flows = [
        _make_flow(f"f{i}", "192.168.1.10", 5000 + i, f"10.0.0.{i}", 80 + i)
        for i in range(1, 8)
    ]
    win = _make_window("0", 0, 60, flows)
    graph_seq = build_temporal_graph_sequence(windows=[win])

    res_b = fuse_forecast_with_temporal_graph(baseline_points, graph_seq, mode="MODE_B")
    assert res_b.active_mode == "MODE_B"
    assert res_b.graph_context_available is True
    assert len(res_b.fused_points) == 2
    assert res_b.fused_points[0].mode == "MODE_B_GRAPH_FUSED"
    assert len(res_b.mitre_structural_attributions) > 0
