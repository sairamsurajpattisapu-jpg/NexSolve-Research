"""Tests for native NFStream-inspired flow intelligence and statistics."""
import pytest
from nexsolve_core.flow.statistics import (
    aggregate_flow_statistics_summary,
    build_flow_statistical_evidence,
    compute_flow_statistical_profile,
)
from nexsolve_core.schemas import FlowRecord, Provenance


def _make_sample_flow(
    flow_id: str,
    fwd_pkts: int,
    rev_pkts: int,
    fwd_bytes: int,
    rev_bytes: int,
    duration: float,
) -> FlowRecord:
    return FlowRecord(
        flow_id=flow_id,
        start_timestamp=100.0,
        end_timestamp=100.0 + duration,
        duration_seconds=duration,
        src_ip="192.168.1.10",
        src_port=50000,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        forward_packet_count=fwd_pkts,
        reverse_packet_count=rev_pkts,
        total_packet_count=fwd_pkts + rev_pkts,
        forward_bytes=fwd_bytes,
        reverse_bytes=rev_bytes,
        total_bytes=fwd_bytes + rev_bytes,
        packet_rate=(fwd_pkts + rev_pkts) / max(0.001, duration),
        byte_rate=(fwd_bytes + rev_bytes) / max(0.001, duration),
        syn_count=1,
        ack_count=1,
        fin_count=0,
        rst_count=0,
        retransmission_count=0,
        completeness="COMPLETE",
        provenance=Provenance("cap", (0,)),
    )


def test_flow_profile_asymmetry():
    """Verify bidirectional packet and byte asymmetry calculations."""
    flow = _make_sample_flow("f1", fwd_pkts=10, rev_pkts=0, fwd_bytes=1000, rev_bytes=0, duration=1.0)
    profile = compute_flow_statistical_profile(flow)
    assert profile.packet_asymmetry_ratio == 1.0
    assert profile.byte_asymmetry_ratio == 1.0

    balanced = _make_sample_flow("f2", fwd_pkts=10, rev_pkts=10, fwd_bytes=500, rev_bytes=500, duration=2.0)
    p_bal = compute_flow_statistical_profile(balanced)
    assert p_bal.packet_asymmetry_ratio == 0.0
    assert p_bal.byte_asymmetry_ratio == 0.0


def test_aggregate_flow_statistics_and_evidence():
    """Verify aggregate summary and scanning anomaly detection via single packet ratio."""
    # Create 25 single-packet flows (simulating sweep scan)
    flows = [
        _make_sample_flow(f"f-{i}", fwd_pkts=1, rev_pkts=0, fwd_bytes=60, rev_bytes=0, duration=0.01)
        for i in range(25)
    ]
    summary = aggregate_flow_statistics_summary(flows)
    assert summary.total_flows == 25
    assert summary.single_packet_flows == 25
    assert summary.single_packet_flow_ratio == 1.0

    evidence = build_flow_statistical_evidence(summary)
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.mitre_technique_id == "T1046"
    assert ev.modality.value == "ANOMALY"
    assert ev.temporal_scope.value == "OBSERVED"


def test_empty_flows_safely_aggregates():
    """Empty flow input safely yields zero statistics."""
    summary = aggregate_flow_statistics_summary([])
    assert summary.total_flows == 0
    assert summary.single_packet_flow_ratio == 0.0
    assert summary.profiles == ()
    assert build_flow_statistical_evidence(summary) == ()
