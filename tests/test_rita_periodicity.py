"""Tests for native RITA-inspired periodicity and interval regularity analyzer."""
import pytest
from nexsolve_core.behavior.periodicity import (
    PeriodicityClassification,
    analyze_periodicity_groups,
    calculate_bowley_skewness,
    calculate_interval_entropy,
    calculate_mad,
)
from nexsolve_core.schemas import FlowRecord, Provenance


def _make_flow(src_ip: str, dst_ip: str, dst_port: int, start_time: float, dur: float = 1.0) -> FlowRecord:
    return FlowRecord(
        flow_id=f"flow-{src_ip}-{dst_ip}-{start_time}",
        start_timestamp=start_time,
        end_timestamp=start_time + dur,
        duration_seconds=dur,
        src_ip=src_ip,
        src_port=49152,
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="TCP",
        forward_packet_count=5,
        reverse_packet_count=5,
        total_packet_count=10,
        forward_bytes=500,
        reverse_bytes=500,
        total_bytes=1000,
        packet_rate=10.0,
        byte_rate=1000.0,
        syn_count=1,
        ack_count=1,
        fin_count=1,
        rst_count=0,
        retransmission_count=0,
        completeness="COMPLETE",
        provenance=Provenance("test_cap", (0,)),
    )


def test_insufficient_observations():
    """Fewer than 4 connections must yield INSUFFICIENT_OBSERVATIONS."""
    flows = [
        _make_flow("10.0.0.1", "1.1.1.1", 443, 100.0),
        _make_flow("10.0.0.1", "1.1.1.1", 443, 160.0),
    ]
    summary = analyze_periodicity_groups(flows, min_connections=4)
    assert summary.total_groups_evaluated == 1
    assert summary.insufficient_groups == 1
    assert summary.groups[0].classification == PeriodicityClassification.INSUFFICIENT_OBSERVATIONS
    assert summary.groups[0].regularity_score == 0.0


def test_highly_periodic_metronome():
    """Metronome intervals (e.g. exactly 60.0s) must yield HIGHLY_PERIODIC."""
    flows = [
        _make_flow("10.0.0.5", "192.168.1.100", 8080, 100.0 + i * 60.0)
        for i in range(10)
    ]
    summary = analyze_periodicity_groups(flows)
    assert summary.total_groups_evaluated == 1
    g = summary.groups[0]
    assert g.classification == PeriodicityClassification.HIGHLY_PERIODIC
    assert g.regularity_score >= 0.95
    assert g.median_interval_seconds == 60.0
    assert g.mad_interval_seconds == 0.0
    assert g.coefficient_of_variation == 0.0
    assert g.jitter_seconds == 0.0


def test_irregular_random_intervals():
    """High jitter irregular connections must yield IRREGULAR."""
    # Deliberate chaotic timestamps: intervals 5s, 120s, 3s, 500s, 12s, 80s
    times = [100.0, 105.0, 225.0, 228.0, 728.0, 740.0, 820.0]
    flows = [_make_flow("10.0.0.2", "8.8.8.8", 53, t) for t in times]
    summary = analyze_periodicity_groups(flows)
    assert summary.total_groups_evaluated == 1
    g = summary.groups[0]
    assert g.classification == PeriodicityClassification.IRREGULAR
    assert g.regularity_score < 0.40


def test_bowley_skewness_and_mad_edge_cases():
    """Zero dispersion and small lists must safely calculate without exception."""
    assert calculate_bowley_skewness([10.0, 10.0, 10.0, 10.0]) == 0.0
    assert calculate_mad([10.0, 10.0, 10.0], 10.0) == 0.0
    assert calculate_interval_entropy([5.0, 5.0, 5.0]) == 0.0
    assert calculate_bowley_skewness([]) is None


def test_empty_flows():
    """Empty flow list produces empty summary."""
    summary = analyze_periodicity_groups([])
    assert summary.total_groups_evaluated == 0
    assert summary.groups == ()
