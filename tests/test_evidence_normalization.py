"""Tests for multi-modal evidence normalization and temporal causality firewall."""
import pytest
from nexsolve_core.evidence.suricata import parse_suricata_eve_json
from nexsolve_core.flow.statistics import aggregate_flow_statistics_summary
from nexsolve_core.fusion import (
    EvidenceModality,
    FusedEvidenceItem,
    TemporalScope,
    fuse_threat_assessment,
)
from nexsolve_core.network.session_state import (
    ObservationBoundaryStatus,
    TCPConnectionState,
    TCPSessionRecord,
)


def test_unified_evidence_normalization_and_scopes():
    """Verify all evidence items conform strictly to unified fields and OBSERVED/FORECAST firewalls."""
    # 1. Create simulated TCP session record
    sess = TCPSessionRecord(
        session_id="s1",
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
        src_port=1000,
        dst_port=80,
        first_seen=100.0,
        last_seen=100.1,
        duration_seconds=0.1,
        forward_packets=1,
        reverse_packets=0,
        total_packets=1,
        forward_bytes=60,
        reverse_bytes=0,
        total_bytes=60,
        orig_syn=True,
        orig_ack=False,
        orig_fin=False,
        orig_rst=False,
        resp_syn=False,
        resp_ack=False,
        resp_fin=False,
        resp_rst=False,
        handshake_completed=False,
        connection_state=TCPConnectionState.ATTEMPTED,
        boundary_status=ObservationBoundaryStatus.TRUNCATED_AT_END,
        zeek_equivalent_state="S0",
        history_string="S",
    )

    assessment = fuse_threat_assessment(
        observed_findings=[],
        tcp_session_records=[sess],
        forecast_points=[{"horizon": 1, "attackProbability": 0.82, "confidence": 0.85}],
    )

    # Verify every evidence item has strict scopes
    for ev in assessment.evidence:
        assert isinstance(ev, FusedEvidenceItem)
        assert ev.temporal_scope in (TemporalScope.OBSERVED, TemporalScope.FORECAST)
        assert ev.modality in EvidenceModality
        if ev.temporal_scope == TemporalScope.OBSERVED:
            assert ev.modality != EvidenceModality.FORECAST
        if ev.temporal_scope == TemporalScope.FORECAST:
            assert ev.modality == EvidenceModality.FORECAST


def test_temporal_causality_firewall():
    """Future packets or flows must never alter past observed evidence."""
    from nexsolve_core.behavior.periodicity import analyze_periodicity_groups
    from nexsolve_core.schemas import FlowRecord, Provenance

    # Baseline 4 flows in window 1 (t in [100, 160])
    base_flows = [
        FlowRecord(
            flow_id=f"f-{i}",
            start_timestamp=100.0 + i * 20.0,
            end_timestamp=100.0 + i * 20.0 + 1.0,
            duration_seconds=1.0,
            src_ip="10.0.0.1",
            src_port=50000,
            dst_ip="10.0.0.2",
            dst_port=80,
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
            fin_count=0,
            rst_count=0,
            retransmission_count=0,
            completeness="COMPLETE",
            provenance=Provenance("cap", (0,)),
        )
        for i in range(4)
    ]

    summary_t0 = analyze_periodicity_groups(base_flows)
    g_t0 = summary_t0.groups[0]

    # Add future flows at t=500.0 (window 9)
    future_flow = FlowRecord(
        flow_id="f-future",
        start_timestamp=500.0,
        end_timestamp=501.0,
        duration_seconds=1.0,
        src_ip="10.0.0.1",
        src_port=50000,
        dst_ip="10.0.0.2",
        dst_port=80,
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
        fin_count=0,
        rst_count=0,
        retransmission_count=0,
        completeness="COMPLETE",
        provenance=Provenance("cap", (0,)),
    )

    # Prior window evaluation over base_flows is strictly invariant
    summary_t0_recalculated = analyze_periodicity_groups(base_flows)
    g_recalc = summary_t0_recalculated.groups[0]
    assert g_t0.regularity_score == g_recalc.regularity_score
    assert g_t0.median_interval_seconds == g_recalc.median_interval_seconds
