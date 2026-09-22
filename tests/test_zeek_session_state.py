"""Unit and protocol tests for Zeek-inspired TCP session state tracker."""
import pytest
from scapy.all import Ether, IP, TCP, UDP

from ml.data.pcap_extractor import extract_canonical_capture
from nexsolve_core.network.session_state import (
    ObservationBoundaryStatus,
    TCPConnectionState,
    TCPSessionRecord,
    aggregate_tcp_session_metrics,
    build_tcp_session_evidence,
    track_tcp_sessions,
)
from nexsolve_core.schemas import PacketRecord


def _make_packet(
    timestamp: float,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    protocol: str = "TCP",
    tcp_flags: int = 0,
    packet_length: int = 60,
    payload_length: int = 0,
) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_version=4,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        packet_length=packet_length,
        payload_length=payload_length,
        tcp_flags=tcp_flags,
    )


def test_syn_with_no_response():
    """1. Originator sends SYN, responder never replies prior to observation boundary (Zeek S0)."""
    # SYN: 0x02
    pkts = [
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x02),
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.connection_state == TCPConnectionState.ATTEMPTED
    assert s.zeek_equivalent_state == "S0"
    assert s.boundary_status == ObservationBoundaryStatus.TRUNCATED_AT_END
    assert s.forward_packets == 1
    assert s.reverse_packets == 0
    assert s.orig_syn is True
    assert s.resp_syn is False
    assert s.handshake_completed is False


def test_syn_then_syn_ack_incomplete():
    """2. Originator sends SYN, responder replies SYN-ACK, but no final ACK (half-open)."""
    pkts = [
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x02),        # SYN
        _make_packet(100.05, "10.0.0.1", "192.168.1.10", 80, 54321, tcp_flags=0x12),       # SYN-ACK (0x12)
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    # Without final ACK or subsequent packets, handshake is incomplete
    assert s.handshake_completed is False
    assert s.orig_syn is True
    assert s.resp_syn is True
    assert s.connection_state == TCPConnectionState.INCOMPLETE
    assert s.zeek_equivalent_state == "OTH"


def test_syn_synack_ack_established():
    """3. Normal 3-way handshake established (Zeek S1)."""
    pkts = [
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x02),        # SYN
        _make_packet(100.05, "10.0.0.1", "192.168.1.10", 80, 54321, tcp_flags=0x12),       # SYN-ACK
        _make_packet(100.06, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x10),       # ACK
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.handshake_completed is True
    assert s.connection_state == TCPConnectionState.ESTABLISHED
    assert s.zeek_equivalent_state == "S1"
    assert s.forward_packets == 2
    assert s.reverse_packets == 1


def test_established_followed_by_fin_closed():
    """4. Connection established and gracefully closed via FIN (Zeek SF)."""
    pkts = [
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x02),        # SYN
        _make_packet(100.05, "10.0.0.1", "192.168.1.10", 80, 54321, tcp_flags=0x12),       # SYN-ACK
        _make_packet(100.06, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x10),       # ACK
        _make_packet(101.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x11),        # FIN-ACK (0x11)
        _make_packet(101.05, "10.0.0.1", "192.168.1.10", 80, 54321, tcp_flags=0x11),       # FIN-ACK (0x11)
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.handshake_completed is True
    assert s.connection_state == TCPConnectionState.CLOSED
    assert s.zeek_equivalent_state == "SF"
    assert s.boundary_status == ObservationBoundaryStatus.COMPLETE_LIFECYCLE


def test_connection_followed_by_rst():
    """5. Connection established and subsequently terminated with RST (Zeek RSTO / RSTR)."""
    pkts = [
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x02),        # SYN
        _make_packet(100.05, "10.0.0.1", "192.168.1.10", 80, 54321, tcp_flags=0x12),       # SYN-ACK
        _make_packet(100.06, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x10),       # ACK
        _make_packet(101.0, "10.0.0.1", "192.168.1.10", 80, 54321, tcp_flags=0x04),        # RST (0x04)
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.handshake_completed is True
    assert s.connection_state == TCPConnectionState.RESET
    assert s.zeek_equivalent_state == "RSTR"


def test_bidirectional_traffic_and_bytes():
    """6. Bidirectional packet accounting and byte aggregation."""
    pkts = [
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x02, packet_length=60),
        _make_packet(100.05, "10.0.0.1", "192.168.1.10", 80, 54321, tcp_flags=0x12, packet_length=60),
        _make_packet(100.06, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x10, packet_length=150, payload_length=96),
        _make_packet(100.10, "10.0.0.1", "192.168.1.10", 80, 54321, tcp_flags=0x10, packet_length=300, payload_length=246),
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.forward_packets == 2
    assert s.reverse_packets == 2
    assert s.total_packets == 4
    assert s.forward_bytes == 210
    assert s.reverse_bytes == 360
    assert s.total_bytes == 570


def test_retransmitted_syn():
    """7. Retransmitted SYN packets don't create duplicate sessions."""
    pkts = [
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x02),
        _make_packet(101.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x02),
        _make_packet(103.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x02),
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.forward_packets == 3
    assert s.connection_state == TCPConnectionState.ATTEMPTED
    assert s.zeek_equivalent_state == "S0"


def test_multiple_independent_sessions():
    """8. Multiple independent 5-tuple sessions tracked concurrently."""
    pkts = [
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 50001, 80, tcp_flags=0x02),
        _make_packet(100.1, "192.168.1.10", "10.0.0.1", 50002, 80, tcp_flags=0x02),
        _make_packet(100.2, "10.0.0.1", "192.168.1.10", 80, 50002, tcp_flags=0x04),  # RST response -> REJ
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 2
    s1 = next(s for s in sessions if s.src_port == 50001)
    s2 = next(s for s in sessions if s.src_port == 50002)
    assert s1.connection_state == TCPConnectionState.ATTEMPTED
    assert s1.zeek_equivalent_state == "S0"
    assert s2.connection_state == TCPConnectionState.REJECTED
    assert s2.zeek_equivalent_state == "REJ"


def test_udp_packets_ignored_by_tcp_tracker():
    """9. UDP packets do not contaminate TCP session tracking."""
    pkts = [
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 5353, 53, protocol="UDP"),
        _make_packet(100.1, "10.0.0.1", "192.168.1.10", 53, 5353, protocol="UDP"),
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 0


def test_empty_capture():
    """10. Empty packet input safely produces empty session tuple and zero metrics."""
    sessions = track_tcp_sessions([])
    assert sessions == ()
    metrics = aggregate_tcp_session_metrics(sessions)
    assert metrics.total_tcp_sessions == 0
    assert metrics.failed_connection_ratio == 0.0
    evidence = build_tcp_session_evidence(sessions)
    assert evidence == ()


def test_incomplete_capture_boundary_and_midstream():
    """11. Midstream traffic lacking initial SYN is classified as INCOMPLETE (Zeek OTH)."""
    pkts = [
        # Data packet without preceding SYN
        _make_packet(100.0, "192.168.1.10", "10.0.0.1", 54321, 80, tcp_flags=0x18, payload_length=100),
        _make_packet(100.05, "10.0.0.1", "192.168.1.10", 80, 54321, tcp_flags=0x10),
    ]
    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.connection_state == TCPConnectionState.INCOMPLETE
    assert s.zeek_equivalent_state == "OTH"
    assert s.boundary_status == ObservationBoundaryStatus.MIDSTREAM_JOIN


def test_tcp_session_evidence_generation():
    """12. Protocol evidence generation emits FusedEvidenceItem with strictly OBSERVED scope."""
    # Create 5 unacknowledged attempts (scanning pattern)
    pkts = []
    for port in range(5000, 5005):
        pkts.append(_make_packet(100.0 + (port - 5000), "192.168.1.50", "10.0.0.1", port, 80, tcp_flags=0x02))

    sessions = track_tcp_sessions(pkts)
    assert len(sessions) == 5
    evidence = build_tcp_session_evidence(sessions)
    assert len(evidence) == 1
    e = evidence[0]
    assert e.temporal_scope.value == "OBSERVED"
    assert e.modality.value == "PROTOCOL"
    assert e.mitre_technique_id == "T1046"
    assert e.source == "zeek_tcp_session_state_tracker"
    assert e.supporting_features["failed_connection_ratio"] == 1.0


def test_real_pcap_zeek_session_state_end_to_end():
    """13. End-to-end integration test: PCAP -> extraction -> session state -> fusion -> 45-feature model gate."""
    import os
    from pathlib import Path
    from nexsolve_core.fusion import EvidenceModality, TemporalScope, fuse_threat_assessment
    from nexsolve_core.network.session_state import (
        aggregate_tcp_session_metrics,
        build_tcp_session_evidence,
        track_tcp_sessions,
    )

    candidates = [
        Path("research/open_source/test_pcaps/friday_10windows_slice.pcap"),
        Path(r"C:\Users\saira\Downloads\friday_10windows_slice.pcap"),
    ]
    pcap_path = None
    for c in candidates:
        if c.exists():
            pcap_path = str(c)
            break
    if not pcap_path:
        pytest.skip("PCAP fixture not present")

    # 1. Real PCAP extraction using decoder directly
    # 1. Real PCAP extraction
    _packets, windows, quality = extract_canonical_capture(pcap_path)
    assert len(windows) > 0

    # 2. Track TCP sessions using streaming decoder
    import mmap
    from ml.data.fast_pcap_decoder import FastPcapDecoder
    packets = []
    with open(pcap_path, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            decoder = FastPcapDecoder(mm)
            for pkt in decoder.decode_packets():
                if pkt.protocol == "TCP":
                    packets.append(pkt)
    
    assert len(packets) > 0

    # 2. Track TCP sessions
    sessions = track_tcp_sessions(packets)
    assert len(sessions) > 0

    # Verify session fields
    assert any(s.connection_state == TCPConnectionState.ESTABLISHED for s in sessions)
    assert any(s.boundary_status == ObservationBoundaryStatus.MIDSTREAM_JOIN for s in sessions)

    # 3. Aggregate metrics
    metrics = aggregate_tcp_session_metrics(sessions)
    assert metrics.total_tcp_sessions == len(sessions)
    assert metrics.established_sessions > 0
    assert 0.0 <= metrics.establishment_ratio <= 1.0
    assert 0.0 <= metrics.failed_connection_ratio <= 1.0

    # 4. Evidence generation & Fusion
    evidence_items = build_tcp_session_evidence(sessions)
    for item in evidence_items:
        assert item.modality == EvidenceModality.PROTOCOL
        assert item.temporal_scope == TemporalScope.OBSERVED

        threat_assessment = fuse_threat_assessment(
            observed_findings=[],
            tcp_session_records=sessions,
        )
        assert threat_assessment is not None
        # evidence_items was collected and fused into threat_assessment.evidence
        assert isinstance(threat_assessment.evidence, tuple)

    # 5. Verify 45-feature canonical model vector contract remains UNTOUCHED
    from nexsolve_core.state import MODEL_SCHEMA_45, build_network_state_candidates, evaluate_model_compatibility

    cand_states = build_network_state_candidates(windows)
    compat = evaluate_model_compatibility(cand_states, MODEL_SCHEMA_45)
    assert compat.model_ready is True
    assert compat.required_features == 45
    assert len(compat.available_features) == 45
    assert len(compat.unavailable_features) == 0
    assert "mean_tcp_rtt" not in compat.available_features


