from __future__ import annotations

import pytest

from nexsolve_core.schemas import (
    CaptureQuality,
    ModelCompatibilityError,
    PacketRecord,
    QualityStatus,
    Provenance,
    build_flows,
    build_temporal_windows,
    make_capture_quality,
    model_compatibility_report,
)


def packet(index: int, timestamp: float, source: str, destination: str, *, protocol: str = "TCP", source_port: int | None = 1000, destination_port: int | None = 80, length: int = 100, flags: int | None = 0x10) -> PacketRecord:
    return PacketRecord(
        timestamp=timestamp,
        src_ip=source,
        dst_ip=destination,
        ip_version=6 if ":" in source else 4,
        protocol=protocol,
        src_port=source_port,
        dst_port=destination_port,
        packet_length=length,
        payload_length=max(length - 40, 0),
        tcp_flags=flags,
        packet_index=index,
        provenance=Provenance("capture-test", (index,), (), (), (timestamp,), "packet_extraction"),
    )


def test_packet_record_preserves_missing_ports_and_provenance():
    record = packet(4, 12.5, "10.0.0.1", "10.0.0.2", protocol="ICMP", source_port=None, destination_port=None, flags=None)
    assert record.src_port is None
    assert record.dst_port is None
    assert record.provenance is not None
    assert record.provenance.packet_indexes == (4,)


def test_flow_grouping_is_bidirectional_and_deterministic():
    packets = (
        packet(0, 1.0, "10.0.0.1", "10.0.0.2", flags=0x02, length=120),
        packet(1, 2.0, "10.0.0.2", "10.0.0.1", source_port=80, destination_port=1000, flags=0x12, length=90),
    )
    first = build_flows(packets, "capture-test")
    second = build_flows(tuple(reversed(packets)), "capture-test")
    assert first == second
    assert len(first) == 1
    assert first[0].forward_packet_count == 1
    assert first[0].reverse_packet_count == 1
    assert first[0].total_packet_count == 2
    assert first[0].forward_bytes == 120
    assert first[0].reverse_bytes == 90
    assert first[0].completeness == "INCOMPLETE"


def test_temporal_windows_have_deterministic_boundaries_and_provenance():
    packets = (packet(1, 2.0, "10.0.0.1", "10.0.0.2"), packet(0, 1.0, "10.0.0.1", "10.0.0.2"))
    flows = build_flows(packets, "capture-test")
    quality = make_capture_quality(packets, incomplete_flow_count=1, capture_id="capture-test")
    windows = build_temporal_windows(packets, flows, quality)
    assert [window.start_timestamp for window in windows] == [0]
    assert windows[0].provenance.packet_indexes == (0, 1)
    assert windows[0].ordering.startswith("timestamp_sorted")


def test_capture_quality_does_not_mark_incomplete_capture_good():
    records = (packet(0, 1.0, "10.0.0.1", "10.0.0.2", flags=0x02),)
    quality = make_capture_quality(records, incomplete_flow_count=1, capture_id="capture-test")
    assert isinstance(quality, CaptureQuality)
    assert quality.status == QualityStatus.INSUFFICIENT
    assert quality.incomplete_flow_count == 1


def test_model_compatibility_reports_missing_features_without_zero_fill():
    quality = make_capture_quality((), capture_id="capture-test")
    report = model_compatibility_report((), {"flow_features": ["flow_count"], "packet_features": ["packet_count"], "temporal_features": ["delta_flow_count"]})
    assert report.model_ready is False
    assert "flow_count" in report.missing_features
    assert "delta_flow_count" in report.missing_features
    assert report.to_dict()["reason"]
    assert quality.status == QualityStatus.INSUFFICIENT


def test_incompatible_windows_cannot_be_adapted_to_network_state():
    quality = make_capture_quality((packet(0, 1.0, "10.0.0.1", "10.0.0.2"),), capture_id="capture-test")
    windows = build_temporal_windows((packet(0, 1.0, "10.0.0.1", "10.0.0.2"),), (), quality)
    from nexsolve_core.schemas import temporal_windows_to_network_states

    with pytest.raises(ModelCompatibilityError):
        temporal_windows_to_network_states(windows, {"flow_features": ["flow_count"], "packet_features": ["packet_count"], "temporal_features": ["delta_flow_count"]})


@pytest.mark.parametrize("protocol", ["UDP", "ICMP", "ARP"])
def test_non_tcp_protocols_remain_explicit(protocol: str):
    ports = (None, None) if protocol in {"ICMP", "ARP"} else (53, 5353)
    record = packet(0, 1.0, "10.0.0.1", "10.0.0.2", protocol=protocol, source_port=ports[0], destination_port=ports[1], flags=None)
    assert record.protocol == protocol
    assert record.src_port == ports[0]
    assert record.dst_port == ports[1]


def test_scapy_packet_conversion_is_skipped_without_dependency():
    scapy = pytest.importorskip("scapy.all")
    from ml.data.pcap_extractor import packet_record_from_pkt

    converted = packet_record_from_pkt(scapy.Ether() / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(sport=1234, dport=80, flags="S"), packet_index=7, capture_id="capture-test")
    assert isinstance(converted, PacketRecord)
    assert converted.ip_version == 4
    assert converted.packet_index == 7
    assert converted.src_port == 1234

    ethernet = lambda: scapy.Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")
    ipv6_udp = packet_record_from_pkt(ethernet() / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2") / scapy.UDP(sport=53, dport=5353), packet_index=8, capture_id="capture-test")
    assert ipv6_udp is not None and ipv6_udp.ip_version == 6 and ipv6_udp.protocol == "UDP"
    ipv6_tcp = packet_record_from_pkt(ethernet() / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2") / scapy.TCP(sport=1234, dport=443, flags="S"), packet_index=11, capture_id="capture-test")
    assert ipv6_tcp is not None and ipv6_tcp.ip_version == 6 and ipv6_tcp.protocol == "TCP"
    icmp = packet_record_from_pkt(ethernet() / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.ICMP(), packet_index=9, capture_id="capture-test")
    assert icmp is not None and icmp.protocol == "ICMP" and icmp.src_port is None
    arp = packet_record_from_pkt(ethernet() / scapy.ARP(psrc="10.0.0.1", pdst="10.0.0.2"), packet_index=10, capture_id="capture-test")
    assert arp is not None and arp.protocol == "ARP" and arp.src_port is None


def test_network_evidence_multi_sensor_factories():
    from nexsolve_core.schemas import NetworkEvidence, SensorType, EvidenceDirection
    from nexsolve_core.evidence.suricata import SuricataAlertRecord
    from nexsolve_core.network.session_state import TCPSessionRecord, TCPConnectionState, ObservationBoundaryStatus

    # 1. Packet Record
    p = packet(1, 100.0, "192.168.1.5", "10.0.0.1", protocol="TCP", source_port=5000, destination_port=80, length=120)
    ev_pkt = NetworkEvidence.from_packet_record(p)
    assert ev_pkt.sensor_type == SensorType.PCAP_WIRE
    assert ev_pkt.direction == EvidenceDirection.INTERNAL_LATERAL
    assert ev_pkt.bytes_count == 120
    assert ev_pkt.packets_count == 1
    assert "payload_length" not in ev_pkt.missing_fields

    # 2. Suricata Alert Record
    alert = SuricataAlertRecord(
        timestamp=105.0,
        gid=1,
        signature_id=2001,
        rev=1,
        signature="ET SCAN Potential Nmap Scan",
        category="Attempted Information Leak",
        severity=1,
        action="allowed",
        src_ip="192.168.1.5",
        dst_ip="10.0.0.1",
        src_port=5000,
        dst_port=80,
        protocol="TCP",
        mitre_technique_id="T1046",
        metadata={},
    )
    ev_sur = NetworkEvidence.from_suricata_alert(alert)
    assert ev_sur.sensor_type == SensorType.SURICATA_EVE
    assert ev_sur.confidence == 0.90
    assert "T1046" in ev_sur.mitre_techniques
    assert "bytes_count" in ev_sur.missing_fields

    # 3. TCP Session Record
    sess = TCPSessionRecord(
        session_id="s_test",
        src_ip="192.168.1.5",
        dst_ip="10.0.0.1",
        src_port=5000,
        dst_port=80,
        first_seen=100.0,
        last_seen=105.0,
        duration_seconds=5.0,
        forward_packets=10,
        reverse_packets=10,
        total_packets=20,
        forward_bytes=1000,
        reverse_bytes=1000,
        total_bytes=2000,
        orig_syn=True,
        orig_ack=True,
        orig_fin=False,
        orig_rst=False,
        resp_syn=True,
        resp_ack=True,
        resp_fin=False,
        resp_rst=False,
        handshake_completed=True,
        connection_state=TCPConnectionState.ESTABLISHED,
        boundary_status=ObservationBoundaryStatus.COMPLETE_LIFECYCLE,
        zeek_equivalent_state="SF",
        history_string="ShADaFf",
    )
    ev_zk = NetworkEvidence.from_tcp_session(sess)
    assert ev_zk.sensor_type == SensorType.ZEEK_CONN
    assert ev_zk.bytes_count == 2000
    assert ev_zk.packets_count == 20
    assert ev_zk.duration_seconds == 5.0

