from __future__ import annotations

import pytest

from nexsolve_core.schemas import PacketRecord, QualityStatus, Provenance, build_flows, make_capture_quality

scapy = pytest.importorskip("scapy.all")
from scapy.layers.inet6 import IPv6ExtHdrFragment, IPv6ExtHdrHopByHop, ICMPv6EchoRequest
from ml.data.pcap_extractor import packet_record_from_pkt


def ethernet():
    return scapy.Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02")


def test_ipv6_extension_and_fragment_metadata_are_explicit():
    extended = packet_record_from_pkt(ethernet() / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrHopByHop() / scapy.TCP(sport=1, dport=443, flags="S"), packet_index=1, capture_id="capture")
    fragmented = packet_record_from_pkt(ethernet() / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2") / IPv6ExtHdrFragment(offset=3, m=1, id=77) / scapy.UDP(sport=1, dport=2), packet_index=2, capture_id="capture")
    assert extended is not None and extended.protocol == "TCP"
    assert extended.ipv6_extension_headers == ("IPv6ExtHdrHopByHop",)
    assert fragmented is not None and fragmented.protocol == "UDP"
    assert fragmented.ipv6_fragment_id == 77
    assert fragmented.ipv6_fragment_offset == 3
    assert fragmented.ipv6_more_fragments is True


def test_icmp_and_icmpv6_type_code_are_preserved_without_ports():
    icmp = packet_record_from_pkt(ethernet() / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.ICMP(type=8, code=0), packet_index=1, capture_id="capture")
    icmpv6 = packet_record_from_pkt(ethernet() / scapy.IPv6(src="2001:db8::1", dst="2001:db8::2") / ICMPv6EchoRequest(), packet_index=2, capture_id="capture")
    assert icmp is not None and icmp.protocol == "ICMP" and icmp.icmp_type == 8 and icmp.icmp_code == 0
    assert icmpv6 is not None and icmpv6.protocol == "ICMPv6" and icmpv6.icmp_type == 128 and icmpv6.icmp_code == 0
    assert icmp.src_port is None and icmpv6.dst_port is None


def test_vlan_metadata_including_stack_is_preserved():
    tagged = packet_record_from_pkt(ethernet() / scapy.Dot1Q(vlan=10) / scapy.Dot1Q(vlan=20) / scapy.IP(src="10.0.0.1", dst="10.0.0.2") / scapy.TCP(sport=1, dport=2), packet_index=3, capture_id="capture")
    assert tagged is not None
    assert tagged.vlan_ids == (10, 20)
    assert tagged.vlan_id == 10


def test_truncation_is_true_when_declared_ip_length_exceeds_observed_bytes():
    record = packet_record_from_pkt(ethernet() / scapy.IP(src="10.0.0.1", dst="10.0.0.2", len=200) / scapy.TCP(sport=1, dport=2), packet_index=4, capture_id="capture")
    assert record is not None
    assert record.truncation_status == "TRUE"


def test_quality_tracks_timestamp_duplicate_and_truncation_semantics():
    packets = (
        PacketRecord(1.0, "10.0.0.1", "10.0.0.2", 4, "TCP", packet_index=0, provenance=Provenance("capture", (0,), source_timestamps=(1.0,))),
        PacketRecord(1.0, "10.0.0.1", "10.0.0.2", 4, "TCP", packet_index=1, provenance=Provenance("capture", (1,), source_timestamps=(1.0,))),
    )
    quality = make_capture_quality(packets, total_packets_observed=2, duplicate_packets=1, timestamp_equal_count=1, timestamps_reordered=True, original_order_preserved=False, truncation_unknown_count=2, capture_id="capture")
    assert quality.status == QualityStatus.DEGRADED
    assert quality.duplicate_ratio == 0.5
    assert quality.timestamp_equal_count == 1
    assert quality.timestamps_reordered is True
    assert quality.original_order_preserved is False
    assert quality.truncation_unknown_count == 2


def test_tcp_completeness_is_conservative():
    def tcp(index, timestamp, flags, source="10.0.0.1", destination="10.0.0.2"):
        return PacketRecord(timestamp, source, destination, 4, "TCP", 1000 if source.endswith("1") else 80, 80 if source.endswith("1") else 1000, 60, 0, tcp_flags=flags, packet_index=index)

    syn_only = build_flows((tcp(0, 1, 0x02),), "capture")[0]
    handshake_fin = build_flows((tcp(0, 1, 0x02), tcp(1, 2, 0x12, "10.0.0.2", "10.0.0.1"), tcp(2, 3, 0x10), tcp(3, 4, 0x01)), "capture")[0]
    handshake_rst = build_flows((tcp(0, 1, 0x02), tcp(1, 2, 0x12, "10.0.0.2", "10.0.0.1"), tcp(2, 3, 0x10), tcp(3, 4, 0x04, "10.0.0.2", "10.0.0.1")), "capture")[0]
    assert syn_only.completeness == "INCOMPLETE"
    assert handshake_fin.completeness == "COMPLETE"
    assert handshake_rst.completeness == "COMPLETE"
