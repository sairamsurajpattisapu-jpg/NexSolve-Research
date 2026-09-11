"""Canonical, evidence-preserving objects for the live capture pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping


class QualityStatus(StrEnum):
    GOOD = "GOOD"
    DEGRADED = "DEGRADED"
    INSUFFICIENT = "INSUFFICIENT"


@dataclass(frozen=True)
class Provenance:
    capture_id: str
    packet_indexes: tuple[int, ...] = ()
    flow_ids: tuple[str, ...] = ()
    window_ids: tuple[str, ...] = ()
    source_timestamps: tuple[float, ...] = ()
    transformation_stage: str = "unknown"


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    src_ip: str | None
    dst_ip: str | None
    ip_version: int | None
    protocol: str | None
    src_port: int | None = None
    dst_port: int | None = None
    packet_length: int | None = None
    payload_length: int | None = None
    ttl: int | None = None
    tcp_flags: int | None = None
    tcp_window: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    fragment_offset: int | None = None
    more_fragments: bool | None = None
    identification: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    ipv6_extension_headers: tuple[str, ...] = ()
    ipv6_fragment_id: int | None = None
    ipv6_fragment_offset: int | None = None
    ipv6_more_fragments: bool | None = None
    vlan_id: int | None = None
    vlan_priority: int | None = None
    vlan_ids: tuple[int, ...] = ()
    packet_index: int | None = None
    capture_relative_timestamp: float | None = None
    parsing_status: str = "parsed"
    malformed: bool = False
    unsupported_reason: str | None = None
    truncation_status: str = "UNKNOWN"
    duplicate_of_index: int | None = None
    provenance: Provenance | None = None

    def to_dict(self) -> dict[str, Any]:
        result = {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ip_version": self.ip_version,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "packet_length": self.packet_length,
            "payload_length": self.payload_length,
            "ttl": getattr(self, "ttl", None),
            "tcp_flags": self.tcp_flags,
            "tcp_window": self.tcp_window,
            "tcp_seq": self.tcp_seq,
            "tcp_ack": self.tcp_ack,
            "fragment_offset": self.fragment_offset,
            "more_fragments": self.more_fragments,
            "identification": self.identification,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "ipv6_extension_headers": list(self.ipv6_extension_headers),
            "ipv6_fragment_id": self.ipv6_fragment_id,
            "ipv6_fragment_offset": self.ipv6_fragment_offset,
            "ipv6_more_fragments": self.ipv6_more_fragments,
            "vlan_id": self.vlan_id,
            "vlan_priority": self.vlan_priority,
            "vlan_ids": list(self.vlan_ids),
            "parsing_status": self.parsing_status,
            "unsupported_reason": self.unsupported_reason,
            "truncation_status": self.truncation_status,
            "duplicate_of_index": self.duplicate_of_index,
        }
        return result


@dataclass(frozen=True)
class FlowRecord:
    flow_id: str
    start_timestamp: float
    end_timestamp: float
    duration_seconds: float
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    forward_packet_count: int
    reverse_packet_count: int
    total_packet_count: int
    forward_bytes: int
    reverse_bytes: int
    total_bytes: int
    packet_rate: float | None
    byte_rate: float | None
    syn_count: int
    ack_count: int
    fin_count: int
    rst_count: int
    retransmission_count: int
    completeness: str
    provenance: Provenance


@dataclass(frozen=True)
class CaptureQuality:
    total_packets_observed: int
    parsed_packets: int
    malformed_packets: int
    unsupported_packets: int
    truncated_packets: int
    timestamp_anomalies: int
    duplicate_packets: int
    ipv4_count: int
    ipv6_count: int
    tcp_count: int
    udp_count: int
    icmp_count: int
    arp_count: int
    vlan_count: int
    fragmented_packet_count: int
    incomplete_flow_count: int
    status: QualityStatus
    reason: str
    capture_id: str
    truncation_unknown_count: int = 0
    timestamp_equal_count: int = 0
    invalid_timestamp_count: int = 0
    timestamps_reordered: bool = False
    original_order_preserved: bool = True
    duplicate_ratio: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        result = {key: getattr(self, key) for key in self.__dataclass_fields__}
        result["status"] = self.status.value
        return result


@dataclass(frozen=True)
class TemporalWindow:
    window_id: str
    start_timestamp: int
    end_timestamp: int
    duration_seconds: int
    packet_count: int
    flow_count: int
    packets: tuple[PacketRecord, ...]
    flows: tuple[FlowRecord, ...]
    aggregate_features: Mapping[str, Any]
    detection_features: Mapping[str, Any]
    quality: CaptureQuality
    ordering: str
    provenance: Provenance
    raw_observed_count: int = 0
    deduplicated_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "window_start": self.start_timestamp,
            "window_end": self.end_timestamp,
            "duration_seconds": self.duration_seconds,
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            **dict(self.aggregate_features),
            **dict(self.detection_features),
            "provenance": {
                "capture_id": self.provenance.capture_id,
                "packet_indexes": list(self.provenance.packet_indexes),
                "flow_ids": list(self.provenance.flow_ids),
                "window_ids": list(self.provenance.window_ids),
                "source_timestamps": list(self.provenance.source_timestamps),
                "transformation_stage": self.provenance.transformation_stage,
            },
            "quality": self.quality.to_dict(),
            "ordering": self.ordering,
            "raw_observed_count": self.raw_observed_count or self.packet_count,
            "deduplicated_count": self.deduplicated_count or self.packet_count,
        }


@dataclass(frozen=True)
class NetworkStateCompatibility:
    model_ready: bool
    available_features: tuple[str, ...]
    missing_features: tuple[str, ...]
    unreliable_features: tuple[str, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_ready": self.model_ready,
            "available_features": list(self.available_features),
            "missing_features": list(self.missing_features),
            "unreliable_features": list(self.unreliable_features),
            "reason": self.reason,
        }


class ModelCompatibilityError(ValueError):
    """Raised when a capture cannot satisfy the existing model contract."""


def _endpoint_key(packet: PacketRecord) -> tuple[Any, ...]:
    left = (packet.src_ip, packet.src_port)
    right = (packet.dst_ip, packet.dst_port)
    endpoints = tuple(sorted((left, right)))
    return (packet.protocol, packet.ip_version, *endpoints)


def _direction(packet: PacketRecord, origin: tuple[Any, ...]) -> bool:
    return (packet.src_ip, packet.src_port) == origin


def _flow_completeness(protocol: str | None, packets: list[PacketRecord]) -> str:
    if protocol != "TCP":
        return "not_applicable"
    flags = [packet.tcp_flags or 0 for packet in packets]
    saw_syn = any(value & 0x02 for value in flags)
    saw_syn_ack = any(value & 0x12 == 0x12 for value in flags)
    saw_handshake_ack = any(value & 0x10 and not value & 0x02 for value in flags)
    saw_termination = any(value & 0x05 for value in flags)
    if saw_syn and saw_syn_ack and saw_handshake_ack and saw_termination:
        return "COMPLETE"
    if saw_syn:
        return "INCOMPLETE"
    return "UNKNOWN"


def build_flows(packets: Iterable[PacketRecord], capture_id: str = "unknown") -> tuple[FlowRecord, ...]:
    grouped: dict[tuple[Any, ...], list[PacketRecord]] = {}
    for packet in packets:
        grouped.setdefault(_endpoint_key(packet), []).append(packet)
    flows: list[FlowRecord] = []
    for index, key in enumerate(sorted(grouped, key=str), start=1):
        members = sorted(grouped[key], key=lambda item: (item.timestamp, item.packet_index if item.packet_index is not None else -1))
        origin = (members[0].src_ip, members[0].src_port)
        forward = [packet for packet in members if _direction(packet, origin)]
        reverse = [packet for packet in members if not _direction(packet, origin)]
        start = min(packet.timestamp for packet in members)
        end = max(packet.timestamp for packet in members)
        duration = max(0.0, end - start)
        forward_bytes = sum(packet.packet_length or 0 for packet in forward)
        reverse_bytes = sum(packet.packet_length or 0 for packet in reverse)
        flags = [packet.tcp_flags or 0 for packet in members]
        packet_indexes = tuple(packet.packet_index for packet in members if packet.packet_index is not None)
        timestamps = tuple(packet.timestamp for packet in members)
        flow_id = f"flow-{index:06d}"
        provenance = Provenance(capture_id, packet_indexes, (flow_id,), (), timestamps, "flow_reconstruction")
        flows.append(FlowRecord(
            flow_id=flow_id,
            start_timestamp=start,
            end_timestamp=end,
            duration_seconds=duration,
            src_ip=members[0].src_ip,
            src_port=members[0].src_port,
            dst_ip=members[0].dst_ip,
            dst_port=members[0].dst_port,
            protocol=members[0].protocol,
            forward_packet_count=len(forward),
            reverse_packet_count=len(reverse),
            total_packet_count=len(members),
            forward_bytes=forward_bytes,
            reverse_bytes=reverse_bytes,
            total_bytes=forward_bytes + reverse_bytes,
            packet_rate=(len(members) / duration) if duration > 0 else None,
            byte_rate=((forward_bytes + reverse_bytes) / duration) if duration > 0 else None,
            syn_count=sum(bool(value & 0x02) for value in flags),
            ack_count=sum(bool(value & 0x10) for value in flags),
            fin_count=sum(bool(value & 0x01) for value in flags),
            rst_count=sum(bool(value & 0x04) for value in flags),
            retransmission_count=0,
            completeness=_flow_completeness(members[0].protocol, members),
            provenance=provenance,
        ))
    return tuple(flows)


def _quality_status(total: int, parsed: int, malformed: int, unsupported: int, truncated: int, truncation_unknown: int, anomalies: int, duplicates: int, fragmented: int, incomplete: int) -> tuple[QualityStatus, str]:
    if parsed < 2 or total == 0:
        return QualityStatus.INSUFFICIENT, "Capture is empty or too small to establish reliable traffic quality."
    if malformed or unsupported or truncated or anomalies or duplicates or fragmented or incomplete:
        return QualityStatus.DEGRADED, "Capture contains parsing, support, truncation, ordering, duplicate, or flow-completeness limitations."
    if truncation_unknown:
        return QualityStatus.DEGRADED, "Capture length metadata was insufficient to prove truncation status for some packets."
    return QualityStatus.GOOD, "All observed packets were parsed with no recorded quality degradation."


def make_capture_quality(
    packets: Iterable[PacketRecord],
    *,
    total_packets_observed: int | None = None,
    malformed_packets: int = 0,
    unsupported_packets: int = 0,
    truncated_packets: int = 0,
    timestamp_anomalies: int = 0,
    duplicate_packets: int = 0,
    truncation_unknown_count: int = 0,
    timestamp_equal_count: int = 0,
    invalid_timestamp_count: int = 0,
    timestamps_reordered: bool = False,
    original_order_preserved: bool = True,
    incomplete_flow_count: int = 0,
    capture_id: str = "unknown",
) -> CaptureQuality:
    records = tuple(packets)
    protocols = {packet.protocol for packet in records}
    total = total_packets_observed if total_packets_observed is not None else len(records)
    fragmented_packets = sum(bool(packet.fragment_offset or packet.more_fragments) for packet in records)
    status, reason = _quality_status(total, len(records), malformed_packets, unsupported_packets, truncated_packets, truncation_unknown_count, timestamp_anomalies, duplicate_packets, fragmented_packets, incomplete_flow_count)
    return CaptureQuality(
        total_packets_observed=total_packets_observed if total_packets_observed is not None else len(records),
        parsed_packets=len(records),
        malformed_packets=malformed_packets,
        unsupported_packets=unsupported_packets,
        truncated_packets=truncated_packets,
        timestamp_anomalies=timestamp_anomalies,
        duplicate_packets=duplicate_packets,
        ipv4_count=sum(packet.ip_version == 4 for packet in records),
        ipv6_count=sum(packet.ip_version == 6 for packet in records),
        tcp_count=sum(packet.protocol == "TCP" for packet in records),
        udp_count=sum(packet.protocol == "UDP" for packet in records),
        icmp_count=sum(packet.protocol in {"ICMP", "ICMPv6"} for packet in records),
        arp_count=sum(packet.protocol == "ARP" for packet in records),
        vlan_count=sum(packet.vlan_id is not None for packet in records),
        fragmented_packet_count=fragmented_packets,
        incomplete_flow_count=incomplete_flow_count,
        status=status,
        reason=reason,
        capture_id=capture_id,
        truncation_unknown_count=truncation_unknown_count,
        timestamp_equal_count=timestamp_equal_count,
        invalid_timestamp_count=invalid_timestamp_count,
        timestamps_reordered=timestamps_reordered,
        original_order_preserved=original_order_preserved,
        duplicate_ratio=duplicate_packets / max(total, 1),
    )


def build_temporal_windows(
    packets: Iterable[PacketRecord],
    flows: Iterable[FlowRecord],
    quality: CaptureQuality,
    *,
    window_seconds: int = 60,
) -> tuple[TemporalWindow, ...]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    packet_groups: dict[int, list[PacketRecord]] = {}
    for packet in packets:
        packet_groups.setdefault(int(packet.timestamp // window_seconds), []).append(packet)
    flow_groups: dict[int, list[FlowRecord]] = {}
    for flow in flows:
        for bucket in range(int(flow.start_timestamp // window_seconds), int(flow.end_timestamp // window_seconds) + 1):
            flow_groups.setdefault(bucket, []).append(flow)
    windows: list[TemporalWindow] = []
    for bucket in sorted(packet_groups):
        original_members = tuple(packet_groups[bucket])
        members = tuple(sorted(original_members, key=lambda item: (item.timestamp, item.packet_index if item.packet_index is not None else -1)))
        start = bucket * window_seconds
        flow_members = tuple(sorted({flow.flow_id: flow for flow in flow_groups.get(bucket, ())}.values(), key=lambda item: item.flow_id))
        packet_indexes = tuple(packet.packet_index for packet in members if packet.packet_index is not None)
        timestamps = tuple(packet.timestamp for packet in members)
        window_id = f"window-{bucket:012d}"
        provenance = Provenance(quality.capture_id, packet_indexes, tuple(flow.flow_id for flow in flow_members), (window_id,), timestamps, "temporal_windowing")
        fingerprints = {(packet.timestamp, packet.src_ip, packet.dst_ip, packet.protocol, packet.src_port, packet.dst_port, packet.packet_length, packet.tcp_seq) for packet in members}
        ordering = "timestamp_sorted_within_deterministic_bucket" if members != original_members else "original_capture_order_preserved"
        windows.append(TemporalWindow(window_id, start, start + window_seconds, window_seconds, len(members), len(flow_members), members, flow_members, {}, {}, quality, ordering, provenance, len(members), len(fingerprints)))
    return tuple(windows)


def model_compatibility_report(windows: Iterable[TemporalWindow], feature_schema: Mapping[str, list[str]]) -> NetworkStateCompatibility:
    window_list = tuple(windows)
    expected = tuple(name for group in ("flow_features", "packet_features", "temporal_features") for name in feature_schema.get(group, []))
    observed = {name for window in window_list for name in window.aggregate_features}
    available = tuple(name for name in expected if name in observed)
    missing = tuple(name for name in expected if name not in observed)
    return NetworkStateCompatibility(not missing, available, missing, (), "Canonical PCAP windows do not yet provide the model's complete flow and temporal state contract; no missing feature is fabricated or zero-filled.")


def temporal_windows_to_network_states(windows: Iterable[TemporalWindow], feature_schema: Mapping[str, list[str]]) -> tuple[Any, ...]:
    window_list = tuple(windows)
    compatibility = model_compatibility_report(window_list, feature_schema)
    if not compatibility.model_ready:
        raise ModelCompatibilityError(compatibility.reason)
    from world_model import NetworkState

    states = []
    for window in window_list:
        features = dict(window.aggregate_features)
        groups = [dict((name, float(features[name])) for name in feature_schema[group]) for group in ("flow_features", "packet_features", "temporal_features")]
        states.append(NetworkState(window.start_timestamp, groups[0], groups[1], groups[2], None, True))
    return tuple(states)
