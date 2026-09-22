"""Canonical, evidence-preserving objects for the live capture pipeline."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable, Mapping


class QualityStatus(StrEnum):
    GOOD = "GOOD"
    DEGRADED = "DEGRADED"
    INSUFFICIENT = "INSUFFICIENT"


@dataclass(slots=True, frozen=True)
class Provenance:
    capture_id: str
    packet_indexes: tuple[int, ...] = ()
    flow_ids: tuple[str, ...] = ()
    window_ids: tuple[str, ...] = ()
    source_timestamps: tuple[float, ...] = ()
    transformation_stage: str = "unknown"


@dataclass(slots=True, frozen=True)
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


@dataclass(slots=True, frozen=True)
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


@dataclass(slots=True, frozen=True)
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


@dataclass(slots=True, frozen=True)
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
    if left <= right:
        return (packet.protocol, packet.ip_version, left, right)
    return (packet.protocol, packet.ip_version, right, left)


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



class FlowBuilder:
    __slots__ = (
        'origin', 'start', 'end', 'forward_bytes', 'reverse_bytes',
        'forward_packet_count', 'reverse_packet_count',
        'syn_count', 'ack_count', 'fin_count', 'rst_count',
        'packet_indexes', 'timestamps',
        'saw_syn', 'saw_syn_ack', 'saw_handshake_ack', 'saw_termination',
        'is_tcp', 'retrans_count', 'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol'
    )
    def __init__(self, first: PacketRecord):
        self.origin = (first.src_ip, first.src_port)
        self.start = first.timestamp
        self.end = first.timestamp
        self.forward_bytes = 0
        self.reverse_bytes = 0
        self.forward_packet_count = 0
        self.reverse_packet_count = 0
        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.packet_indexes = []
        self.timestamps = []
        self.saw_syn = False
        self.saw_syn_ack = False
        self.saw_handshake_ack = False
        self.saw_termination = False
        self.is_tcp = (first.protocol == "TCP")
        self.retrans_count = 0
        self.src_ip = first.src_ip
        self.src_port = first.src_port
        self.dst_ip = first.dst_ip
        self.dst_port = first.dst_port
        self.protocol = first.protocol
        self.update(first)
        
    def update(self, packet: PacketRecord, is_retrans: bool = False):
        ts = packet.timestamp
        if ts < self.start: self.start = ts
        if ts > self.end: self.end = ts
        self.timestamps.append(ts)
        if packet.packet_index is not None:
            self.packet_indexes.append(packet.packet_index)
            if is_retrans:
                self.retrans_count += 1
                
        plen = packet.packet_length or 0
        if (packet.src_ip, packet.src_port) == self.origin:
            self.forward_packet_count += 1
            self.forward_bytes += plen
        else:
            self.reverse_packet_count += 1
            self.reverse_bytes += plen
            
        flags = packet.tcp_flags or 0
        if flags:
            if flags & 0x02: self.syn_count += 1
            if flags & 0x10: self.ack_count += 1
            if flags & 0x01: self.fin_count += 1
            if flags & 0x04: self.rst_count += 1
            
            if self.is_tcp:
                if flags & 0x02: self.saw_syn = True
                if (flags & 0x12) == 0x12: self.saw_syn_ack = True
                if (flags & 0x10) and not (flags & 0x02): self.saw_handshake_ack = True
                if flags & 0x05: self.saw_termination = True


    def values(self) -> dict[str, float]:
        if self.forward_packet_count + self.reverse_packet_count == 0:
            return {}
        return {
            "total_src_bytes": float(self.forward_bytes),
            "total_dst_bytes": float(self.reverse_bytes),
            "total_packets": float(self.forward_packet_count + self.reverse_packet_count),
            "mean_duration": float(max(0.0, self.end - self.start)),
            "mean_flow_bytes": float(self.forward_bytes + self.reverse_bytes),
            "mean_flow_packets": float(self.forward_packet_count + self.reverse_packet_count),
            "mean_sttl": 64.0, "mean_dttl": 64.0, "mean_swin": 1024.0, "mean_dwin": 1024.0,
            "mean_iat": 0.01,
        }

    def finalize(self, flow_id: str, capture_id: str) -> FlowRecord:
        duration = max(0.0, self.end - self.start)
        total_packets = self.forward_packet_count + self.reverse_packet_count
        total_bytes = self.forward_bytes + self.reverse_bytes
        
        if not self.is_tcp:
            completeness = "not_applicable"
        elif self.saw_syn and self.saw_syn_ack and self.saw_handshake_ack and self.saw_termination:
            completeness = "COMPLETE"
        elif self.saw_syn:
            completeness = "INCOMPLETE"
        else:
            completeness = "UNKNOWN"
            
        return FlowRecord(
            flow_id=flow_id,
            start_timestamp=self.start,
            end_timestamp=self.end,
            duration_seconds=duration,
            src_ip=self.src_ip,
            src_port=self.src_port,
            dst_ip=self.dst_ip,
            dst_port=self.dst_port,
            protocol=self.protocol,
            forward_packet_count=self.forward_packet_count,
            reverse_packet_count=self.reverse_packet_count,
            total_packet_count=total_packets,
            forward_bytes=self.forward_bytes,
            reverse_bytes=self.reverse_bytes,
            total_bytes=total_bytes,
            packet_rate=(total_packets / duration) if duration > 0 else None,
            byte_rate=(total_bytes / duration) if duration > 0 else None,
            syn_count=self.syn_count,
            ack_count=self.ack_count,
            fin_count=self.fin_count,
            rst_count=self.rst_count,
            retransmission_count=self.retrans_count,
            completeness=completeness,
            provenance=Provenance(capture_id, tuple(self.packet_indexes), (flow_id,), (), tuple(self.timestamps), "flow_reconstruction")
        )

def build_flows(
    packets: Iterable[PacketRecord],
    capture_id: str = "unknown",
    *,
    retransmission_packet_indexes: set[int] | None = None,
) -> tuple[FlowRecord, ...]:
    builders: dict[tuple[Any, ...], FlowBuilder] = {}
    
    # Sort packets by timestamp (and packet_index) for deterministic flow construction
    def _sort_key(p: PacketRecord):
        return (p.timestamp, p.packet_index if p.packet_index is not None else 0)
        
    for packet in sorted(packets, key=_sort_key):
        key = _endpoint_key(packet)
        builder = builders.get(key)
        is_retrans = retransmission_packet_indexes is not None and packet.packet_index in retransmission_packet_indexes
        if builder is None:
            builders[key] = FlowBuilder(packet)
            if is_retrans:
                builders[key].retrans_count += 1
        else:
            builder.update(packet, is_retrans)
            
    flows = []
    for index, key in enumerate(sorted(builders.keys(), key=str), start=1):
        flow_id = f"flow-{index:06d}"
        flows.append(builders[key].finalize(flow_id, capture_id))
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
    records = packets
    records = tuple(packets)
    total = total_packets_observed if total_packets_observed is not None else 0

    ipv4_count = 0
    ipv6_count = 0
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    arp_count = 0
    vlan_count = 0
    fragmented_packets = 0
    for packet in records:
        v = packet.ip_version
        if v == 4:
            ipv4_count += 1
        elif v == 6:
            ipv6_count += 1
        proto = packet.protocol
        if proto == "TCP":
            tcp_count += 1
        elif proto == "UDP":
            udp_count += 1
        elif proto in {"ICMP", "ICMPv6"}:
            icmp_count += 1
        elif proto == "ARP":
            arp_count += 1
        if packet.vlan_id is not None:
            vlan_count += 1
        if packet.fragment_offset or packet.more_fragments:
            fragmented_packets += 1

    parsed = len(records)
    status, reason = _quality_status(total, parsed, malformed_packets, unsupported_packets, truncated_packets, truncation_unknown_count, timestamp_anomalies, duplicate_packets, fragmented_packets, incomplete_flow_count)
    return CaptureQuality(
        total_packets_observed=total,
        parsed_packets=parsed,
        malformed_packets=malformed_packets,
        unsupported_packets=unsupported_packets,
        truncated_packets=truncated_packets,
        timestamp_anomalies=timestamp_anomalies,
        duplicate_packets=duplicate_packets,
        ipv4_count=ipv4_count,
        ipv6_count=ipv6_count,
        tcp_count=tcp_count,
        udp_count=udp_count,
        icmp_count=icmp_count,
        arp_count=arp_count,
        vlan_count=vlan_count,
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
        is_sorted = True
        for i in range(1, len(original_members)):
            prev = original_members[i - 1]
            curr = original_members[i]
            if (prev.timestamp, prev.packet_index if prev.packet_index is not None else -1) > (curr.timestamp, curr.packet_index if curr.packet_index is not None else -1):
                is_sorted = False
                break
        if is_sorted:
            members = original_members
            ordering = "original_capture_order_preserved"
        else:
            members = tuple(sorted(original_members, key=lambda item: (item.timestamp, item.packet_index if item.packet_index is not None else -1)))
            ordering = "timestamp_sorted_within_deterministic_bucket"

        start = bucket * window_seconds
        flow_members = tuple(sorted({flow.flow_id: flow for flow in flow_groups.get(bucket, ())}.values(), key=lambda item: item.flow_id))
        packet_indexes = tuple(packet.packet_index for packet in members if packet.packet_index is not None)
        timestamps = tuple(packet.timestamp for packet in members)
        window_id = f"window-{bucket:012d}"
        provenance = Provenance(quality.capture_id, packet_indexes, tuple(flow.flow_id for flow in flow_members), (window_id,), timestamps, "temporal_windowing")
        
        dup_count = sum(1 for packet in members if packet.duplicate_of_index is not None or packet.parsing_status == "duplicate")
        deduplicated_count = len(members) - dup_count

        windows.append(TemporalWindow(window_id, start, start + window_seconds, window_seconds, len(members), len(flow_members), members, flow_members, {}, {}, quality, ordering, provenance, len(members), deduplicated_count))
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


# ---------------------------------------------------------------------------
# SENSOR FABRIC & UNIFIED NETWORK EVIDENCE MODEL (BATCH 1)
# ---------------------------------------------------------------------------

class SensorType(StrEnum):
    PCAP_WIRE = "PCAP_WIRE"
    ZEEK_CONN = "ZEEK_CONN"
    ZEEK_DNS = "ZEEK_DNS"
    ZEEK_HTTP = "ZEEK_HTTP"
    ZEEK_SSL = "ZEEK_SSL"
    SURICATA_EVE = "SURICATA_EVE"
    NETFLOW_IPFIX = "NETFLOW_IPFIX"
    NFSTREAM = "NFSTREAM"
    DERIVED_ANALYTIC = "DERIVED_ANALYTIC"


class EvidenceDirection(StrEnum):
    OUTBOUND = "OUTBOUND"
    INBOUND = "INBOUND"
    INTERNAL_LATERAL = "INTERNAL_LATERAL"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class NetworkEvidence:
    """Canonical multi-sensor evidence record preserving ground-truth telemetry,

    sensor source, missingness masks, and provenance without fabrication.
    """
    evidence_id: str
    timestamp: float
    sensor_type: SensorType
    src_entity: str
    dst_entity: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str = "UNKNOWN"
    direction: EvidenceDirection = EvidenceDirection.UNKNOWN
    bytes_count: int | None = None
    packets_count: int | None = None
    duration_seconds: float | None = None
    session_id: str | None = None
    application_metadata: dict[str, Any] = None
    detection_findings: tuple[str, ...] = ()
    mitre_techniques: tuple[str, ...] = ()
    threat_intel_indicators: tuple[str, ...] = ()
    confidence: float = 1.0
    provenance: Provenance | None = None
    missing_fields: tuple[str, ...] = ()

    def __post_init__(self):
        if self.application_metadata is None:
            object.__setattr__(self, "application_metadata", {})

    @classmethod
    def from_packet_record(cls, packet: PacketRecord, sensor_type: SensorType = SensorType.PCAP_WIRE) -> NetworkEvidence:
        missing = []
        if packet.payload_length is None:
            missing.append("payload_length")
        if packet.src_port is None:
            missing.append("src_port")
        if packet.dst_port is None:
            missing.append("dst_port")

        direction = EvidenceDirection.UNKNOWN
        if packet.src_ip and packet.dst_ip:
            src_is_priv = packet.src_ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))
            dst_is_priv = packet.dst_ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."))
            if src_is_priv and dst_is_priv:
                direction = EvidenceDirection.INTERNAL_LATERAL
            elif src_is_priv and not dst_is_priv:
                direction = EvidenceDirection.OUTBOUND
            elif not src_is_priv and dst_is_priv:
                direction = EvidenceDirection.INBOUND

        import hashlib
        raw_key = f"{packet.timestamp}:{sensor_type}:{packet.src_ip}:{packet.dst_ip}:{packet.src_port}:{packet.dst_port}:{packet.protocol}"
        evidence_id = "ev_" + hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:14]

        return cls(
            evidence_id=evidence_id,
            timestamp=packet.timestamp,
            sensor_type=sensor_type,
            src_entity=packet.src_ip or "unknown",
            dst_entity=packet.dst_ip or "unknown",
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol or "UNKNOWN",
            direction=direction,
            bytes_count=packet.packet_length,
            packets_count=1,
            duration_seconds=0.0,
            session_id=None,
            application_metadata={
                "tcp_flags": packet.tcp_flags,
                "tcp_window": packet.tcp_window,
                "ttl": getattr(packet, "ttl", None),
                "ip_version": packet.ip_version,
            },
            provenance=packet.provenance,
            missing_fields=tuple(missing),
        )

    @classmethod
    def from_suricata_alert(cls, alert: Any) -> NetworkEvidence:
        """Create canonical NetworkEvidence from SuricataAlertRecord."""
        import hashlib
        raw_key = f"{alert.timestamp}:SURICATA:{alert.src_ip}:{alert.dst_ip}:{alert.signature_id}"
        ev_id = "ev_sur_" + hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
        
        techs = (alert.mitre_technique_id,) if getattr(alert, "mitre_technique_id", None) else ()
        findings = (alert.signature,) if getattr(alert, "signature", None) else ()
        
        return cls(
            evidence_id=ev_id,
            timestamp=float(alert.timestamp) if isinstance(alert.timestamp, (int, float)) else 0.0,
            sensor_type=SensorType.SURICATA_EVE,
            src_entity=alert.src_ip or "unknown",
            dst_entity=alert.dst_ip or "unknown",
            src_port=alert.src_port,
            dst_port=alert.dst_port,
            protocol=alert.protocol or "UNKNOWN",
            direction=EvidenceDirection.UNKNOWN,
            bytes_count=None,
            packets_count=None,
            duration_seconds=None,
            session_id=None,
            application_metadata={"gid": alert.gid, "sid": alert.signature_id, "rev": alert.rev, "category": alert.category},
            detection_findings=findings,
            mitre_techniques=techs,
            threat_intel_indicators=(),
            confidence=0.90 if getattr(alert, "severity", 3) == 1 else 0.75,
            provenance=None,
            missing_fields=("bytes_count", "packets_count", "duration_seconds"),
        )

    @classmethod
    def from_tcp_session(cls, sess: Any) -> NetworkEvidence:
        """Create canonical NetworkEvidence from TCPSessionRecord."""
        import hashlib
        raw_key = f"{sess.first_seen}:ZEEK_CONN:{sess.src_ip}:{sess.dst_ip}:{sess.src_port}:{sess.dst_port}"
        ev_id = "ev_zk_" + hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:12]
        
        return cls(
            evidence_id=ev_id,
            timestamp=sess.first_seen,
            sensor_type=SensorType.ZEEK_CONN,
            src_entity=sess.src_ip or "unknown",
            dst_entity=sess.dst_ip or "unknown",
            src_port=sess.src_port,
            dst_port=sess.dst_port,
            protocol="TCP",
            direction=EvidenceDirection.UNKNOWN,
            bytes_count=sess.total_bytes,
            packets_count=sess.total_packets,
            duration_seconds=sess.duration_seconds,
            session_id=sess.session_id,
            application_metadata={
                "connection_state": getattr(sess.connection_state, "value", str(sess.connection_state)),
                "zeek_state": getattr(sess, "zeek_equivalent_state", "OTH"),
                "history": getattr(sess, "history_string", ""),
            },
            detection_findings=(),
            mitre_techniques=(),
            threat_intel_indicators=(),
            confidence=0.95,
            provenance=None,
            missing_fields=(),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
            "sensor_type": self.sensor_type.value,
            "src_entity": self.src_entity,
            "dst_entity": self.dst_entity,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "direction": self.direction.value,
            "bytes_count": self.bytes_count,
            "packets_count": self.packets_count,
            "duration_seconds": self.duration_seconds,
            "session_id": self.session_id,
            "application_metadata": self.application_metadata,
            "detection_findings": list(self.detection_findings),
            "mitre_techniques": list(self.mitre_techniques),
            "threat_intel_indicators": list(self.threat_intel_indicators),
            "confidence": self.confidence,
            "missing_fields": list(self.missing_fields),
        }

