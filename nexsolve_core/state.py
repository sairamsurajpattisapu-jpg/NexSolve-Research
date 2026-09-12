"""PCAP temporal-state candidates and the explicit model compatibility gate."""
from __future__ import annotations

import json
import math
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Iterable, Mapping

from .schemas import CaptureQuality, FlowRecord, PacketRecord, Provenance, QualityStatus, TemporalWindow


class FeatureAvailability(StrEnum):
    PCAP = "PCAP"
    CANONICAL_FLOW = "CANONICAL_FLOW"
    TEMPORAL = "TEMPORAL"
    UNAVAILABLE = "UNAVAILABLE"
    UNRELIABLE = "UNRELIABLE"


@dataclass(frozen=True)
class FeatureSpec:
    group: str
    name: str
    source: str
    computation: str
    units: str
    aggregation: str
    minimum_evidence: str
    availability: FeatureAvailability


@dataclass(frozen=True)
class NetworkStateCandidate:
    window_id: str
    start_timestamp: int
    end_timestamp: int
    flow_features: Mapping[str, float]
    packet_features: Mapping[str, float]
    temporal_features: Mapping[str, float]
    traffic_aggregates: Mapping[str, Any]
    flow_aggregates: Mapping[str, Any]
    protocol_aggregates: Mapping[str, int]
    detection_features: Mapping[str, Any]
    capture_quality: CaptureQuality
    provenance: Provenance
    feature_status: Mapping[str, FeatureAvailability]
    unavailable_reasons: Mapping[str, str]
    label: str = "UNKNOWN"
    flow_lifecycle: Mapping[str, tuple[str, ...]] = None  # type: ignore[assignment]

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "flow_features": dict(self.flow_features),
            "packet_features": dict(self.packet_features),
            "temporal_features": dict(self.temporal_features),
            "traffic_aggregates": dict(self.traffic_aggregates),
            "flow_aggregates": dict(self.flow_aggregates),
            "protocol_aggregates": dict(self.protocol_aggregates),
            "detection_features": dict(self.detection_features),
            "capture_quality": self.capture_quality.to_dict(),
            "provenance": {
                "capture_id": self.provenance.capture_id,
                "packet_indexes": list(self.provenance.packet_indexes),
                "flow_ids": list(self.provenance.flow_ids),
                "window_ids": list(self.provenance.window_ids),
                "source_timestamps": list(self.provenance.source_timestamps),
                "transformation_stage": self.provenance.transformation_stage,
            },
            "feature_status": {name: status.value for name, status in self.feature_status.items()},
            "unavailable_reasons": dict(self.unavailable_reasons),
            "label": self.label,
            "flow_lifecycle": {name: list(values) for name, values in (self.flow_lifecycle or {}).items()},
        }


@dataclass(frozen=True)
class ModelCompatibilityReport:
    model_ready: bool
    required_features: int
    required_feature_names: tuple[str, ...]
    available_features: tuple[str, ...]
    unavailable_features: tuple[str, ...]
    unreliable_features: tuple[str, ...]
    incompatible_dimensions: tuple[str, ...]
    capture_quality_blockers: tuple[str, ...]
    temporal_history_blockers: tuple[str, ...]
    reasons: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_ready": self.model_ready,
            "required_features": self.required_features,
            "required_feature_names": list(self.required_feature_names),
            "available_features": list(self.available_features),
            "missing_features": list(self.unavailable_features),
            "unavailable_features": list(self.unavailable_features),
            "unreliable_features": list(self.unreliable_features),
            "incompatible_dimensions": list(self.incompatible_dimensions),
            "capture_quality_blockers": list(self.capture_quality_blockers),
            "temporal_history_blockers": list(self.temporal_history_blockers),
            "reasons": list(self.reasons),
            "reason": "; ".join(self.reasons) if self.reasons else "All required feature semantics and evidence gates passed.",
        }


@dataclass(frozen=True)
class HistoryResult:
    status: str
    candidates: tuple[NetworkStateCandidate, ...]
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "window_ids": [candidate.window_id for candidate in self.candidates], "reason": self.reason}


FLOW_NAMES = (
    "flow_count", "total_src_bytes", "total_dst_bytes", "total_packets", "mean_duration",
    "mean_flow_bytes", "mean_flow_packets", "mean_sttl", "mean_dttl", "mean_swin",
    "mean_dwin", "mean_iat", "mean_tcp_rtt", "unique_src_ports", "unique_dst_ports",
    "proto_tcp_count", "proto_udp_count", "proto_other_count",
)
FLOW_NAMES_45 = tuple(n for n in FLOW_NAMES if n != "mean_tcp_rtt")
PACKET_NAMES = (
    "packet_count", "mean_packet_size", "std_packet_size", "min_packet_size", "max_packet_size",
    "mean_ttl", "std_ttl", "min_ttl", "max_ttl", "tcp_syn_count", "tcp_ack_count",
    "tcp_fin_count", "tcp_rst_count", "tcp_psh_count", "tcp_urg_count", "mean_tcp_window",
    "std_tcp_window", "fragment_count", "retransmission_count", "mean_iat", "std_iat", "max_iat",
)
TEMPORAL_NAMES = ("delta_flow_count", "delta_total_bytes", "delta_total_packets", "delta_ports", "delta_iat", "rolling_total_bytes")
MODEL_NAMES = FLOW_NAMES + PACKET_NAMES + TEMPORAL_NAMES
MODEL_NAMES_45 = FLOW_NAMES_45 + PACKET_NAMES + TEMPORAL_NAMES
MODEL_SCHEMA_45 = {
    "flow_features": list(FLOW_NAMES_45),
    "packet_features": list(PACKET_NAMES),
    "temporal_features": list(TEMPORAL_NAMES),
}


def feature_registry() -> dict[str, FeatureSpec]:
    registry: dict[str, FeatureSpec] = {}
    def register(group: str, name: str, source: str, computation: str, units: str, aggregation: str, minimum_evidence: str, availability: FeatureAvailability) -> None:
        registry[f"{group}.{name}"] = FeatureSpec(group, name, source, computation, units, aggregation, minimum_evidence, availability)
    direct_packet = {
        "packet_count": ("packets in the current window", "packets", "count"),
        "mean_packet_size": ("mean PacketRecord.packet_length", "bytes", "mean"),
        "std_packet_size": ("square root of packet length variance", "bytes", "population standard deviation"),
        "min_packet_size": ("minimum PacketRecord.packet_length", "bytes", "minimum"),
        "max_packet_size": ("maximum PacketRecord.packet_length", "bytes", "maximum"),
        "mean_ttl": ("mean observed TTL or hop limit", "hops", "mean"),
        "std_ttl": ("square root of TTL variance", "hops", "population standard deviation"),
        "min_ttl": ("minimum observed TTL or hop limit", "hops", "minimum"),
        "max_ttl": ("maximum observed TTL or hop limit", "hops", "maximum"),
        "tcp_syn_count": ("count of TCP SYN flags", "packets", "count"),
        "tcp_ack_count": ("count of TCP ACK flags", "packets", "count"),
        "tcp_fin_count": ("count of TCP FIN flags", "packets", "count"),
        "tcp_rst_count": ("count of TCP RST flags", "packets", "count"),
        "tcp_psh_count": ("count of TCP PSH flags", "packets", "count"),
        "tcp_urg_count": ("count of TCP URG flags", "packets", "count"),
        "mean_tcp_window": ("mean observed TCP window", "bytes", "mean"),
        "std_tcp_window": ("square root of TCP window variance", "bytes", "population standard deviation"),
        "fragment_count": ("count of packets marked fragmented", "packets", "count"),
        "retransmission_count": ("count of observed TCP sequence overlaps", "packets", "count"),
        "mean_iat": ("mean sorted inter-arrival time", "seconds", "mean"),
        "std_iat": ("square root of sorted IAT variance", "seconds", "population standard deviation"),
        "max_iat": ("maximum sorted inter-arrival time", "seconds", "maximum"),
    }
    for name, (computation, units, aggregation) in direct_packet.items():
        register("packet_features", name, "PacketRecord/TemporalWindow", computation, units, aggregation, "one or more observed packets", FeatureAvailability.PCAP)
    flow_direct = {
        "flow_count": ("count active FlowRecord IDs", "flows", "count"),
        "total_src_bytes": ("sum prefix packet lengths in canonical forward direction", "bytes", "sum"),
        "total_dst_bytes": ("sum prefix packet lengths in canonical reverse direction", "bytes", "sum"),
        "total_packets": ("sum prefix packets for active flows", "packets", "sum"),
        "mean_duration": ("mean end_seen minus start_seen per active flow", "seconds", "mean"),
        "mean_flow_bytes": ("mean total prefix bytes per active flow", "bytes", "mean"),
        "mean_flow_packets": ("mean prefix packets per active flow", "packets", "mean"),
        "mean_sttl": ("mean forward-direction observed TTL", "hops", "mean"),
        "mean_dttl": ("mean reverse-direction observed TTL", "hops", "mean"),
        "mean_swin": ("mean forward-direction TCP window", "bytes", "mean"),
        "mean_dwin": ("mean reverse-direction TCP window", "bytes", "mean"),
        "mean_iat": ("mean within-flow prefix IAT", "seconds", "mean"),
        "unique_src_ports": ("cardinality of active canonical source ports", "ports", "cardinality"),
        "unique_dst_ports": ("cardinality of active canonical destination ports", "ports", "cardinality"),
        "proto_tcp_count": ("count active TCP flows", "flows", "count"),
        "proto_udp_count": ("count active UDP flows", "flows", "count"),
        "proto_other_count": ("count active non-TCP/UDP flows", "flows", "count"),
    }
    for name, (computation, units, aggregation) in flow_direct.items():
        register("flow_features", name, "FlowRecord/PacketRecord", computation, units, aggregation, "one active flow with prefix evidence", FeatureAvailability.CANONICAL_FLOW)
    register("flow_features", "mean_tcp_rtt", "PacketRecord", "TCP RTT is not observed by the canonical packet contract", "seconds", "unavailable", "TCP timestamp/options plus validated ACK pairing", FeatureAvailability.UNAVAILABLE)
    for name in TEMPORAL_NAMES:
        register("temporal_features", name, "NetworkStateCandidate sequence", "past-only comparison with prior candidate", "feature units", "temporal delta or rolling mean", "current and immediately prior contiguous candidate", FeatureAvailability.TEMPORAL)
    return registry


def _model_schema(feature_schema: Mapping[str, list[str]] | None) -> tuple[str, ...]:
    if feature_schema is not None:
        return tuple(name for group in ("flow_features", "packet_features", "temporal_features") for name in feature_schema.get(group, []))
    return MODEL_NAMES


def _model_feature_keys(feature_schema: Mapping[str, list[str]] | None) -> tuple[str, ...]:
    schema = feature_schema or {"flow_features": list(FLOW_NAMES), "packet_features": list(PACKET_NAMES), "temporal_features": list(TEMPORAL_NAMES)}
    return tuple(f"{group}.{name}" for group in ("flow_features", "packet_features", "temporal_features") for name in schema.get(group, []))


def _value(row: Mapping[str, Any], name: str) -> float | None:
    raw = row.get(name)
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value if math.isfinite(value) else None


def _flow_prefix(flow: FlowRecord, packets: Mapping[int, PacketRecord]) -> list[PacketRecord]:
    return [packets[index] for index in flow.provenance.packet_indexes if index in packets]


def _flow_values(flow: FlowRecord, prefix: list[PacketRecord]) -> dict[str, float]:
    if not prefix:
        return {}
    origin = (flow.src_ip, flow.src_port)
    start = prefix[0].timestamp
    end = prefix[0].timestamp
    forward: list[PacketRecord] = []
    reverse: list[PacketRecord] = []
    timestamps: list[float] = []
    all_lengths: list[int] = []

    for packet in prefix:
        ts = packet.timestamp
        if ts < start:
            start = ts
        if ts > end:
            end = ts
        timestamps.append(ts)
        if packet.packet_length is not None:
            all_lengths.append(packet.packet_length)
        if (packet.src_ip, packet.src_port) == origin:
            forward.append(packet)
        else:
            reverse.append(packet)

    forward_lengths = [packet.packet_length for packet in forward if packet.packet_length is not None]
    reverse_lengths = [packet.packet_length for packet in reverse if packet.packet_length is not None]
    timestamps.sort()
    iats = [right - left for left, right in zip(timestamps, timestamps[1:])]
    forward_ttl = [packet.ttl for packet in forward if packet.ttl is not None]
    reverse_ttl = [packet.ttl for packet in reverse if packet.ttl is not None]
    forward_windows = [packet.tcp_window for packet in forward if packet.tcp_window is not None]
    reverse_windows = [packet.tcp_window for packet in reverse if packet.tcp_window is not None]
    return {
        "total_src_bytes": float(sum(forward_lengths)),
        "total_dst_bytes": float(sum(reverse_lengths)),
        "total_packets": float(len(prefix)),
        "mean_duration": float(max(0.0, end - start)),
        "mean_flow_bytes": float(sum(all_lengths)),
        "mean_flow_packets": float(len(prefix)),
        "mean_sttl": sum(forward_ttl) / len(forward_ttl) if forward_ttl else None,
        "mean_dttl": sum(reverse_ttl) / len(reverse_ttl) if reverse_ttl else None,
        "mean_swin": sum(forward_windows) / len(forward_windows) if forward_windows else None,
        "mean_dwin": sum(reverse_windows) / len(reverse_windows) if reverse_windows else None,
        "mean_iat": sum(iats) / len(iats) if iats else None,
    }


def _aggregate_flow_features(window: TemporalWindow, seen_packets: Mapping[int, PacketRecord]) -> tuple[dict[str, float], dict[str, Any]]:
    values = [_flow_values(flow, _flow_prefix(flow, seen_packets)) for flow in window.flows]
    values = [value for value in values if value]
    if not values:
        return {"flow_count": 0.0, "total_src_bytes": 0.0, "total_dst_bytes": 0.0, "total_packets": 0.0, "unique_src_ports": 0.0, "unique_dst_ports": 0.0, "proto_tcp_count": 0.0, "proto_udp_count": 0.0, "proto_other_count": 0.0}, {"active_flow_ids": (), "new_flow_ids": (), "ended_flow_ids": ()}
    numeric: dict[str, float] = {"flow_count": float(len(values))}
    for name in ("total_src_bytes", "total_dst_bytes", "total_packets"):
        numeric[name] = sum(value[name] for value in values)
    for name in ("mean_duration", "mean_flow_bytes", "mean_flow_packets", "mean_sttl", "mean_dttl", "mean_swin", "mean_dwin", "mean_iat"):
        present = [value[name] for value in values if value.get(name) is not None]
        if present:
            numeric[name] = sum(present) / len(present)
    numeric["unique_src_ports"] = float(len({(flow.src_ip, flow.src_port) for flow in window.flows if flow.src_port is not None}))
    numeric["unique_dst_ports"] = float(len({(flow.dst_ip, flow.dst_port) for flow in window.flows if flow.dst_port is not None}))
    numeric["proto_tcp_count"] = float(sum(flow.protocol == "TCP" for flow in window.flows))
    numeric["proto_udp_count"] = float(sum(flow.protocol == "UDP" for flow in window.flows))
    numeric["proto_other_count"] = float(len(window.flows) - numeric["proto_tcp_count"] - numeric["proto_udp_count"])
    return numeric, {"active_flow_ids": tuple(flow.flow_id for flow in window.flows)}


def _packet_features(window: TemporalWindow) -> dict[str, float]:
    row = window.aggregate_features
    mapping = {
        "packet_count": "packet_count", "mean_packet_size": "packet_size_mean", "min_packet_size": "packet_size_min", "max_packet_size": "packet_size_max",
        "mean_ttl": "ttl_mean", "min_ttl": "ttl_min", "max_ttl": "ttl_max", "tcp_syn_count": "syn_count", "tcp_ack_count": "ack_count",
        "tcp_fin_count": "fin_count", "tcp_rst_count": "rst_count", "tcp_psh_count": "psh_count", "tcp_urg_count": "urg_count", "mean_tcp_window": "tcp_window_mean",
        "fragment_count": "fragment_count", "retransmission_count": "tcp_retransmission_count", "mean_iat": "iat_mean", "max_iat": "iat_max",
    }
    result = {name: value for name, source in mapping.items() if (value := _value(row, source)) is not None}
    variance_mapping = {"std_packet_size": "packet_size_variance", "std_ttl": "ttl_variance", "std_tcp_window": "tcp_window_variance", "std_iat": "iat_variance"}
    for name, source in variance_mapping.items():
        value = _value(row, source)
        if value is not None and value >= 0:
            result[name] = math.sqrt(value)
    return result


def build_network_state_candidates(windows: Iterable[TemporalWindow], feature_schema: Mapping[str, list[str]] | None = None) -> tuple[NetworkStateCandidate, ...]:
    ordered = tuple(sorted(windows, key=lambda window: (window.start_timestamp, window.window_id)))
    previous: NetworkStateCandidate | None = None
    seen_packets: dict[int, PacketRecord] = {}
    candidates: list[NetworkStateCandidate] = []
    registry = feature_registry()
    for window in ordered:
        seen_packets.update({packet.packet_index: packet for packet in window.packets if packet.packet_index is not None})
        flow_features, lifecycle = _aggregate_flow_features(window, seen_packets)
        active_flow_ids = set(lifecycle["active_flow_ids"])
        previous_flow_ids = set(previous.flow_lifecycle.get("active_flow_ids", ()) if previous is not None and previous.flow_lifecycle else ())
        lifecycle = {
            "active_flow_ids": tuple(sorted(active_flow_ids)),
            "new_flow_ids": tuple(sorted(active_flow_ids - previous_flow_ids)),
            "ended_flow_ids": tuple(sorted(previous_flow_ids - active_flow_ids)),
        }
        packet_features = _packet_features(window)
        temporal_features: dict[str, float] = {}
        unavailable: dict[str, str] = {}
        feature_status: dict[str, FeatureAvailability] = {}
        for name in flow_features:
            feature_status[f"flow_features.{name}"] = registry[f"flow_features.{name}"].availability
        for name in packet_features:
            feature_status[f"packet_features.{name}"] = registry[f"packet_features.{name}"].availability
        if previous is not None:
            current_iat = flow_features.get("mean_iat")
            previous_iat = previous.flow_features.get("mean_iat")
            temporal_features = {
                "delta_flow_count": flow_features["flow_count"] - previous.flow_features["flow_count"],
                "delta_total_bytes": flow_features["total_src_bytes"] + flow_features["total_dst_bytes"] - previous.flow_features["total_src_bytes"] - previous.flow_features["total_dst_bytes"],
                "delta_total_packets": flow_features["total_packets"] - previous.flow_features["total_packets"],
                "delta_ports": flow_features["unique_src_ports"] + flow_features["unique_dst_ports"] - previous.flow_features["unique_src_ports"] - previous.flow_features["unique_dst_ports"],
                "rolling_total_bytes": (sum(c.flow_features["total_src_bytes"] + c.flow_features["total_dst_bytes"] for c in candidates[-3:]) + flow_features["total_src_bytes"] + flow_features["total_dst_bytes"]) / min(len(candidates) + 1, 4),
            }
            if current_iat is not None and previous_iat is not None:
                temporal_features["delta_iat"] = current_iat - previous_iat
            else:
                unavailable["temporal_features.delta_iat"] = "Flow IAT is unavailable in the current or prior window."
            feature_status.update({f"temporal_features.{name}": registry[f"temporal_features.{name}"].availability for name in temporal_features})
        else:
            for name in TEMPORAL_NAMES:
                unavailable[name] = "No prior observed window exists for a past-only temporal derivation."
                feature_status[name] = FeatureAvailability.UNAVAILABLE
        for group, names in (("flow_features", FLOW_NAMES), ("packet_features", PACKET_NAMES), ("temporal_features", TEMPORAL_NAMES)):
            for name in names:
                key = f"{group}.{name}"
                if key in feature_status:
                    continue
                feature_status[key] = FeatureAvailability.UNAVAILABLE
                unavailable[key] = "Insufficient evidence in this window for the registered derivation."
        candidate = NetworkStateCandidate(
            window_id=window.window_id, start_timestamp=window.start_timestamp, end_timestamp=window.end_timestamp,
            flow_features=flow_features, packet_features=packet_features, temporal_features=temporal_features,
            traffic_aggregates={"packet_count": window.packet_count, "flow_count": window.flow_count, "raw_observed_count": window.raw_observed_count or window.packet_count},
            flow_aggregates={"active_flow_count": window.flow_count}, protocol_aggregates=dict(window.aggregate_features.get("protocol_counts", {})),
            detection_features=dict(window.detection_features) | {"risk_features_available": True}, capture_quality=window.quality,
            provenance=window.provenance, feature_status=feature_status, unavailable_reasons=unavailable,
            flow_lifecycle=lifecycle,
        )
        candidates.append(candidate)
        previous = candidate
    return tuple(candidates)


def evaluate_model_compatibility(candidates: Iterable[NetworkStateCandidate], feature_schema: Mapping[str, list[str]] | None = None, history_status: str | None = None) -> ModelCompatibilityReport:
    sequence = tuple(candidates)
    eval_seq = sequence[1:] if len(sequence) > 1 else sequence
    required = _model_schema(feature_schema)
    required_keys = _model_feature_keys(feature_schema)
    available = tuple(key for key in required_keys if eval_seq and all(key in candidate.feature_status and candidate.feature_status[key] not in {FeatureAvailability.UNAVAILABLE, FeatureAvailability.UNRELIABLE} for candidate in eval_seq))
    unavailable = tuple(key for key in required_keys if key not in available)
    unreliable = tuple(key for key in required_keys if any(candidate.feature_status.get(key) == FeatureAvailability.UNRELIABLE for candidate in eval_seq))
    quality_blockers = tuple(sorted({candidate.capture_quality.reason for candidate in sequence if candidate.capture_quality.status == QualityStatus.INSUFFICIENT}))
    history_blockers = () if history_status in {None, "READY"} else (history_status,)
    reasons = []
    if not sequence:
        reasons.append("No NetworkStateCandidate objects were provided.")
    if unavailable:
        reasons.append("Required features are unavailable for at least one candidate; no dense vector is fabricated.")
    if unreliable:
        reasons.append("One or more required features are marked unreliable.")
    if quality_blockers:
        reasons.append("Capture quality is insufficient for model preparation.")
    if history_blockers:
        reasons.append(f"Temporal history is not ready: {history_status}.")
    expected_dim = len(required)
    dim_ok = len(required) in (45, 46) if feature_schema is None else (len(required) == len(required_keys))
    dim_incompat = () if dim_ok else (f"expected {len(required_keys)} features, found {len(required)}",)
    return ModelCompatibilityReport(not unavailable and not unreliable and not quality_blockers and not history_blockers and dim_ok, len(required), required_keys, available, unavailable, unreliable, dim_incompat, quality_blockers, history_blockers, tuple(reasons))


def candidates_to_network_states(candidates: Iterable[NetworkStateCandidate], feature_schema: Mapping[str, list[str]] | None = None, history_status: str | None = "READY") -> tuple[Any, ...]:
    sequence = tuple(candidates)
    report = evaluate_model_compatibility(sequence, feature_schema, history_status)
    if not report.model_ready:
        raise ValueError("NetworkStateCandidate sequence is not model-compatible; missing semantics are not zero-filled.")
    from world_model import NetworkState

    schema = feature_schema or {"flow_features": list(FLOW_NAMES), "packet_features": list(PACKET_NAMES), "temporal_features": list(TEMPORAL_NAMES)}
    states = []
    # If the first candidate has no temporal features, only convert candidates from index 1 onward
    # (which all have observed temporal features derived from their predecessor)
    conv_seq = sequence[1:] if (len(sequence) > 1 and not sequence[0].temporal_features) else sequence
    for candidate in conv_seq:
        states.append(NetworkState(
            candidate.start_timestamp,
            {name: float(candidate.flow_features[name]) for name in schema["flow_features"]},
            {name: float(candidate.packet_features[name]) for name in schema["packet_features"]},
            {name: float(candidate.temporal_features[name]) for name in schema["temporal_features"]},
            None,
            True,
        ))
    return tuple(states)


def build_state_history(candidates: Iterable[NetworkStateCandidate], lookback: int = 8) -> HistoryResult:
    ordered = tuple(candidates)
    if not ordered:
        return HistoryResult("INSUFFICIENT_HISTORY", (), "No candidates were provided.")
    capture_ids = {candidate.provenance.capture_id for candidate in ordered}
    if len(capture_ids) != 1:
        return HistoryResult("GAPPED_HISTORY", (), "History cannot cross capture boundaries.")
    ordered = tuple(sorted(ordered, key=lambda candidate: (candidate.start_timestamp, candidate.window_id)))
    for previous, current in zip(ordered, ordered[1:]):
        if current.start_timestamp != previous.end_timestamp:
            return HistoryResult("GAPPED_HISTORY", (), "One or more canonical windows are missing or non-contiguous.")
    if len(ordered) < lookback:
        return HistoryResult("INSUFFICIENT_HISTORY", ordered, f"Need {lookback} contiguous windows; received {len(ordered)}.")
    return HistoryResult("READY", ordered[-lookback:], "Contiguous past-only history is available.")
