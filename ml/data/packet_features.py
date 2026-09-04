"""Deterministic packet-window utilities for validated PCAP extraction.

These helpers remain guarded: they do not fabricate labels or packet data.
They only normalize actual observations and aggregate defensible statistics.
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

PACKET_FEATURE_CATEGORIES = (
    "ttl",
    "ttl_variance",
    "tcp_window",
    "tcp_flags",
    "fragmentation",
    "payload_size",
    "packet_length",
    "packet_iat",
    "retransmissions",
    "scan_signatures",
)


@dataclass(frozen=True)
class PacketRecord:
    timestamp: float
    src_ip: str | None
    dst_ip: str | None
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


@dataclass(frozen=True)
class PacketWindow:
    window_start: float
    window_end: float
    observations: tuple[dict[str, Any], ...]


def _as_number(value: Any) -> float | None:
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def normalize_packet_record(record: dict[str, Any]) -> PacketRecord:
    required = ("timestamp", "src_ip", "dst_ip", "protocol")
    missing = [field for field in required if field not in record]
    if missing:
        raise ValueError(f"packet record missing required fields: {', '.join(missing)}")

    timestamp = _as_number(record["timestamp"])
    if timestamp is None:
        raise ValueError("packet timestamp must be a numeric epoch value")

    protocol = str(record["protocol"]).upper() if record["protocol"] is not None else None
    src_port = record.get("src_port")
    dst_port = record.get("dst_port")
    packet_length = record.get("packet_length")
    payload_length = record.get("payload_length")
    ttl = record.get("ttl")
    tcp_flags = record.get("tcp_flags")
    tcp_window = record.get("tcp_window")
    tcp_seq = record.get("tcp_seq")
    tcp_ack = record.get("tcp_ack")
    fragment_offset = record.get("fragment_offset")
    more_fragments = record.get("more_fragments")
    identification = record.get("identification")

    return PacketRecord(
        timestamp=timestamp,
        src_ip=str(record["src_ip"]) if record.get("src_ip") is not None else None,
        dst_ip=str(record["dst_ip"]) if record.get("dst_ip") is not None else None,
        protocol=protocol,
        src_port=int(src_port) if src_port is not None else None,
        dst_port=int(dst_port) if dst_port is not None else None,
        packet_length=int(packet_length) if packet_length is not None else None,
        payload_length=int(payload_length) if payload_length is not None else None,
        ttl=int(ttl) if ttl is not None else None,
        tcp_flags=int(tcp_flags) if tcp_flags is not None else None,
        tcp_window=int(tcp_window) if tcp_window is not None else None,
        tcp_seq=int(tcp_seq) if tcp_seq is not None else None,
        tcp_ack=int(tcp_ack) if tcp_ack is not None else None,
        fragment_offset=int(fragment_offset) if fragment_offset is not None else None,
        more_fragments=bool(more_fragments) if more_fragments is not None else None,
        identification=int(identification) if identification is not None else None,
    )


def validate_packet_window(window: PacketWindow | dict[str, Any]) -> PacketWindow:
    if isinstance(window, dict):
        observations = tuple(window.get("observations", ()))
        window = PacketWindow(
            window_start=float(window.get("window_start", 0.0)),
            window_end=float(window.get("window_end", 0.0)),
            observations=tuple(dict(observation) for observation in observations),
        )

    if window.window_end <= window.window_start:
        raise ValueError("packet window end must be after start")

    for observation in window.observations:
        for field in ("timestamp", "src_ip", "dst_ip", "protocol"):
            if field not in observation:
                raise ValueError(f"packet observation missing {field}")
        if _as_number(observation["timestamp"]) is None:
            raise ValueError("packet timestamp must be numeric epoch seconds")
    return window


def build_packet_windows(records: Sequence[PacketRecord], window_seconds: int = 60) -> dict[int, list[PacketRecord]]:
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    buckets: dict[int, list[PacketRecord]] = {}
    for record in sorted(records, key=lambda item: item.timestamp):
        bucket = int(record.timestamp // window_seconds)
        buckets.setdefault(bucket, []).append(record)
    return buckets


def _percentile(values: Sequence[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    p = (len(ordered) - 1) * q
    lower = int(math.floor(p))
    upper = int(math.ceil(p))
    if lower == upper:
        return float(ordered[lower])
    fraction = p - lower
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)


def _mean(values: Sequence[float]) -> float:
    return float(sum(values) / len(values)) if values else 0.0


def _variance(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    mu = _mean(values)
    return float(sum((v - mu) ** 2 for v in values) / len(values))


def aggregate_window_features(window: Sequence[PacketRecord] | dict[str, Any], window_start: int | None = None) -> dict[str, Any]:
    if isinstance(window, dict):
        observations = window.get("observations", ())
        records = [normalize_packet_record(item) for item in observations]
        if window_start is None:
            window_start = int(window.get("window_start", 0))
    else:
        records = list(window)

    if not records:
        return {
            "packet_count": 0,
            "ttl_mean": None,
            "ttl_variance": None,
            "ttl_min": None,
            "ttl_max": None,
            "tcp_window_mean": None,
            "tcp_window_variance": None,
            "tcp_window_min": None,
            "tcp_window_max": None,
            "packet_size_mean": None,
            "packet_size_median": None,
            "packet_size_variance": None,
            "packet_size_p95": None,
            "payload_mean": None,
            "payload_median": None,
            "payload_variance": None,
            "payload_p95": None,
            "payload_zero_ratio": None,
            "iat_mean": None,
            "iat_median": None,
            "iat_variance": None,
            "iat_p95": None,
            "syn_count": 0,
            "ack_count": 0,
            "fin_count": 0,
            "rst_count": 0,
            "psh_count": 0,
            "urg_count": 0,
            "fragment_count": 0,
            "fragment_ratio": 0.0,
            "tcp_count": 0,
            "udp_count": 0,
            "icmp_count": 0,
            "unique_src_ips": 0,
            "unique_dst_ips": 0,
            "unique_dst_ports": 0,
            "protocol_counts": {},
            "window_start": window_start,
        }

    ttl_values = [float(record.ttl) for record in records if record.ttl is not None]
    tcp_window_values = [float(record.tcp_window) for record in records if record.tcp_window is not None]
    packet_sizes = [float(record.packet_length) for record in records if record.packet_length is not None]
    payload_values = [float(record.payload_length) for record in records if record.payload_length is not None]
    timestamps = sorted(float(record.timestamp) for record in records)
    iats = []
    for current, previous in zip(timestamps[1:], timestamps):
        iats.append(current - previous)

    protocol_counts = Counter(record.protocol for record in records if record.protocol is not None)
    flags = Counter()
    for record in records:
        if record.tcp_flags is not None:
            flags_value = int(record.tcp_flags)
            if flags_value & 0x02:
                flags["syn_count"] += 1
            if flags_value & 0x10:
                flags["ack_count"] += 1
            if flags_value & 0x01:
                flags["fin_count"] += 1
            if flags_value & 0x04:
                flags["rst_count"] += 1
            if flags_value & 0x08:
                flags["psh_count"] += 1
            if flags_value & 0x20:
                flags["urg_count"] += 1

    fragment_count = sum(
        1
        for record in records
        if (record.fragment_offset is not None and int(record.fragment_offset) > 0)
        or (record.more_fragments is not None and bool(record.more_fragments))
    )
    fragment_ratio = float(fragment_count / len(records)) if records else 0.0

    features = {
        "packet_count": len(records),
        "ttl_mean": _mean(ttl_values) if ttl_values else None,
        "ttl_variance": _variance(ttl_values) if ttl_values else None,
        "ttl_min": min(ttl_values) if ttl_values else None,
        "ttl_max": max(ttl_values) if ttl_values else None,
        "tcp_window_mean": _mean(tcp_window_values) if tcp_window_values else None,
        "tcp_window_variance": _variance(tcp_window_values) if tcp_window_values else None,
        "tcp_window_min": min(tcp_window_values) if tcp_window_values else None,
        "tcp_window_max": max(tcp_window_values) if tcp_window_values else None,
        "packet_size_mean": _mean(packet_sizes) if packet_sizes else None,
        "packet_size_median": _percentile(packet_sizes, 0.5) if packet_sizes else None,
        "packet_size_variance": _variance(packet_sizes) if packet_sizes else None,
        "packet_size_p95": _percentile(packet_sizes, 0.95) if packet_sizes else None,
        "payload_mean": _mean(payload_values) if payload_values else None,
        "payload_median": _percentile(payload_values, 0.5) if payload_values else None,
        "payload_variance": _variance(payload_values) if payload_values else None,
        "payload_p95": _percentile(payload_values, 0.95) if payload_values else None,
        "payload_zero_ratio": float(sum(1 for value in payload_values if value == 0) / len(payload_values)) if payload_values else None,
        "iat_mean": _mean(iats) if iats else None,
        "iat_median": _percentile(iats, 0.5) if iats else None,
        "iat_variance": _variance(iats) if iats else None,
        "iat_p95": _percentile(iats, 0.95) if iats else None,
        "syn_count": flags.get("syn_count", 0),
        "ack_count": flags.get("ack_count", 0),
        "fin_count": flags.get("fin_count", 0),
        "rst_count": flags.get("rst_count", 0),
        "psh_count": flags.get("psh_count", 0),
        "urg_count": flags.get("urg_count", 0),
        "fragment_count": fragment_count,
        "fragment_ratio": fragment_ratio,
        "tcp_count": protocol_counts.get("TCP", 0),
        "udp_count": protocol_counts.get("UDP", 0),
        "icmp_count": protocol_counts.get("ICMP", 0),
        "unique_src_ips": len({record.src_ip for record in records if record.src_ip is not None}),
        "unique_dst_ips": len({record.dst_ip for record in records if record.dst_ip is not None}),
        "unique_dst_ports": len({record.dst_port for record in records if record.dst_port is not None}),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "window_start": window_start if window_start is not None else min(float(record.timestamp) for record in records) // 60 * 60,
    }
    return features


def determines_window_features(window: Sequence[PacketRecord] | dict[str, Any]) -> dict[str, Any]:
    return aggregate_window_features(window)


def packet_feature_vector(window: PacketWindow | dict[str, Any]) -> dict[str, Any]:
    """A structurally valid packet window remains a placeholder until a real PCAP is processed."""
    validated_window = validate_packet_window(window)
    return {
        "available": False,
        "status": "PENDING_PCAP",
        "features": {},
        "categories": list(PACKET_FEATURE_CATEGORIES),
        "observation_count": len(validated_window.observations),
        "window_start": validated_window.window_start,
        "window_end": validated_window.window_end,
    }


def determine_label_alignment_status(label_state: dict[str, Any]) -> str:
    if not label_state:
        return "BLOCKED"
    status = str(label_state.get("status", "")).upper()
    if status in {"VALIDATED", "PARTIALLY_VALIDATED"}:
        return status
    if status == "BLOCKED":
        return "BLOCKED"
    return "PARTIALLY_VALIDATED"