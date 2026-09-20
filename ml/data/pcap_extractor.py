from __future__ import annotations

import json
import math
import argparse
import os
import time
import tracemalloc
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from scapy.all import ARP, Dot1Q, ICMP, IP, IPv6, PcapNgReader, TCP, UDP
from scapy.layers.inet6 import IPv6ExtHdrFragment

from ml.data.fast_pcap_decoder import FastPcapDecoder

from nexsolve_core.schemas import (
    PacketRecord,
    Provenance,
    TemporalWindow,
    build_flows,
    build_temporal_windows,
    make_capture_quality,
)
from ml.data.packet_features import aggregate_window_features


@dataclass(frozen=True)
class PcapExtractionResult:
    path: str
    packets_read: int
    packets_parsed: int
    malformed_packets: int
    processing_time_seconds: float
    packets_per_second: float
    peak_memory_bytes: int | None
    packet_features_extracted: int
    packet_windows: int
    ipv4: int
    ipv6: int
    tcp: int
    udp: int
    icmp: int
    missing_ttl: int
    missing_payload: int
    fragmented_packets: int
    first_timestamp_utc: str | None
    last_timestamp_utc: str | None
    duration_seconds: float | None
    output_json: dict[str, Any]


def _safe_float(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if math.isnan(number) or math.isinf(number):
        return None
    return number


def _payload_layers(layer: Any) -> Iterator[Any]:
    current = layer
    while current is not None and current.__class__.__name__ != "NoPayload":
        yield current
        current = getattr(current, "payload", None)


def _truncation_status(pkt: Any) -> str:
    if IP in pkt:
        ip_layer = pkt[IP]
        declared = getattr(ip_layer, "len", None)
        if declared is None:
            return "UNKNOWN"
        return "FALSE" if len(bytes(ip_layer)) >= int(declared) else "TRUE"
    if IPv6 in pkt:
        ipv6_layer = pkt[IPv6]
        declared = getattr(ipv6_layer, "plen", None)
        if declared is None:
            return "UNKNOWN"
        return "FALSE" if len(bytes(ipv6_layer)) >= int(declared) + 40 else "TRUE"
    return "UNKNOWN"


def packet_record_from_pkt(
    pkt: Any,
    *,
    packet_index: int | None = None,
    capture_id: str = "unknown",
    capture_start: float | None = None,
) -> PacketRecord | None:
    timestamp = _safe_float(getattr(pkt, "time", None))
    if timestamp is None or timestamp < 0:
        return None
    parsing_status = "parsed"
    unsupported_reason = None
    icmp_type = icmp_code = None
    extension_headers: tuple[str, ...] = ()
    src_ip = dst_ip = None
    ttl = ip_version = None
    protocol = "UNSUPPORTED"
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip, dst_ip, ttl, ip_version = str(ip_layer.src), str(ip_layer.dst), getattr(ip_layer, "ttl", None), 4
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP" if pkt.haslayer(ICMP) else f"IPv4_PROTO_{ip_layer.proto}"
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip, dst_ip, ttl, ip_version = str(ip_layer.src), str(ip_layer.dst), getattr(ip_layer, "hlim", None), 6
        extension_headers = tuple(layer.__class__.__name__ for layer in _payload_layers(ip_layer.payload) if layer.__class__.__name__.startswith("IPv6ExtHdr"))
        icmpv6 = next((layer for layer in _payload_layers(ip_layer.payload) if layer.__class__.__name__.startswith("ICMPv6")), None)
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMPv6" if icmpv6 is not None else f"IPv6_NEXT_HEADER_{ip_layer.nh}"
        if extension_headers and any(name not in {"IPv6ExtHdrHopByHop", "IPv6ExtHdrRouting", "IPv6ExtHdrDestOpt", "IPv6ExtHdrFragment"} for name in extension_headers):
            parsing_status = "unsupported"
            unsupported_reason = "Unsupported IPv6 extension header chain."
    elif pkt.haslayer(ARP):
        arp_layer = pkt[ARP]
        src_ip, dst_ip, protocol = str(getattr(arp_layer, "psrc", "")) or None, str(getattr(arp_layer, "pdst", "")) or None, "ARP"
    else:
        parsing_status = "unsupported"
        unsupported_reason = "Link-layer or protocol semantics are unavailable."
    if protocol.startswith(("IPv4_PROTO_", "IPv6_NEXT_HEADER_")):
        parsing_status = "unsupported"
        unsupported_reason = "Transport protocol is unavailable to the canonical extractor."

    payload_length = None
    src_port = dst_port = None
    tcp_flags = tcp_window = tcp_seq = tcp_ack = None
    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        src_port, dst_port = int(tcp_layer.sport), int(tcp_layer.dport)
        tcp_flags, tcp_window = int(tcp_layer.flags), int(tcp_layer.window)
        tcp_seq, tcp_ack = int(tcp_layer.seq), int(tcp_layer.ack)
        payload_length = len(bytes(tcp_layer.payload))
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        src_port, dst_port = int(udp_layer.sport), int(udp_layer.dport)
        payload_length = len(bytes(udp_layer.payload))
    else:
        icmp_layer = pkt[ICMP] if pkt.haslayer(ICMP) else next((layer for layer in _payload_layers(pkt[IPv6].payload) if layer.__class__.__name__.startswith("ICMPv6")), None) if IPv6 in pkt else None
        if icmp_layer is not None:
            icmp_type, icmp_code = int(getattr(icmp_layer, "type", 0)), int(getattr(icmp_layer, "code", 0))
            payload_length = len(bytes(icmp_layer.payload))

    fragment_offset = more_fragments = identification = None
    ipv6_fragment_id = ipv6_fragment_offset = None
    ipv6_more_fragments = None
    if IP in pkt:
        ipv4 = pkt[IP]
        fragment_offset, more_fragments, identification = int(ipv4.frag or 0), bool(ipv4.flags & 0x1), int(ipv4.id)
    elif IPv6 in pkt:
        fragment = pkt.getlayer(IPv6ExtHdrFragment)
        if fragment is not None:
            ipv6_fragment_offset, ipv6_more_fragments, ipv6_fragment_id = int(fragment.offset), bool(fragment.m), int(fragment.id)
            fragment_offset, more_fragments, identification = ipv6_fragment_offset, ipv6_more_fragments, ipv6_fragment_id
    vlan_layers = tuple(layer for layer in _payload_layers(pkt) if isinstance(layer, Dot1Q))
    vlan = vlan_layers[0] if vlan_layers else None
    return PacketRecord(
        timestamp=timestamp, src_ip=src_ip, dst_ip=dst_ip, ip_version=ip_version, protocol=protocol,
        src_port=src_port, dst_port=dst_port, packet_length=len(bytes(pkt)), payload_length=payload_length,
        ttl=int(ttl) if ttl is not None else None, tcp_flags=tcp_flags, tcp_window=tcp_window,
        tcp_seq=tcp_seq, tcp_ack=tcp_ack, fragment_offset=fragment_offset, more_fragments=more_fragments,
        identification=identification, icmp_type=icmp_type, icmp_code=icmp_code,
        ipv6_extension_headers=extension_headers, ipv6_fragment_id=ipv6_fragment_id,
        ipv6_fragment_offset=ipv6_fragment_offset, ipv6_more_fragments=ipv6_more_fragments,
        vlan_id=int(vlan.vlan) if vlan is not None else None, vlan_priority=int(vlan.prio) if vlan is not None else None,
        vlan_ids=tuple(int(layer.vlan) for layer in vlan_layers),
        packet_index=packet_index, capture_relative_timestamp=(timestamp - capture_start) if capture_start is not None else None,
        parsing_status=parsing_status, unsupported_reason=unsupported_reason,
        truncation_status=_truncation_status(pkt),
        provenance=Provenance(capture_id, (packet_index,) if packet_index is not None else (), (), (), (timestamp,), "packet_extraction"),
    )


def iter_streaming_packets(path: str | Path) -> Iterator[PacketRecord]:
    pcap_path = Path(path)
    try:
        if pcap_path.is_file() and pcap_path.stat().st_size >= 24:
            import mmap

            with open(pcap_path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    decoder = FastPcapDecoder(mm, capture_id=pcap_path.name)
                    if decoder.valid and not decoder.fallback_needed:
                        for record in decoder.decode_packets():
                            if record is not None:
                                yield record
                        return
    except Exception:
        pass

    reader = PcapNgReader(str(pcap_path))
    try:
        for packet_index, pkt in enumerate(reader):
            record = packet_record_from_pkt(pkt, packet_index=packet_index, capture_id=pcap_path.name)
            if record is not None:
                yield record
    finally:
        reader.close()


def _window_bucket(ts: float, window_seconds: int = 60) -> int:
    return int(float(ts) // window_seconds)


def _percentile_sorted(ordered: list[float], quantile: float) -> float | None:
    if not ordered:
        return None
    if len(ordered) == 1:
        return float(ordered[0])
    p = (len(ordered) - 1) * quantile
    lower = int(math.floor(p))
    upper = int(math.ceil(p))
    if lower == upper:
        return float(ordered[lower])
    return float(ordered[lower] + (ordered[upper] - ordered[lower]) * (p - lower))


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    return _percentile_sorted(sorted(values), quantile)


def compute_packet_window_stats(
    records: list[dict[str, Any]] | list[PacketRecord] | tuple[PacketRecord, ...],
    retransmission_count: int = 0,
    *,
    calculate_port_scan: bool = False,
) -> dict[str, Any]:
    if not records:
        return {"packet_count": 0, "ttl_mean": None, "ttl_variance": None, "ttl_min": None, "ttl_max": None, "tcp_window_mean": None, "tcp_window_variance": None, "tcp_window_min": None, "tcp_window_max": None, "packet_size_mean": None, "packet_size_median": None, "packet_size_variance": None, "packet_size_p95": None, "payload_mean": None, "payload_median": None, "payload_variance": None, "payload_p95": None, "payload_zero_ratio": None, "iat_mean": None, "iat_median": None, "iat_variance": None, "iat_p95": None, "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0, "psh_count": 0, "urg_count": 0, "fragment_count": 0, "fragment_ratio": 0.0, "tcp_count": 0, "udp_count": 0, "icmp_count": 0, "unique_src_ips": 0, "unique_dst_ips": 0, "unique_dst_ports": 0, "protocol_counts": {}}

    is_rec = isinstance(records[0], PacketRecord)

    ttl_values: list[float] = []
    packet_sizes: list[float] = []
    payload_values: list[float] = []
    tcp_window_values: list[float] = []
    raw_timestamps: list[float] = []

    protocol_counts: dict[str, int] = {}
    unique_src_ips: set[str] = set()
    unique_dst_ips: set[str] = set()
    unique_dst_ports: set[int] = set()

    syn_count = ack_count = fin_count = rst_count = psh_count = urg_count = cwr_count = ece_count = 0
    syn_attempts = 0
    responses = 0
    tcp_window_zero_count = 0
    fragment_count = 0
    tcp_payloads: list[float] = []
    tcp_with_payload = 0

    if is_rec:
        for record in records:
            if record.ttl is not None:
                ttl_values.append(float(record.ttl))
            if record.packet_length is not None:
                packet_sizes.append(float(record.packet_length))
            if record.payload_length is not None:
                payload_values.append(float(record.payload_length))
            if record.tcp_window is not None:
                tcp_window_values.append(float(record.tcp_window))
            raw_timestamps.append(float(record.timestamp))

            proto = record.protocol
            if proto is not None:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            if record.src_ip is not None:
                unique_src_ips.add(record.src_ip)
            if record.dst_ip is not None:
                unique_dst_ips.add(record.dst_ip)
            if record.dst_port is not None:
                unique_dst_ports.add(record.dst_port)

            value = int(record.tcp_flags or 0)
            if value:
                if value & 0x02:
                    syn_count += 1
                    if not (value & 0x10):
                        syn_attempts += 1
                if value & 0x10: ack_count += 1
                if value & 0x01: fin_count += 1
                if value & 0x04: rst_count += 1
                if value & 0x08: psh_count += 1
                if value & 0x20: urg_count += 1
                if value & 0x80: cwr_count += 1
                if value & 0x40: ece_count += 1
                if value & 0x12: responses += 1

            if proto == "TCP" and record.tcp_window is not None and int(record.tcp_window or 0) == 0:
                tcp_window_zero_count += 1

            if (record.fragment_offset is not None and int(record.fragment_offset or 0) > 0) or (record.more_fragments is True):
                fragment_count += 1

            if proto == "TCP" and record.payload_length is not None:
                pl = float(record.payload_length)
                tcp_payloads.append(pl)
                if pl > 0:
                    tcp_with_payload += 1
    else:
        for record in records:
            if record.get("ttl") is not None:
                ttl_values.append(float(record["ttl"]))
            if record.get("packet_length") is not None:
                packet_sizes.append(float(record["packet_length"]))
            if record.get("payload_length") is not None:
                payload_values.append(float(record["payload_length"]))
            if record.get("tcp_window") is not None:
                tcp_window_values.append(float(record["tcp_window"]))
            raw_timestamps.append(float(record["timestamp"]))

            proto = record.get("protocol")
            if proto is not None:
                protocol_counts[proto] = protocol_counts.get(proto, 0) + 1

            if record.get("src_ip") is not None:
                unique_src_ips.add(record["src_ip"])
            if record.get("dst_ip") is not None:
                unique_dst_ips.add(record["dst_ip"])
            if record.get("dst_port") is not None:
                unique_dst_ports.add(record["dst_port"])

            value = int(record.get("tcp_flags") or 0)
            if value:
                if value & 0x02:
                    syn_count += 1
                    if not (value & 0x10):
                        syn_attempts += 1
                if value & 0x10: ack_count += 1
                if value & 0x01: fin_count += 1
                if value & 0x04: rst_count += 1
                if value & 0x08: psh_count += 1
                if value & 0x20: urg_count += 1
                if value & 0x80: cwr_count += 1
                if value & 0x40: ece_count += 1
                if value & 0x12: responses += 1

            if proto == "TCP" and record.get("tcp_window") is not None and int(record.get("tcp_window") or 0) == 0:
                tcp_window_zero_count += 1

            if (record.get("fragment_offset") is not None and int(record.get("fragment_offset") or 0) > 0) or (record.get("more_fragments") is True):
                fragment_count += 1

            if proto == "TCP" and record.get("payload_length") is not None:
                pl = float(record["payload_length"])
                tcp_payloads.append(pl)
                if pl > 0:
                    tcp_with_payload += 1

    is_ts_sorted = True
    for idx in range(1, len(raw_timestamps)):
        if raw_timestamps[idx] < raw_timestamps[idx - 1]:
            is_ts_sorted = False
            break
    timestamps = raw_timestamps if is_ts_sorted else sorted(raw_timestamps)
    iats = [current - previous for current, previous in zip(timestamps[1:], timestamps)]

    def mean(values: list[float]) -> float | None:
        return sum(values) / len(values) if values else None

    def variance(values: list[float]) -> float | None:
        if not values:
            return None
        mu = sum(values) / len(values)
        return sum((value - mu) ** 2 for value in values) / len(values)

    packet_sizes.sort()
    payload_values.sort()
    iats.sort()

    fragment_ratio = fragment_count / len(records) if records else 0.0

    second_bins = Counter(int(ts) for ts in timestamps)
    packet_rate_peak = float(max(second_bins.values())) if second_bins else 0.0

    def skewness(values: list[float]) -> float:
        n = len(values)
        if n < 3:
            return 0.0
        mu = sum(values) / n
        m2 = sum((v - mu) ** 2 for v in values) / n
        if m2 < 1e-12:
            return 0.0
        m3 = sum((v - mu) ** 3 for v in values) / n
        std = math.sqrt(m2)
        factor = math.sqrt(n * (n - 1)) / (n - 2)
        return float(factor * (m3 / (std ** 3)))

    obs_duration = (timestamps[-1] - timestamps[0]) if (timestamps and timestamps[-1] > timestamps[0]) else 60.0
    payload_sum = sum(payload_values)
    payload_rate_bytes_sec = float(payload_sum / obs_duration) if payload_values and obs_duration > 0 else 0.0

    return {
        "packet_count": len(records),
        "ttl_mean": mean(ttl_values),
        "ttl_variance": variance(ttl_values),
        "ttl_min": min(ttl_values) if ttl_values else None,
        "ttl_max": max(ttl_values) if ttl_values else None,
        "tcp_window_mean": mean(tcp_window_values),
        "tcp_window_variance": variance(tcp_window_values),
        "tcp_window_min": min(tcp_window_values) if tcp_window_values else None,
        "tcp_window_max": max(tcp_window_values) if tcp_window_values else None,
        "packet_size_mean": mean(packet_sizes),
        "packet_size_median": _percentile_sorted(packet_sizes, 0.5),
        "packet_size_variance": variance(packet_sizes),
        "packet_size_min": packet_sizes[0] if packet_sizes else None,
        "packet_size_max": packet_sizes[-1] if packet_sizes else None,
        "packet_size_p95": _percentile_sorted(packet_sizes, 0.95),
        "payload_mean": mean(payload_values),
        "payload_median": _percentile_sorted(payload_values, 0.5),
        "payload_variance": variance(payload_values),
        "payload_p95": _percentile_sorted(payload_values, 0.95),
        "payload_zero_ratio": sum(1 for value in payload_values if value == 0) / len(payload_values) if payload_values else None,
        "iat_mean": mean(iats),
        "iat_median": _percentile_sorted(iats, 0.5),
        "iat_variance": variance(iats),
        "iat_min": iats[0] if iats else None,
        "iat_max": iats[-1] if iats else None,
        "iat_p95": _percentile_sorted(iats, 0.95),
        "syn_count": syn_count,
        "ack_count": ack_count,
        "fin_count": fin_count,
        "rst_count": rst_count,
        "psh_count": psh_count,
        "urg_count": urg_count,
        "cwr_count": cwr_count,
        "ece_count": ece_count,
        "fragment_count": fragment_count,
        "fragment_ratio": fragment_ratio,
        "tcp_count": protocol_counts.get("TCP", 0),
        "udp_count": protocol_counts.get("UDP", 0),
        "icmp_count": protocol_counts.get("ICMP", 0),
        "unique_src_ips": len(unique_src_ips),
        "unique_dst_ips": len(unique_dst_ips),
        "unique_dst_ports": len(unique_dst_ports),
        "tcp_retransmission_count": retransmission_count,
        "tcp_retransmission_rate": retransmission_count / max(tcp_with_payload, 1),
        "port_scan_score": (
            min(
                1.0,
                0.4 * min(len(unique_dst_ports) / 100.0, 1.0)
                + 0.3 * min(syn_attempts / 100.0, 1.0)
                + 0.2 * min(len(unique_dst_ips) / 25.0, 1.0)
                + 0.1 * (1.0 - min(responses / max(syn_attempts, 1), 1.0))
            )
            if (calculate_port_scan and records)
            else None
        ),
        "protocol_counts": dict(sorted(protocol_counts.items())),
        "packet_size_skewness": skewness(packet_sizes),
        "packet_rate_peak": packet_rate_peak,
        "tcp_window_zero_count": tcp_window_zero_count,
        "udp_packet_ratio": float(protocol_counts.get("UDP", 0) / len(records)) if records else 0.0,
        "icmp_packet_ratio": float(protocol_counts.get("ICMP", 0) / len(records)) if records else 0.0,
        "mean_tcp_payload_size": mean(tcp_payloads) if tcp_payloads else 0.0,
        "max_tcp_payload_size": float(max(tcp_payloads)) if tcp_payloads else 0.0,
        "payload_rate_bytes_sec": payload_rate_bytes_sec,
    }


def _detect_retransmission(record: dict[str, Any] | PacketRecord, sequence_ends: dict[tuple[Any, ...], int]) -> bool:
    if isinstance(record, PacketRecord):
        if record.protocol != "TCP" or not record.payload_length:
            return False
        key = (record.src_ip, record.src_port, record.dst_ip, record.dst_port)
        sequence = int(record.tcp_seq or 0)
        end = sequence + int(record.payload_length)
    else:
        if record.get("protocol") != "TCP" or not record.get("payload_length"):
            return False
        key = (record["src_ip"], record["src_port"], record["dst_ip"], record["dst_port"])
        sequence = int(record.get("tcp_seq") or 0)
        end = sequence + int(record["payload_length"])
    previous_end = sequence_ends.get(key)
    sequence_ends[key] = max(previous_end or end, end)
    return previous_end is not None and sequence < previous_end


def _port_scan_score(records: list[dict[str, Any]] | list[PacketRecord] | tuple[PacketRecord, ...]) -> float:
    if not records:
        return 0.0
    syn_attempts = 0
    responses = 0
    unique_ports: set[int] = set()
    unique_destinations: set[str] = set()
    if isinstance(records[0], PacketRecord):
        for r in records:
            flags = int(r.tcp_flags or 0)
            if (flags & 0x02) and not (flags & 0x10):
                syn_attempts += 1
            if flags & 0x12:
                responses += 1
            if r.dst_port is not None:
                unique_ports.add(r.dst_port)
            if r.dst_ip is not None:
                unique_destinations.add(r.dst_ip)
    else:
        for r in records:
            flags = int(r.get("tcp_flags") or 0)
            if (flags & 0x02) and not (flags & 0x10):
                syn_attempts += 1
            if flags & 0x12:
                responses += 1
            if r.get("dst_port") is not None:
                unique_ports.add(r["dst_port"])
            if r.get("dst_ip") is not None:
                unique_destinations.add(r["dst_ip"])
    return min(1.0, 0.4 * min(len(unique_ports) / 100.0, 1.0) + 0.3 * min(syn_attempts / 100.0, 1.0) + 0.2 * min(len(unique_destinations) / 25.0, 1.0) + 0.1 * (1.0 - min(responses / max(syn_attempts, 1), 1.0)))


class _WindowAccumulator:
    def __init__(self, sample_limit: int = 8192) -> None:
        self.sample_limit = sample_limit
        self.count = 0
        self.numeric: dict[str, list[float | None]] = {name: [0.0, 0.0, None, None, 0.0] for name in ("ttl", "tcp_window", "packet_size", "payload", "iat")}
        self.samples: dict[str, list[float]] = {name: [] for name in ("packet_size", "payload", "iat")}
        self.protocols = Counter()
        self.flags = Counter()
        self.src_ips: set[str] = set()
        self.dst_ips: set[str] = set()
        self.dst_ports: set[int] = set()
        self.fragment_count = 0
        self.last_timestamp: float | None = None
        self.retransmission_count = 0
        self.syn_attempts = 0
        self.responses = 0

    def _add_numeric(self, name: str, value: Any) -> None:
        number = _safe_float(value)
        if number is None:
            return
        state = self.numeric[name]
        state[0] = float(state[0]) + 1
        state[1] = float(state[1]) + number
        state[2] = number if state[2] is None else min(float(state[2]), number)
        state[3] = number if state[3] is None else max(float(state[3]), number)
        state[4] = float(state[4]) + number * number
        if name in self.samples:
            sample = self.samples[name]
            if len(sample) < self.sample_limit:
                sample.append(number)
            elif int(state[0]) % self.sample_limit == 0:
                sample[int(state[0]) // self.sample_limit % self.sample_limit] = number

    def update(self, record: dict[str, Any], retransmitted: bool = False) -> None:
        self.count += 1
        for name, field in (("ttl", "ttl"), ("tcp_window", "tcp_window"), ("packet_size", "packet_length"), ("payload", "payload_length")):
            self._add_numeric(name, record.get(field))
        timestamp = _safe_float(record.get("timestamp"))
        if timestamp is not None and self.last_timestamp is not None:
            self._add_numeric("iat", timestamp - self.last_timestamp)
        self.last_timestamp = timestamp
        protocol = record.get("protocol")
        self.protocols[protocol] += 1
        self.src_ips.add(record["src_ip"]) if record.get("src_ip") is not None else None
        self.dst_ips.add(record["dst_ip"]) if record.get("dst_ip") is not None else None
        self.dst_ports.add(record["dst_port"]) if record.get("dst_port") is not None else None
        value = int(record.get("tcp_flags") or 0)
        for name, mask in (("syn_count", 2), ("ack_count", 16), ("fin_count", 1), ("rst_count", 4), ("psh_count", 8), ("urg_count", 32)):
            self.flags[name] += bool(value & mask)
        self.syn_attempts += bool(value & 2 and not value & 16)
        self.responses += bool(value & 18)
        self.fragment_count += bool(record.get("fragment_offset") or record.get("more_fragments"))
        self.retransmission_count += retransmitted

    def finalize(self, window_start: int, window_end: int) -> dict[str, Any]:
        result: dict[str, Any] = {"window_start": window_start, "window_end": window_end, "packet_count": self.count}
        for name, state in self.numeric.items():
            count, total, minimum, maximum, sum_squares = state
            result[f"{name}_mean"] = total / count if count else None
            result[f"{name}_variance"] = sum_squares / count - (total / count) ** 2 if count else None
            result[f"{name}_min"] = minimum
            result[f"{name}_max"] = maximum
        for name in ("packet_size", "payload", "iat"):
            result[f"{name}_median"] = _percentile(self.samples[name], 0.5)
            result[f"{name}_p95"] = _percentile(self.samples[name], 0.95)
        result["payload_zero_ratio"] = sum(value == 0 for value in self.samples["payload"]) / len(self.samples["payload"]) if self.samples["payload"] else None
        result.update(self.flags)
        result.update({"fragment_count": self.fragment_count, "fragment_ratio": self.fragment_count / self.count if self.count else 0.0, "tcp_count": self.protocols["TCP"], "udp_count": self.protocols["UDP"], "icmp_count": self.protocols["ICMP"], "unique_src_ips": len(self.src_ips), "unique_dst_ips": len(self.dst_ips), "unique_dst_ports": len(self.dst_ports), "tcp_retransmission_count": self.retransmission_count, "tcp_retransmission_rate": self.retransmission_count / max(self.protocols["TCP"], 1), "port_scan_score": min(1.0, 0.4 * min(len(self.dst_ports) / 100.0, 1.0) + 0.3 * min(self.syn_attempts / 100.0, 1.0) + 0.2 * min(len(self.dst_ips) / 25.0, 1.0) + 0.1 * (1.0 - min(self.responses / max(self.syn_attempts, 1), 1.0))), "protocol_counts": dict(sorted(self.protocols.items()))})
        return result


def extract_canonical_capture(
    pcap_path: str | Path,
    window_seconds: int = 60,
    max_packets: int | None = None,
) -> tuple[tuple[PacketRecord, ...], tuple[TemporalWindow, ...], dict[str, Any]]:
    capture_path = Path(pcap_path)
    capture_id = capture_path.name
    packets: list[PacketRecord] = []
    malformed = 0
    unsupported = 0
    truncated = 0
    truncation_unknown = 0
    timestamp_anomalies = 0
    timestamp_equal = 0
    invalid_timestamp = 0
    duplicate_count = 0
    fingerprints: set[tuple[Any, ...]] = set()
    first_fingerprint_index: dict[tuple[Any, ...], int] = {}
    previous_timestamp: float | None = None
    fast_decoder_succeeded = False
    try:
        if capture_path.is_file() and capture_path.stat().st_size >= 24:
            import mmap

            with open(capture_path, "rb") as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    decoder = FastPcapDecoder(mm, capture_id=capture_id)
                    if decoder.valid and not decoder.fallback_needed:
                        packet_index = 0
                        for record in decoder.decode_packets(max_packets=max_packets):
                            if record is None:
                                invalid_timestamp += 1
                                malformed += 1
                                packet_index += 1
                                continue
                            if previous_timestamp is not None and record.timestamp < previous_timestamp:
                                timestamp_anomalies += 1
                            elif previous_timestamp is not None and record.timestamp == previous_timestamp:
                                timestamp_equal += 1
                            previous_timestamp = record.timestamp
                            fingerprint = (record.timestamp, record.src_ip, record.dst_ip, record.protocol, record.src_port, record.dst_port, record.packet_length, record.tcp_seq)
                            if fingerprint in fingerprints:
                                duplicate_count += 1
                                record = replace(record, duplicate_of_index=first_fingerprint_index[fingerprint], parsing_status="duplicate")
                            else:
                                first_fingerprint_index[fingerprint] = packet_index
                            fingerprints.add(fingerprint)
                            if record.parsing_status == "unsupported" or record.unsupported_reason is not None:
                                unsupported += 1
                            if record.truncation_status == "TRUE":
                                truncated += 1
                            elif record.truncation_status == "UNKNOWN":
                                truncation_unknown += 1
                            packets.append(record)
                            packet_index += 1
                        fast_decoder_succeeded = True
    except Exception:
        fast_decoder_succeeded = False
        packets.clear()
        fingerprints.clear()
        first_fingerprint_index.clear()
        malformed = unsupported = truncated = truncation_unknown = timestamp_anomalies = timestamp_equal = invalid_timestamp = duplicate_count = 0
        previous_timestamp = None

    if not fast_decoder_succeeded:
        if not capture_path.is_file() or capture_path.stat().st_size < 24:
            malformed += 1
        else:
            reader = None
            try:
                reader = PcapNgReader(str(capture_path))
                for packet_index, pkt in enumerate(reader):
                    if max_packets is not None and packet_index >= max_packets:
                        break
                    try:
                        record = packet_record_from_pkt(pkt, packet_index=packet_index, capture_id=capture_id)
                    except Exception:
                        malformed += 1
                        continue
                    if record is None:
                        invalid_timestamp += 1
                        malformed += 1
                        continue
                    if previous_timestamp is not None and record.timestamp < previous_timestamp:
                        timestamp_anomalies += 1
                    elif previous_timestamp is not None and record.timestamp == previous_timestamp:
                        timestamp_equal += 1
                    previous_timestamp = record.timestamp
                    fingerprint = (record.timestamp, record.src_ip, record.dst_ip, record.protocol, record.src_port, record.dst_port, record.packet_length, record.tcp_seq)
                    if fingerprint in fingerprints:
                        duplicate_count += 1
                        record = replace(record, duplicate_of_index=first_fingerprint_index[fingerprint], parsing_status="duplicate")
                    else:
                        first_fingerprint_index[fingerprint] = packet_index
                    fingerprints.add(fingerprint)
                    if record.parsing_status == "unsupported" or record.unsupported_reason is not None:
                        unsupported += 1
                    if record.truncation_status == "TRUE":
                        truncated += 1
                    elif record.truncation_status == "UNKNOWN":
                        truncation_unknown += 1
                    packets.append(record)
            except Exception:
                malformed += 1
            finally:
                if reader is not None:
                    try:
                        reader.close()
                    except Exception:
                        pass
                import gc
                gc.collect()

    retransmission_packet_indexes: set[int] = set()
    sequence_ends: dict[tuple[Any, ...], int] = {}
    retransmissions_by_window: Counter[int] = Counter()
    ttl_available = 0
    tcp_win_available = 0
    payload_available = 0
    timestamps_reordered = False
    prev_ts: float | None = None

    for packet in packets:
        if _detect_retransmission(packet, sequence_ends) and packet.packet_index is not None:
            retransmission_packet_indexes.add(packet.packet_index)
            retransmissions_by_window[_window_bucket(packet.timestamp, window_seconds)] += 1
        if packet.ttl is not None:
            ttl_available += 1
        if packet.tcp_window is not None:
            tcp_win_available += 1
        if packet.payload_length is not None:
            payload_available += 1
        if prev_ts is not None and packet.timestamp < prev_ts:
            timestamps_reordered = True
        prev_ts = packet.timestamp

    flows = list(build_flows(packets, capture_id, retransmission_packet_indexes=retransmission_packet_indexes))
    incomplete_flow_count = sum(flow.protocol == "TCP" and flow.completeness != "COMPLETE" for flow in flows)
    quality = make_capture_quality(
        packets,
        total_packets_observed=len(packets) + malformed,
        malformed_packets=malformed,
        unsupported_packets=unsupported,
        truncated_packets=truncated,
        truncation_unknown_count=truncation_unknown,
        timestamp_anomalies=timestamp_anomalies,
        timestamp_equal_count=timestamp_equal,
        invalid_timestamp_count=invalid_timestamp,
        duplicate_packets=duplicate_count,
        timestamps_reordered=timestamps_reordered,
        original_order_preserved=not timestamps_reordered,
        incomplete_flow_count=incomplete_flow_count,
        capture_id=capture_id,
    )
    windows = list(build_temporal_windows(packets, flows, quality, window_seconds=window_seconds))
    enriched: list[TemporalWindow] = []
    for window in windows:
        bucket = window.start_timestamp // window_seconds
        retrans_count = retransmissions_by_window[bucket]
        features = compute_packet_window_stats(window.packets, retrans_count, calculate_port_scan=True)
        enriched.append(replace(window, aggregate_features=features, detection_features={"retransmission_count": retrans_count}))
    legacy_quality = quality.to_dict()
    legacy_quality.update({
        "packets_read": quality.total_packets_observed,
        "packets_parsed": quality.parsed_packets,
        "packet_windows": len(enriched),
        "window_seconds": window_seconds,
        "extraction_errors": [],
        "ttl_available_packets": ttl_available,
        "tcp_window_available_packets": tcp_win_available,
        "payload_available_packets": payload_available,
        "fragmented_packets": quality.fragmented_packet_count,
        "truncated_packets": quality.truncated_packets,
        "truncation_unknown_count": quality.truncation_unknown_count,
        "timestamp_anomalies": quality.timestamp_anomalies,
        "timestamp_equal_count": quality.timestamp_equal_count,
        "timestamps_reordered": quality.timestamps_reordered,
        "original_order_preserved": quality.original_order_preserved,
        "duplicate_packets": quality.duplicate_packets,
        "duplicate_ratio": quality.duplicate_ratio,
        "ipv4": quality.ipv4_count,
        "ipv6": quality.ipv6_count,
        "tcp": quality.tcp_count,
        "udp": quality.udp_count,
        "icmp": quality.icmp_count,
        "arp": quality.arp_count,
        "vlan": quality.vlan_count,
        "status": quality.status.value,
    })
    return tuple(packets), tuple(enriched), legacy_quality


def extract_packet_windows(pcap_path: str | Path, window_seconds: int = 60, max_packets: int | None = None, checkpoint_path: str | Path | None = None, progress_interval: int = 100_000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    del checkpoint_path, progress_interval
    _packets, canonical_windows, quality = extract_canonical_capture(pcap_path, window_seconds, max_packets)
    return [window.to_dict() for window in canonical_windows], quality


def _write_parquet(rows: list[dict[str, Any]], path: Path) -> int:
    import pyarrow as pa
    import pyarrow.parquet as pq

    pq.write_table(pa.Table.from_pylist(rows), path, compression="zstd")
    return path.stat().st_size


def generate_packet_reports(pcap_path: str | Path, report_dir: str | Path | None = None, output_path: str | Path = "data/processed/cic_ids2017_packet_windows.parquet", max_packets: int | None = None) -> dict[str, Any]:
    pcap_path = Path(pcap_path)
    report_dir = Path(report_dir) if report_dir is not None else Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_path = report_dir / "cic_packet_features.checkpoint.json"

    start = time.perf_counter()
    tracemalloc.start()
    rows, quality = extract_packet_windows(pcap_path, max_packets=max_packets, checkpoint_path=checkpoint_path)
    if not rows:
        raise RuntimeError("extraction produced zero packet windows")
    temporary_output = output_path.with_suffix(output_path.suffix + ".tmp")
    output_file_size = _write_parquet(rows, temporary_output)
    os.replace(temporary_output, output_path)
    elapsed = time.perf_counter() - start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    packet_count = sum(int(row["packet_count"]) for row in rows)
    tcp = sum(int(row["tcp_count"]) for row in rows)
    udp = sum(int(row["udp_count"]) for row in rows)
    icmp = sum(int(row["icmp_count"]) for row in rows)
    fragmented_packets = sum(int(row["fragment_count"]) for row in rows)

    summary = {
        "pcap_path": str(pcap_path),
        "pcap_size_bytes": pcap_path.stat().st_size,
        "sha256": "beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0",
        "packets_read": quality["packets_read"],
        "packets_parsed": quality["packets_parsed"],
        "malformed_packets": quality["malformed_packets"],
        "extraction_errors": quality["extraction_errors"],
        "processing_time_seconds": round(elapsed, 6),
        "packets_per_second": round(quality["packets_parsed"] / elapsed, 2) if elapsed > 0 else 0.0,
        "peak_memory_bytes": peak,
        "packet_features_extracted": [key for key in rows[0] if key not in {"window_start", "window_end", "packet_count"}] if rows else [],
        "packet_windows": quality["packet_windows"],
        "ipv4": quality["ipv4"],
        "ipv6": quality["ipv6"],
        "output_path": str(output_path),
        "output_file_size_bytes": output_file_size,
        "packet_count": packet_count,
        "tcp": quality["tcp"],
        "udp": quality["udp"],
        "icmp": quality["icmp"],
        "ttl_available_packets": quality["ttl_available_packets"],
        "tcp_window_available_packets": quality["tcp_window_available_packets"],
        "payload_available_packets": quality["payload_available_packets"],
        "fragmented_packets": quality["fragmented_packets"],
        "retransmission_status": "AVAILABLE",
        "port_scan_status": "AVAILABLE_TRAFFIC_DERIVED",
        "timestamp_window_unit": "UTC epoch seconds; window_start is floor(timestamp / 60) * 60",
    }

    packet_md = "# CIC Packet Features\n\n" + "\n".join(f"- {key}: {value}" for key, value in summary.items() if key != "packet_window_rows") + "\n\nPort-scan score formula: 0.4*min(unique destination ports/100, 1) + 0.3*min(SYN attempts/100, 1) + 0.2*min(unique destinations/25, 1) + 0.1*(1 - min(response packets/SYN attempts, 1)). Scores use traffic observations only; labels and filenames are not used.\n"

    (report_dir / "cic_packet_features.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    (report_dir / "cic_packet_features.md").write_text(packet_md, encoding="utf-8")

    provenance_path = Path("ml/data/feature_provenance.json")
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    provenance["status"] = "PACKET_WINDOWS_EXTRACTED_NOT_PROMOTED"
    provenance["packet_extraction_run"] = {"output_path": str(output_path), "packet_windows": summary["packet_windows"], "feature_count": len(summary["packet_features_extracted"]), "status": "COMPLETE"}
    provenance_path.write_text(json.dumps(provenance, indent=2), encoding="utf-8")
    checkpoint_path.write_text(json.dumps({**summary, "status": "COMPLETE"}, indent=2), encoding="utf-8")
    return summary


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stream real PCAP packets into deterministic 60-second Parquet windows.")
    parser.add_argument("--pcap", default=r"C:\Users\saira\Downloads\Friday-WorkingHours.pcap")
    parser.add_argument("--output", default="data/processed/cic_ids2017_packet_windows.parquet")
    parser.add_argument("--reports", default="reports")
    parser.add_argument("--max-packets", type=int, default=None)
    args = parser.parse_args()
    result = generate_packet_reports(args.pcap, Path(args.reports), args.output, args.max_packets)
    print(json.dumps({
        "packets_read": result["packets_read"],
        "packets_parsed": result["packets_parsed"],
        "malformed_packets": result["malformed_packets"],
        "processing_time_seconds": result["processing_time_seconds"],
        "packets_per_second": result["packets_per_second"],
        "peak_memory_bytes": result["peak_memory_bytes"],
        "packet_features_extracted": result["packet_features_extracted"],
        "packet_windows": result["packet_windows"],
        "retransmission_status": result["retransmission_status"],
    }, indent=2))
