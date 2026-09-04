from __future__ import annotations

import json
import math
import argparse
import os
import time
import tracemalloc
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from scapy.all import ICMP, IP, IPv6, PcapNgReader, TCP, UDP


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


def packet_record_from_pkt(pkt: Any) -> dict[str, Any] | None:
    timestamp = _safe_float(getattr(pkt, "time", None))
    if timestamp is None:
        return None
    if IP in pkt:
        ip_layer = pkt[IP]
        src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)
        ttl = getattr(ip_layer, "ttl", None)
        ip_version = 4
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP" if pkt.haslayer(ICMP) else str(ip_layer.proto)
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        src_ip, dst_ip = str(ip_layer.src), str(ip_layer.dst)
        ttl = getattr(ip_layer, "hlim", None)
        ip_version = 6
        protocol = "TCP" if pkt.haslayer(TCP) else "UDP" if pkt.haslayer(UDP) else "ICMP" if pkt.haslayer(ICMP) else "IPv6"
    else:
        src_ip, dst_ip, ttl, ip_version = None, None, None, None
        protocol = "other"

    payload_length = None
    src_port = dst_port = None
    tcp_flags = tcp_window = tcp_seq = tcp_ack = None
    fragment_offset = None
    more_fragments = None
    identification = None

    if pkt.haslayer(TCP):
        tcp_layer = pkt[TCP]
        src_port = int(getattr(tcp_layer, "sport", 0) or 0)
        dst_port = int(getattr(tcp_layer, "dport", 0) or 0)
        tcp_flags = int(getattr(tcp_layer, "flags", 0) or 0)
        tcp_window = int(getattr(tcp_layer, "window", 0) or 0)
        tcp_seq = int(getattr(tcp_layer, "seq", 0) or 0)
        tcp_ack = int(getattr(tcp_layer, "ack", 0) or 0)
        payload_length = len(bytes(tcp_layer.payload))
    elif pkt.haslayer(UDP):
        udp_layer = pkt[UDP]
        src_port = int(getattr(udp_layer, "sport", 0) or 0)
        dst_port = int(getattr(udp_layer, "dport", 0) or 0)
        payload_length = len(bytes(udp_layer.payload))
    elif pkt.haslayer(ICMP):
        payload_length = len(bytes(pkt[ICMP].payload))

    if IP in pkt:
        ipv4 = pkt[IP]
        fragment_offset = int(getattr(ipv4, "frag", 0) or 0)
        more_fragments = bool(getattr(ipv4, "flags", 0) & 0x1) if hasattr(ipv4, "flags") else None
        identification = int(getattr(ipv4, "id", 0) or 0)
    elif IPv6 in pkt:
        fragment_offset = getattr(pkt[IPv6], "frag", None)
        more_fragments = None
        identification = None

    packet_length = len(bytes(pkt))
    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_length": packet_length,
        "payload_length": payload_length,
        "ttl": int(ttl) if ttl is not None else None,
        "ip_version": ip_version,
        "tcp_flags": tcp_flags,
        "tcp_window": tcp_window,
        "tcp_seq": tcp_seq,
        "tcp_ack": tcp_ack,
        "fragment_offset": fragment_offset,
        "more_fragments": more_fragments,
        "identification": identification,
    }


def iter_streaming_packets(path: str | Path) -> Iterator[dict[str, Any]]:
    pcap_path = Path(path)
    reader = PcapNgReader(str(pcap_path))
    try:
        for pkt in reader:
            record = packet_record_from_pkt(pkt)
            if record is not None:
                yield record
    finally:
        reader.close()


def _window_bucket(ts: float, window_seconds: int = 60) -> int:
    return int(float(ts) // window_seconds)


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower, upper = int(math.floor(position)), int(math.ceil(position))
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def compute_packet_window_stats(records: list[dict[str, Any]], retransmission_count: int = 0) -> dict[str, Any]:
    if not records:
        return {"packet_count": 0, "ttl_mean": None, "ttl_variance": None, "ttl_min": None, "ttl_max": None, "tcp_window_mean": None, "tcp_window_variance": None, "tcp_window_min": None, "tcp_window_max": None, "packet_size_mean": None, "packet_size_median": None, "packet_size_variance": None, "packet_size_p95": None, "payload_mean": None, "payload_median": None, "payload_variance": None, "payload_p95": None, "payload_zero_ratio": None, "iat_mean": None, "iat_median": None, "iat_variance": None, "iat_p95": None, "syn_count": 0, "ack_count": 0, "fin_count": 0, "rst_count": 0, "psh_count": 0, "urg_count": 0, "fragment_count": 0, "fragment_ratio": 0.0, "tcp_count": 0, "udp_count": 0, "icmp_count": 0, "unique_src_ips": 0, "unique_dst_ips": 0, "unique_dst_ports": 0, "protocol_counts": {}}

    ttl_values = [float(record["ttl"]) for record in records if record.get("ttl") is not None]
    packet_sizes = [float(record["packet_length"]) for record in records if record.get("packet_length") is not None]
    payload_values = [float(record["payload_length"]) for record in records if record.get("payload_length") is not None]
    tcp_window_values = [float(record["tcp_window"]) for record in records if record.get("tcp_window") is not None]
    timestamps = sorted(float(record["timestamp"]) for record in records)
    iats = []
    for current, previous in zip(timestamps[1:], timestamps):
        iats.append(current - previous)

    def mean(values: list[float]) -> float | None:
        return sum(values) / len(values) if values else None

    def variance(values: list[float]) -> float | None:
        if not values:
            return None
        mu = mean(values)
        return sum((value - mu) ** 2 for value in values) / len(values) if mu is not None else None

    def percentile(values: list[float], quantile: float) -> float | None:
        if not values:
            return None
        ordered = sorted(values)
        if len(ordered) == 1:
            return float(ordered[0])
        p = (len(ordered) - 1) * quantile
        lower = int(math.floor(p))
        upper = int(math.ceil(p))
        if lower == upper:
            return float(ordered[lower])
        fraction = p - lower
        return float(ordered[lower] + (ordered[upper] - ordered[lower]) * fraction)

    protocol_counts = Counter(record.get("protocol") for record in records if record.get("protocol") is not None)
    flags = Counter()
    for record in records:
        value = int(record.get("tcp_flags") or 0)
        if value & 0x02:
            flags["syn_count"] += 1
        if value & 0x10:
            flags["ack_count"] += 1
        if value & 0x01:
            flags["fin_count"] += 1
        if value & 0x04:
            flags["rst_count"] += 1
        if value & 0x08:
            flags["psh_count"] += 1
        if value & 0x20:
            flags["urg_count"] += 1

    fragment_count = sum(1 for record in records if (record.get("fragment_offset") is not None and int(record.get("fragment_offset") or 0) > 0) or (record.get("more_fragments") is True))
    fragment_ratio = fragment_count / len(records) if records else 0.0

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
        "packet_size_median": percentile(packet_sizes, 0.5),
        "packet_size_variance": variance(packet_sizes),
        "packet_size_p95": percentile(packet_sizes, 0.95),
        "payload_mean": mean(payload_values),
        "payload_median": percentile(payload_values, 0.5),
        "payload_variance": variance(payload_values),
        "payload_p95": percentile(payload_values, 0.95),
        "payload_zero_ratio": sum(1 for value in payload_values if value == 0) / len(payload_values) if payload_values else None,
        "iat_mean": mean(iats),
        "iat_median": percentile(iats, 0.5),
        "iat_variance": variance(iats),
        "iat_p95": percentile(iats, 0.95),
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
        "unique_src_ips": len({record["src_ip"] for record in records if record.get("src_ip") is not None}),
        "unique_dst_ips": len({record["dst_ip"] for record in records if record.get("dst_ip") is not None}),
        "unique_dst_ports": len({record["dst_port"] for record in records if record.get("dst_port") is not None}),
        "tcp_retransmission_count": retransmission_count,
        "tcp_retransmission_rate": retransmission_count / max(sum(record.get("protocol") == "TCP" and record.get("payload_length") is not None and record.get("payload_length") > 0 for record in records), 1),
        "port_scan_score": None,
        "protocol_counts": dict(sorted(protocol_counts.items())),
    }


def _detect_retransmission(record: dict[str, Any], sequence_ends: dict[tuple[Any, ...], int]) -> bool:
    if record.get("protocol") != "TCP" or not record.get("payload_length"):
        return False
    key = (record["src_ip"], record["src_port"], record["dst_ip"], record["dst_port"])
    sequence = int(record.get("tcp_seq") or 0)
    end = sequence + int(record["payload_length"])
    previous_end = sequence_ends.get(key)
    sequence_ends[key] = max(previous_end or end, end)
    return previous_end is not None and sequence < previous_end


def _port_scan_score(records: list[dict[str, Any]]) -> float:
    syn_attempts = sum(bool((r.get("tcp_flags") or 0) & 0x02 and not (r.get("tcp_flags") or 0) & 0x10) for r in records)
    responses = sum(bool((r.get("tcp_flags") or 0) & 0x12) for r in records)
    unique_ports = len({r["dst_port"] for r in records if r.get("dst_port") is not None})
    unique_destinations = len({r["dst_ip"] for r in records if r.get("dst_ip") is not None})
    return min(1.0, 0.4 * min(unique_ports / 100.0, 1.0) + 0.3 * min(syn_attempts / 100.0, 1.0) + 0.2 * min(unique_destinations / 25.0, 1.0) + 0.1 * (1.0 - min(responses / max(syn_attempts, 1), 1.0)))


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


def extract_packet_windows(pcap_path: str | Path, window_seconds: int = 60, max_packets: int | None = None, checkpoint_path: str | Path | None = None, progress_interval: int = 100_000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    buckets: dict[int, _WindowAccumulator] = {}
    finalized: list[dict[str, Any]] = []
    retransmissions: defaultdict[int, int] = defaultdict(int)
    sequence_ends: dict[tuple[Any, ...], int] = {}
    quality: dict[str, Any] = {"packets_read": 0, "packets_parsed": 0, "malformed_packets": 0, "extraction_errors": [], "ttl_available_packets": 0, "tcp_window_available_packets": 0, "payload_available_packets": 0, "fragmented_packets": 0, "ipv4": 0, "ipv6": 0, "tcp": 0, "udp": 0, "icmp": 0}
    previous_bucket: int | None = None
    reader = PcapNgReader(str(pcap_path))
    try:
        for pkt in reader:
            if max_packets is not None and quality["packets_read"] >= max_packets:
                break
            quality["packets_read"] += 1
            try:
                record = packet_record_from_pkt(pkt)
            except Exception as exc:
                quality["malformed_packets"] += 1
                quality["extraction_errors"].append(type(exc).__name__)
                continue
            if record is None:
                quality["malformed_packets"] += 1
                continue
            quality["packets_parsed"] += 1
            quality["ipv4"] += record.get("ip_version") == 4
            quality["ipv6"] += record.get("ip_version") == 6
            quality[record["protocol"].lower()] = quality.get(record["protocol"].lower(), 0) + 1
            quality["ttl_available_packets"] += record["ttl"] is not None
            quality["tcp_window_available_packets"] += record["tcp_window"] is not None
            quality["payload_available_packets"] += record["payload_length"] is not None
            quality["fragmented_packets"] += bool(record["fragment_offset"] or record["more_fragments"])
            bucket = _window_bucket(float(record["timestamp"]), window_seconds)
            if previous_bucket is not None and bucket != previous_bucket:
                finalized.append(buckets.pop(previous_bucket).finalize(previous_bucket * window_seconds, (previous_bucket + 1) * window_seconds))
            retransmitted = _detect_retransmission(record, sequence_ends)
            buckets.setdefault(bucket, _WindowAccumulator()).update(record, retransmitted)
            if retransmitted:
                retransmissions[bucket] += 1
            previous_bucket = bucket
            if checkpoint_path is not None and quality["packets_read"] % progress_interval == 0:
                checkpoint = {**quality, "status": "RUNNING", "packet_windows_finalized": len(finalized), "input_path": str(pcap_path)}
                Path(checkpoint_path).write_text(json.dumps(checkpoint, indent=2), encoding="utf-8")
                print(f"progress packets_read={quality['packets_read']} packets_parsed={quality['packets_parsed']} windows={len(finalized)}", flush=True)
    finally:
        reader.close()
    for bucket, records in sorted(buckets.items()):
        finalized.append(records.finalize(bucket * window_seconds, (bucket + 1) * window_seconds))
    quality["packet_windows"] = len(finalized)
    quality["window_seconds"] = window_seconds
    quality["status"] = "COMPLETE"
    return finalized, quality


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
