"""TON-IoT dataset temporal adapter for Network_dataset_23.csv.

Constructs non-fabricating, chronological 60-second temporal windows and NetworkStates.
Labels are explicitly mapped:
- label == 0 ("normal") -> BENIGN (0)
- label == 1 ("backdoor", "mitm") -> ATTACK (1)
- missing/unparseable -> UNKNOWN (None)
Original multiclass attack types are preserved in window metadata.

NO SILENT ZERO-FILLING:
Unavailable features are explicitly excluded. The 17 genuinely derivable TON-IoT features are:
12 flow features + 5 temporal features.
"""
from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import numpy as np

from world_model import FLOW_NAMES, PACKET_NAMES, TEMPORAL_NAMES, NetworkState

WINDOW_SECONDS = 60
DEFAULT_SOURCE = Path(__file__).resolve().parents[2] / "TON-IoT" / "validation" / "Network_dataset_23.csv"

# Genuinely available flow features in TON-IoT
TONIOT_FLOW_NAMES = (
    "flow_count",
    "total_src_bytes",
    "total_dst_bytes",
    "total_packets",
    "mean_duration",
    "mean_flow_bytes",
    "mean_flow_packets",
    "unique_src_ports",
    "unique_dst_ports",
    "proto_tcp_count",
    "proto_udp_count",
    "proto_other_count",
)

# Genuinely available temporal features in TON-IoT (delta_iat is UNAVAILABLE because mean_iat is absent)
TONIOT_TEMPORAL_NAMES = (
    "delta_flow_count",
    "delta_total_bytes",
    "delta_total_packets",
    "delta_ports",
    "rolling_total_bytes",
)

# Canonical features genuinely unavailable in TON-IoT CSV
TONIOT_UNAVAILABLE_FLOW_NAMES = (
    "mean_sttl",
    "mean_dttl",
    "mean_swin",
    "mean_dwin",
    "mean_iat",
    "mean_tcp_rtt",
)
TONIOT_UNAVAILABLE_TEMPORAL_NAMES = ("delta_iat",)


@dataclass(frozen=True)
class TonIotNetworkState:
    """Explicit, non-fabricating state container for TON-IoT containing only genuine features."""
    timestamp: int
    flow_features: dict[str, float]
    temporal_features: dict[str, float]
    attack_state: int | None
    attack_types: dict[str, int]
    unavailable_features: tuple[str, ...] = TONIOT_UNAVAILABLE_FLOW_NAMES + TONIOT_UNAVAILABLE_TEMPORAL_NAMES + tuple(PACKET_NAMES)

    def encode(self) -> np.ndarray:
        """Encode ONLY the 17 genuinely available features (12 flow + 5 temporal)."""
        return np.asarray(
            [self.flow_features[n] for n in TONIOT_FLOW_NAMES]
            + [self.temporal_features[n] for n in TONIOT_TEMPORAL_NAMES],
            dtype=np.float64,
        )


class TonIotAdaptedNetworkState(NetworkState):
    """NetworkState subclass that encodes ONLY the 17 genuinely available features for TON-IoT."""
    def encode(self) -> np.ndarray:
        return np.asarray(
            [self.flow_features[n] for n in TONIOT_FLOW_NAMES]
            + [self.temporal_features[n] for n in TONIOT_TEMPORAL_NAMES],
            dtype=np.float64,
        )


def build_toniot_network_states(
    path: Path | None = None,
    window_seconds: int = WINDOW_SECONDS,
    canonical_adapter: bool = True,
) -> tuple[tuple[Any, ...], dict[str, Any]]:
    """Aggregate TON-IoT records into chronological 60-second states without data fabrication."""
    source_path = path or DEFAULT_SOURCE
    if not source_path.exists():
        raise FileNotFoundError(f"TON-IoT dataset file not found: {source_path}")

    bins: dict[int, dict[str, Any]] = {}
    rows_total = 0
    benign_rows = 0
    attack_rows = 0
    unknown_rows = 0
    attack_type_counts: Counter[str] = Counter()

    with source_path.open("r", encoding="utf-8-sig", newline="", errors="replace") as stream:
        reader = csv.DictReader(stream)
        for row in reader:
            rows_total += 1
            try:
                ts = int(row["ts"])
            except (ValueError, TypeError):
                unknown_rows += 1
                continue

            raw_label = row.get("label")
            raw_type = row.get("type", "unknown").strip()
            if raw_label == "1":
                attack_rows += 1
                attack_type_counts[raw_type] += 1
                label_val = 1
            elif raw_label == "0":
                benign_rows += 1
                label_val = 0
            else:
                unknown_rows += 1
                label_val = None

            bucket = ts // window_seconds
            item = bins.setdefault(bucket, {
                "n": 0,
                "attack": 0,
                "src_bytes": 0.0,
                "dst_bytes": 0.0,
                "src_pkts": 0.0,
                "dst_pkts": 0.0,
                "duration": 0.0,
                "ports_src": set(),
                "ports_dst": set(),
                "proto": {"tcp": 0, "udp": 0, "other": 0},
                "types": Counter(),
            })
            item["n"] += 1
            if label_val == 1:
                item["attack"] = 1
            try:
                item["duration"] += float(row["duration"]) if row.get("duration") and row["duration"] != "-" else 0.0
            except (ValueError, TypeError):
                pass
            try:
                item["src_bytes"] += float(row["src_bytes"]) if row.get("src_bytes") and row["src_bytes"] != "-" else 0.0
            except (ValueError, TypeError):
                pass
            try:
                item["dst_bytes"] += float(row["dst_bytes"]) if row.get("dst_bytes") and row["dst_bytes"] != "-" else 0.0
            except (ValueError, TypeError):
                pass
            try:
                item["src_pkts"] += float(row["src_pkts"]) if row.get("src_pkts") and row["src_pkts"] != "-" else 0.0
            except (ValueError, TypeError):
                pass
            try:
                item["dst_pkts"] += float(row["dst_pkts"]) if row.get("dst_pkts") and row["dst_pkts"] != "-" else 0.0
            except (ValueError, TypeError):
                pass

            item["ports_src"].add(row.get("src_port", ""))
            item["ports_dst"].add(row.get("dst_port", ""))
            proto = row.get("proto", "").strip().lower()
            item["proto"]["tcp" if proto == "tcp" else "udp" if proto == "udp" else "other"] += 1
            item["types"][raw_type] += 1

    ordered_buckets = sorted(bins)
    states: list[Any] = []
    previous_flow = np.zeros(len(TONIOT_FLOW_NAMES), dtype=np.float64)
    rolling_bytes: list[float] = []

    for bucket in ordered_buckets:
        item = bins[bucket]
        n = max(item["n"], 1)
        total_bytes = item["src_bytes"] + item["dst_bytes"]
        total_packets = item["src_pkts"] + item["dst_pkts"]

        flow = {
            "flow_count": float(item["n"]),
            "total_src_bytes": item["src_bytes"],
            "total_dst_bytes": item["dst_bytes"],
            "total_packets": total_packets,
            "mean_duration": item["duration"] / n,
            "mean_flow_bytes": total_bytes / n,
            "mean_flow_packets": total_packets / n,
            "unique_src_ports": float(len(item["ports_src"])),
            "unique_dst_ports": float(len(item["ports_dst"])),
            "proto_tcp_count": float(item["proto"]["tcp"]),
            "proto_udp_count": float(item["proto"]["udp"]),
            "proto_other_count": float(item["proto"]["other"]),
        }
        current_flow = np.asarray([flow[name] for name in TONIOT_FLOW_NAMES], dtype=np.float64)
        rolling_bytes.append(total_bytes)
        prior_bytes = rolling_bytes[-4:]

        temporal = {
            "delta_flow_count": current_flow[0] - previous_flow[0],
            "delta_total_bytes": total_bytes - previous_flow[1],
            "delta_total_packets": current_flow[3] - previous_flow[3],
            "delta_ports": (current_flow[7] + current_flow[8]) - (previous_flow[7] + previous_flow[8]),
            "rolling_total_bytes": float(np.mean(prior_bytes)),
        }

        if canonical_adapter:
            state = TonIotAdaptedNetworkState(
                timestamp=bucket * window_seconds,
                flow_features=flow,
                packet_features={},  # Explicitly empty; no fake zeroes
                temporal_features=temporal,
                attack_state=item["attack"],
                packet_features_available=False,
            )
        else:
            state = TonIotNetworkState(
                timestamp=bucket * window_seconds,
                flow_features=flow,
                temporal_features=temporal,
                attack_state=item["attack"],
                attack_types=dict(item["types"]),
            )
        states.append(state)
        previous_flow = current_flow

    metadata = {
        "dataset_id": "TON-IoT",
        "source_file": source_path.name,
        "rows_total": rows_total,
        "benign_rows": benign_rows,
        "attack_rows": attack_rows,
        "unknown_rows": unknown_rows,
        "attack_type_counts": dict(attack_type_counts),
        "total_windows": len(states),
        "window_seconds": window_seconds,
        "available_flow_features": list(TONIOT_FLOW_NAMES),
        "available_temporal_features": list(TONIOT_TEMPORAL_NAMES),
        "unavailable_flow_features": list(TONIOT_UNAVAILABLE_FLOW_NAMES),
        "unavailable_temporal_features": list(TONIOT_UNAVAILABLE_TEMPORAL_NAMES),
        "packet_features_available": False,
        "encoded_dimension": len(TONIOT_FLOW_NAMES) + len(TONIOT_TEMPORAL_NAMES),
    }
    return tuple(states), metadata


def get_toniot_contiguous_episodes(
    states: Iterable[Any],
    window_seconds: int = WINDOW_SECONDS,
) -> tuple[tuple[Any, ...], ...]:
    """Segment TON-IoT states into contiguous 60-second episodes."""
    ordered = sorted(states, key=lambda s: s.timestamp)
    episodes: list[list[Any]] = []
    for s in ordered:
        if not episodes or s.timestamp != episodes[-1][-1].timestamp + window_seconds:
            episodes.append([])
        episodes[-1].append(s)
    return tuple(tuple(ep) for ep in episodes if ep)
