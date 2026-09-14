"""Temporal Entity Tracking Engine.

Maintains deterministic multi-window entity histories for IPs, ports, and communication pairs:
- First/last seen window timestamps
- Activity counts and peer fan-out
- Byte/packet volume tracking
- Protocol state changes across windows
- Finding and alert associations
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


@dataclass(frozen=True)
class TemporalEntityHistory:
    """Historical profile of an observed network entity across temporal windows."""
    entity_key: str
    entity_type: str  # "IP", "COMMUNICATION_PAIR", "PORT"
    first_seen_window: int
    last_seen_window: int
    active_windows: tuple[int, ...]
    activity_count: int
    unique_peers: tuple[str, ...]
    unique_ports: tuple[int, ...]
    total_packets: int
    total_bytes: int
    session_count: int
    findings_count: int
    observed_states: tuple[str, ...]
    is_expanding_peers: bool
    is_expanding_ports: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_key": self.entity_key,
            "entity_type": self.entity_type,
            "first_seen_window": self.first_seen_window,
            "last_seen_window": self.last_seen_window,
            "active_windows": list(self.active_windows),
            "activity_count": self.activity_count,
            "unique_peers": list(self.unique_peers),
            "unique_ports": list(self.unique_ports),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "session_count": self.session_count,
            "findings_count": self.findings_count,
            "observed_states": list(self.observed_states),
            "is_expanding_peers": self.is_expanding_peers,
            "is_expanding_ports": self.is_expanding_ports,
        }


def build_temporal_entity_histories(
    flows: Sequence[Any] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, TemporalEntityHistory]:
    """Build deterministic temporal entity tracking maps."""
    histories: dict[str, dict[str, Any]] = {}

    def get_or_create(key: str, etype: str) -> dict[str, Any]:
        if key not in histories:
            histories[key] = {
                "entity_key": key,
                "entity_type": etype,
                "active_windows": set(),
                "activity_count": 0,
                "peers": set(),
                "ports": set(),
                "packets": 0,
                "bytes": 0,
                "sessions": 0,
                "findings": 0,
                "states": set(),
            }
        return histories[key]

    # Process flows
    if flows:
        for fl in flows:
            src = fl.get("src_ip") if isinstance(fl, dict) else getattr(fl, "src_ip", None)
            dst = fl.get("dst_ip") if isinstance(fl, dict) else getattr(fl, "dst_ip", None)
            port = fl.get("dst_port") if isinstance(fl, dict) else getattr(fl, "dst_port", None)
            w_idx = fl.get("window_index", 0) if isinstance(fl, dict) else (getattr(fl, "window_index", 0) or 0)
            pkts = fl.get("packets", 1) if isinstance(fl, dict) else (getattr(fl, "packets", 1) or 1)
            byts = fl.get("bytes", 0) if isinstance(fl, dict) else (getattr(fl, "bytes", 0) or 0)

            if src:
                h_src = get_or_create(src, "IP")
                h_src["active_windows"].add(w_idx)
                h_src["activity_count"] += 1
                if dst:
                    h_src["peers"].add(dst)
                if port is not None:
                    h_src["ports"].add(int(port))
                h_src["packets"] += pkts
                h_src["bytes"] += byts

            if dst:
                h_dst = get_or_create(dst, "IP")
                h_dst["active_windows"].add(w_idx)
                h_dst["activity_count"] += 1
                if src:
                    h_dst["peers"].add(src)
                if port is not None:
                    h_dst["ports"].add(int(port))
                h_dst["packets"] += pkts
                h_dst["bytes"] += byts

    # Process TCP sessions
    if tcp_sessions:
        for s in tcp_sessions:
            src = getattr(s, "src_ip", None)
            dst = getattr(s, "dst_ip", None)
            port = getattr(s, "dst_port", None)
            w_idx = getattr(s, "window_index", 0) or 0
            state = getattr(s, "state", "OTH")
            pkts = getattr(s, "packet_count", 1) or 1
            byts = getattr(s, "byte_count", 0) or 0

            if src:
                h_src = get_or_create(src, "IP")
                h_src["active_windows"].add(w_idx)
                h_src["activity_count"] += 1
                if dst:
                    h_src["peers"].add(dst)
                if port is not None:
                    h_src["ports"].add(int(port))
                h_src["packets"] += pkts
                h_src["bytes"] += byts
                h_src["sessions"] += 1
                h_src["states"].add(str(state))

            if dst:
                h_dst = get_or_create(dst, "IP")
                h_dst["active_windows"].add(w_idx)
                h_dst["activity_count"] += 1
                if src:
                    h_dst["peers"].add(src)
                if port is not None:
                    h_dst["ports"].add(int(port))
                h_dst["packets"] += pkts
                h_dst["bytes"] += byts
                h_dst["sessions"] += 1
                h_dst["states"].add(str(state))

    # Process Findings
    if observed_findings:
        for f in observed_findings:
            src = f.get("source_ip")
            dst = f.get("destination_ip")
            w_idx = int(f.get("window_index") or 0)
            if src:
                h = get_or_create(str(src), "IP")
                h["active_windows"].add(w_idx)
                h["findings"] += 1
            if dst:
                h = get_or_create(str(dst), "IP")
                h["active_windows"].add(w_idx)
                h["findings"] += 1

    result: dict[str, TemporalEntityHistory] = {}
    for key, data in histories.items():
        w_sorted = sorted(data["active_windows"]) if data["active_windows"] else [0]
        peers_sorted = sorted(data["peers"])
        ports_sorted = sorted(data["ports"])
        states_sorted = sorted(data["states"])

        # Determine expansion heuristics
        expanding_peers = len(peers_sorted) >= 5
        expanding_ports = len(ports_sorted) >= 5

        result[key] = TemporalEntityHistory(
            entity_key=key,
            entity_type=data["entity_type"],
            first_seen_window=w_sorted[0],
            last_seen_window=w_sorted[-1],
            active_windows=tuple(w_sorted),
            activity_count=data["activity_count"],
            unique_peers=tuple(peers_sorted),
            unique_ports=tuple(ports_sorted),
            total_packets=data["packets"],
            total_bytes=data["bytes"],
            session_count=data["sessions"],
            findings_count=data["findings"],
            observed_states=tuple(states_sorted),
            is_expanding_peers=expanding_peers,
            is_expanding_ports=expanding_ports,
        )

    return result
