"""Behavioral Intelligence Engine for NexSolve.

Extracts interaction dynamics, diversity metrics, dispersion, and churn:
- Peer diversity & new peer rate
- Destination & source diversity
- Port & protocol entropy (Shannon entropy)
- Directional fan-in and fan-out concentration
- Gini coefficient of volumetric distribution
- Edge churn and connection churn
- Behavioral novelty and persistence tracking
"""
from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import numpy as np


@dataclass(frozen=True)
class BehavioralVector:
    """Calculated behavioral intelligence features for an observation window."""
    peer_diversity: float
    new_peer_rate: float
    dest_diversity: float
    src_diversity: float
    port_entropy: float
    protocol_entropy: float
    fan_in_ratio: float
    fan_out_ratio: float
    traffic_concentration_gini: float
    edge_churn_rate: float
    connection_churn_rate: float
    behavioral_novelty_score: float

    def to_dict(self) -> dict[str, float]:
        return {
            "peer_diversity": float(self.peer_diversity),
            "new_peer_rate": float(self.new_peer_rate),
            "dest_diversity": float(self.dest_diversity),
            "src_diversity": float(self.src_diversity),
            "port_entropy": float(self.port_entropy),
            "protocol_entropy": float(self.protocol_entropy),
            "fan_in_ratio": float(self.fan_in_ratio),
            "fan_out_ratio": float(self.fan_out_ratio),
            "traffic_concentration_gini": float(self.traffic_concentration_gini),
            "edge_churn_rate": float(self.edge_churn_rate),
            "connection_churn_rate": float(self.connection_churn_rate),
            "behavioral_novelty_score": float(self.behavioral_novelty_score),
        }

    def to_array(self) -> np.ndarray:
        return np.array([
            self.peer_diversity,
            self.new_peer_rate,
            self.dest_diversity,
            self.src_diversity,
            self.port_entropy,
            self.protocol_entropy,
            self.fan_in_ratio,
            self.fan_out_ratio,
            self.traffic_concentration_gini,
            self.edge_churn_rate,
            self.connection_churn_rate,
            self.behavioral_novelty_score,
        ], dtype=np.float64)


def compute_shannon_entropy(counts: Sequence[int | float]) -> float:
    """Compute normalized Shannon entropy: H(X) = -sum(p * log2(p))."""
    total = sum(counts)
    if total <= 0:
        return 0.0
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return float(entropy)


def compute_gini_coefficient(values: Sequence[float]) -> float:
    """Compute Gini inequality coefficient across volumetric flow allocations."""
    if not values:
        return 0.0
    arr = np.array(values, dtype=np.float64)
    if np.all(arr == 0.0):
        return 0.0
    arr = np.sort(np.abs(arr))
    n = len(arr)
    index = np.arange(1, n + 1)
    return float((2.0 * np.sum(index * arr) - (n + 1) * np.sum(arr)) / (n * np.sum(arr) + 1e-9))


class BehavioralEngine:
    """Computes behavioral interaction patterns across flow and endpoint telemetry."""

    def compute_behavioral_vector(
        self,
        current_flows: Sequence[Mapping[str, Any]],
        historical_peers: set[str] | None = None,
        prior_edges: set[tuple[str, str, int]] | None = None,
    ) -> tuple[BehavioralVector, set[str], set[tuple[str, str, int]]]:
        """Extracts behavioral vectors from flow sessions observed in the current window."""
        n_flows = max(len(current_flows), 1)

        src_ips: set[str] = set()
        dst_ips: set[str] = set()
        dst_ports: list[int] = []
        protocols: list[str] = []
        flow_bytes: list[float] = []
        current_edges: set[tuple[str, str, int]] = set()

        inbound_counts: Counter[str] = Counter()
        outbound_counts: Counter[str] = Counter()

        for f in current_flows:
            s_ip = str(f.get("src_ip", f.get("source_ip", "")) or "").strip()
            d_ip = str(f.get("dst_ip", f.get("destination_ip", "")) or "").strip()
            
            raw_d_port = f.get("dst_port") if f.get("dst_port") is not None else f.get("destination_port")
            try:
                d_port = int(raw_d_port) if raw_d_port is not None else 0
                if d_port < 0 or d_port > 65535:
                    d_port = 0
            except (ValueError, TypeError):
                d_port = 0

            raw_proto = f.get("proto") if f.get("proto") is not None else f.get("protocol", "other")
            proto = str(raw_proto or "other").lower()

            try:
                s_b = float(f.get("src_bytes")) if f.get("src_bytes") is not None else 0.0
            except (ValueError, TypeError):
                s_b = 0.0
            try:
                d_b = float(f.get("dst_bytes")) if f.get("dst_bytes") is not None else 0.0
            except (ValueError, TypeError):
                d_b = 0.0
            bytes_val = s_b + d_b

            if s_ip:
                src_ips.add(s_ip)
                outbound_counts[s_ip] += 1
            if d_ip:
                dst_ips.add(d_ip)
                inbound_counts[d_ip] += 1
            if d_port > 0:
                dst_ports.append(d_port)
            protocols.append(proto)
            flow_bytes.append(bytes_val)

            if s_ip and d_ip:
                current_edges.add((s_ip, d_ip, d_port))

        all_current_peers = src_ips.union(dst_ips)

        # 1. Diversities
        peer_div = len(all_current_peers) / float(n_flows)
        src_div = len(src_ips) / float(n_flows)
        dst_div = len(dst_ips) / float(n_flows)

        # 2. New peer rate
        if historical_peers:
            new_peers = len(all_current_peers - historical_peers)
            new_peer_rate = new_peers / max(1.0, float(len(all_current_peers)))
        else:
            new_peer_rate = 0.0

        # 3. Entropies
        port_counts = list(Counter(dst_ports).values())
        proto_counts = list(Counter(protocols).values())
        port_entropy = compute_shannon_entropy(port_counts)
        protocol_entropy = compute_shannon_entropy(proto_counts)

        # 4. Fan-in / Fan-out ratios
        fan_in_ratio = (
            sum(inbound_counts.values()) / max(1.0, float(len(inbound_counts)))
            if inbound_counts else 1.0
        )
        fan_out_ratio = (
            sum(outbound_counts.values()) / max(1.0, float(len(outbound_counts)))
            if outbound_counts else 1.0
        )

        # 5. Gini concentration
        gini = compute_gini_coefficient(flow_bytes)

        # 6. Edge churn rate
        if prior_edges is not None:
            symmetric_diff = current_edges.symmetric_difference(prior_edges)
            edge_churn = len(symmetric_diff) / max(1.0, float(len(current_edges) + len(prior_edges)))
        else:
            edge_churn = 0.0

        # 7. Connection churn rate
        def _safe_f_dur(flow_item: Mapping[str, Any]) -> float:
            d_val = flow_item.get("duration")
            if d_val is None:
                return 0.0
            try:
                return float(d_val)
            except (ValueError, TypeError):
                return 0.0

        short_lived = sum(1 for f in current_flows if _safe_f_dur(f) < 2.0)
        conn_churn = short_lived / float(n_flows)

        # 8. Behavioral novelty score
        # Elevated by high entropy, unusual peer expansion, and extreme fan-out
        novelty = min(5.0, (new_peer_rate * 2.0) + (edge_churn * 1.5) + (port_entropy / 8.0))

        vec = BehavioralVector(
            peer_diversity=peer_div,
            new_peer_rate=new_peer_rate,
            dest_diversity=dst_div,
            src_diversity=src_div,
            port_entropy=port_entropy,
            protocol_entropy=protocol_entropy,
            fan_in_ratio=fan_in_ratio,
            fan_out_ratio=fan_out_ratio,
            traffic_concentration_gini=gini,
            edge_churn_rate=edge_churn,
            connection_churn_rate=conn_churn,
            behavioral_novelty_score=novelty,
        )

        return vec, all_current_peers, current_edges
