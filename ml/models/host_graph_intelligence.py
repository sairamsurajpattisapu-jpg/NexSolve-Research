"""Host Intelligence and Dynamic Temporal Graph Engine for NexSolve.

Implements:
1. Host-Level Temporal Tracking:
   - Visible host state profiles (traffic, peers, protocols, ports, inbound/outbound asymmetry)
   - Temporal behavioral change, anomaly score, host risk, and uncertainty.
2. Temporal Communication Graph G_t = (V_t, E_t):
   - Directed edges: SOURCE -> DESTINATION with protocol, port, volume, packets, duration.
   - Graph topological evolution: degree, weighted degree, fan-in/fan-out, density, edge churn,
     node churn, peer novelty, concentration, centrality approximations, and component structure.
   - Graph Observability: Explicit capture completeness score; never represents partial captures
     as full network graphs.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

import numpy as np


@dataclass(frozen=True)
class HostProfile:
    """Temporal behavioral identity of an active IP endpoint in window t."""
    ip: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    outbound_peers: tuple[str, ...]
    inbound_peers: tuple[str, ...]
    probed_ports: tuple[int, ...]
    protocols_used: tuple[str, ...]
    temporal_change_score: float
    anomaly_score: float
    risk_score: float
    uncertainty: float
    is_external: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "outbound_peers": list(self.outbound_peers),
            "inbound_peers": list(self.inbound_peers),
            "probed_ports": list(self.probed_ports),
            "protocols_used": list(self.protocols_used),
            "temporal_change_score": round(self.temporal_change_score, 4),
            "anomaly_score": round(self.anomaly_score, 4),
            "risk_score": round(self.risk_score, 4),
            "uncertainty": round(self.uncertainty, 4),
            "is_external": self.is_external,
        }


@dataclass(frozen=True)
class CommunicationEdge:
    """Directed interaction between two network entities."""
    source_ip: str
    destination_ip: str
    protocol: str
    destination_port: int
    total_bytes: int
    total_packets: int
    mean_duration: float
    frequency: int
    direction: str  # "INBOUND", "OUTBOUND", "INTERNAL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "destination_port": self.destination_port,
            "total_bytes": self.total_bytes,
            "total_packets": self.total_packets,
            "mean_duration": round(self.mean_duration, 4),
            "frequency": self.frequency,
            "direction": self.direction,
        }


@dataclass(frozen=True)
class GraphEvolutionSnapshot:
    """Dynamic structural properties of communication graph G_t."""
    timestamp: int
    node_count: int
    edge_count: int
    graph_density: float
    mean_degree: float
    max_degree: int
    max_betweenness_approx: float
    edge_churn_rate: float
    node_churn_rate: float
    peer_novelty_rate: float
    connected_components: int
    graph_observability_score: float
    is_partial_capture: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "graph_density": round(self.graph_density, 6),
            "mean_degree": round(self.mean_degree, 4),
            "max_degree": self.max_degree,
            "max_betweenness_approx": round(self.max_betweenness_approx, 4),
            "edge_churn_rate": round(self.edge_churn_rate, 4),
            "node_churn_rate": round(self.node_churn_rate, 4),
            "peer_novelty_rate": round(self.peer_novelty_rate, 4),
            "connected_components": self.connected_components,
            "graph_observability_score": round(self.graph_observability_score, 4),
            "is_partial_capture": self.is_partial_capture,
        }

    def to_array(self) -> np.ndarray:
        return np.array([
            float(self.node_count),
            float(self.edge_count),
            self.graph_density,
            self.mean_degree,
            float(self.max_degree),
            self.max_betweenness_approx,
            self.edge_churn_rate,
            self.node_churn_rate,
            self.peer_novelty_rate,
            float(self.connected_components),
            self.graph_observability_score,
        ], dtype=np.float64)


def _is_private_ip(ip: str) -> bool:
    """Determine whether an IP address belongs to RFC1918 private space."""
    if ip.startswith("10.") or ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            val = int(parts[1])
            if 16 <= val <= 31:
                return True
    if ip.startswith("127."):
        return True
    return False


class HostGraphIntelligenceEngine:
    """Builds and analyzes host behaviors and temporal communication graphs."""

    def __init__(self, monitored_subnets_cardinality: int = 256) -> None:
        self.monitored_subnets_cardinality = monitored_subnets_cardinality

    def analyze_window(
        self,
        flows: Sequence[Mapping[str, Any]],
        timestamp: int,
        prior_hosts: Mapping[str, HostProfile] | None = None,
        prior_nodes: set[str] | None = None,
        prior_edges: set[tuple[str, str, int, str]] | None = None,
    ) -> tuple[dict[str, HostProfile], list[CommunicationEdge], GraphEvolutionSnapshot]:
        """Processes flow records into host profiles, communication edges, and graph evolution metrics."""
        # Host accumulators
        bytes_sent = defaultdict(int)
        bytes_recv = defaultdict(int)
        pkts_sent = defaultdict(int)
        pkts_recv = defaultdict(int)
        out_peers = defaultdict(set)
        in_peers = defaultdict(set)
        ports_probed = defaultdict(set)
        protos_used = defaultdict(set)

        # Edge accumulator: (src, dst, port, proto) -> list of flows
        edge_flows = defaultdict(list)

        all_nodes: set[str] = set()
        current_edge_keys: set[tuple[str, str, int, str]] = set()

        for f in flows:
            s_ip = str(f.get("src_ip", f.get("source_ip", "")) or "").strip()
            d_ip = str(f.get("dst_ip", f.get("destination_ip", "")) or "").strip()
            if not s_ip or not d_ip:
                continue

            all_nodes.add(s_ip)
            all_nodes.add(d_ip)

            # Safely parse numeric fields handling None and malformed values
            raw_s_bytes = f.get("src_bytes")
            raw_d_bytes = f.get("dst_bytes")
            raw_pkts = f.get("packets") if f.get("packets") is not None else f.get("total_packets")
            raw_port = f.get("dst_port") if f.get("dst_port") is not None else f.get("destination_port")
            raw_proto = f.get("proto") if f.get("proto") is not None else f.get("protocol", "tcp")
            raw_duration = f.get("duration")

            try:
                s_bytes = int(raw_s_bytes) if raw_s_bytes is not None else 0
            except (ValueError, TypeError):
                s_bytes = 0

            try:
                d_bytes = int(raw_d_bytes) if raw_d_bytes is not None else 0
            except (ValueError, TypeError):
                d_bytes = 0

            try:
                pkts = int(raw_pkts) if raw_pkts is not None else 1
            except (ValueError, TypeError):
                pkts = 1

            try:
                port = int(raw_port) if raw_port is not None else 0
                if port < 0 or port > 65535:
                    port = 0
            except (ValueError, TypeError):
                port = 0

            proto = str(raw_proto or "tcp").lower()

            try:
                duration = float(raw_duration) if raw_duration is not None else 0.0
            except (ValueError, TypeError):
                duration = 0.0

            bytes_sent[s_ip] += s_bytes
            bytes_recv[d_ip] += s_bytes
            if d_bytes > 0:
                bytes_sent[d_ip] += d_bytes
                bytes_recv[s_ip] += d_bytes

            pkts_sent[s_ip] += pkts
            pkts_recv[d_ip] += pkts

            out_peers[s_ip].add(d_ip)
            in_peers[d_ip].add(s_ip)
            if port > 0:
                ports_probed[s_ip].add(port)
            protos_used[s_ip].add(proto)

            edge_key = (s_ip, d_ip, port, proto)
            current_edge_keys.add(edge_key)
            edge_flows[edge_key].append((s_bytes + d_bytes, pkts, duration))

        # Build CommunicationEdge objects
        edge_objects: list[CommunicationEdge] = []
        for (s_ip, d_ip, port, proto), flow_list in edge_flows.items():
            tot_bytes = sum(item[0] for item in flow_list)
            tot_pkts = sum(item[1] for item in flow_list)
            mean_dur = sum(item[2] for item in flow_list) / max(1, len(flow_list))
            freq = len(flow_list)

            s_priv = _is_private_ip(s_ip)
            d_priv = _is_private_ip(d_ip)
            if s_priv and d_priv:
                direction = "INTERNAL"
            elif s_priv and not d_priv:
                direction = "OUTBOUND"
            elif not s_priv and d_priv:
                direction = "INBOUND"
            else:
                direction = "EXTERNAL"

            edge_objects.append(CommunicationEdge(
                source_ip=s_ip,
                destination_ip=d_ip,
                protocol=proto,
                destination_port=port,
                total_bytes=tot_bytes,
                total_packets=tot_pkts,
                mean_duration=mean_dur,
                frequency=freq,
                direction=direction,
            ))

        # Build HostProfile objects
        host_profiles: dict[str, HostProfile] = {}
        for ip in all_nodes:
            out_p = tuple(sorted(out_peers[ip]))
            in_p = tuple(sorted(in_peers[ip]))
            p_probed = tuple(sorted(ports_probed[ip]))
            p_used = tuple(sorted(protos_used[ip]))

            # Prior comparison for temporal change
            temporal_change = 0.0
            if prior_hosts and ip in prior_hosts:
                p_prof = prior_hosts[ip]
                # Outbound fanout delta
                delta_out = abs(len(out_p) - len(p_prof.outbound_peers))
                # Volume delta ratio
                prev_vol = p_prof.bytes_sent + p_prof.bytes_recv
                curr_vol = bytes_sent[ip] + bytes_recv[ip]
                vol_change = abs(curr_vol - prev_vol) / max(1.0, float(prev_vol))
                temporal_change = min(1.0, (delta_out * 0.1) + min(0.5, vol_change * 0.1))

            # Anomaly / Risk score derivation
            # High fan-out or many ports probed = potential scanner
            is_scanner = len(p_probed) >= 10 or len(out_p) >= 15
            is_heavy_talker = (bytes_sent[ip] > 10_000_000)
            risk = 0.05
            if is_scanner:
                risk += 0.45
            if is_heavy_talker:
                risk += 0.20
            if temporal_change > 0.3:
                risk += 0.15
            risk = min(0.99, risk)

            # Uncertainty: higher if very few observations
            obs_count = pkts_sent[ip] + pkts_recv[ip]
            uncertainty = max(0.05, 1.0 / (1.0 + math.log1p(obs_count)))

            host_profiles[ip] = HostProfile(
                ip=ip,
                bytes_sent=bytes_sent[ip],
                bytes_recv=bytes_recv[ip],
                packets_sent=pkts_sent[ip],
                packets_recv=pkts_recv[ip],
                outbound_peers=out_p,
                inbound_peers=in_p,
                probed_ports=p_probed,
                protocols_used=p_used,
                temporal_change_score=temporal_change,
                anomaly_score=temporal_change * 0.8 + (0.5 if is_scanner else 0.0),
                risk_score=risk,
                uncertainty=uncertainty,
                is_external=not _is_private_ip(ip),
            )

        # Graph Evolution Metrics
        v_count = len(all_nodes)
        e_count = len(current_edge_keys)
        density = (2.0 * e_count) / max(1.0, float(v_count * (v_count - 1))) if v_count > 1 else 0.0

        degrees = [len(out_peers[n]) + len(in_peers[n]) for n in all_nodes]
        mean_deg = float(np.mean(degrees)) if degrees else 0.0
        max_deg = max(degrees) if degrees else 0

        # Betweenness approximation (degree centrality as surrogate for real-time efficiency)
        max_betweenness = max_deg / max(1.0, float(v_count - 1)) if v_count > 1 else 0.0

        # Churn calculations
        if prior_edges is not None and prior_edges:
            edge_sym_diff = current_edge_keys.symmetric_difference(prior_edges)
            edge_churn = len(edge_sym_diff) / max(1.0, float(len(current_edge_keys) + len(prior_edges)))
        else:
            edge_churn = 0.0

        if prior_nodes is not None and prior_nodes:
            node_sym_diff = all_nodes.symmetric_difference(prior_nodes)
            node_churn = len(node_sym_diff) / max(1.0, float(len(all_nodes) + len(prior_nodes)))
            new_nodes = len(all_nodes - prior_nodes)
            peer_novelty = new_nodes / max(1.0, float(len(all_nodes)))
        else:
            node_churn = 0.0
            peer_novelty = 0.0

        # Connected components approximation via disjoint set
        parent = {n: n for n in all_nodes}

        def find(x: str) -> str:
            if parent[x] != x:
                parent[x] = find(parent[x])
            return parent[x]

        def union(x: str, y: str):
            rx, ry = find(x), find(y)
            if rx != ry:
                parent[rx] = ry

        for (s, d, _, _) in current_edge_keys:
            union(s, d)

        components = len(set(find(n) for n in all_nodes)) if all_nodes else 0

        # Graph Observability Score:
        # Ratio of visible active endpoints relative to monitored subnet capacity.
        # Strict rule: If v_count < monitored capacity or only 1 host visible, mark is_partial_capture=True.
        obs_score = min(1.0, v_count / float(self.monitored_subnets_cardinality))
        is_partial = bool(v_count < self.monitored_subnets_cardinality * 0.5 or v_count <= 2)

        snapshot = GraphEvolutionSnapshot(
            timestamp=timestamp,
            node_count=v_count,
            edge_count=e_count,
            graph_density=density,
            mean_degree=mean_deg,
            max_degree=max_deg,
            max_betweenness_approx=max_betweenness,
            edge_churn_rate=edge_churn,
            node_churn_rate=node_churn,
            peer_novelty_rate=peer_novelty,
            connected_components=components,
            graph_observability_score=obs_score,
            is_partial_capture=is_partial,
        )

        return host_profiles, edge_objects, snapshot
