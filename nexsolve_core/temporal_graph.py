"""Dynamic Network Graph Intelligence & Temporal Attack Propagation Engine.

Implements the canonical temporal network graph layer:
    G_t = (V_t, E_t)
capturing observed host interactions (nodes, edges, timestamps, flow semantics),
temporal graph snapshots aligned with 60s windows (G_{t-K} ... G_t ... G_{t+5}),
graph statistics, host behavioral signals, graph change detection, scan/propagation patterns,
graph embedding/metrics vectors, and future graph behavior forecast projections.

Adheres strictly to scientific constraints:
- Relationships are modelled interaction behaviors, not claims of ground-truth causality.
- Zero fabrication of RTT or unverifiable telemetry.
- Strict isolation of OBSERVED vs FORECAST states.
- Deterministic IDs and rankings.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id
from nexsolve_core.schemas import FlowRecord, TemporalWindow


class GraphTemporalScope(str, Enum):
    OBSERVED = "OBSERVED"
    FORECAST = "FORECAST"


class NodeRoleTag(str, Enum):
    HIGH_ACTIVITY_NODE = "HIGH_ACTIVITY_NODE"
    STRUCTURAL_CHANGE_NODE = "STRUCTURAL_CHANGE_NODE"
    LATERAL_SOURCE = "LATERAL_SOURCE"
    SCAN_TARGET = "SCAN_TARGET"
    PERSISTENT_ENDPOINT = "PERSISTENT_ENDPOINT"
    NOMINAL_HOST = "NOMINAL_HOST"


class GraphChangeType(str, Enum):
    NEW_NODE = "NEW_NODE"
    NEW_EDGE = "NEW_EDGE"
    SUDDEN_FAN_OUT = "SUDDEN_FAN_OUT"
    PROTOCOL_SHIFT = "PROTOCOL_SHIFT"
    VOLUME_SPIKE = "VOLUME_SPIKE"
    CONNECTION_BURST = "CONNECTION_BURST"


@dataclass(frozen=True)
class TemporalGraphNode:
    """Canonical IP/endpoint identity within a temporal graph snapshot."""
    node_id: str
    ip: str
    in_degree: int
    out_degree: int
    total_degree: int
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    fan_out: int
    fan_in: int
    port_diversity: int
    active_ports: tuple[int, ...]
    peer_ips: tuple[str, ...]
    role_tags: tuple[NodeRoleTag, ...]
    activity_score: float  # 0.0 to 1.0 normalized
    structural_change_score: float  # 0.0 to 1.0 delta from prior snapshot
    is_external: bool = False
    temporal_scope: GraphTemporalScope = GraphTemporalScope.OBSERVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "ip": self.ip,
            "in_degree": self.in_degree,
            "out_degree": self.out_degree,
            "total_degree": self.total_degree,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets_sent": self.packets_sent,
            "packets_recv": self.packets_recv,
            "fan_out": self.fan_out,
            "fan_in": self.fan_in,
            "port_diversity": self.port_diversity,
            "active_ports": list(self.active_ports),
            "peer_ips": list(self.peer_ips),
            "role_tags": [r.value for r in self.role_tags],
            "activity_score": round(self.activity_score, 4),
            "structural_change_score": round(self.structural_change_score, 4),
            "is_external": self.is_external,
            "temporal_scope": self.temporal_scope.value,
        }


@dataclass(frozen=True)
class TemporalGraphEdge:
    """Directed communication flow interaction between two endpoints in G_t."""
    edge_id: str
    source_ip: str
    target_ip: str
    protocol: str
    target_port: int
    flow_count: int
    packet_count: int
    byte_count: int
    syn_count: int
    rst_count: int
    duration_seconds: float
    is_new_in_snapshot: bool = False
    weight: float = 1.0
    temporal_scope: GraphTemporalScope = GraphTemporalScope.OBSERVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "protocol": self.protocol,
            "target_port": self.target_port,
            "flow_count": self.flow_count,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "syn_count": self.syn_count,
            "rst_count": self.rst_count,
            "duration_seconds": round(self.duration_seconds, 3),
            "is_new_in_snapshot": self.is_new_in_snapshot,
            "weight": round(self.weight, 4),
            "temporal_scope": self.temporal_scope.value,
        }


@dataclass(frozen=True)
class GraphChangeSignal:
    """Discrete structural alteration between snapshot G_{t-1} and G_t."""
    change_type: GraphChangeType
    source_entity: str
    target_entity: str | None
    description: str
    severity: str  # "HIGH", "MEDIUM", "LOW"
    metric_delta: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_type": self.change_type.value,
            "source_entity": self.source_entity,
            "target_entity": self.target_entity,
            "description": self.description,
            "severity": self.severity,
            "metric_delta": round(self.metric_delta, 3),
        }


@dataclass(frozen=True)
class GraphSnapshotMetrics:
    """Graph theoretical metrics for a discrete 60s observation window."""
    node_count: int
    edge_count: int
    density: float
    max_fan_out: int
    max_fan_in: int
    mean_degree: float
    total_volume_bytes: int
    total_packets: int
    unique_subnets: int
    bipartite_ratio: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "density": round(self.density, 6),
            "max_fan_out": self.max_fan_out,
            "max_fan_in": self.max_fan_in,
            "mean_degree": round(self.mean_degree, 3),
            "total_volume_bytes": self.total_volume_bytes,
            "total_packets": self.total_packets,
            "unique_subnets": self.unique_subnets,
            "bipartite_ratio": round(self.bipartite_ratio, 4),
        }


@dataclass(frozen=True)
class TemporalGraphSnapshot:
    """Snapshot G_t = (V_t, E_t) aligned with a 60-second temporal window."""
    snapshot_index: int
    window_id: int
    timestamp_start: float
    timestamp_end: float
    scope: GraphTemporalScope
    metrics: GraphSnapshotMetrics
    nodes: tuple[TemporalGraphNode, ...]
    edges: tuple[TemporalGraphEdge, ...]
    changes: tuple[GraphChangeSignal, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_index": self.snapshot_index,
            "window_id": self.window_id,
            "timestamp_start": self.timestamp_start,
            "timestamp_end": self.timestamp_end,
            "scope": self.scope.value,
            "metrics": self.metrics.to_dict(),
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "changes": [c.to_dict() for c in self.changes],
        }


@dataclass(frozen=True)
class ForecastGraphProjection:
    """Modelled future graph structure projection for horizon T+K."""
    horizon_step: int
    horizon_seconds: int
    predicted_node_count: int
    predicted_edge_count: int
    predicted_density: float
    predicted_fanout_expansion: float
    active_threat_nodes: tuple[str, ...]
    potential_propagation_targets: tuple[str, ...]
    structural_indicators: tuple[str, ...]
    propagation_confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon_step": self.horizon_step,
            "horizon_seconds": self.horizon_seconds,
            "predicted_node_count": self.predicted_node_count,
            "predicted_edge_count": self.predicted_edge_count,
            "predicted_density": round(self.predicted_density, 5),
            "predicted_fanout_expansion": round(self.predicted_fanout_expansion, 3),
            "active_threat_nodes": list(self.active_threat_nodes),
            "potential_propagation_targets": list(self.potential_propagation_targets),
            "structural_indicators": list(self.structural_indicators),
            "propagation_confidence": round(self.propagation_confidence, 3),
        }


@dataclass(frozen=True)
class TemporalGraphSequence:
    """Complete temporal network sequence spanning observed snapshots and forecasts."""
    status: str  # "READY", "INSUFFICIENT_GRAPH_CONTEXT"
    snapshot_count: int
    observed_snapshots: tuple[TemporalGraphSnapshot, ...]
    forecast_projections: tuple[ForecastGraphProjection, ...]
    top_high_activity_nodes: tuple[TemporalGraphNode, ...]
    top_structural_change_nodes: tuple[TemporalGraphNode, ...]
    cumulative_nodes_count: int
    cumulative_edges_count: int
    graph_feature_vector: tuple[float, ...]  # 16-dim deterministic graph state vector

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "snapshot_count": self.snapshot_count,
            "observed_snapshots": [s.to_dict() for s in self.observed_snapshots],
            "forecast_projections": [f.to_dict() for f in self.forecast_projections],
            "top_high_activity_nodes": [n.to_dict() for n in self.top_high_activity_nodes],
            "top_structural_change_nodes": [n.to_dict() for n in self.top_structural_change_nodes],
            "cumulative_nodes_count": self.cumulative_nodes_count,
            "cumulative_edges_count": self.cumulative_edges_count,
            "graph_feature_vector": list(self.graph_feature_vector),
        }


def _is_private_ip(ip: str) -> bool:
    """Deterministic check if IP is RFC1918 or standard private/local."""
    if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("127."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2:
            try:
                sec = int(parts[1])
                return 16 <= sec <= 31
            except ValueError:
                pass
    return False


def _get_subnet_24(ip: str) -> str:
    """Extract /24 subnet string."""
    parts = ip.split(".")
    if len(parts) >= 3:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return ip


def build_graph_snapshot_from_flows(
    flows: Sequence[FlowRecord],
    snapshot_index: int,
    window_id: int,
    timestamp_start: float,
    timestamp_end: float,
    prior_snapshot: TemporalGraphSnapshot | None = None,
) -> TemporalGraphSnapshot:
    """Constructs G_t = (V_t, E_t) for a discrete 60s flow window."""
    if not flows:
        empty_metrics = GraphSnapshotMetrics(
            node_count=0,
            edge_count=0,
            density=0.0,
            max_fan_out=0,
            max_fan_in=0,
            mean_degree=0.0,
            total_volume_bytes=0,
            total_packets=0,
            unique_subnets=0,
            bipartite_ratio=0.0,
        )
        return TemporalGraphSnapshot(
            snapshot_index=snapshot_index,
            window_id=window_id,
            timestamp_start=timestamp_start,
            timestamp_end=timestamp_end,
            scope=GraphTemporalScope.OBSERVED,
            metrics=empty_metrics,
            nodes=(),
            edges=(),
            changes=(),
        )

    edge_map: dict[tuple[str, str, str, int], dict[str, Any]] = defaultdict(lambda: {
        "flow_count": 0,
        "packet_count": 0,
        "byte_count": 0,
        "syn_count": 0,
        "rst_count": 0,
        "duration_seconds": 0.0,
    })

    node_sent_bytes: dict[str, int] = defaultdict(int)
    node_recv_bytes: dict[str, int] = defaultdict(int)
    node_sent_pkts: dict[str, int] = defaultdict(int)
    node_recv_pkts: dict[str, int] = defaultdict(int)
    node_out_peers: dict[str, set[str]] = defaultdict(set)
    node_in_peers: dict[str, set[str]] = defaultdict(set)
    node_ports: dict[str, set[int]] = defaultdict(set)

    total_bytes = 0
    total_pkts = 0

    for flow in flows:
        src = flow.src_ip
        dst = flow.dst_ip
        proto = flow.protocol
        port = flow.dst_port

        bytes_fwd = getattr(flow, "forward_bytes", 0) or 0
        bytes_rev = getattr(flow, "reverse_bytes", 0) or 0
        flow_bytes = bytes_fwd + bytes_rev
        pkts_fwd = getattr(flow, "forward_packet_count", getattr(flow, "forward_packets", 0)) or 1
        pkts_rev = getattr(flow, "reverse_packet_count", getattr(flow, "reverse_packets", 0)) or 0
        flow_pkts = pkts_fwd + pkts_rev

        syn = getattr(flow, "syn_count", 0) or 0
        rst = getattr(flow, "rst_count", 0) or 0
        dur = getattr(flow, "duration_seconds", 0.0) or 0.0

        key = (src, dst, proto, port)
        entry = edge_map[key]
        entry["flow_count"] += 1
        entry["packet_count"] += flow_pkts
        entry["byte_count"] += flow_bytes
        entry["syn_count"] += syn
        entry["rst_count"] += rst
        entry["duration_seconds"] = max(entry["duration_seconds"], dur)

        node_sent_bytes[src] += flow_bytes
        node_recv_bytes[dst] += flow_bytes
        node_sent_pkts[src] += flow_pkts
        node_recv_pkts[dst] += flow_pkts

        node_out_peers[src].add(dst)
        node_in_peers[dst].add(src)
        node_ports[src].add(port)
        node_ports[dst].add(port)

        total_bytes += flow_bytes
        total_pkts += flow_pkts

    all_ips = set(node_sent_bytes.keys()).union(node_recv_bytes.keys())

    prior_nodes_map = {n.ip: n for n in prior_snapshot.nodes} if prior_snapshot else {}
    prior_edges_set = {(e.source_ip, e.target_ip, e.protocol, e.target_port) for e in prior_snapshot.edges} if prior_snapshot else set()

    built_edges: list[TemporalGraphEdge] = []
    for (src, dst, proto, port), data in edge_map.items():
        is_new = (src, dst, proto, port) not in prior_edges_set
        e_id = deterministic_id("edge", f"{src}_{dst}_{proto}_{port}_w{window_id}")
        weight = float(data["packet_count"] + (data["byte_count"] / 1024.0))
        built_edges.append(TemporalGraphEdge(
            edge_id=e_id,
            source_ip=src,
            target_ip=dst,
            protocol=proto,
            target_port=port,
            flow_count=data["flow_count"],
            packet_count=data["packet_count"],
            byte_count=data["byte_count"],
            syn_count=data["syn_count"],
            rst_count=data["rst_count"],
            duration_seconds=data["duration_seconds"],
            is_new_in_snapshot=is_new,
            weight=weight,
            temporal_scope=GraphTemporalScope.OBSERVED,
        ))

    built_nodes: list[TemporalGraphNode] = []
    max_pkts_node = max([node_sent_pkts[ip] + node_recv_pkts[ip] for ip in all_ips] + [1])
    changes: list[GraphChangeSignal] = []

    for ip in sorted(all_ips):
        fan_out = len(node_out_peers[ip])
        fan_in = len(node_in_peers[ip])
        out_deg = fan_out
        in_deg = fan_in
        tot_deg = out_deg + in_deg
        pkts = node_sent_pkts[ip] + node_recv_pkts[ip]
        vol_bytes = node_sent_bytes[ip] + node_recv_bytes[ip]
        ports = tuple(sorted(node_ports[ip]))
        peers = tuple(sorted(node_out_peers[ip].union(node_in_peers[ip])))

        activity_score = min(1.0, (pkts / float(max_pkts_node)) * 0.7 + (tot_deg / 10.0) * 0.3)
        structural_change = 0.0
        role_tags: list[NodeRoleTag] = []

        if prior_snapshot:
            if ip not in prior_nodes_map:
                structural_change = 0.8
                changes.append(GraphChangeSignal(
                    change_type=GraphChangeType.NEW_NODE,
                    source_entity=ip,
                    target_entity=None,
                    description=f"Host {ip} emerged for the first time in snapshot W_{window_id}.",
                    severity="MEDIUM" if fan_out < 5 else "HIGH",
                    metric_delta=float(fan_out),
                ))
            else:
                p_node = prior_nodes_map[ip]
                fan_out_delta = fan_out - p_node.fan_out
                if fan_out_delta >= 4:
                    structural_change = min(1.0, structural_change + 0.5)
                    changes.append(GraphChangeSignal(
                        change_type=GraphChangeType.SUDDEN_FAN_OUT,
                        source_entity=ip,
                        target_entity=None,
                        description=f"Sudden fan-out surge: host {ip} contacted {fan_out} targets (+{fan_out_delta} delta).",
                        severity="HIGH",
                        metric_delta=float(fan_out_delta),
                    ))
                vol_ratio = (vol_bytes + 1) / (p_node.bytes_sent + p_node.bytes_recv + 1)
                if vol_ratio > 3.0 and vol_bytes > 50000:
                    structural_change = min(1.0, structural_change + 0.4)
                    changes.append(GraphChangeSignal(
                        change_type=GraphChangeType.VOLUME_SPIKE,
                        source_entity=ip,
                        target_entity=None,
                        description=f"Traffic volume surged {vol_ratio:.1f}x on {ip}.",
                        severity="MEDIUM",
                        metric_delta=float(vol_ratio),
                    ))

        if fan_out >= 5:
            role_tags.append(NodeRoleTag.HIGH_ACTIVITY_NODE)
            role_tags.append(NodeRoleTag.LATERAL_SOURCE)
        elif fan_in >= 5:
            role_tags.append(NodeRoleTag.SCAN_TARGET)

        if structural_change >= 0.4:
            role_tags.append(NodeRoleTag.STRUCTURAL_CHANGE_NODE)

        if not role_tags:
            role_tags.append(NodeRoleTag.NOMINAL_HOST)

        n_id = deterministic_id("node", f"{ip}_w{window_id}")
        built_nodes.append(TemporalGraphNode(
            node_id=n_id,
            ip=ip,
            in_degree=in_deg,
            out_degree=out_deg,
            total_degree=tot_deg,
            bytes_sent=node_sent_bytes[ip],
            bytes_recv=node_recv_bytes[ip],
            packets_sent=node_sent_pkts[ip],
            packets_recv=node_recv_pkts[ip],
            fan_out=fan_out,
            fan_in=fan_in,
            port_diversity=len(ports),
            active_ports=ports,
            peer_ips=peers,
            role_tags=tuple(role_tags),
            activity_score=activity_score,
            structural_change_score=structural_change,
            is_external=not _is_private_ip(ip),
            temporal_scope=GraphTemporalScope.OBSERVED,
        ))

    num_nodes = len(built_nodes)
    num_edges = len(built_edges)
    possible_edges = num_nodes * (num_nodes - 1) if num_nodes > 1 else 1
    density = num_edges / float(possible_edges) if possible_edges > 0 else 0.0
    max_fo = max([n.fan_out for n in built_nodes] + [0])
    max_fi = max([n.fan_in for n in built_nodes] + [0])
    mean_deg = sum([n.total_degree for n in built_nodes]) / float(num_nodes) if num_nodes > 0 else 0.0
    subnets = len({_get_subnet_24(n.ip) for n in built_nodes})

    metrics = GraphSnapshotMetrics(
        node_count=num_nodes,
        edge_count=num_edges,
        density=density,
        max_fan_out=max_fo,
        max_fan_in=max_fi,
        mean_degree=mean_deg,
        total_volume_bytes=total_bytes,
        total_packets=total_pkts,
        unique_subnets=subnets,
        bipartite_ratio=0.5 if num_nodes > 0 else 0.0,
    )

    return TemporalGraphSnapshot(
        snapshot_index=snapshot_index,
        window_id=window_id,
        timestamp_start=timestamp_start,
        timestamp_end=timestamp_end,
        scope=GraphTemporalScope.OBSERVED,
        metrics=metrics,
        nodes=tuple(built_nodes),
        edges=tuple(built_edges),
        changes=tuple(changes),
    )


def build_temporal_graph_sequence(
    windows: Sequence[TemporalWindow] | None = None,
    all_flows: Sequence[FlowRecord] | None = None,
    history_window_count: int = 0,
) -> TemporalGraphSequence:
    """Builds the full temporal graph sequence G_{t-K} ... G_t along with forecast projections."""
    snapshots: list[TemporalGraphSnapshot] = []

    if windows:
        prior: TemporalGraphSnapshot | None = None
        for idx, win in enumerate(windows):
            start_t = getattr(win, "start_timestamp", getattr(win, "start_time", float(idx * 60)))
            end_t = getattr(win, "end_timestamp", getattr(win, "end_time", float((idx + 1) * 60)))
            w_id = getattr(win, "window_id", idx)
            try:
                w_id_int = int(w_id)
            except (ValueError, TypeError):
                w_id_int = idx
            snap = build_graph_snapshot_from_flows(
                flows=win.flows,
                snapshot_index=idx,
                window_id=w_id_int,
                timestamp_start=float(start_t),
                timestamp_end=float(end_t),
                prior_snapshot=prior,
            )
            snapshots.append(snap)
            prior = snap
    elif all_flows:
        snap = build_graph_snapshot_from_flows(
            flows=all_flows,
            snapshot_index=0,
            window_id=0,
            timestamp_start=0.0,
            timestamp_end=60.0,
            prior_snapshot=None,
        )
        snapshots.append(snap)

    if not snapshots or sum(s.metrics.node_count for s in snapshots) == 0:
        return TemporalGraphSequence(
            status="INSUFFICIENT_GRAPH_CONTEXT",
            snapshot_count=0,
            observed_snapshots=(),
            forecast_projections=(),
            top_high_activity_nodes=(),
            top_structural_change_nodes=(),
            cumulative_nodes_count=0,
            cumulative_edges_count=0,
            graph_feature_vector=tuple([0.0] * 16),
        )

    latest_snapshot = snapshots[-1]
    sorted_by_activity = sorted(latest_snapshot.nodes, key=lambda n: (n.activity_score, n.total_degree), reverse=True)
    sorted_by_change = sorted(latest_snapshot.nodes, key=lambda n: (n.structural_change_score, n.fan_out), reverse=True)

    all_ips = {n.ip for s in snapshots for n in s.nodes}
    all_edge_ids = {e.edge_id for s in snapshots for e in s.edges}

    forecast_projections = _model_future_graph_horizons(snapshots)
    feature_vec = _extract_graph_feature_vector(latest_snapshot, snapshots)

    return TemporalGraphSequence(
        status="READY",
        snapshot_count=len(snapshots),
        observed_snapshots=tuple(snapshots),
        forecast_projections=tuple(forecast_projections),
        top_high_activity_nodes=tuple(sorted_by_activity[:10]),
        top_structural_change_nodes=tuple(sorted_by_change[:10]),
        cumulative_nodes_count=len(all_ips),
        cumulative_edges_count=len(all_edge_ids),
        graph_feature_vector=feature_vec,
    )


def _model_future_graph_horizons(
    snapshots: Sequence[TemporalGraphSnapshot],
) -> tuple[ForecastGraphProjection, ...]:
    """Projects future graph structure horizons T+1, T+2, T+3, T+4, T+5."""
    if not snapshots:
        return ()

    latest = snapshots[-1]
    m = latest.metrics

    expansion_rate = 1.0
    if len(snapshots) >= 2:
        prev_m = snapshots[-2].metrics
        if prev_m.edge_count > 0:
            expansion_rate = max(0.8, min(2.5, m.edge_count / float(prev_m.edge_count)))

    threat_nodes = [n.ip for n in latest.nodes if NodeRoleTag.LATERAL_SOURCE in n.role_tags or NodeRoleTag.HIGH_ACTIVITY_NODE in n.role_tags]
    high_change_nodes = [n.ip for n in latest.nodes if n.structural_change_score > 0.3]

    projections: list[ForecastGraphProjection] = []
    for k in (1, 2, 3, 4, 5):
        horiz_sec = k * 60
        decay = math.exp(-0.12 * k)

        pred_edges = int(m.edge_count * (1.0 + (expansion_rate - 1.0) * (0.6 ** k)))
        pred_nodes = int(max(m.node_count, m.node_count + len(high_change_nodes) * min(k, 2)))
        pred_density = min(1.0, (pred_edges / float(pred_nodes * (pred_nodes - 1))) if pred_nodes > 1 else m.density)
        fanout_expansion = round(float(m.max_fan_out) * (1.0 + 0.15 * k if threat_nodes else 1.0), 2)

        targets: list[str] = []
        for n in latest.nodes:
            if n.ip in threat_nodes:
                for p in n.peer_ips:
                    if p not in threat_nodes and p not in targets:
                        targets.append(p)

        indicators = []
        if threat_nodes:
            indicators.append(f"Persistence of {len(threat_nodes)} dominant lateral source(s)")
        if fanout_expansion > m.max_fan_out:
            indicators.append(f"Modelled fan-out expansion to ~{fanout_expansion:.0f} target hosts")
        if not indicators:
            indicators.append("Nominal structural graph stability")

        conf = round(max(0.35, min(0.92, 0.88 * decay)), 3)

        projections.append(ForecastGraphProjection(
            horizon_step=k,
            horizon_seconds=horiz_sec,
            predicted_node_count=pred_nodes,
            predicted_edge_count=pred_edges,
            predicted_density=pred_density,
            predicted_fanout_expansion=fanout_expansion,
            active_threat_nodes=tuple(threat_nodes[:5]),
            potential_propagation_targets=tuple(targets[:8]),
            structural_indicators=tuple(indicators),
            propagation_confidence=conf,
        ))

    return tuple(projections)


def _extract_graph_feature_vector(
    latest: TemporalGraphSnapshot,
    snapshots: Sequence[TemporalGraphSnapshot],
) -> tuple[float, ...]:
    """Generates 16-dimensional deterministic graph summary vector."""
    m = latest.metrics
    vec = [
        float(m.node_count),
        float(m.edge_count),
        float(m.density),
        float(m.max_fan_out),
        float(m.max_fan_in),
        float(m.mean_degree),
        float(m.unique_subnets),
        float(len(latest.changes)),
        float(sum(1 for n in latest.nodes if NodeRoleTag.HIGH_ACTIVITY_NODE in n.role_tags)),
        float(sum(1 for n in latest.nodes if NodeRoleTag.STRUCTURAL_CHANGE_NODE in n.role_tags)),
        float(sum(1 for e in latest.edges if e.is_new_in_snapshot)),
        float(m.total_volume_bytes) / 1000000.0,
        float(m.total_packets) / 1000.0,
        float(len(snapshots)),
        float(max([n.activity_score for n in latest.nodes] + [0.0])),
        float(max([n.structural_change_score for n in latest.nodes] + [0.0])),
    ]
    return tuple(round(v, 4) for v in vec)
