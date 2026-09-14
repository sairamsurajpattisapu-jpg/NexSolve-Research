"""Temporal Network World Model & Intelligence State Engine for NexSolve.

Maintains a comprehensive, deterministic, time-evolving temporal network world state:
- What entities existed and when they were observed (first_seen, last_seen, active_windows)
- Communication relationships, status (NEW, PERSISTED, NOT_OBSERVED_IN_WINDOW)
- Behavior signals, deviations, changes between consecutive windows
- Inferred attack states, attack kinematics, behavioral episodes
- Evidence graph bindings and incident correlation linkages
- Downstream forecast context (strictly separated from historical ground truth)
- Temporal diffing between arbitrary windows
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from nexsolve_core.behavior.change_detection import BehaviorChangeSignal
from nexsolve_core.behavior.episodes import BehavioralEpisode
from nexsolve_core.graph.models import deterministic_id
from nexsolve_core.temporal.entity_history import TemporalEntityHistory

if TYPE_CHECKING:
    from nexsolve_core.intelligence.attack_state import InferredAttackState
    from nexsolve_core.intelligence.threat_view import ThreatCentricView


class RelationshipStatus(str, Enum):
    """Lifecycle status of a communication relationship in a temporal window."""
    NEW = "NEW"
    PERSISTED = "PERSISTED"
    NOT_OBSERVED_IN_WINDOW = "NOT_OBSERVED_IN_WINDOW"
    LAST_OBSERVED_AT_CAPTURE_BOUNDARY = "LAST_OBSERVED_AT_CAPTURE_BOUNDARY"


class EntityWindowPresence(str, Enum):
    """Observation status of an entity within a specific temporal window."""
    ACTIVE = "ACTIVE"
    NOT_OBSERVED_IN_WINDOW = "NOT_OBSERVED_IN_WINDOW"
    NEWLY_EMERGED = "NEWLY_EMERGED"
    LAST_OBSERVED_AT_CAPTURE_BOUNDARY = "LAST_OBSERVED_AT_CAPTURE_BOUNDARY"


@dataclass(frozen=True)
class EntityTemporalState:
    """State of an entity within or across temporal windows."""
    entity_key: str
    entity_type: str  # "IP", "SUBNET", "PORT"
    presence: EntityWindowPresence
    window_index: int
    attack_state: str  # e.g., "RECONNAISSANCE", "LATERAL_MOVEMENT", "BENIGN", "SUSPICIOUS"
    fanout: int
    port_diversity: int
    bytes_sent: int
    bytes_recv: int
    packets: int
    failure_ratio: float
    active_peers: tuple[str, ...]
    active_ports: tuple[int, ...]
    is_expanding_peers: bool = False
    is_expanding_ports: bool = False
    associated_findings_count: int = 0
    composite_risk_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_key": self.entity_key,
            "entity_type": self.entity_type,
            "presence": self.presence.value,
            "window_index": self.window_index,
            "attack_state": self.attack_state,
            "fanout": self.fanout,
            "port_diversity": self.port_diversity,
            "bytes_sent": self.bytes_sent,
            "bytes_recv": self.bytes_recv,
            "packets": self.packets,
            "failure_ratio": round(self.failure_ratio, 3),
            "active_peers": list(self.active_peers),
            "active_ports": list(self.active_ports),
            "is_expanding_peers": self.is_expanding_peers,
            "is_expanding_ports": self.is_expanding_ports,
            "associated_findings_count": self.associated_findings_count,
            "composite_risk_score": round(self.composite_risk_score, 2),
        }


@dataclass(frozen=True)
class RelationshipTemporalState:
    """Directed communication relationship between two entities."""
    relationship_id: str
    src_entity: str
    dst_entity: str
    dst_port: int | None
    protocol: str
    status: RelationshipStatus
    first_seen_window: int
    last_seen_window: int
    window_index: int
    packet_count: int
    byte_count: int
    connection_count: int
    failed_attempts: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "relationship_id": self.relationship_id,
            "src_entity": self.src_entity,
            "dst_entity": self.dst_entity,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "status": self.status.value,
            "first_seen_window": self.first_seen_window,
            "last_seen_window": self.last_seen_window,
            "window_index": self.window_index,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "connection_count": self.connection_count,
            "failed_attempts": self.failed_attempts,
        }


@dataclass(frozen=True)
class TemporalNetworkWindow:
    """Summary of a specific temporal time slice in the network world."""
    window_id: str
    sequence_index: int
    start_time: float
    end_time: float
    duration_seconds: float
    packet_count: int
    flow_count: int
    tcp_retransmission_rate: float
    active_entity_count: int
    active_relationship_count: int
    change_signals_count: int
    dominant_attack_stage: str | None
    is_capture_boundary: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "sequence_index": self.sequence_index,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration_seconds, 2),
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "tcp_retransmission_rate": round(self.tcp_retransmission_rate, 4),
            "active_entity_count": self.active_entity_count,
            "active_relationship_count": self.active_relationship_count,
            "change_signals_count": self.change_signals_count,
            "dominant_attack_stage": self.dominant_attack_stage,
            "is_capture_boundary": self.is_capture_boundary,
        }


@dataclass(frozen=True)
class WorldStateSnapshot:
    """Full deterministic state snapshot of the network at window index w."""
    window_index: int
    window_id: str
    start_time: float
    end_time: float
    duration_seconds: float
    packet_count: int
    flow_count: int
    entities: dict[str, EntityTemporalState]  # entity_key -> state
    relationships: dict[str, RelationshipTemporalState]  # rel_id -> state
    behavior_changes: tuple[dict[str, Any], ...]
    attack_states: tuple[dict[str, Any], ...]
    evidence_keys: tuple[str, ...]
    is_capture_boundary: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_index": self.window_index,
            "window_id": self.window_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration_seconds": round(self.duration_seconds, 2),
            "packet_count": self.packet_count,
            "flow_count": self.flow_count,
            "entities": {k: v.to_dict() for k, v in self.entities.items()},
            "relationships": {k: v.to_dict() for k, v in self.relationships.items()},
            "behavior_changes": list(self.behavior_changes),
            "attack_states": list(self.attack_states),
            "evidence_keys": list(self.evidence_keys),
            "is_capture_boundary": self.is_capture_boundary,
        }


@dataclass(frozen=True)
class WorldStateDiff:
    """Deterministic diff between two world state snapshots A and B."""
    window_a: int
    window_b: int
    entities_added: tuple[str, ...]
    entities_persisted: tuple[str, ...]
    entities_not_observed: tuple[str, ...]
    relationships_added: tuple[str, ...]
    relationships_not_observed: tuple[str, ...]
    attack_state_transitions: tuple[dict[str, Any], ...]
    fanout_surges: tuple[dict[str, Any], ...]
    volume_deltas: tuple[dict[str, Any], ...]
    new_evidence_keys: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_a": self.window_a,
            "window_b": self.window_b,
            "entities_added": list(self.entities_added),
            "entities_persisted": list(self.entities_persisted),
            "entities_not_observed": list(self.entities_not_observed),
            "relationships_added": list(self.relationships_added),
            "relationships_not_observed": list(self.relationships_not_observed),
            "attack_state_transitions": list(self.attack_state_transitions),
            "fanout_surges": list(self.fanout_surges),
            "volume_deltas": list(self.volume_deltas),
            "new_evidence_keys": list(self.new_evidence_keys),
        }


@dataclass(frozen=True)
class TemporalNetworkWorldState:
    """Unified Temporal Network World State representation for the entire capture."""
    capture_id: str
    total_windows: int
    total_packets: int
    total_flows: int
    duration_seconds: float
    windows: tuple[TemporalNetworkWindow, ...]
    snapshots: dict[int, WorldStateSnapshot]  # window_index -> snapshot
    entity_trajectories: dict[str, tuple[int, ...]]  # entity_key -> active windows
    relationship_trajectories: dict[str, tuple[int, ...]]  # rel_id -> active windows
    episodes: tuple[BehavioralEpisode, ...]
    attack_states: tuple[InferredAttackState, ...]
    threat_views: tuple[ThreatCentricView, ...]
    change_signals: tuple[BehaviorChangeSignal, ...]
    forecast_points: tuple[dict[str, Any], ...]
    graph_summary: dict[str, int]
    incident_story_id: str | None = None
    campaign_cluster_count: int = 0

    def get_snapshot(self, window_index: int) -> WorldStateSnapshot | None:
        return self.snapshots.get(window_index)

    def diff_windows(self, window_a: int, window_b: int) -> WorldStateDiff:
        return diff_snapshots(
            self.snapshots.get(window_a),
            self.snapshots.get(window_b),
            window_a,
            window_b,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "capture_id": self.capture_id,
            "total_windows": self.total_windows,
            "total_packets": self.total_packets,
            "total_flows": self.total_flows,
            "duration_seconds": round(self.duration_seconds, 2),
            "windows": [w.to_dict() for w in self.windows],
            "snapshots": {str(k): v.to_dict() for k, v in self.snapshots.items()},
            "entity_trajectories": {k: list(v) for k, v in self.entity_trajectories.items()},
            "relationship_trajectories": {k: list(v) for k, v in self.relationship_trajectories.items()},
            "episodes": [e.to_dict() for e in self.episodes],
            "attack_states": [s.to_dict() for s in self.attack_states],
            "threat_views": [t.to_dict() for t in self.threat_views],
            "change_signals": [c.to_dict() for c in self.change_signals],
            "forecast_points": list(self.forecast_points),
            "graph_summary": self.graph_summary,
            "incident_story_id": self.incident_story_id,
            "campaign_cluster_count": self.campaign_cluster_count,
        }


def diff_snapshots(
    snap_a: WorldStateSnapshot | None,
    snap_b: WorldStateSnapshot | None,
    idx_a: int,
    idx_b: int,
) -> WorldStateDiff:
    """Compute the deterministic difference between two snapshots A and B."""
    if snap_a is None and snap_b is None:
        return WorldStateDiff(idx_a, idx_b, (), (), (), (), (), (), (), (), ())

    ents_a = snap_a.entities if snap_a else {}
    ents_b = snap_b.entities if snap_b else {}
    rels_a = snap_a.relationships if snap_a else {}
    rels_b = snap_b.relationships if snap_b else {}

    keys_a = set(ents_a.keys())
    keys_b = set(ents_b.keys())

    added_entities = sorted(list(keys_b - keys_a))
    persisted_entities = sorted(list(keys_b & keys_a))
    not_observed_entities = sorted(list(keys_a - keys_b))

    rel_keys_a = set(rels_a.keys())
    rel_keys_b = set(rels_b.keys())
    added_relationships = sorted(list(rel_keys_b - rel_keys_a))
    not_observed_relationships = sorted(list(rel_keys_a - rel_keys_b))

    # Detect attack state transitions
    attack_state_transitions: list[dict[str, Any]] = []
    for ent in persisted_entities:
        state_a = ents_a[ent].attack_state
        state_b = ents_b[ent].attack_state
        if state_a != state_b:
            attack_state_transitions.append({
                "entity": ent,
                "from_state": state_a,
                "to_state": state_b,
                "from_window": idx_a,
                "to_window": idx_b,
            })

    # Detect fanout surges
    fanout_surges: list[dict[str, Any]] = []
    for ent in persisted_entities:
        fo_a = ents_a[ent].fanout
        fo_b = ents_b[ent].fanout
        if fo_b > fo_a and (fo_b - fo_a >= 3 or (fo_a > 0 and fo_b / fo_a >= 2.0)):
            fanout_surges.append({
                "entity": ent,
                "baseline_fanout": fo_a,
                "current_fanout": fo_b,
                "increase": fo_b - fo_a,
            })

    # Volume deltas
    volume_deltas: list[dict[str, Any]] = []
    for ent in persisted_entities:
        pkts_a = ents_a[ent].packets
        pkts_b = ents_b[ent].packets
        bytes_a = ents_a[ent].bytes_sent + ents_a[ent].bytes_recv
        bytes_b = ents_b[ent].bytes_sent + ents_b[ent].bytes_recv
        if pkts_b != pkts_a or bytes_b != bytes_a:
            volume_deltas.append({
                "entity": ent,
                "delta_packets": pkts_b - pkts_a,
                "delta_bytes": bytes_b - bytes_a,
            })

    # New evidence
    ev_a = set(snap_a.evidence_keys) if snap_a else set()
    ev_b = set(snap_b.evidence_keys) if snap_b else set()
    new_evidence = sorted(list(ev_b - ev_a))

    return WorldStateDiff(
        window_a=idx_a,
        window_b=idx_b,
        entities_added=tuple(added_entities),
        entities_persisted=tuple(persisted_entities),
        entities_not_observed=tuple(not_observed_entities),
        relationships_added=tuple(added_relationships),
        relationships_not_observed=tuple(not_observed_relationships),
        attack_state_transitions=tuple(attack_state_transitions),
        fanout_surges=tuple(fanout_surges),
        volume_deltas=tuple(volume_deltas),
        new_evidence_keys=tuple(new_evidence),
    )


def build_temporal_network_world_state(
    capture_id: str,
    windows: Sequence[Any],
    flows: Sequence[Any] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    entity_histories: Mapping[str, TemporalEntityHistory] | None = None,
    entity_profiles: Mapping[str, Any] | None = None,
    attack_states: Sequence[InferredAttackState] | None = None,
    threat_views: Sequence[ThreatCentricView] | None = None,
    episodes: Sequence[BehavioralEpisode] | None = None,
    change_signals: Sequence[BehaviorChangeSignal] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
    evidence_graph: Any | None = None,
    threat_assessment: Any | None = None,
    incident_story: Any | None = None,
    campaign_clusters: Sequence[Any] | None = None,
) -> TemporalNetworkWorldState:
    """Deterministic builder for the complete Temporal Network World State."""
    flows = flows or ()
    tcp_sessions = tcp_sessions or ()
    entity_histories = entity_histories or {}
    entity_profiles = entity_profiles or {}
    attack_states = attack_states or ()
    threat_views = threat_views or ()
    episodes = episodes or ()
    change_signals = change_signals or ()
    forecast_points = forecast_points or ()
    campaign_clusters = campaign_clusters or ()

    num_windows = len(windows)
    max_window_idx = max(num_windows - 1, 0)

    # Index attack states by (entity, window_index) and entity overall
    entity_attack_state_map: dict[str, str] = {}
    for st in attack_states:
        ent = getattr(st, "entity", None)
        phase = getattr(st, "attack_phase", None)
        if ent and phase:
            phase_val = phase.value if hasattr(phase, "value") else str(phase)
            entity_attack_state_map[ent] = phase_val

    # Group flows and sessions by window_index
    window_flows: dict[int, list[Any]] = {i: [] for i in range(num_windows)}
    for fl in flows:
        w_idx = fl.get("window_index", 0) if isinstance(fl, dict) else (getattr(fl, "window_index", 0) or 0)
        if 0 <= w_idx < num_windows:
            window_flows[w_idx].append(fl)

    window_sessions: dict[int, list[Any]] = {i: [] for i in range(num_windows)}
    for s in tcp_sessions:
        w_idx = getattr(s, "window_index", 0) or 0
        if 0 <= w_idx < num_windows:
            window_sessions[w_idx].append(s)

    # Group change signals by window_after
    window_changes: dict[int, list[dict[str, Any]]] = {i: [] for i in range(num_windows)}
    for ch in change_signals:
        w_after = getattr(ch, "window_after", None)
        if w_after is not None and 0 <= w_after < num_windows:
            window_changes[w_after].append(ch.to_dict())

    # Map relationships across windows
    # (src, dst, port, proto) -> { "first_seen": int, "last_seen": int, "windows": set() }
    rel_first_seen: dict[str, int] = {}
    rel_last_seen: dict[str, int] = {}
    rel_active_windows: dict[str, set[int]] = {}

    # Pre-pass to compute first_seen and last_seen for all relationships
    for w_idx in range(num_windows):
        for fl in window_flows[w_idx]:
            src = fl.get("src_ip") if isinstance(fl, dict) else getattr(fl, "src_ip", None)
            dst = fl.get("dst_ip") if isinstance(fl, dict) else getattr(fl, "dst_ip", None)
            port = fl.get("dst_port") if isinstance(fl, dict) else getattr(fl, "dst_port", None)
            proto = fl.get("protocol", "TCP") if isinstance(fl, dict) else getattr(fl, "protocol", "TCP")
            if src and dst:
                rel_id = f"{src}->{dst}:{port or 0}/{proto}"
                if rel_id not in rel_first_seen:
                    rel_first_seen[rel_id] = w_idx
                rel_last_seen[rel_id] = w_idx
                rel_active_windows.setdefault(rel_id, set()).add(w_idx)

    # Compute entity trajectories
    entity_trajectories: dict[str, list[int]] = {}
    for ent, hist in entity_histories.items():
        entity_trajectories[ent] = list(hist.active_windows)

    # Build snapshots per window
    snapshots: dict[int, WorldStateSnapshot] = {}
    window_summaries: list[TemporalNetworkWindow] = []

    total_packets_all = 0
    total_flows_all = 0
    total_duration = 0.0

    for w_idx, win in enumerate(windows):
        w_id = getattr(win, "window_id", f"win_{w_idx}")
        start_t = getattr(win, "start_timestamp", float(w_idx * 60))
        end_t = getattr(win, "end_timestamp", float((w_idx + 1) * 60))
        duration = float(end_t - start_t)
        total_duration += duration

        w_fls = window_flows[w_idx]
        w_sess = window_sessions[w_idx]
        pkts_in_win = sum(f.get("packets", 1) if isinstance(f, dict) else getattr(f, "packets", 1) for f in w_fls)
        total_packets_all += pkts_in_win
        total_flows_all += len(w_fls)

        is_boundary = (w_idx == max_window_idx)

        # Build entities active in this window
        window_entities: dict[str, EntityTemporalState] = {}
        ent_stats: dict[str, dict[str, Any]] = {}

        for fl in w_fls:
            src = fl.get("src_ip") if isinstance(fl, dict) else getattr(fl, "src_ip", None)
            dst = fl.get("dst_ip") if isinstance(fl, dict) else getattr(fl, "dst_ip", None)
            port = fl.get("dst_port") if isinstance(fl, dict) else getattr(fl, "dst_port", None)
            pkts = fl.get("packets", 1) if isinstance(fl, dict) else getattr(fl, "packets", 1)
            byts = fl.get("bytes", 0) if isinstance(fl, dict) else getattr(fl, "bytes", 0)

            for ip, is_src in ((src, True), (dst, False)):
                if not ip:
                    continue
                if ip not in ent_stats:
                    ent_stats[ip] = {
                        "peers": set(),
                        "ports": set(),
                        "bytes_sent": 0,
                        "bytes_recv": 0,
                        "packets": 0,
                        "failures": 0,
                        "sessions": 0,
                    }
                ent_stats[ip]["packets"] += pkts
                if is_src:
                    ent_stats[ip]["bytes_sent"] += byts
                    if dst:
                        ent_stats[ip]["peers"].add(dst)
                    if port:
                        ent_stats[ip]["ports"].add(int(port))
                else:
                    ent_stats[ip]["bytes_recv"] += byts
                    if src:
                        ent_stats[ip]["peers"].add(src)

        for s in w_sess:
            src = getattr(s, "src_ip", None)
            dst = getattr(s, "dst_ip", None)
            state = getattr(s, "state", "OTH")
            is_fail = state in ("REJ", "RSTOS0", "RSTR", "OTH")
            for ip in (src, dst):
                if ip and ip in ent_stats:
                    ent_stats[ip]["sessions"] += 1
                    if is_fail:
                        ent_stats[ip]["failures"] += 1

        for ip, stats in ent_stats.items():
            hist = entity_histories.get(ip)
            first_seen = hist.first_seen_window if hist else w_idx
            last_seen = hist.last_seen_window if hist else w_idx

            if is_boundary and last_seen == w_idx:
                presence = EntityWindowPresence.LAST_OBSERVED_AT_CAPTURE_BOUNDARY
            elif first_seen == w_idx:
                presence = EntityWindowPresence.NEWLY_EMERGED
            else:
                presence = EntityWindowPresence.ACTIVE

            prof = entity_profiles.get(ip)
            risk = getattr(prof, "composite_risk_score", 0.0) if prof else 0.0
            findings_cnt = hist.findings_count if hist else 0
            fail_ratio = (stats["failures"] / stats["sessions"]) if stats["sessions"] > 0 else 0.0

            window_entities[ip] = EntityTemporalState(
                entity_key=ip,
                entity_type="IP",
                presence=presence,
                window_index=w_idx,
                attack_state=entity_attack_state_map.get(ip, "BENIGN"),
                fanout=len(stats["peers"]),
                port_diversity=len(stats["ports"]),
                bytes_sent=stats["bytes_sent"],
                bytes_recv=stats["bytes_recv"],
                packets=stats["packets"],
                failure_ratio=fail_ratio,
                active_peers=tuple(sorted(stats["peers"])),
                active_ports=tuple(sorted(stats["ports"])),
                is_expanding_peers=len(stats["peers"]) >= 5,
                is_expanding_ports=len(stats["ports"]) >= 5,
                associated_findings_count=findings_cnt,
                composite_risk_score=float(risk),
            )

        # Build relationships active in this window
        window_relationships: dict[str, RelationshipTemporalState] = {}
        rel_stats: dict[str, dict[str, Any]] = {}

        for fl in w_fls:
            src = fl.get("src_ip") if isinstance(fl, dict) else getattr(fl, "src_ip", None)
            dst = fl.get("dst_ip") if isinstance(fl, dict) else getattr(fl, "dst_ip", None)
            port = fl.get("dst_port") if isinstance(fl, dict) else getattr(fl, "dst_port", None)
            proto = fl.get("protocol", "TCP") if isinstance(fl, dict) else getattr(fl, "protocol", "TCP")
            pkts = fl.get("packets", 1) if isinstance(fl, dict) else getattr(fl, "packets", 1)
            byts = fl.get("bytes", 0) if isinstance(fl, dict) else getattr(fl, "bytes", 0)

            if src and dst:
                rel_id = f"{src}->{dst}:{port or 0}/{proto}"
                if rel_id not in rel_stats:
                    rel_stats[rel_id] = {
                        "src": src,
                        "dst": dst,
                        "port": port,
                        "proto": proto,
                        "pkts": 0,
                        "byts": 0,
                        "conns": 0,
                        "fails": 0,
                    }
                rel_stats[rel_id]["pkts"] += pkts
                rel_stats[rel_id]["byts"] += byts
                rel_stats[rel_id]["conns"] += 1

        for rel_id, rdata in rel_stats.items():
            fseen = rel_first_seen.get(rel_id, w_idx)
            lseen = rel_last_seen.get(rel_id, w_idx)

            if is_boundary and lseen == w_idx:
                status = RelationshipStatus.LAST_OBSERVED_AT_CAPTURE_BOUNDARY
            elif fseen == w_idx:
                status = RelationshipStatus.NEW
            else:
                status = RelationshipStatus.PERSISTED

            window_relationships[rel_id] = RelationshipTemporalState(
                relationship_id=rel_id,
                src_entity=rdata["src"],
                dst_entity=rdata["dst"],
                dst_port=rdata["port"],
                protocol=rdata["proto"],
                status=status,
                first_seen_window=fseen,
                last_seen_window=lseen,
                window_index=w_idx,
                packet_count=rdata["pkts"],
                byte_count=rdata["byts"],
                connection_count=rdata["conns"],
                failed_attempts=rdata["fails"],
            )

        # Evidence keys in this window
        ev_keys: list[str] = []
        if threat_assessment and hasattr(threat_assessment, "evidence"):
            for ev in threat_assessment.evidence:
                if getattr(ev, "window_index", None) == w_idx:
                    ev_keys.append(getattr(ev, "evidence_id", f"ev_{w_idx}"))

        # Snapshot
        snapshot = WorldStateSnapshot(
            window_index=w_idx,
            window_id=w_id,
            start_time=start_t,
            end_time=end_t,
            duration_seconds=duration,
            packet_count=pkts_in_win,
            flow_count=len(w_fls),
            entities=window_entities,
            relationships=window_relationships,
            behavior_changes=tuple(window_changes[w_idx]),
            attack_states=tuple([s.to_dict() for s in attack_states if getattr(s, "window_index", -1) == w_idx]),
            evidence_keys=tuple(ev_keys),
            is_capture_boundary=is_boundary,
        )
        snapshots[w_idx] = snapshot

        # Window summary
        tcp_retrans = getattr(win, "tcp_retransmission_rate", 0.0)
        dominant_stage = None
        for st in attack_states:
            if getattr(st, "window_index", -1) == w_idx:
                p = getattr(st, "attack_phase", None)
                dominant_stage = p.value if hasattr(p, "value") else str(p)
                break

        window_summaries.append(
            TemporalNetworkWindow(
                window_id=w_id,
                sequence_index=w_idx,
                start_time=start_t,
                end_time=end_t,
                duration_seconds=duration,
                packet_count=pkts_in_win,
                flow_count=len(w_fls),
                tcp_retransmission_rate=float(tcp_retrans),
                active_entity_count=len(window_entities),
                active_relationship_count=len(window_relationships),
                change_signals_count=len(window_changes[w_idx]),
                dominant_attack_stage=dominant_stage,
                is_capture_boundary=is_boundary,
            )
        )

    # Graph summary
    graph_summary = {
        "nodes": getattr(evidence_graph, "node_count", 0),
        "edges": getattr(evidence_graph, "edge_count", 0),
        "chains": len(getattr(evidence_graph, "chains", ())),
    }

    story_id = getattr(incident_story, "story_id", None) if incident_story else None

    return TemporalNetworkWorldState(
        capture_id=capture_id,
        total_windows=num_windows,
        total_packets=total_packets_all,
        total_flows=total_flows_all,
        duration_seconds=total_duration,
        windows=tuple(window_summaries),
        snapshots=snapshots,
        entity_trajectories={k: tuple(v) for k, v in entity_trajectories.items()},
        relationship_trajectories={k: tuple(sorted(v)) for k, v in rel_active_windows.items()},
        episodes=tuple(episodes),
        attack_states=tuple(attack_states),
        threat_views=tuple(threat_views),
        change_signals=tuple(change_signals),
        forecast_points=tuple(dict(p) for p in forecast_points),
        graph_summary=graph_summary,
        incident_story_id=story_id,
        campaign_cluster_count=len(campaign_clusters),
    )
