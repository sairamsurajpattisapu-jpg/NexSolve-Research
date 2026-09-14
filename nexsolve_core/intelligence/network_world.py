"""Network World State Runtime Object.

Represents a comprehensive snapshot of the evaluated network:
- Temporal metadata (timestamp, window indices, duration)
- Active entities & communication pairs
- Flow and TCP session summaries
- Multi-modal behavioral and protocol signals
- Inferred attack states and behavioral episodes
- Evidence intelligence graph integration
- World-model forecast signals and progression projections
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from nexsolve_core.behavior.episodes import BehavioralEpisode
from nexsolve_core.behavior.change_detection import BehaviorChangeSignal
from nexsolve_core.temporal.entity_history import TemporalEntityHistory
from nexsolve_core.intelligence.attack_state import InferredAttackState
from nexsolve_core.intelligence.threat_view import ThreatCentricView


from nexsolve_core.temporal.world_state import (
    EntityTemporalState,
    EntityWindowPresence,
    RelationshipStatus,
    RelationshipTemporalState,
    TemporalNetworkWindow,
    TemporalNetworkWorldState,
    WorldStateDiff,
    WorldStateSnapshot,
    build_temporal_network_world_state,
    diff_snapshots,
)


@dataclass(frozen=True)
class NetworkWorldState:
    """Consolidated runtime state of the entire network capture and intelligence layer."""
    capture_id: str
    total_packets: int
    total_flows: int
    total_windows: int
    duration_seconds: float
    active_entity_count: int
    active_session_count: int
    episodes: tuple[BehavioralEpisode, ...]
    attack_states: tuple[InferredAttackState, ...]
    threat_views: tuple[ThreatCentricView, ...]
    change_signals: tuple[BehaviorChangeSignal, ...]
    forecast_points: tuple[dict[str, Any], ...]
    graph_node_count: int
    graph_edge_count: int
    graph_chain_count: int
    temporal_world_state: TemporalNetworkWorldState | None = None

    def to_dict(self) -> dict[str, Any]:
        res: dict[str, Any] = {
            "capture_id": self.capture_id,
            "total_packets": self.total_packets,
            "total_flows": self.total_flows,
            "total_windows": self.total_windows,
            "duration_seconds": round(self.duration_seconds, 2),
            "active_entity_count": self.active_entity_count,
            "active_session_count": self.active_session_count,
            "episodes": [e.to_dict() for e in self.episodes],
            "attack_states": [s.to_dict() for s in self.attack_states],
            "threat_views": [t.to_dict() for t in self.threat_views],
            "change_signals": [c.to_dict() for c in self.change_signals],
            "forecast_points": list(self.forecast_points),
            "graph_summary": {
                "nodes": self.graph_node_count,
                "edges": self.graph_edge_count,
                "chains": self.graph_chain_count,
            },
        }
        if self.temporal_world_state:
            res["temporal_world_state"] = self.temporal_world_state.to_dict()
        return res


def build_network_world_state(
    capture_id: str,
    total_packets: int,
    total_flows: int,
    total_windows: int,
    duration_seconds: float,
    entity_histories: Mapping[str, TemporalEntityHistory],
    episodes: Sequence[BehavioralEpisode],
    attack_states: Sequence[InferredAttackState],
    threat_views: Sequence[ThreatCentricView],
    change_signals: Sequence[BehaviorChangeSignal],
    forecast_points: Sequence[Mapping[str, Any]],
    evidence_graph: Any,
    windows: Sequence[Any] | None = None,
    flows: Sequence[Any] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    entity_profiles: Mapping[str, Any] | None = None,
    threat_assessment: Any | None = None,
    incident_story: Any | None = None,
    campaign_clusters: Sequence[Any] | None = None,
) -> NetworkWorldState:
    """Build unified NetworkWorldState snapshot and TemporalNetworkWorldState."""
    temp_world: TemporalNetworkWorldState | None = None
    if windows is not None:
        temp_world = build_temporal_network_world_state(
            capture_id=capture_id,
            windows=windows,
            flows=flows,
            tcp_sessions=tcp_sessions,
            entity_histories=entity_histories,
            entity_profiles=entity_profiles,
            attack_states=attack_states,
            threat_views=threat_views,
            episodes=episodes,
            change_signals=change_signals,
            forecast_points=forecast_points,
            evidence_graph=evidence_graph,
            threat_assessment=threat_assessment,
            incident_story=incident_story,
            campaign_clusters=campaign_clusters,
        )

    return NetworkWorldState(
        capture_id=capture_id,
        total_packets=total_packets,
        total_flows=total_flows,
        total_windows=total_windows,
        duration_seconds=duration_seconds,
        active_entity_count=len(entity_histories),
        active_session_count=sum(h.session_count for h in entity_histories.values()),
        episodes=tuple(episodes),
        attack_states=tuple(attack_states),
        threat_views=tuple(threat_views),
        change_signals=tuple(change_signals),
        forecast_points=tuple(dict(p) for p in forecast_points),
        graph_node_count=getattr(evidence_graph, "node_count", 0),
        graph_edge_count=getattr(evidence_graph, "edge_count", 0),
        graph_chain_count=len(getattr(evidence_graph, "chains", ())),
        temporal_world_state=temp_world,
    )

