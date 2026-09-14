import pytest
import numpy as np
from typing import List, Dict, Any

from nexsolve_core.behavior.episodes import (
    BehavioralEpisode,
    EpisodeSeverity,
    build_behavioral_episodes,
)
from nexsolve_core.temporal.entity_history import (
    TemporalEntityHistory,
    build_temporal_entity_histories,
)
from nexsolve_core.behavior.change_detection import (
    BehaviorChangeSignal,
    ChangeType,
    detect_behavior_changes,
)
from nexsolve_core.intelligence.attack_state import (
    AttackStateEnum,
    InferredAttackState,
    infer_attack_states,
)
from nexsolve_core.intelligence.threat_view import (
    ThreatCentricView,
    build_threat_centric_views,
)
from nexsolve_core.intelligence.network_world import (
    NetworkWorldState,
    build_network_world_state,
)
from nexsolve_core.graph.models import GraphNode, GraphEdge, NodeType, EdgeType, Scope
from nexsolve_core.graph.graph import EvidenceGraph


class DummySession:
    def __init__(self, src_ip, dst_ip, dst_port, window_index=0, state="ESTABLISHED", packet_count=10, byte_count=1000):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.window_index = window_index
        self.state = state
        self.packet_count = packet_count
        self.byte_count = byte_count


def test_behavioral_episodes_generation():
    """Verify grouping and severity calculation for behavioral episodes."""
    findings = [
        {
            "finding_id": "find-01",
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "attack_category": "Reconnaissance Port Scan",
            "window_index": 0,
            "severity": "HIGH",
        },
        {
            "finding_id": "find-02",
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "attack_category": "Reconnaissance Sweep",
            "window_index": 1,
            "severity": "CRITICAL",
        },
        {
            "finding_id": "find-03",
            "source_ip": "10.0.0.99",
            "destination_ip": "172.16.0.5",
            "attack_category": "Anomaly",
            "window_index": 2,
            "severity": "LOW",
        }
    ]

    episodes = build_behavioral_episodes(observed_findings=findings)
    assert len(episodes) >= 2

    # Episode targeting 10.0.0.1
    ep1 = [e for e in episodes if e.primary_entity == "10.0.0.1"][0]
    assert ep1.start_window == 0
    assert ep1.end_window == 1
    assert ep1.severity == EpisodeSeverity.HIGH
    assert "T1046" in ep1.mitre_techniques


def test_temporal_entity_tracking():
    """Verify temporal aggregation across observation windows for entities."""
    flows = [
        {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.1", "dst_port": 80, "bytes": 500, "packets": 5, "window_index": 0},
        {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.2", "dst_port": 443, "bytes": 1200, "packets": 10, "window_index": 0},
        {"src_ip": "192.168.1.100", "dst_ip": "10.0.0.3", "dst_port": 8080, "bytes": 800, "packets": 8, "window_index": 1},
    ]

    histories = build_temporal_entity_histories(flows=flows)
    assert "192.168.1.100" in histories

    h = histories["192.168.1.100"]
    assert h.entity_key == "192.168.1.100"
    assert len(h.active_windows) == 2
    assert h.total_bytes == 2500
    assert h.total_packets == 23
    assert len(h.unique_peers) == 3
    assert len(h.unique_ports) == 3
    assert 80 in h.unique_ports
    assert 443 in h.unique_ports
    assert 8080 in h.unique_ports


def test_behavior_change_detection():
    """Verify detection of significant changes in entity fan-out, volume, or error rates."""
    sessions = []
    # Window 0: 1 session to port 80
    sessions.append(DummySession("192.168.1.200", "10.0.0.1", 80, window_index=0))

    # Window 1: 15 sessions across 10 distinct ports -> PORT_FANOUT_SURGE and CONN_SURGE
    for p in range(100, 110):
        sessions.append(DummySession("192.168.1.200", "10.0.0.1", p, window_index=1))
    for _ in range(5):
        sessions.append(DummySession("192.168.1.200", "10.0.0.1", 100, window_index=1))

    changes = detect_behavior_changes(tcp_sessions=sessions)
    assert len(changes) > 0

    change_types = {c.change_type for c in changes}
    assert ChangeType.PORT_FANOUT_SURGE in change_types or ChangeType.CONNECTION_ATTEMPT_SURGE in change_types
    for c in changes:
        assert c.entity == "192.168.1.200"
        assert c.magnitude > 0


def test_attack_state_inference():
    """Verify empirical attack state inference from signals and findings."""
    findings = [
        {
            "finding_id": "find-1",
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "attack_category": "Reconnaissance Scan",
            "window_index": 0,
            "severity": "HIGH",
        }
    ]
    sessions = [
        DummySession("192.168.1.50", "10.0.0.1", 80, window_index=0, state="REJECTED")
    ]

    states = infer_attack_states(
        observed_findings=findings,
        tcp_sessions=sessions,
    )
    assert len(states) >= 1
    # Findings map to primary target or source
    st = states[0]
    assert st.state in [AttackStateEnum.RECONNAISSANCE, AttackStateEnum.UNKNOWN_STATE]
    assert "T1046" in st.mitre_techniques or len(st.supporting_findings) > 0


def test_threat_centric_views():
    """Verify synthesis of threat views with contradiction tracking."""
    findings = [
        {
            "finding_id": "find-dos",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "attack_category": "Denial of Service Flood",
            "window_index": 1,
            "severity": "CRITICAL",
        }
    ]
    sessions = [
        DummySession("192.168.1.10", "10.0.0.5", 80, window_index=1, state="RESET", packet_count=5000, byte_count=500000)
    ]
    attack_states = infer_attack_states(observed_findings=findings, tcp_sessions=sessions)
    episodes = build_behavioral_episodes(observed_findings=findings, tcp_sessions=sessions)

    views = build_threat_centric_views(
        attack_states=attack_states,
        episodes=episodes,
        observed_findings=findings,
    )
    assert len(views) >= 1
    tv = views[0]
    assert tv.threat_level in ["CRITICAL", "HIGH"]
    assert len(tv.explanation_chain) > 0


def test_network_world_state():
    """Verify NetworkWorldState serializability and structural integrity."""
    graph = EvidenceGraph()
    world_state = build_network_world_state(
        capture_id="cap_test_123",
        total_packets=1000,
        total_flows=50,
        total_windows=3,
        duration_seconds=180.0,
        entity_histories={},
        episodes=(),
        attack_states=(),
        threat_views=(),
        change_signals=(),
        forecast_points=(),
        evidence_graph=graph,
    )

    d = world_state.to_dict()
    assert d["capture_id"] == "cap_test_123"
    assert d["total_packets"] == 1000
    assert d["total_flows"] == 50
    assert d["duration_seconds"] == 180.0
    assert d["graph_summary"]["nodes"] == 0


def test_graph_deterministic_queries():
    """Verify graph query methods: contradictions, entity timeline, and neighbors."""
    graph = EvidenceGraph()

    # Add entity node
    graph.add_node(GraphNode(
        id="ent_192.168.1.100",
        node_type=NodeType.IP,
        entity_key="192.168.1.100",
        label="192.168.1.100",
        timestamp=100.0,
        scope=Scope.OBSERVED,
        provenance={"source": "TEST"},
    ))

    # Add signal node
    graph.add_node(GraphNode(
        id="sig_scan_1",
        node_type=NodeType.BEHAVIOR_SIGNAL,
        entity_key="192.168.1.100",
        label="SYN Port Scan",
        timestamp=105.0,
        scope=Scope.OBSERVED,
        properties={"mitre_tactic": "TA0007"},
        provenance={"source": "TEST"},
    ))

    # Add peer entity node
    graph.add_node(GraphNode(
        id="ent_10.0.0.1",
        node_type=NodeType.IP,
        entity_key="10.0.0.1",
        label="10.0.0.1",
        timestamp=100.0,
        scope=Scope.OBSERVED,
        provenance={"source": "TEST"},
    ))

    # Add contradicting signal node
    graph.add_node(GraphNode(
        id="sig_benign_heartbeat",
        node_type=NodeType.BEHAVIOR_SIGNAL,
        entity_key="192.168.1.100",
        label="Benign Heartbeat Pattern",
        timestamp=106.0,
        scope=Scope.OBSERVED,
        provenance={"source": "TEST"},
    ))

    # Add edges
    graph.add_edge(GraphEdge(
        id="edge_1",
        source_id="ent_192.168.1.100",
        target_id="ent_10.0.0.1",
        edge_type=EdgeType.COMMUNICATES_WITH,
        scope=Scope.OBSERVED,
        reason="IP communications",
        rule_id="R001",
    ))

    graph.add_edge(GraphEdge(
        id="edge_2",
        source_id="sig_benign_heartbeat",
        target_id="sig_scan_1",
        edge_type=EdgeType.CONTRADICTS,
        scope=Scope.OBSERVED,
        reason="Periodic benign heartbeat contradicts attack",
        rule_id="R008",
    ))

    # Query contradictions
    contras = graph.get_contradicting_evidence("sig_scan_1")
    assert len(contras) == 1
    assert contras[0].id == "sig_benign_heartbeat"

    # Query neighbors
    neighbors = graph.get_entity_neighbors("192.168.1.100")
    assert any(n["id"] == "ent_10.0.0.1" for n in neighbors)

    # Query timeline
    timeline = graph.get_entity_timeline("192.168.1.100")
    assert len(timeline) >= 1


