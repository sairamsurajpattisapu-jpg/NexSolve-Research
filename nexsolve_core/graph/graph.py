"""In-memory deterministic Evidence Intelligence Graph and query engine.

Enforces:
- Deterministic node & edge storage with index lookups.
- Strict isolation of OBSERVED vs FORECAST queries.
- Precedence and causal traversal.
- Evidence chain generation linking network entities to findings and forecasts.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable, Sequence

from nexsolve_core.graph.models import (
    EdgeType,
    EvidenceChain,
    GraphEdge,
    GraphNode,
    NodeType,
    Scope,
    deterministic_id,
)


class EvidenceGraph:
    "In-memory deterministic property graph for security evidence correlation."

    def __init__(self) -> None:
        self._nodes: dict[str, GraphNode] = {}
        self._edges: dict[str, GraphEdge] = {}
        # Adjacency indexes for fast deterministic traversal
        self._out_edges: dict[str, list[str]] = defaultdict(list)
        self._in_edges: dict[str, list[str]] = defaultdict(list)
        self._type_index: dict[NodeType, list[str]] = defaultdict(list)
        self._scope_index: dict[Scope, list[str]] = defaultdict(list)
        self._entity_index: dict[str, list[str]] = defaultdict(list)
        self._chains: list[EvidenceChain] = []

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    @property
    def chains(self) -> tuple[EvidenceChain, ...]:
        return tuple(self._chains)

    def add_node(self, node: GraphNode) -> bool:
        "Add node if not present. Returns True if newly added, False if duplicate."
        if node.id in self._nodes:
            return False
        self._nodes[node.id] = node
        self._type_index[node.node_type].append(node.id)
        self._scope_index[node.scope].append(node.id)
        self._entity_index[node.entity_key].append(node.id)
        return True

    def add_edge(self, edge: GraphEdge) -> bool:
        """Add edge if not present. Validates that source and target nodes exist."""
        if edge.id in self._edges:
            return False
        if edge.source_id not in self._nodes or edge.target_id not in self._nodes:
            raise ValueError(f"Cannot add edge {edge.id}: source {edge.source_id} or target {edge.target_id} does not exist.")
        self._edges[edge.id] = edge
        self._out_edges[edge.source_id].append(edge.id)
        self._in_edges[edge.target_id].append(edge.id)
        return True

    def get_node(self, node_id: str) -> GraphNode | None:
        return self._nodes.get(node_id)

    def get_edge(self, edge_id: str) -> GraphEdge | None:
        return self._edges.get(edge_id)

    def get_nodes_by_type(self, node_type: NodeType) -> tuple[GraphNode, ...]:
        return tuple(self._nodes[nid] for nid in self._type_index.get(node_type, ()))

    def get_nodes_by_scope(self, scope: Scope) -> tuple[GraphNode, ...]:
        return tuple(self._nodes[nid] for nid in self._scope_index.get(scope, ()))

    def get_nodes_for_entity(self, entity_key: str) -> tuple[GraphNode, ...]:
        return tuple(self._nodes[nid] for nid in self._entity_index.get(entity_key, ()))

    def get_out_edges(self, node_id: str) -> tuple[GraphEdge, ...]:
        return tuple(self._edges[eid] for eid in self._out_edges.get(node_id, ()))

    def get_in_edges(self, node_id: str) -> tuple[GraphEdge, ...]:
        return tuple(self._edges[eid] for eid in self._in_edges.get(node_id, ()))

    def get_supporting_evidence(self, finding_id: str) -> tuple[GraphNode, ...]:
        "Return all signal/observation nodes that directly SUPPORT or CORRELATE_WITH a finding."
        supporting = []
        for edge in self.get_in_edges(finding_id):
            if edge.edge_type in (EdgeType.SUPPORTS, EdgeType.CORRELATES_WITH, EdgeType.INDICATES):
                node = self.get_node(edge.source_id)
                if node:
                    supporting.append(node)
        return tuple(supporting)

    def get_entity_context(self, entity_key: str) -> dict[str, Any]:
        "Gather all nodes, sessions, and findings associated with a canonical entity."
        nodes = self.get_nodes_for_entity(entity_key)
        findings = []
        sessions = []
        behaviors = []
        for n in nodes:
            if n.node_type == NodeType.FINDING:
                findings.append(n)
            elif n.node_type == NodeType.TCP_SESSION:
                sessions.append(n)
            elif n.node_type == NodeType.BEHAVIOR_SIGNAL:
                behaviors.append(n)
        return {
            'entity_key': entity_key,
            'total_associated_nodes': len(nodes),
            'findings': [f.to_dict() for f in findings],
            'sessions': [s.to_dict() for s in sessions],
            'behavioral_signals': [b.to_dict() for b in behaviors],
        }

    def get_entity_dossier(self, entity_key: str) -> dict[str, Any]:
        """Gather full multi-modal relational intelligence for an entity IP or key."""
        nodes = self.get_nodes_for_entity(entity_key)
        inbound_peers: set[str] = set()
        outbound_peers: set[str] = set()
        targeted_ports: set[int] = set()
        attack_states: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        sessions: list[dict[str, Any]] = []
        behavior_signals: list[dict[str, Any]] = []

        ip_node_id = deterministic_id('ip', entity_key)
        # Check outbound edges from entity IP node
        for e in self.get_out_edges(ip_node_id):
            tgt = self.get_node(e.target_id)
            if not tgt:
                continue
            if tgt.node_type == NodeType.TCP_SESSION:
                # Find where this session goes
                for sess_edge in self.get_out_edges(tgt.id):
                    dest = self.get_node(sess_edge.target_id)
                    if dest:
                        if dest.node_type == NodeType.IP and dest.entity_key != entity_key:
                            outbound_peers.add(dest.entity_key)
                        elif dest.node_type == NodeType.PORT:
                            try:
                                targeted_ports.add(int(dest.entity_key))
                            except ValueError:
                                pass
            elif tgt.node_type == NodeType.ATTACK_STATE:
                attack_states.append(tgt.to_dict())

        # Check inbound edges to entity IP node
        for e in self.get_in_edges(ip_node_id):
            src = self.get_node(e.source_id)
            if not src:
                continue
            if src.node_type == NodeType.TCP_SESSION:
                # Find who initiated this session
                for sess_in in self.get_in_edges(src.id):
                    init_node = self.get_node(sess_in.source_id)
                    if init_node and init_node.node_type == NodeType.IP and init_node.entity_key != entity_key:
                        inbound_peers.add(init_node.entity_key)

        for n in nodes:
            if n.node_type == NodeType.FINDING:
                findings.append(n.to_dict())
            elif n.node_type == NodeType.TCP_SESSION:
                sessions.append(n.to_dict())
            elif n.node_type == NodeType.BEHAVIOR_SIGNAL:
                behavior_signals.append(n.to_dict())
            elif n.node_type == NodeType.ATTACK_STATE and n.to_dict() not in attack_states:
                attack_states.append(n.to_dict())

        return {
            'entity_key': entity_key,
            'total_associated_nodes': len(nodes),
            'inbound_peers': sorted(list(inbound_peers)),
            'outbound_peers': sorted(list(outbound_peers)),
            'targeted_ports': sorted(list(targeted_ports)),
            'attack_states': attack_states,
            'findings': findings,
            'sessions': sessions,
            'behavior_signals': behavior_signals,
        }

    def get_preceding_evidence(self, node_id: str) -> tuple[GraphNode, ...]:
        "Return all nodes that strictly TEMPORALLY_PRECEDES the given node."
        preceding = []
        for edge in self.get_in_edges(node_id):
            if edge.edge_type == EdgeType.TEMPORALLY_PRECEDES:
                node = self.get_node(edge.source_id)
                if node:
                    preceding.append(node)
        return tuple(preceding)

    def get_contradicting_evidence(self, finding_id: str) -> tuple[GraphNode, ...]:
        "Return all nodes with a CONTRADICTS edge to/from the finding or its signals."
        contradicting = []
        for edge in self.get_in_edges(finding_id):
            if edge.edge_type == EdgeType.CONTRADICTS:
                n = self.get_node(edge.source_id)
                if n:
                    contradicting.append(n)
        for edge in self.get_out_edges(finding_id):
            if edge.edge_type == EdgeType.CONTRADICTS:
                n = self.get_node(edge.target_id)
                if n:
                    contradicting.append(n)
        return tuple(contradicting)

    def get_entity_timeline(self, entity_key: str) -> list[dict[str, Any]]:
        "Return chronological list of events/nodes associated with an entity."
        nodes = self.get_nodes_for_entity(entity_key)
        timeline = []
        for n in nodes:
            timeline.append({
                'id': n.id,
                'node_type': n.node_type.value,
                'label': n.label,
                'scope': n.scope.value,
                'timestamp': n.timestamp,
                'window_id': n.window_id,
            })
        timeline.sort(key=lambda x: (x.get('window_id') is not None, x.get('window_id') or 0, str(x.get('timestamp') or '')))
        return timeline

    def get_entity_neighbors(self, entity_key: str) -> list[dict[str, Any]]:
        "Return all adjacent entities directly connected via graph edges."
        nodes = self.get_nodes_for_entity(entity_key)
        neighbor_ids: set[str] = set()
        for n in nodes:
            for e in self.get_out_edges(n.id):
                neighbor_ids.add(e.target_id)
            for e in self.get_in_edges(n.id):
                neighbor_ids.add(e.source_id)
        neighbors = []
        for nid in sorted(neighbor_ids):
            node = self.get_node(nid)
            if node and node.entity_key != entity_key:
                neighbors.append(node.to_dict())
        return neighbors

    def get_mitre_evidence(self, technique_id: str) -> list[dict[str, Any]]:
        "Return all finding nodes that map to a specific MITRE technique."
        m_node_id = f"mitre_{technique_id}"
        findings = []
        for e in self.get_in_edges(m_node_id):
            if e.edge_type == EdgeType.MAPS_TO_TECHNIQUE:
                f_node = self.get_node(e.source_id)
                if f_node:
                    findings.append(f_node.to_dict())
        return findings

    def get_incident_phases(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        """Return all incident phase nodes in chronological sequence."""
        phase_nodes = self.get_nodes_by_type(NodeType.PHASE)
        if incident_id:
            phase_nodes = [n for n in phase_nodes if n.properties.get("incident_id") == incident_id]
        sorted_phases = sorted(phase_nodes, key=lambda n: (n.properties.get("start_window", 0), n.timestamp or 0))
        return [p.to_dict() for p in sorted_phases]

    def get_incident_events(self, incident_id: str | None = None) -> list[dict[str, Any]]:
        """Return all reconstructed incident events in chronological sequence."""
        event_nodes = self.get_nodes_by_type(NodeType.INCIDENT_EVENT)
        if incident_id:
            event_nodes = [n for n in event_nodes if n.properties.get("incident_id") == incident_id]
        sorted_events = sorted(event_nodes, key=lambda n: (n.window_id or 0, n.timestamp or 0))
        return [e.to_dict() for e in sorted_events]

    def get_related_incidents(self, incident_id: str) -> list[dict[str, Any]]:
        """Find incidents correlated directly or via shared campaign clusters."""
        inc_node_id = f"incident_{incident_id}"
        related: list[dict[str, Any]] = []
        for e in self.get_out_edges(inc_node_id):
            if e.edge_type in (EdgeType.CORRELATES_WITH, EdgeType.MEMBER_OF_CAMPAIGN):
                tgt = self.get_node(e.target_id)
                if tgt:
                    related.append(tgt.to_dict())
        for e in self.get_in_edges(inc_node_id):
            if e.edge_type in (EdgeType.CORRELATES_WITH, EdgeType.MEMBER_OF_CAMPAIGN):
                src = self.get_node(e.source_id)
                if src:
                    related.append(src.to_dict())
        return related

    def get_campaign_clusters(self) -> list[dict[str, Any]]:
        """Return all campaign cluster nodes."""
        clusters = self.get_nodes_by_type(NodeType.CAMPAIGN_CLUSTER)
        return [c.to_dict() for c in clusters]

    def add_chain(self, chain: EvidenceChain) -> None:
        self._chains.append(chain)

    def build_evidence_chains(self) -> tuple[EvidenceChain, ...]:
        "Trace deterministic evidence chains ending at FINDING or FORECAST_SIGNAL nodes."
        chains: list[EvidenceChain] = []

        # 1. Trace Observed Finding Chains
        for finding in self.get_nodes_by_type(NodeType.FINDING):
            supporting_nodes = self.get_supporting_evidence(finding.id)
            node_ids = [s.id for s in supporting_nodes] + [finding.id]
            edge_ids = []
            for edge in self.get_in_edges(finding.id):
                if edge.edge_type in (EdgeType.SUPPORTS, EdgeType.CORRELATES_WITH):
                    edge_ids.append(edge.id)
            mitre_tech = finding.properties.get('mitre_technique_id')
            supp_types = ', '.join(s.node_type.value for s in supporting_nodes) or 'direct observation'
            explanation = (
                f"Observed finding '{finding.label}' is supported by {len(supporting_nodes)} "
                f"independent signal(s) ({supp_types})."
            )
            chains.append(EvidenceChain(
                chain_id=f"chain_obs_{finding.id}",
                terminal_node_id=finding.id,
                scope=Scope.OBSERVED,
                title=f"Observed Finding: {finding.label}",
                node_ids=tuple(node_ids),
                edge_ids=tuple(edge_ids),
                explanation=explanation,
                mitre_technique_id=mitre_tech,
            ))

        # 2. Trace Forecast Chains (Strictly separated from observed chains)
        for forecast in self.get_nodes_by_type(NodeType.FORECAST_SIGNAL):
            preceding_nodes = self.get_preceding_evidence(forecast.id)
            node_ids = [p.id for p in preceding_nodes] + [forecast.id]
            edge_ids = []
            for edge in self.get_in_edges(forecast.id):
                if edge.edge_type == EdgeType.TEMPORALLY_PRECEDES:
                    edge_ids.append(edge.id)
            tech = forecast.properties.get('predicted_technique')
            horizon = forecast.properties.get('horizon_minutes', 1)
            pred_type = forecast.properties.get('prediction_type', 'STATE_PERSISTENCE')
            explanation = (
                f"Forecast at horizon K={horizon}m predicts {pred_type} grounded on "
                f"{len(preceding_nodes)} observed prior finding(s)."
            )
            chains.append(EvidenceChain(
                chain_id=f"chain_fc_{forecast.id}",
                terminal_node_id=forecast.id,
                scope=Scope.FORECAST,
                title=f"Forecast Horizon K={horizon}m ({pred_type})",
                node_ids=tuple(node_ids),
                edge_ids=tuple(edge_ids),
                explanation=explanation,
                mitre_technique_id=tech,
            ))

        self._chains = chains
        return tuple(chains)

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete graph structure for API responses."""
        nodes_by_type_count = {t.value: len(self._type_index.get(t, ())) for t in NodeType if t in self._type_index}
        edges_by_type_count = defaultdict(int)
        for e in self._edges.values():
            edges_by_type_count[e.edge_type.value] += 1

        # Generate entity dossiers for primary IP entities
        ip_nodes = self.get_nodes_by_type(NodeType.IP)
        dossiers = {n.entity_key: self.get_entity_dossier(n.entity_key) for n in ip_nodes[:20]}

        return {
            'statistics': {
                'total_nodes': len(self._nodes),
                'total_edges': len(self._edges),
                'total_chains': len(self._chains),
                'observed_node_count': len(self._scope_index.get(Scope.OBSERVED, ())),
                'forecast_node_count': len(self._scope_index.get(Scope.FORECAST, ())),
                'nodes_by_type': nodes_by_type_count,
                'edges_by_type': dict(edges_by_type_count),
            },
            'nodes': [n.to_dict() for n in self._nodes.values()],
            'edges': [e.to_dict() for e in self._edges.values()],
            'chains': [c.to_dict() for c in self._chains],
            'dossiers': dossiers,
        }

