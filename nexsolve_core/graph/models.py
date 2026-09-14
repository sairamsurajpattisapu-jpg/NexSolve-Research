from __future__ import annotations
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class NodeType(str, Enum):
    IP = 'IP'
    PORT = 'PORT'
    FLOW = 'FLOW'
    TCP_SESSION = 'TCP_SESSION'
    COMMUNICATION_PAIR = 'COMMUNICATION_PAIR'
    WINDOW = 'WINDOW'
    FINDING = 'FINDING'
    BEHAVIOR_SIGNAL = 'BEHAVIOR_SIGNAL'
    PROTOCOL_SIGNAL = 'PROTOCOL_SIGNAL'
    ANOMALY_SIGNAL = 'ANOMALY_SIGNAL'
    CHANGE_SIGNAL = 'CHANGE_SIGNAL'
    FORECAST_SIGNAL = 'FORECAST_SIGNAL'
    MITRE_TECHNIQUE = 'MITRE_TECHNIQUE'
    ATTACK_STATE = 'ATTACK_STATE'
    EPISODE = 'EPISODE'
    CAMPAIGN = 'CAMPAIGN'
    PATTERN = 'PATTERN'
    BASELINE_CHANGE = 'BASELINE_CHANGE'
    TRANSITION = 'TRANSITION'
    INCIDENT = 'INCIDENT'
    PHASE = 'PHASE'
    INCIDENT_EVENT = 'INCIDENT_EVENT'
    CAMPAIGN_CLUSTER = 'CAMPAIGN_CLUSTER'
    CORRELATION = 'CORRELATION'

class EdgeType(str, Enum):
    OBSERVED_IN = 'OBSERVED_IN'
    BELONGS_TO = 'BELONGS_TO'
    COMMUNICATES_WITH = 'COMMUNICATES_WITH'
    USES_PORT = 'USES_PORT'
    PART_OF_FLOW = 'PART_OF_FLOW'
    PART_OF_SESSION = 'PART_OF_SESSION'
    SAME_ENTITY = 'SAME_ENTITY'
    SAME_WINDOW = 'SAME_WINDOW'
    TEMPORALLY_PRECEDES = 'TEMPORALLY_PRECEDES'
    SUPPORTS = 'SUPPORTS'
    CORRELATES_WITH = 'CORRELATES_WITH'
    INDICATES = 'INDICATES'
    ASSOCIATED_WITH = 'ASSOCIATED_WITH'
    MAPS_TO_TECHNIQUE = 'MAPS_TO_TECHNIQUE'
    FORECASTS = 'FORECASTS'
    CONTRADICTS = 'CONTRADICTS'
    PART_OF_EPISODE = 'PART_OF_EPISODE'
    MANIFESTS_CHANGE = 'MANIFESTS_CHANGE'
    PART_OF_CAMPAIGN = 'PART_OF_CAMPAIGN'
    TRANSITIONS_TO = 'TRANSITIONS_TO'
    PARTICIPATES_IN_PATTERN = 'PARTICIPATES_IN_PATTERN'
    DEVIATES_FROM = 'DEVIATES_FROM'
    CONTAINS_EVENT = 'CONTAINS_EVENT'
    CONTAINS_PHASE = 'CONTAINS_PHASE'
    PARTICIPATES_IN = 'PARTICIPATES_IN'
    TARGETS = 'TARGETS'
    MEMBER_OF_CAMPAIGN = 'MEMBER_OF_CAMPAIGN'
    SHARES_BEHAVIOR = 'SHARES_BEHAVIOR'
    SHARES_TARGET_PATTERN = 'SHARES_TARGET_PATTERN'
    SHARES_INFRASTRUCTURE_PATTERN = 'SHARES_INFRASTRUCTURE_PATTERN'
    EVOLVES_FROM = 'EVOLVES_FROM'

class Scope(str, Enum):
    OBSERVED = 'OBSERVED'
    FORECAST = 'FORECAST'
    METADATA = 'METADATA'

def deterministic_id(prefix: str, *components: Any) -> str:
    raw = ':'.join(str(c).strip() for c in components)
    digest = hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]
    return f'{prefix}_{digest}'

@dataclass(frozen=True)
class GraphNode:
    id: str
    node_type: NodeType
    entity_key: str
    label: str
    scope: Scope
    timestamp: float | str | None = None
    window_id: int | str | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'node_type': self.node_type.value,
            'entity_key': self.entity_key,
            'label': self.label,
            'scope': self.scope.value,
            'timestamp': self.timestamp,
            'window_id': self.window_id,
            'properties': self.properties,
            'provenance': self.provenance,
        }

@dataclass(frozen=True)
class GraphEdge:
    id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    scope: Scope
    reason: str
    rule_id: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    supporting_evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'source_id': self.source_id,
            'target_id': self.target_id,
            'edge_type': self.edge_type.value,
            'scope': self.scope.value,
            'reason': self.reason,
            'rule_id': self.rule_id,
            'properties': self.properties,
            'supporting_evidence_ids': list(self.supporting_evidence_ids),
        }

@dataclass(frozen=True)
class EvidenceChain:
    chain_id: str
    terminal_node_id: str
    scope: Scope
    title: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    explanation: str
    mitre_technique_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'chain_id': self.chain_id,
            'terminal_node_id': self.terminal_node_id,
            'scope': self.scope.value,
            'title': self.title,
            'node_ids': list(self.node_ids),
            'edge_ids': list(self.edge_ids),
            'explanation': self.explanation,
            'mitre_technique_id': self.mitre_technique_id,
        }
