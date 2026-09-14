from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Sequence

class QueryTarget(str, Enum):
    ENTITY = 'ENTITY'
    EVENT = 'EVENT'
    INCIDENT = 'INCIDENT'
    CAMPAIGN = 'CAMPAIGN'
    EPISODE = 'EPISODE'
    PHASE = 'PHASE'
    EVIDENCE = 'EVIDENCE'
    BEHAVIOR = 'BEHAVIOR'
    TECHNIQUE = 'TECHNIQUE'
    GRAPH_NEIGHBOR = 'GRAPH_NEIGHBOR'
    EXPLANATION = 'EXPLANATION'

class QueryOperator(str, Enum):
    EQUALS = '='
    NOT_EQUALS = '!='
    GREATER_THAN = '>'
    GREATER_THAN_OR_EQUAL = '>='
    LESS_THAN = '<'
    LESS_THAN_OR_EQUAL = '<='
    IN = 'IN'
    NOT_IN = 'NOT_IN'
    CONTAINS = 'CONTAINS'
    STARTS_WITH = 'STARTS_WITH'
    ENDS_WITH = 'ENDS_WITH'
    EXISTS = 'EXISTS'
    NOT_EXISTS = 'NOT_EXISTS'
    BETWEEN = 'BETWEEN'

class TemporalRelation(str, Enum):
    DURING = 'DURING'
    BEFORE = 'BEFORE'
    AFTER = 'AFTER'
    WITHIN = 'WITHIN'
    OVERLAPS = 'OVERLAPS'
    ANY = 'ANY'

class EpistemicScope(str, Enum):
    OBSERVED_ONLY = 'OBSERVED_ONLY'
    INFERRED_AND_SUPPORTED = 'INFERRED_AND_SUPPORTED'
    FORECAST_ONLY = 'FORECAST_ONLY'
    ALL = 'ALL'

@dataclass(frozen=True)
class QueryPredicate:
    field: str
    operator: QueryOperator
    value: Any = None
    value_to: Any = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'field': self.field,
            'operator': self.operator.value,
            'value': self.value,
            'value_to': self.value_to,
        }

@dataclass(frozen=True)
class TemporalScope:
    relation: TemporalRelation = TemporalRelation.ANY
    start_time: float | str | None = None
    end_time: float | str | None = None
    window_range: tuple[int, int] | None = None
    reference_event_id: str | None = None
    reference_window: int | None = None
    window_delta: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'relation': self.relation.value,
            'start_time': self.start_time,
            'end_time': self.end_time,
            'window_range': list(self.window_range) if self.window_range else None,
            'reference_event_id': self.reference_event_id,
            'reference_window': self.reference_window,
            'window_delta': self.window_delta,
        }

@dataclass(frozen=True)
class GraphTraversalScope:
    start_node_id: str | None = None
    entity_key: str | None = None
    max_depth: int = 2
    edge_types: tuple[str, ...] = ()
    target_node_types: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            'start_node_id': self.start_node_id,
            'entity_key': self.entity_key,
            'max_depth': self.max_depth,
            'edge_types': list(self.edge_types),
            'target_node_types': list(self.target_node_types),
        }

@dataclass(frozen=True)
class QueryRequest:
    query_id: str
    target: QueryTarget
    predicates: tuple[QueryPredicate, ...] = ()
    temporal: TemporalScope = field(default_factory=TemporalScope)
    graph: GraphTraversalScope = field(default_factory=GraphTraversalScope)
    epistemic_scope: EpistemicScope = EpistemicScope.OBSERVED_ONLY
    sort_by: str | None = None
    sort_descending: bool = True
    limit: int = 50
    offset: int = 0
    explain: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            'query_id': self.query_id,
            'target': self.target.value,
            'predicates': [p.to_dict() for p in self.predicates],
            'temporal': self.temporal.to_dict(),
            'graph': self.graph.to_dict(),
            'epistemic_scope': self.epistemic_scope.value,
            'sort_by': self.sort_by,
            'sort_descending': self.sort_descending,
            'limit': self.limit,
            'offset': self.offset,
            'explain': self.explain,
        }

@dataclass(frozen=True)
class QueryMatch:
    match_id: str
    target: QueryTarget
    entity_key: str | None
    label: str
    primary_category: str
    semantic_state: str
    epistemic_status: str
    match_score: float
    time_window: tuple[float | str | None, float | str | None]
    matched_predicates: tuple[str, ...]
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    uncertainties: tuple[str, ...]
    graph_node_ids: tuple[str, ...]
    graph_evidence_path: tuple[str, ...]
    properties: dict[str, Any] = field(default_factory=dict)
    analyst_decision_id: str | None = None
    next_question: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            'match_id': self.match_id,
            'target': self.target.value,
            'entity_key': self.entity_key,
            'label': self.label,
            'primary_category': self.primary_category,
            'semantic_state': self.semantic_state,
            'epistemic_status': self.epistemic_status,
            'match_score': round(self.match_score, 3),
            'time_window': list(self.time_window),
            'matched_predicates': list(self.matched_predicates),
            'supporting_evidence': list(self.supporting_evidence),
            'contradicting_evidence': list(self.contradicting_evidence),
            'uncertainties': list(self.uncertainties),
            'graph_node_ids': list(self.graph_node_ids),
            'graph_evidence_path': list(self.graph_evidence_path),
            'properties': self.properties,
            'analyst_decision_id': self.analyst_decision_id,
            'next_question': self.next_question,
        }

@dataclass(frozen=True)
class QueryResult:
    query_id: str
    target: QueryTarget
    total_matches: int
    matches: tuple[QueryMatch, ...]
    truncated: bool
    execution_duration_ms: float
    query_summary: str
    uncertainties: tuple[str, ...]
    applied_epistemic_scope: str

    def to_dict(self) -> dict[str, Any]:
        return {
            'query_id': self.query_id,
            'target': self.target.value,
            'total_matches': self.total_matches,
            'matches': [m.to_dict() for m in self.matches],
            'truncated': self.truncated,
            'execution_duration_ms': round(self.execution_duration_ms, 2),
            'query_summary': self.query_summary,
            'uncertainties': list(self.uncertainties),
            'applied_epistemic_scope': self.applied_epistemic_scope,
        }