from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

from nexsolve_core.graph.models import EdgeType, GraphEdge, GraphNode, NodeType, Scope, deterministic_id


@dataclass(frozen=True)
class CorrelationRule:
    rule_id: str
    name: str
    description: str
    source_node_type: NodeType
    target_node_type: NodeType
    edge_type: EdgeType


# Formal Rule Registry
RULES: dict[str, CorrelationRule] = {
    'R001_SAME_ENTITY_COMMUNICATION': CorrelationRule(
        rule_id='R001',
        name='Same Entity Communication',
        description='Source IP participates in a communication pair.',
        source_node_type=NodeType.IP,
        target_node_type=NodeType.COMMUNICATION_PAIR,
        edge_type=EdgeType.COMMUNICATES_WITH,
    ),
    'R002_PORT_USAGE': CorrelationRule(
        rule_id='R002',
        name='Port Usage',
        description='Communication pair or session targets a destination port.',
        source_node_type=NodeType.COMMUNICATION_PAIR,
        target_node_type=NodeType.PORT,
        edge_type=EdgeType.USES_PORT,
    ),
    'R003_SESSION_FLOW_MEMBERSHIP': CorrelationRule(
        rule_id='R003',
        name='Session Flow Membership',
        description='A flow belongs to a stateful TCP conversation session.',
        source_node_type=NodeType.FLOW,
        target_node_type=NodeType.TCP_SESSION,
        edge_type=EdgeType.PART_OF_SESSION,
    ),
    'R004_WINDOW_OBSERVATION': CorrelationRule(
        rule_id='R004',
        name='Window Observation',
        description='An activity or signal was observed within a specific 60-second temporal window.',
        source_node_type=NodeType.FLOW,
        target_node_type=NodeType.WINDOW,
        edge_type=EdgeType.OBSERVED_IN,
    ),
    'R005_PROTOCOL_SUPPORTS_FINDING': CorrelationRule(
        rule_id='R005',
        name='Protocol Supports Finding',
        description='An observed protocol or session anomaly (e.g. half-open SYN flood or rejection spike) provides direct protocol support for a port scan or reconnaissance finding.',
        source_node_type=NodeType.PROTOCOL_SIGNAL,
        target_node_type=NodeType.FINDING,
        edge_type=EdgeType.SUPPORTS,
    ),
    'R006_BEHAVIOR_CORRELATES_FINDING': CorrelationRule(
        rule_id='R006',
        name='Behavior Correlates With Finding',
        description='A behavioral signal (e.g. RITA periodicity or beaconing) correlates with an observed finding involving the same entity in the same temporal window.',
        source_node_type=NodeType.BEHAVIOR_SIGNAL,
        target_node_type=NodeType.FINDING,
        edge_type=EdgeType.CORRELATES_WITH,
    ),
    'R007_FINDING_MAPS_TECHNIQUE': CorrelationRule(
        rule_id='R007',
        name='Finding Maps to Technique',
        description='An observed finding maps to an empirical MITRE ATT&CK technique.',
        source_node_type=NodeType.FINDING,
        target_node_type=NodeType.MITRE_TECHNIQUE,
        edge_type=EdgeType.MAPS_TO_TECHNIQUE,
    ),
    'R008_TEMPORALLY_PRECEDES': CorrelationRule(
        rule_id='R008',
        name='Temporal Precedence',
        description='An observed state or finding strictly precedes a forecast signal or subsequent window.',
        source_node_type=NodeType.FINDING,
        target_node_type=NodeType.FORECAST_SIGNAL,
        edge_type=EdgeType.TEMPORALLY_PRECEDES,
    ),
    'R009_FORECAST_MAPS_STATE': CorrelationRule(
        rule_id='R009',
        name='Forecast Maps to Attack State',
        description='A multi-step forecast signal forecasts a future attack state or continuation.',
        source_node_type=NodeType.FORECAST_SIGNAL,
        target_node_type=NodeType.ATTACK_STATE,
        edge_type=EdgeType.FORECASTS,
    ),
    'R010_EVIDENCE_CONTRADICTION': CorrelationRule(
        rule_id='R010',
        name='Evidence Contradiction',
        description='Two signals involving the same entity reach conflicting conclusions (e.g. periodic timing on a known benign protocol), marked with CONTRADICTS instead of score averaging.',
        source_node_type=NodeType.BEHAVIOR_SIGNAL,
        target_node_type=NodeType.PROTOCOL_SIGNAL,
        edge_type=EdgeType.CONTRADICTS,
    ),
    'R011_EPISODE_MEMBERSHIP': CorrelationRule(
        rule_id='R011',
        name='Episode Membership',
        description='An entity, finding, or session belongs to a coherent temporal behavioral episode.',
        source_node_type=NodeType.FINDING,
        target_node_type=NodeType.EPISODE,
        edge_type=EdgeType.PART_OF_EPISODE,
    ),
    'R012_CHANGE_MANIFESTATION': CorrelationRule(
        rule_id='R012',
        name='Change Manifestation',
        description='An entity manifests a significant temporal behavior change across consecutive windows.',
        source_node_type=NodeType.IP,
        target_node_type=NodeType.CHANGE_SIGNAL,
        edge_type=EdgeType.MANIFESTS_CHANGE,
    ),
    'R013_CAMPAIGN_MEMBERSHIP': CorrelationRule(
        rule_id='R013',
        name='Campaign Membership',
        description='A behavioral episode belongs to a coordinated multi-episode attack campaign.',
        source_node_type=NodeType.EPISODE,
        target_node_type=NodeType.CAMPAIGN,
        edge_type=EdgeType.PART_OF_CAMPAIGN,
    ),
    'R014_KINEMATIC_TRANSITION': CorrelationRule(
        rule_id='R014',
        name='Kinematic State Transition',
        description='An entity transitions from one observable attack kinematic state to another across temporal windows.',
        source_node_type=NodeType.ATTACK_STATE,
        target_node_type=NodeType.ATTACK_STATE,
        edge_type=EdgeType.TRANSITIONS_TO,
    ),
    'R015_PATTERN_PARTICIPATION': CorrelationRule(
        rule_id='R015',
        name='Attack Pattern Participation',
        description='An entity participates as a primary actor or target in a multi-entity attack pattern.',
        source_node_type=NodeType.IP,
        target_node_type=NodeType.PATTERN,
        edge_type=EdgeType.PARTICIPATES_IN_PATTERN,
    ),
    'R016_BASELINE_DEVIATION': CorrelationRule(
        rule_id='R016',
        name='Baseline Deviation',
        description='An entity exhibits a statistically significant deviation from its established local temporal baseline.',
        source_node_type=NodeType.IP,
        target_node_type=NodeType.BASELINE_CHANGE,
        edge_type=EdgeType.DEVIATES_FROM,
    ),
}


