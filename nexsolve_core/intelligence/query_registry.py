from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable

from nexsolve_core.intelligence.query_model import QueryOperator, QueryTarget

@dataclass(frozen=True)
class FieldDescriptor:
    name: str
    target: QueryTarget
    data_type: str  # 'number', 'string', 'boolean', 'list'
    description: str
    allowed_operators: tuple[QueryOperator, ...]
    example: Any

# Registry of controlled query predicates
PREDICATE_REGISTRY: dict[str, FieldDescriptor] = {
    # Entity predicates
    'entity.ip': FieldDescriptor(
        name='entity.ip',
        target=QueryTarget.ENTITY,
        data_type='string',
        description='Entity IPv4 address or hostname',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN, QueryOperator.CONTAINS, QueryOperator.STARTS_WITH),
        example='208.111.178.163',
    ),
    'entity.role': FieldDescriptor(
        name='entity.role',
        target=QueryTarget.ENTITY,
        data_type='string',
        description='Behavioral or operational role (SUSPECT, RECON_SOURCE, SERVER, INTERNAL_PEER)',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN, QueryOperator.CONTAINS),
        example='RECON_SOURCE',
    ),
    'entity.attack_state': FieldDescriptor(
        name='entity.attack_state',
        target=QueryTarget.ENTITY,
        data_type='string',
        description='Current inferred attack state (BENIGN, RECONNAISSANCE, EXPLOITATION, etc.)',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN),
        example='RECONNAISSANCE',
    ),
    'entity.priority': FieldDescriptor(
        name='entity.priority',
        target=QueryTarget.ENTITY,
        data_type='string',
        description='Analyst triage priority (P0, P1, P2, P3, P4)',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN),
        example='P0',
    ),
    'entity.risk_score': FieldDescriptor(
        name='entity.risk_score',
        target=QueryTarget.ENTITY,
        data_type='number',
        description='Deterministic threat risk score [0..100]',
        allowed_operators=(QueryOperator.GREATER_THAN, QueryOperator.GREATER_THAN_OR_EQUAL, QueryOperator.LESS_THAN, QueryOperator.LESS_THAN_OR_EQUAL, QueryOperator.BETWEEN),
        example=75.0,
    ),
    'entity.fanout': FieldDescriptor(
        name='entity.fanout',
        target=QueryTarget.ENTITY,
        data_type='number',
        description='Unique destination IP count contacted by this entity',
        allowed_operators=(QueryOperator.GREATER_THAN, QueryOperator.GREATER_THAN_OR_EQUAL, QueryOperator.LESS_THAN, QueryOperator.LESS_THAN_OR_EQUAL, QueryOperator.BETWEEN),
        example=10,
    ),
    'entity.port_diversity': FieldDescriptor(
        name='entity.port_diversity',
        target=QueryTarget.ENTITY,
        data_type='number',
        description='Count of distinct destination ports targeted',
        allowed_operators=(QueryOperator.GREATER_THAN, QueryOperator.GREATER_THAN_OR_EQUAL, QueryOperator.LESS_THAN, QueryOperator.LESS_THAN_OR_EQUAL, QueryOperator.BETWEEN),
        example=20,
    ),
    'entity.failure_ratio': FieldDescriptor(
        name='entity.failure_ratio',
        target=QueryTarget.ENTITY,
        data_type='number',
        description='Ratio of failed/rejected sessions to total connection attempts [0.0..1.0]',
        allowed_operators=(QueryOperator.GREATER_THAN, QueryOperator.GREATER_THAN_OR_EQUAL, QueryOperator.LESS_THAN, QueryOperator.LESS_THAN_OR_EQUAL),
        example=0.70,
    ),
    'entity.packet_volume': FieldDescriptor(
        name='entity.packet_volume',
        target=QueryTarget.ENTITY,
        data_type='number',
        description='Total packet volume across capture windows',
        allowed_operators=(QueryOperator.GREATER_THAN, QueryOperator.GREATER_THAN_OR_EQUAL, QueryOperator.LESS_THAN, QueryOperator.LESS_THAN_OR_EQUAL),
        example=1000,
    ),
    'entity.behavior_change': FieldDescriptor(
        name='entity.behavior_change',
        target=QueryTarget.ENTITY,
        data_type='boolean',
        description='Whether entity manifested a statistically or structurally significant behavior change',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS),
        example=True,
    ),
    'entity.beaconing': FieldDescriptor(
        name='entity.beaconing',
        target=QueryTarget.ENTITY,
        data_type='boolean',
        description='Whether periodic communication or low-jitter beaconing was detected',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS),
        example=True,
    ),
    # Event & Phase predicates
    'event.type': FieldDescriptor(
        name='event.type',
        target=QueryTarget.EVENT,
        data_type='string',
        description='Chronological event category (PORT_SCAN_STARTED, FANOUT_INCREASED, etc.)',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN),
        example='PORT_SCAN_STARTED',
    ),
    'event.phase': FieldDescriptor(
        name='event.phase',
        target=QueryTarget.EVENT,
        data_type='string',
        description='Associated attack phase (RECONNAISSANCE, ESCALATION, CAPTURE_BOUNDARY)',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN),
        example='RECONNAISSANCE',
    ),
    'phase.state': FieldDescriptor(
        name='phase.state',
        target=QueryTarget.PHASE,
        data_type='string',
        description='Phase attack state classification',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN),
        example='RECONNAISSANCE',
    ),
    # Evidence & Technique predicates
    'evidence.technique': FieldDescriptor(
        name='evidence.technique',
        target=QueryTarget.EVIDENCE,
        data_type='string',
        description='MITRE ATT&CK technique ID (T1046, T1110, T1041, etc.)',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN),
        example='T1046',
    ),
    'evidence.source': FieldDescriptor(
        name='evidence.source',
        target=QueryTarget.EVIDENCE,
        data_type='string',
        description='Evidence source provider (SURICATA_RULE, RITA_PERIODICITY, ZEEK_SESSION, HEURISTIC)',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN),
        example='SURICATA_RULE',
    ),
    # Incident & Campaign predicates
    'incident.id': FieldDescriptor(
        name='incident.id',
        target=QueryTarget.INCIDENT,
        data_type='string',
        description='Incident identifier',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN),
        example='incident_story_7ca9cd011c0b',
    ),
    'campaign.evolution': FieldDescriptor(
        name='campaign.evolution',
        target=QueryTarget.CAMPAIGN,
        data_type='string',
        description='Campaign evolution state (CHANGING_INFRASTRUCTURE, REPEATED_RECONNAISSANCE, etc.)',
        allowed_operators=(QueryOperator.EQUALS, QueryOperator.NOT_EQUALS, QueryOperator.IN),
        example='CHANGING_INFRASTRUCTURE',
    ),
}

def get_field_descriptor(field_name: str) -> FieldDescriptor | None:
    return PREDICATE_REGISTRY.get(field_name)

def list_registered_fields(target: QueryTarget | None = None) -> list[dict[str, Any]]:
    results = []
    for desc in PREDICATE_REGISTRY.values():
        if target is None or desc.target == target:
            results.append({
                'field': desc.name,
                'target': desc.target.value,
                'data_type': desc.data_type,
                'description': desc.description,
                'allowed_operators': [op.value for op in desc.allowed_operators],
                'example': desc.example,
            })
    return results