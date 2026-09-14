from __future__ import annotations
from dataclasses import dataclass
from typing import Any

from nexsolve_core.intelligence.query_model import (
    EpistemicScope,
    QueryOperator,
    QueryPredicate,
    QueryRequest,
    QueryTarget,
    TemporalRelation,
    TemporalScope,
)

@dataclass(frozen=True)
class HuntTemplate:
    template_id: str
    name: str
    category: str
    description: str
    target: QueryTarget
    default_request: QueryRequest
    analyst_guidance: str
    tags: tuple[str, ...]

HUNT_TEMPLATES: list[HuntTemplate] = [
    HuntTemplate(
        template_id='hunt_recon_fanout',
        name='High Destination-Port & Host Fan-Out',
        category='Reconnaissance',
        description='Identify network entities engaging in horizontal host scans or high destination port sweeping.',
        target=QueryTarget.ENTITY,
        default_request=QueryRequest(
            query_id='req_recon_fanout',
            target=QueryTarget.ENTITY,
            predicates=(
                QueryPredicate(field='entity.port_diversity', operator=QueryOperator.GREATER_THAN_OR_EQUAL, value=5),
            ),
            sort_by='port_diversity',
            sort_descending=True,
            epistemic_scope=EpistemicScope.OBSERVED_ONLY,
        ),
        analyst_guidance='Look for high handshake failure ratios (>60%) and rapid probe bursts across consecutive windows.',
        tags=('reconnaissance', 'scan', 'ports', 'T1046'),
    ),
    HuntTemplate(
        template_id='hunt_recon_state',
        name='Confirmed Reconnaissance Entities',
        category='Reconnaissance',
        description='Find entities with empirically supported or inferred RECONNAISSANCE attack states.',
        target=QueryTarget.ENTITY,
        default_request=QueryRequest(
            query_id='req_recon_state',
            target=QueryTarget.ENTITY,
            predicates=(
                QueryPredicate(field='entity.attack_state', operator=QueryOperator.EQUALS, value='RECONNAISSANCE'),
            ),
            sort_by='risk_score',
            sort_descending=True,
            epistemic_scope=EpistemicScope.OBSERVED_ONLY,
        ),
        analyst_guidance='Corroborate with MITRE T1046 technique mapping and associated behavioral episodes.',
        tags=('reconnaissance', 'attack_state', 'T1046'),
    ),
    HuntTemplate(
        template_id='hunt_behavior_change',
        name='Significant Behavioral Changes',
        category='Behavioral Anomalies',
        description='Hunt for entities that broke baseline network behavior or exhibited sudden activity shifts.',
        target=QueryTarget.ENTITY,
        default_request=QueryRequest(
            query_id='req_behavior_change',
            target=QueryTarget.ENTITY,
            predicates=(
                QueryPredicate(field='entity.behavior_change', operator=QueryOperator.EQUALS, value=True),
            ),
            sort_by='risk_score',
            sort_descending=True,
            epistemic_scope=EpistemicScope.OBSERVED_ONLY,
        ),
        analyst_guidance='Check what_changed delta metrics and baseline deviations to verify if change is operational or hostile.',
        tags=('baseline', 'deviation', 'change_point', 'anomaly'),
    ),
    HuntTemplate(
        template_id='hunt_beaconing_c2',
        name='Periodic Beaconing & Low-Jitter Communication',
        category='Command & Control',
        description='Surface entities with consistent inter-arrival periodicity or repetitive destination signaling.',
        target=QueryTarget.ENTITY,
        default_request=QueryRequest(
            query_id='req_beaconing_c2',
            target=QueryTarget.ENTITY,
            predicates=(
                QueryPredicate(field='entity.beaconing', operator=QueryOperator.EQUALS, value=True),
            ),
            sort_by='packet_volume',
            sort_descending=True,
            epistemic_scope=EpistemicScope.OBSERVED_ONLY,
        ),
        analyst_guidance='Inspect session durations and periodicity score to differentiate NTP/DNS sync from C2 heartbeat.',
        tags=('beaconing', 'c2', 'periodicity', 'rita'),
    ),
    HuntTemplate(
        template_id='hunt_technique_t1046',
        name='Network Service Scanning (T1046) Evidence',
        category='MITRE ATT&CK',
        description='Locate all observed findings and evidence explicitly linked to MITRE technique T1046.',
        target=QueryTarget.EVIDENCE,
        default_request=QueryRequest(
            query_id='req_tech_t1046',
            target=QueryTarget.EVIDENCE,
            predicates=(
                QueryPredicate(field='evidence.technique', operator=QueryOperator.EQUALS, value='T1046'),
            ),
            epistemic_scope=EpistemicScope.OBSERVED_ONLY,
        ),
        analyst_guidance='Examine port distribution and TCP flags (SYN-only vs full handshake) to confirm scanning intent.',
        tags=('mitre', 't1046', 'evidence', 'scanning'),
    ),
    HuntTemplate(
        template_id='hunt_failed_connection_spike',
        name='High Handshake Failure Concentration',
        category='Reconnaissance',
        description='Identify entities with failure ratios exceeding 70%, typical of hostile blind sweeps.',
        target=QueryTarget.ENTITY,
        default_request=QueryRequest(
            query_id='req_failed_conn',
            target=QueryTarget.ENTITY,
            predicates=(
                QueryPredicate(field='entity.failure_ratio', operator=QueryOperator.GREATER_THAN_OR_EQUAL, value=0.70),
            ),
            sort_by='failure_ratio',
            sort_descending=True,
            epistemic_scope=EpistemicScope.OBSERVED_ONLY,
        ),
        analyst_guidance='High failure ratios without preceding DNS resolution strongly indicate automated port sweeps.',
        tags=('handshake_failure', 'rst', 'sweep'),
    ),
    HuntTemplate(
        template_id='hunt_incident_events',
        name='Reconstructed Incident Event Chronology',
        category='Incident Reconstruction',
        description='Review chronological reconstructed events across all phases of the active incident.',
        target=QueryTarget.EVENT,
        default_request=QueryRequest(
            query_id='req_inc_events',
            target=QueryTarget.EVENT,
            predicates=(),
            sort_by='window_id',
            sort_descending=False,
            epistemic_scope=EpistemicScope.OBSERVED_ONLY,
        ),
        analyst_guidance='Follow the event chain from initial host appearance to escalation and capture boundary limits.',
        tags=('incident', 'timeline', 'chronology'),
    ),
    HuntTemplate(
        template_id='hunt_campaign_clusters',
        name='Cross-Capture Campaign Clusters',
        category='Campaign Intelligence',
        description='Examine campaign clusters and correlated multi-capture threat activity.',
        target=QueryTarget.CAMPAIGN,
        default_request=QueryRequest(
            query_id='req_campaign_clusters',
            target=QueryTarget.CAMPAIGN,
            predicates=(),
            epistemic_scope=EpistemicScope.OBSERVED_ONLY,
        ),
        analyst_guidance='Single capture sessions will report baseline isolation. Multi-capture sets highlight infrastructure rotation.',
        tags=('campaign', 'clusters', 'infrastructure_change'),
    ),
]

def get_hunt_templates() -> list[dict[str, Any]]:
    return [
        {
            'template_id': t.template_id,
            'name': t.name,
            'category': t.category,
            'description': t.description,
            'target': t.target.value,
            'default_request': t.default_request.to_dict(),
            'analyst_guidance': t.analyst_guidance,
            'tags': list(t.tags),
        }
        for t in HUNT_TEMPLATES
    ]

def get_template_by_id(template_id: str) -> HuntTemplate | None:
    for t in HUNT_TEMPLATES:
        if t.template_id == template_id:
            return t
    return None