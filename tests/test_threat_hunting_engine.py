"""Tests for Threat Hunting & Intelligence Query Engine."""
from __future__ import annotations
import pytest
from nexsolve_core.intelligence.query_model import (
    EpistemicScope,
    GraphTraversalScope,
    QueryOperator,
    QueryPredicate,
    QueryRequest,
    QueryResult,
    QueryTarget,
    TemporalRelation,
    TemporalScope,
)
from nexsolve_core.intelligence.query_registry import (
    get_field_descriptor,
    list_registered_fields,
)
from nexsolve_core.intelligence.hunt_packs import (
    get_hunt_templates,
    get_template_by_id,
)
from nexsolve_core.intelligence.query_engine import IntelligenceQueryEngine


def test_query_domain_models_and_serialization():
    pred = QueryPredicate(field="entity.port_diversity", operator=QueryOperator.GREATER_THAN_OR_EQUAL, value=5)
    assert pred.to_dict() == {
        "field": "entity.port_diversity",
        "operator": ">=",
        "value": 5,
        "value_to": None,
    }

    temp = TemporalScope(relation=TemporalRelation.DURING, start_time=0.0, end_time=120.0)
    assert temp.to_dict()["relation"] == "DURING"

    req = QueryRequest(
        query_id="q1",
        target=QueryTarget.ENTITY,
        predicates=(pred,),
        temporal=temp,
        epistemic_scope=EpistemicScope.OBSERVED_ONLY,
    )
    d = req.to_dict()
    assert d["target"] == "ENTITY"
    assert len(d["predicates"]) == 1


def test_predicate_registry_completeness():
    fields = list_registered_fields()
    assert len(fields) >= 15
    desc = get_field_descriptor("entity.port_diversity")
    assert desc is not None
    assert desc.data_type in ("int", "number")
    assert ">=" in [op.value for op in desc.allowed_operators]


def test_hunt_packs_registry():
    templates = get_hunt_templates()
    assert len(templates) >= 6
    tpl = get_template_by_id("hunt_recon_fanout")
    assert tpl is not None
    assert tpl.target == QueryTarget.ENTITY
    assert len(tpl.default_request.predicates) > 0


def test_query_engine_execution_with_mock_payload():
    mock_payload = {
        "entity_profiles": {
            "192.168.1.100": {
                "roles": ["SCANNER", "CLIENT"],
                "targeted_ports_count": 25,
                "peer_count": 8,
                "failure_ratio": 0.75,
                "beaconing_detected": False,
                "first_seen_window": 1,
                "last_seen_window": 5,
            },
            "10.0.0.5": {
                "roles": ["SERVER"],
                "targeted_ports_count": 1,
                "peer_count": 2,
                "failure_ratio": 0.05,
                "beaconing_detected": False,
                "first_seen_window": 0,
                "last_seen_window": 10,
            },
        },
        "entity_investigations": {
            "192.168.1.100": {
                "inferred_attack_state": "RECONNAISSANCE",
                "summary": "High destination port scan",
            }
        },
        "prioritized_threats": [
            {
                "entity": "192.168.1.100",
                "priority": "P0",
                "composite_risk_score": 92.5,
            }
        ],
        "detection": {
            "findings": [
                {
                    "finding_id": "f_1",
                    "attack_category": "Reconnaissance",
                    "rule_id": "T1046",
                    "severity": "HIGH",
                    "summary": "Port sweep detected",
                }
            ]
        },
    }

    engine = IntelligenceQueryEngine(mock_payload)

    # 1. Query entities with port_diversity >= 5
    req1 = QueryRequest(
        query_id="q_fanout",
        target=QueryTarget.ENTITY,
        predicates=(
            QueryPredicate(
                field="entity.port_diversity",
                operator=QueryOperator.GREATER_THAN_OR_EQUAL,
                value=5,
            ),
        ),
        epistemic_scope=EpistemicScope.OBSERVED_ONLY,
    )
    res1 = engine.execute_query(req1)
    assert res1.total_matches == 1
    assert res1.matches[0].entity_key == "192.168.1.100"
    assert "RECONNAISSANCE" in res1.matches[0].semantic_state
    assert res1.matches[0].epistemic_status == "OBSERVED"

    # 2. Query evidence with technique T1046
    req2 = QueryRequest(
        query_id="q_ev",
        target=QueryTarget.EVIDENCE,
        predicates=(
            QueryPredicate(
                field="evidence.technique",
                operator=QueryOperator.EQUALS,
                value="T1046",
            ),
        ),
        epistemic_scope=EpistemicScope.OBSERVED_ONLY,
    )
    res2 = engine.execute_query(req2)
    assert res2.total_matches == 1
    assert "Reconnaissance" in res2.matches[0].label or "f_1" in res2.matches[0].label
