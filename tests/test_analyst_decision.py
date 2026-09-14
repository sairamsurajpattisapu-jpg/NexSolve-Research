from __future__ import annotations

import pytest
from nexsolve_core.intelligence.threat_differentiation import (
    differentiate_threat,
    ThreatSemanticTier,
    EvidenceGroundingState,
)
from nexsolve_core.intelligence.what_changed import (
    build_what_changed,
    WhatChangedItem,
)
from nexsolve_core.intelligence.false_positive import (
    evaluate_benign_hypotheses,
    BenignResolutionState,
)
from nexsolve_core.intelligence.questions import (
    generate_analyst_questions,
    InvestigationQuestion,
)
from nexsolve_core.intelligence.investigation_value import (
    compute_investigation_value,
    InvestigationValueReport,
)
from nexsolve_core.intelligence.analyst_decision import (
    build_analyst_decisions,
    AnalystDecision,
    DecisionPriority,
)


def test_threat_differentiation():
    class DummyTraj:
        current_state = "RECONNAISSANCE"
        transitions = [1]

    class DummyProfile:
        roles = ["EXTERNAL_CLIENT"]
        targeted_ports_count = 10
        peer_count = 5

    res = differentiate_threat(
        entity="192.168.1.50",
        entity_profile=DummyProfile(),
        attack_kinematics={"192.168.1.50": DummyTraj()},
        observed_findings=[{"source_ip": "192.168.1.50", "attack_category": "Port Scan"}],
        window_count=5,
    )
    assert res.semantic_tier == ThreatSemanticTier.SUPPORTED_RECONNAISSANCE
    assert res.grounding_state in (
        EvidenceGroundingState.DIRECTLY_OBSERVED,
        EvidenceGroundingState.STRONGLY_SUPPORTED,
        EvidenceGroundingState.SUPPORTED,
    )
    assert len(res.supporting_modalities) > 0


def test_what_changed_detection():
    class DummyTrans:
        window_before = 2
        window_after = 3
        from_state = "BENIGN"
        to_state = "RECONNAISSANCE"
        transition_type = "ESCALATION"

    class DummyTraj:
        transitions = [DummyTrans()]

    class DummySignal:
        entity = "192.168.1.50"
        change_type = "FAN_OUT_SURGE"
        window_index = 3
        description = "Fan-out surged from 2 to 24 targets."

    items = build_what_changed(
        entity="192.168.1.50",
        attack_kinematics={"192.168.1.50": DummyTraj()},
        change_signals=[DummySignal()],
        window_count=5,
    )
    assert len(items) >= 1
    assert any(it.change_dimension == "ATTACK_STATE" for it in items)


def test_false_positive_benign_evaluation():
    class DummyProfile:
        roles = ["EXTERNAL_CLIENT"]
        successful_sessions = 5
        failure_ratio = 0.85
        targeted_ports_count = 15

    class DummyTraj:
        current_state = "RECONNAISSANCE"

    hypotheses = evaluate_benign_hypotheses(
        entity="192.168.1.50",
        entity_profile=DummyProfile(),
        attack_kinematics={"192.168.1.50": DummyTraj()},
    )
    assert len(hypotheses) > 0
    scanner_hyp = next((h for h in hypotheses if "Scanner" in h.title), None)
    assert scanner_hyp is not None
    assert scanner_hyp.resolution_state == BenignResolutionState.SUPPORTED_THREAT


def test_analyst_questions_generation():
    class DummyProfile:
        roles = ["EXTERNAL_CLIENT"]
        targeted_ports_count = 5
        peer_count = 10

    class DummyTraj:
        current_state = "RECONNAISSANCE"

    questions = generate_analyst_questions(
        entity="192.168.1.50",
        entity_profile=DummyProfile(),
        attack_kinematics={"192.168.1.50": DummyTraj()},
        contradictions=["Host role is EXTERNAL_CLIENT but initiates internal sweep scans."],
        window_count=5,
    )
    assert len(questions) >= 1
    assert any(q.category in ("AUTHORIZATION", "ATTACK_SURFACE", "TEMPORAL_PERSISTENCE") for q in questions)


def test_investigation_value_calculation():
    class DummyProfile:
        roles = ["EXTERNAL_CLIENT"]
        targeted_ports_count = 15
        peer_count = 10

    class DummyTraj:
        current_state = "RECONNAISSANCE"

    val = compute_investigation_value(
        entity="192.168.1.50",
        entity_profile=DummyProfile(),
        attack_kinematics={"192.168.1.50": DummyTraj()},
        contradictions=["Conflicting port scan signature"],
        findings_count=4,
        window_count=5,
    )
    assert val.investigation_value_score > 0
    assert val.value_tier in ("VERY_HIGH", "HIGH", "MODERATE", "LOW")
    assert len(val.drivers) > 0


def test_build_analyst_decisions():
    class DummyThreat:
        entity = "192.168.1.50"
        priority_level = "P1_HIGH"
        priority_rank = 1
        drivers = ["Sweep scan detected", "High fan-out"]
        mitigating_factors = []
        uncertainty_factors = []
        associated_campaign_id = None
        recommended_action = "Isolate host."

    class DummyProfile:
        roles = ["EXTERNAL_CLIENT"]
        successful_sessions = 5
        failure_ratio = 0.85
        targeted_ports_count = 10
        peer_count = 12

    class DummyTraj:
        current_state = "RECONNAISSANCE"
        transitions = []

    decisions = build_analyst_decisions(
        prioritized_threats=[DummyThreat()],
        entity_profiles={"192.168.1.50": DummyProfile()},
        attack_kinematics={"192.168.1.50": DummyTraj()},
        campaigns=[],
        patterns=[],
        change_signals=[],
        baseline_deviations=[],
        observed_findings=[{"source_ip": "192.168.1.50", "attack_category": "Port Scan", "finding_id": "f1"}],
        window_count=5,
    )
    assert len(decisions) >= 1
    top = decisions[0]
    assert top.subject == "192.168.1.50"
    assert top.priority == DecisionPriority.P1_HIGH
    assert top.investigation_value is not None
    assert top.threat_differentiation is not None

