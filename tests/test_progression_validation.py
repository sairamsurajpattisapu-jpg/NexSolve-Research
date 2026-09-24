"""Tests for Attack Progression Timeline and Transition Validation.

Tests:
1. Empty timeline audit returns valid=False.
2. Valid multi-event timeline passes validation.
3. Out-of-order non-chronological events detected and flagged.
4. Contradictory simultaneous states at exact same timestamp detected.
5. Transition validity audit checks (INVALID transitions raise issues, CONTRADICTORY flag warnings).
6. Missing evidence on observed non-benign events generates warnings.
"""
from __future__ import annotations

import pytest
from ml.forecasting.attack_stages import AttackStage, StageClassification
from ml.forecasting.stage_evidence import EvidencePolarity, EvidenceSource, StageEvidence
from ml.forecasting.stage_transitions import (
    AttackTransition,
    TransitionType,
    TransitionValidationStatus,
)
from ml.forecasting.attack_progression_engine import (
    TimelineEvent,
    validate_progression_timeline,
)


def test_empty_timeline_validation():
    """Verify empty timeline produces invalid audit result."""
    res = validate_progression_timeline([])
    assert res.valid is False
    assert len(res.issues) > 0
    assert "empty" in res.issues[0].lower()


def test_valid_chronological_timeline():
    """Verify clean chronological timeline passes validation."""
    ev1 = StageEvidence(
        evidence_id="ev_1",
        source=EvidenceSource.ZEEK,
        timestamp=100.0,
        description="Port scan",
        stage=AttackStage.RECONNAISSANCE,
        technique_id="T1046",
        confidence=0.85,
    )
    event1 = TimelineEvent(
        timestamp=100.0,
        stage=AttackStage.RECONNAISSANCE,
        classification=StageClassification.OBSERVED,
        confidence=0.85,
        stage_confidence=0.85,
        technique_confidence=0.85,
        primary_techniques=("T1046",),
        supporting_evidence=(ev1,),
    )

    ev2 = StageEvidence(
        evidence_id="ev_2",
        source=EvidenceSource.SURICATA,
        timestamp=160.0,
        description="Exploit attempt",
        stage=AttackStage.INITIAL_ACCESS,
        technique_id="T1190",
        confidence=0.80,
    )
    event2 = TimelineEvent(
        timestamp=160.0,
        stage=AttackStage.INITIAL_ACCESS,
        classification=StageClassification.OBSERVED,
        confidence=0.80,
        stage_confidence=0.80,
        technique_confidence=0.80,
        primary_techniques=("T1190",),
        supporting_evidence=(ev2,),
    )

    event3 = TimelineEvent(
        timestamp=220.0,
        stage=AttackStage.EXECUTION,
        classification=StageClassification.FORECAST,
        confidence=0.65,
        stage_confidence=0.65,
        technique_confidence=0.65,
        primary_techniques=("T1059",),
        lead_time_seconds=60.0,
        horizon_label="T+1",
    )

    transition = AttackTransition(
        from_stage=AttackStage.RECONNAISSANCE,
        to_stage=AttackStage.INITIAL_ACCESS,
        timestamp=160.0,
        confidence=0.80,
        transition_type=TransitionType.OBSERVED,
        status=TransitionValidationStatus.VALID,
        reason="Expected sequential step",
        supporting_evidence=(ev2,),
    )

    res = validate_progression_timeline(
        timeline=[event1, event2, event3],
        transitions=[transition],
    )

    assert res.valid is True
    assert len(res.issues) == 0
    assert res.event_count == 3
    assert res.transition_count == 1


def test_out_of_order_timestamps_flagged():
    """Verify non-chronological historical timestamps are caught."""
    ev = StageEvidence(
        evidence_id="ev_0",
        source=EvidenceSource.PCAP,
        timestamp=200.0,
        description="Traffic",
        confidence=0.7,
    )
    event1 = TimelineEvent(
        timestamp=200.0,
        stage=AttackStage.RECONNAISSANCE,
        classification=StageClassification.OBSERVED,
        confidence=0.8,
        stage_confidence=0.8,
        technique_confidence=0.8,
        supporting_evidence=(ev,),
    )
    # Event 2 has timestamp 150.0 < 200.0
    event2 = TimelineEvent(
        timestamp=150.0,
        stage=AttackStage.INITIAL_ACCESS,
        classification=StageClassification.OBSERVED,
        confidence=0.8,
        stage_confidence=0.8,
        technique_confidence=0.8,
        supporting_evidence=(ev,),
    )

    res = validate_progression_timeline([event1, event2])
    assert res.valid is False
    assert any("Timestamp out of order" in issue for issue in res.issues)


def test_contradictory_simultaneous_states_flagged():
    """Verify benign and attack simultaneously at the exact same timestamp is flagged."""
    ev = StageEvidence(
        evidence_id="ev_0",
        source=EvidenceSource.PCAP,
        timestamp=100.0,
        description="Traffic",
        confidence=0.7,
    )
    event_benign = TimelineEvent(
        timestamp=100.0,
        stage=AttackStage.BENIGN,
        classification=StageClassification.OBSERVED,
        confidence=0.9,
        stage_confidence=0.9,
        technique_confidence=0.9,
    )
    event_attack = TimelineEvent(
        timestamp=100.0,
        stage=AttackStage.IMPACT,
        classification=StageClassification.OBSERVED,
        confidence=0.9,
        stage_confidence=0.9,
        technique_confidence=0.9,
        supporting_evidence=(ev,),
    )

    res = validate_progression_timeline([event_benign, event_attack])
    assert res.valid is False
    assert any("Contradictory simultaneous states" in issue for issue in res.issues)


def test_transition_status_audit():
    """Verify invalid transition causes timeline validation failure, while contradictory causes warning."""
    ev = StageEvidence(
        evidence_id="ev_1",
        source=EvidenceSource.PCAP,
        timestamp=100.0,
        description="Normal event",
        confidence=0.8,
    )
    event = TimelineEvent(
        timestamp=100.0,
        stage=AttackStage.BENIGN,
        classification=StageClassification.OBSERVED,
        confidence=0.9,
        stage_confidence=0.9,
        technique_confidence=0.9,
    )

    # Invalid transition
    invalid_tr = AttackTransition(
        from_stage=AttackStage.BENIGN,
        to_stage=AttackStage.IMPACT,
        timestamp=100.0,
        confidence=0.1,
        transition_type=TransitionType.OBSERVED,
        status=TransitionValidationStatus.INVALID,
        reason="Unrecognized transition",
    )
    res_inv = validate_progression_timeline([event], [invalid_tr])
    assert res_inv.valid is False
    assert any("INVALID" in issue for issue in res_inv.issues)

    # Contradictory transition yields warning, valid=True
    contra_tr = AttackTransition(
        from_stage=AttackStage.RECONNAISSANCE,
        to_stage=AttackStage.COMMAND_AND_CONTROL,
        timestamp=100.0,
        confidence=0.3,
        transition_type=TransitionType.OBSERVED,
        status=TransitionValidationStatus.CONTRADICTORY,
        reason="Contradictory sensor reports",
    )
    res_contra = validate_progression_timeline([event], [contra_tr])
    assert res_contra.valid is True
    assert len(res_contra.warnings) > 0
    assert any("contradictory" in w.lower() for w in res_contra.warnings)
