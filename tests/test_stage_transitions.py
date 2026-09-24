"""Tests for Attack Stage Transitions and Transition Matrix.

Tests:
1. Normal sequential progression (RECON -> INITIAL_ACCESS -> EXECUTION).
2. Looping and state persistence (RECON -> RECON).
3. Backtracking / non-linear transitions (LATERAL_MOVEMENT -> RECON).
4. Direct evidence requirement for unusual leaps (BENIGN -> EXFILTRATION without evidence yields INSUFFICIENT_EVIDENCE).
5. Corroborated unusual leaps (BENIGN -> EXFILTRATION with evidence yields VALID_BUT_UNUSUAL).
6. Contradictory evidence overrides.
7. Unresolved UNKNOWN state transitions.
8. Transition matrix completeness and consistency.
"""
from __future__ import annotations

import pytest
from ml.forecasting.attack_stages import AttackStage
from ml.forecasting.stage_evidence import (
    EvidencePolarity,
    EvidenceSource,
    StageEvidence,
)
from ml.forecasting.stage_transitions import (
    STAGE_TRANSITION_MATRIX,
    AttackTransition,
    TransitionSemantics,
    TransitionType,
    TransitionValidationStatus,
    validate_transition,
)


def test_expected_sequential_transitions():
    """Verify standard canonical lifecycle steps are VALID and EXPECTED."""
    transitions_to_test = [
        (AttackStage.RECONNAISSANCE, AttackStage.RESOURCE_DEVELOPMENT),
        (AttackStage.INITIAL_ACCESS, AttackStage.EXECUTION),
        (AttackStage.EXECUTION, AttackStage.PERSISTENCE),
        (AttackStage.COMMAND_AND_CONTROL, AttackStage.EXFILTRATION),
    ]

    for s_from, s_to in transitions_to_test:
        rule = STAGE_TRANSITION_MATRIX.get((s_from, s_to))
        assert rule is not None
        assert rule.allowed is True
        assert rule.semantics in (TransitionSemantics.EXPECTED, TransitionSemantics.POSSIBLE)

        trans = validate_transition(
            from_stage=s_from,
            to_stage=s_to,
            timestamp=1710000000.0,
            base_confidence=0.85,
        )
        assert trans.status == TransitionValidationStatus.VALID
        assert 0.0 <= trans.confidence <= 1.0

    # Also verify forward acceleration / leap (ordinal + 2) is valid when corroborated by evidence
    ev_ia = StageEvidence(
        evidence_id="ev_ia",
        source=EvidenceSource.SURICATA,
        timestamp=1710000000.0,
        description="Public exploit triggered",
        stage=AttackStage.INITIAL_ACCESS,
        technique_id="T1190",
        confidence=0.85,
        polarity=EvidencePolarity.SUPPORTING,
    )
    leap_trans = validate_transition(
        from_stage=AttackStage.RECONNAISSANCE,
        to_stage=AttackStage.INITIAL_ACCESS,
        timestamp=1710000000.0,
        evidence=[ev_ia],
        base_confidence=0.85,
    )
    assert leap_trans.status == TransitionValidationStatus.VALID


def test_state_persistence_transition():
    """Verify persistence (staying in same stage) is valid and expected."""
    trans = validate_transition(
        from_stage=AttackStage.LATERAL_MOVEMENT,
        to_stage=AttackStage.LATERAL_MOVEMENT,
        timestamp=1710000010.0,
        base_confidence=0.80,
    )
    assert trans.status == TransitionValidationStatus.VALID
    assert "persistence" in trans.reason.lower()
    assert trans.confidence == 0.80

    # Persistence with contradictory evidence
    contra_ev = StageEvidence(
        evidence_id="ev_contra_1",
        source=EvidenceSource.SURICATA,
        timestamp=1710000010.0,
        description="Host restored to clean image",
        stage=AttackStage.LATERAL_MOVEMENT,
        confidence=0.90,
        polarity=EvidencePolarity.CONTRADICTORY,
    )
    trans_contra = validate_transition(
        from_stage=AttackStage.LATERAL_MOVEMENT,
        to_stage=AttackStage.LATERAL_MOVEMENT,
        timestamp=1710000010.0,
        evidence=[contra_ev],
        base_confidence=0.80,
    )
    assert trans_contra.status == TransitionValidationStatus.CONTRADICTORY
    assert trans_contra.confidence < 0.80


def test_backtracking_and_looping_transitions():
    """Verify non-linear steps like returning to Recon from Lateral Movement are handled."""
    rule = STAGE_TRANSITION_MATRIX.get((AttackStage.LATERAL_MOVEMENT, AttackStage.RECONNAISSANCE))
    assert rule is not None
    assert rule.allowed is True
    assert rule.semantics == TransitionSemantics.UNUSUAL

    # Without evidence, unusual backward transition yields INSUFFICIENT_EVIDENCE
    trans_no_ev = validate_transition(
        from_stage=AttackStage.LATERAL_MOVEMENT,
        to_stage=AttackStage.RECONNAISSANCE,
        timestamp=1710000020.0,
        evidence=[],
    )
    assert trans_no_ev.status == TransitionValidationStatus.INSUFFICIENT_EVIDENCE

    # With corroborating evidence, becomes VALID_BUT_UNUSUAL
    ev = StageEvidence(
        evidence_id="ev_recon_scan",
        source=EvidenceSource.ZEEK,
        timestamp=1710000020.0,
        description="Internal subnet port sweep from compromised node",
        stage=AttackStage.RECONNAISSANCE,
        technique_id="T1046",
        confidence=0.88,
        polarity=EvidencePolarity.SUPPORTING,
    )
    trans_with_ev = validate_transition(
        from_stage=AttackStage.LATERAL_MOVEMENT,
        to_stage=AttackStage.RECONNAISSANCE,
        timestamp=1710000020.0,
        evidence=[ev],
    )
    assert trans_with_ev.status == TransitionValidationStatus.VALID_BUT_UNUSUAL
    assert len(trans_with_ev.supporting_evidence) == 1


def test_unusual_leap_requires_direct_evidence():
    """Verify leap from BENIGN straight to EXFILTRATION strictly requires direct evidence."""
    rule = STAGE_TRANSITION_MATRIX.get((AttackStage.BENIGN, AttackStage.EXFILTRATION))
    assert rule is not None
    assert rule.requires_direct_evidence is True

    # Without evidence
    trans_no_ev = validate_transition(
        from_stage=AttackStage.BENIGN,
        to_stage=AttackStage.EXFILTRATION,
        timestamp=1710000030.0,
        evidence=[],
    )
    assert trans_no_ev.status == TransitionValidationStatus.INSUFFICIENT_EVIDENCE
    assert "requires direct corroborated telemetry" in trans_no_ev.reason

    # With high-confidence exfiltration telemetry
    ev = StageEvidence(
        evidence_id="ev_exfil_1",
        source=EvidenceSource.NFSTREAM,
        timestamp=1710000030.0,
        description="Large egress transfer over encrypted channel",
        stage=AttackStage.EXFILTRATION,
        technique_id="T1041",
        confidence=0.92,
        polarity=EvidencePolarity.SUPPORTING,
    )
    trans_with_ev = validate_transition(
        from_stage=AttackStage.BENIGN,
        to_stage=AttackStage.EXFILTRATION,
        timestamp=1710000030.0,
        evidence=[ev],
    )
    assert trans_with_ev.status == TransitionValidationStatus.VALID_BUT_UNUSUAL
    assert trans_with_ev.confidence > 0.10


def test_contradictory_evidence_outweighs_supporting():
    """Verify that when contradictory evidence outweighs supporting evidence, transition is CONTRADICTORY."""
    sup = StageEvidence(
        evidence_id="ev_sup",
        source=EvidenceSource.HEURISTIC,
        timestamp=1710000040.0,
        description="Heuristic flag for C2 beaconing",
        stage=AttackStage.COMMAND_AND_CONTROL,
        confidence=0.50,
        polarity=EvidencePolarity.SUPPORTING,
    )
    contra1 = StageEvidence(
        evidence_id="ev_contra_1",
        source=EvidenceSource.ZEEK,
        timestamp=1710000040.0,
        description="Known legitimate NTP synchronization server",
        stage=AttackStage.COMMAND_AND_CONTROL,
        confidence=0.95,
        polarity=EvidencePolarity.CONTRADICTORY,
    )
    contra2 = StageEvidence(
        evidence_id="ev_contra_2",
        source=EvidenceSource.PCAP,
        timestamp=1710000040.0,
        description="Strict packet size match with standard NTP protocol",
        stage=AttackStage.COMMAND_AND_CONTROL,
        confidence=0.90,
        polarity=EvidencePolarity.CONTRADICTORY,
    )

    trans = validate_transition(
        from_stage=AttackStage.INITIAL_ACCESS,
        to_stage=AttackStage.COMMAND_AND_CONTROL,
        timestamp=1710000040.0,
        evidence=[sup, contra1, contra2],
        base_confidence=0.75,
    )
    assert trans.status == TransitionValidationStatus.CONTRADICTORY
    assert "Contradictory evidence outweighs" in trans.reason
    assert len(trans.contradictory_evidence) == 2


def test_unknown_stage_transition_handling():
    """Verify transition involving UNKNOWN is marked INSUFFICIENT_EVIDENCE with low confidence."""
    trans1 = validate_transition(
        from_stage=AttackStage.UNKNOWN,
        to_stage=AttackStage.COMMAND_AND_CONTROL,
        timestamp=1710000050.0,
    )
    assert trans1.status == TransitionValidationStatus.INSUFFICIENT_EVIDENCE
    assert trans1.confidence == 0.20

    trans2 = validate_transition(
        from_stage=AttackStage.RECONNAISSANCE,
        to_stage=AttackStage.UNKNOWN,
        timestamp=1710000050.0,
    )
    assert trans2.status == TransitionValidationStatus.INSUFFICIENT_EVIDENCE


def test_transition_matrix_integrity():
    """Verify matrix contains rules for all 15x15 non-unknown stage combinations."""
    known_stages = [s for s in AttackStage if s != AttackStage.UNKNOWN]
    assert len(known_stages) == 15
    expected_pairs = 15 * 15  # 225 pairs
    assert len(STAGE_TRANSITION_MATRIX) == expected_pairs

    for s_from in known_stages:
        for s_to in known_stages:
            assert (s_from, s_to) in STAGE_TRANSITION_MATRIX
            rule = STAGE_TRANSITION_MATRIX[(s_from, s_to)]
            assert 0.0 <= rule.confidence_modifier <= 1.5
            assert isinstance(rule.description, str) and len(rule.description) > 0
