"""Tests for Stage Evidence models, validation, and multi-sensor corroboration.

Tests:
1. StageEvidence initialization with proper types and bounds.
2. Confidence bound enforcement in [0.0, 1.0].
3. Rejection of unverified / fake MITRE technique IDs.
4. Timestamp finiteness enforcement.
5. Multi-sensor agreement calculation (FULL, PARTIAL, CONFLICTING, INSUFFICIENT).
6. Serialization to dictionary.
"""
from __future__ import annotations

import math
import pytest
from ml.forecasting.attack_stages import AttackStage
from ml.forecasting.stage_evidence import (
    EvidencePolarity,
    EvidenceSource,
    SensorAgreement,
    StageEvidence,
    evaluate_sensor_agreement,
)


def test_stage_evidence_valid_construction():
    """Verify valid construction of StageEvidence."""
    ev = StageEvidence(
        evidence_id="ev_001",
        source=EvidenceSource.ZEEK,
        timestamp=1710000000.0,
        description="SYN scan detected on target host",
        stage=AttackStage.RECONNAISSANCE,
        technique_id="T1046",
        feature="syn_ratio",
        feature_value=0.95,
        confidence=0.88,
        polarity=EvidencePolarity.SUPPORTING,
    )
    assert ev.evidence_id == "ev_001"
    assert ev.source == EvidenceSource.ZEEK
    assert ev.stage == AttackStage.RECONNAISSANCE
    assert ev.technique_id == "T1046"
    assert ev.confidence == 0.88
    assert ev.polarity == EvidencePolarity.SUPPORTING

    d = ev.to_dict()
    assert d["evidence_id"] == "ev_001"
    assert d["source"] == "ZEEK"
    assert d["stage"] == "RECONNAISSANCE"
    assert d["technique_id"] == "T1046"
    assert d["confidence"] == 0.88


def test_confidence_bounds_enforcement():
    """Verify confidence strictly requires 0.0 <= confidence <= 1.0."""
    with pytest.raises(ValueError, match="confidence must be in \\[0.0, 1.0\\]"):
        StageEvidence(
            evidence_id="ev_invalid_low",
            source=EvidenceSource.PCAP,
            timestamp=1710000000.0,
            description="Bad confidence",
            confidence=-0.05,
        )

    with pytest.raises(ValueError, match="confidence must be in \\[0.0, 1.0\\]"):
        StageEvidence(
            evidence_id="ev_invalid_high",
            source=EvidenceSource.PCAP,
            timestamp=1710000000.0,
            description="Bad confidence",
            confidence=1.05,
        )


def test_unverified_mitre_technique_rejected():
    """Verify fake MITRE technique IDs are strictly rejected."""
    with pytest.raises(ValueError, match="Invalid or unverified MITRE ATT&CK technique"):
        StageEvidence(
            evidence_id="ev_fake_tech",
            source=EvidenceSource.HEURISTIC,
            timestamp=1710000000.0,
            description="Fabricated technique",
            technique_id="T9999",
        )

    with pytest.raises(ValueError, match="Invalid or unverified MITRE ATT&CK technique"):
        StageEvidence(
            evidence_id="ev_fake_tech",
            source=EvidenceSource.HEURISTIC,
            timestamp=1710000000.0,
            description="Arbitrary string technique",
            technique_id="RANDOM_ATTACK_99",
        )


def test_timestamp_finiteness_enforcement():
    """Verify non-finite timestamps (nan, inf) are rejected."""
    with pytest.raises(ValueError, match="must be a finite float epoch"):
        StageEvidence(
            evidence_id="ev_nan_ts",
            source=EvidenceSource.PCAP,
            timestamp=float("nan"),
            description="NaN timestamp",
        )

    with pytest.raises(ValueError, match="must be a finite float epoch"):
        StageEvidence(
            evidence_id="ev_inf_ts",
            source=EvidenceSource.PCAP,
            timestamp=float("inf"),
            description="Inf timestamp",
        )


def test_sensor_agreement_evaluation():
    """Verify evaluate_sensor_agreement returns correct corroboration state and modifiers."""
    # 1. Empty evidence
    agreement, mod = evaluate_sensor_agreement([])
    assert agreement == SensorAgreement.INSUFFICIENT
    assert mod == 0.50

    # 2. Single sensor supporting
    ev_zeek = StageEvidence(
        evidence_id="ev_z",
        source=EvidenceSource.ZEEK,
        timestamp=1710000000.0,
        description="Zeek scan",
        confidence=0.8,
        polarity=EvidencePolarity.SUPPORTING,
    )
    agreement, mod = evaluate_sensor_agreement([ev_zeek])
    assert agreement == SensorAgreement.PARTIAL
    assert mod == 0.90

    # 3. Multiple independent sensors supporting (FULL agreement)
    ev_suri = StageEvidence(
        evidence_id="ev_s",
        source=EvidenceSource.SURICATA,
        timestamp=1710000000.0,
        description="Suricata scan alert",
        confidence=0.85,
        polarity=EvidencePolarity.SUPPORTING,
    )
    agreement, mod = evaluate_sensor_agreement([ev_zeek, ev_suri])
    assert agreement == SensorAgreement.FULL
    assert mod == 1.10

    # 4. Conflicting sensors (SUPPORTING + CONTRADICTORY)
    ev_contra = StageEvidence(
        evidence_id="ev_c",
        source=EvidenceSource.PCAP,
        timestamp=1710000000.0,
        description="Legitimate internal heartbeat",
        confidence=0.90,
        polarity=EvidencePolarity.CONTRADICTORY,
    )
    agreement, mod = evaluate_sensor_agreement([ev_zeek, ev_suri, ev_contra])
    assert agreement == SensorAgreement.CONFLICTING
    assert mod == 0.45

    # 5. Neutral only
    ev_neutral = StageEvidence(
        evidence_id="ev_n",
        source=EvidenceSource.NFSTREAM,
        timestamp=1710000000.0,
        description="Flow observed",
        confidence=0.50,
        polarity=EvidencePolarity.NEUTRAL,
    )
    agreement, mod = evaluate_sensor_agreement([ev_neutral])
    assert agreement == SensorAgreement.INSUFFICIENT
    assert mod == 0.50
