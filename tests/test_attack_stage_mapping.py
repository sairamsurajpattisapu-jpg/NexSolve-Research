"""Tests for 15-stage canonical attack lifecycle taxonomy and MITRE ATT&CK mapping.

Tests:
1. 15 canonical stages + UNKNOWN all distinct with correct ordinals.
2. AttackStage properties: ordinal, display_name, description, category, mitre_tactics.
3. StageCategory classification (BASELINE, PRE_ATTACK, INTRUSION, EXPANSION, OBJECTIVE, UNKNOWN).
4. Bidirectional mapping to/from legacy AttackProgressionState.
5. Unknown / invalid inputs handled gracefully.
6. Verified MITRE technique registry lookup and validation.
7. Rejection of fake / fabricated MITRE technique IDs.
"""
from __future__ import annotations

import pytest
from ml.forecasting.attack_stages import (
    AttackStage,
    StageCategory,
    StageClassification,
    VERIFIED_MITRE_TECHNIQUES,
    to_canonical_stage,
    to_legacy_stage_name,
    validate_mitre_technique_id,
)
from ml.forecasting.attack_progression import AttackProgressionState


def test_fifteen_canonical_stages_and_unknown():
    """Verify exactly 15 canonical stages plus UNKNOWN exist, all distinct."""
    stages = list(AttackStage)
    assert len(stages) == 16  # 1 benign + 14 attack + 1 unknown

    expected_names = {
        "BENIGN",
        "RECONNAISSANCE",
        "RESOURCE_DEVELOPMENT",
        "INITIAL_ACCESS",
        "EXECUTION",
        "PERSISTENCE",
        "PRIVILEGE_ESCALATION",
        "DEFENSE_EVASION",
        "CREDENTIAL_ACCESS",
        "DISCOVERY",
        "LATERAL_MOVEMENT",
        "COLLECTION",
        "COMMAND_AND_CONTROL",
        "EXFILTRATION",
        "IMPACT",
        "UNKNOWN",
    }
    assert {s.name for s in stages} == expected_names


def test_stage_ordinals_and_categories():
    """Verify ordinals -1 to 14 and proper categorization."""
    assert AttackStage.UNKNOWN.ordinal == -1
    assert AttackStage.UNKNOWN.category == StageCategory.UNKNOWN

    assert AttackStage.BENIGN.ordinal == 0
    assert AttackStage.BENIGN.category == StageCategory.BASELINE

    assert AttackStage.RECONNAISSANCE.ordinal == 1
    assert AttackStage.RECONNAISSANCE.category == StageCategory.PRE_ATTACK

    assert AttackStage.RESOURCE_DEVELOPMENT.ordinal == 2
    assert AttackStage.RESOURCE_DEVELOPMENT.category == StageCategory.PRE_ATTACK

    assert AttackStage.INITIAL_ACCESS.ordinal == 3
    assert AttackStage.INITIAL_ACCESS.category == StageCategory.INTRUSION

    assert AttackStage.EXECUTION.ordinal == 4
    assert AttackStage.EXECUTION.category == StageCategory.INTRUSION

    assert AttackStage.PERSISTENCE.ordinal == 5
    assert AttackStage.PERSISTENCE.category == StageCategory.INTRUSION

    assert AttackStage.PRIVILEGE_ESCALATION.ordinal == 6
    assert AttackStage.PRIVILEGE_ESCALATION.category == StageCategory.INTRUSION

    assert AttackStage.DEFENSE_EVASION.ordinal == 7
    assert AttackStage.DEFENSE_EVASION.category == StageCategory.INTRUSION

    assert AttackStage.CREDENTIAL_ACCESS.ordinal == 8
    assert AttackStage.CREDENTIAL_ACCESS.category == StageCategory.INTRUSION

    assert AttackStage.DISCOVERY.ordinal == 9
    assert AttackStage.DISCOVERY.category == StageCategory.EXPANSION

    assert AttackStage.LATERAL_MOVEMENT.ordinal == 10
    assert AttackStage.LATERAL_MOVEMENT.category == StageCategory.EXPANSION

    assert AttackStage.COLLECTION.ordinal == 11
    assert AttackStage.COLLECTION.category == StageCategory.EXPANSION

    assert AttackStage.COMMAND_AND_CONTROL.ordinal == 12
    assert AttackStage.COMMAND_AND_CONTROL.category == StageCategory.OBJECTIVE

    assert AttackStage.EXFILTRATION.ordinal == 13
    assert AttackStage.EXFILTRATION.category == StageCategory.OBJECTIVE

    assert AttackStage.IMPACT.ordinal == 14
    assert AttackStage.IMPACT.category == StageCategory.OBJECTIVE

    # Verify all non-unknown stages have non-empty display name and description
    stages = list(AttackStage)
    for stage in stages:
        assert isinstance(stage.display_name, str) and len(stage.display_name) > 0
        assert isinstance(stage.description, str) and len(stage.description) > 0


def test_stage_mitre_tactics():
    """Verify MITRE ATT&CK enterprise tactics mapped to stages."""
    assert AttackStage.BENIGN.mitre_tactics == ()
    assert "TA0043" in AttackStage.RECONNAISSANCE.mitre_tactics
    assert "TA0001" in AttackStage.INITIAL_ACCESS.mitre_tactics
    assert "TA0002" in AttackStage.EXECUTION.mitre_tactics
    assert "TA0008" in AttackStage.LATERAL_MOVEMENT.mitre_tactics
    assert "TA0011" in AttackStage.COMMAND_AND_CONTROL.mitre_tactics
    assert "TA0010" in AttackStage.EXFILTRATION.mitre_tactics
    assert "TA0040" in AttackStage.IMPACT.mitre_tactics


def test_bidirectional_legacy_mapping():
    """Verify lossless bidirectional mapping between legacy and canonical stages."""
    # Legacy enum to canonical
    assert to_canonical_stage(AttackProgressionState.BENIGN_OBSERVATION) == AttackStage.BENIGN
    assert to_canonical_stage(AttackProgressionState.RECONNAISSANCE) == AttackStage.RECONNAISSANCE
    assert to_canonical_stage(AttackProgressionState.EXPLOITATION) == AttackStage.INITIAL_ACCESS
    assert to_canonical_stage(AttackProgressionState.COMMAND_AND_CONTROL) == AttackStage.COMMAND_AND_CONTROL
    assert to_canonical_stage(AttackProgressionState.DENIAL_OF_SERVICE) == AttackStage.IMPACT
    assert to_canonical_stage(AttackProgressionState.LATERAL_MOVEMENT) == AttackStage.LATERAL_MOVEMENT
    assert to_canonical_stage(AttackProgressionState.EXFILTRATION) == AttackStage.EXFILTRATION
    assert to_canonical_stage(AttackProgressionState.UNKNOWN_STATE) == AttackStage.UNKNOWN

    # String mapping to canonical
    assert to_canonical_stage("reconnaissance") == AttackStage.RECONNAISSANCE
    assert to_canonical_stage("EXPLOITATION") == AttackStage.INITIAL_ACCESS
    assert to_canonical_stage("DENIAL_OF_SERVICE") == AttackStage.IMPACT
    assert to_canonical_stage("totally_unknown_label") == AttackStage.UNKNOWN
    assert to_canonical_stage(None) == AttackStage.UNKNOWN

    # Canonical stage to legacy string name
    assert to_legacy_stage_name(AttackStage.BENIGN) == "BENIGN_OBSERVATION"
    assert to_legacy_stage_name(AttackStage.RECONNAISSANCE) == "RECONNAISSANCE"
    assert to_legacy_stage_name(AttackStage.INITIAL_ACCESS) == "EXPLOITATION"
    assert to_legacy_stage_name(AttackStage.EXECUTION) == "EXPLOITATION"
    assert to_legacy_stage_name(AttackStage.IMPACT) == "DENIAL_OF_SERVICE"
    assert to_legacy_stage_name(AttackStage.LATERAL_MOVEMENT) == "LATERAL_MOVEMENT"
    assert to_legacy_stage_name(AttackStage.EXFILTRATION) == "EXFILTRATION"
    assert to_legacy_stage_name(AttackStage.COMMAND_AND_CONTROL) == "COMMAND_AND_CONTROL"
    assert to_legacy_stage_name(AttackStage.UNKNOWN) == "UNKNOWN_STATE"


def test_verified_mitre_registry():
    """Verify MITRE techniques registry contains verified techniques with correct metadata."""
    assert len(VERIFIED_MITRE_TECHNIQUES) >= 14

    recon = VERIFIED_MITRE_TECHNIQUES.get("T1046")
    assert recon is not None
    assert recon["name"] == "Network Service Discovery"
    assert recon["primary_stage"] == AttackStage.RECONNAISSANCE

    c2 = VERIFIED_MITRE_TECHNIQUES.get("T1071")
    assert c2 is not None
    assert c2["name"] == "Application Layer Protocol"
    assert c2["primary_stage"] == AttackStage.COMMAND_AND_CONTROL

    dos = VERIFIED_MITRE_TECHNIQUES.get("T1498")
    assert dos is not None
    assert dos["name"] == "Network Denial of Service"
    assert dos["primary_stage"] == AttackStage.IMPACT

    exfil = VERIFIED_MITRE_TECHNIQUES.get("T1041")
    assert exfil is not None
    assert exfil["name"] == "Exfiltration Over C2 Channel"
    assert exfil["primary_stage"] == AttackStage.EXFILTRATION


def test_mitre_technique_validation():
    """Verify validation strictly rejects fabricated or fake technique IDs."""
    # Valid techniques
    assert validate_mitre_technique_id("T1046") is True
    assert validate_mitre_technique_id("t1046") is True  # case insensitive
    assert validate_mitre_technique_id("T1190") is True
    assert validate_mitre_technique_id("T1498") is True

    # Invalid / fabricated techniques
    assert validate_mitre_technique_id("T9999") is False
    assert validate_mitre_technique_id("ATTACK_123") is False
    assert validate_mitre_technique_id("T0000") is False
    assert validate_mitre_technique_id("") is False
    assert validate_mitre_technique_id(None) is False
