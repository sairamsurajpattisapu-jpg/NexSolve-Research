"""Non-Linear Attack Stage Transition Engine and Matrix.

Defines the mathematical kinematics and evidentiary validation of transitions
between analytical attack stages:
- Transitions are NOT assumed to be linear: attackers can skip stages, repeat stages,
  move backward in observable evidence, or execute parallel tasks.
- Impossible/unusual transition safety: provides structured diagnostics (VALID,
  VALID_BUT_UNUSUAL, INSUFFICIENT_EVIDENCE, CONTRADICTORY, INVALID) instead of naive rejection.
- Grounded in empirical transition matrix with explicit evidentiary prerequisites.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import math
from typing import Any, Mapping, Sequence

from ml.forecasting.attack_stages import AttackStage
from ml.forecasting.stage_evidence import (
    EvidencePolarity,
    SensorAgreement,
    StageEvidence,
    evaluate_sensor_agreement,
)


class TransitionType(str, Enum):
    """Temporal context of the stage transition."""
    OBSERVED = "OBSERVED"    # Directly demonstrated between consecutive observed windows
    INFERRED = "INFERRED"    # Derived from multi-window telemetry evolution
    FORECAST = "FORECAST"    # Projected into future horizon T+h
    UNKNOWN = "UNKNOWN"      # Undetermined or uncorroborated


class TransitionSemantics(str, Enum):
    """Plausibility profile of the transition."""
    EXPECTED = "EXPECTED"          # Standard forward progression in intrusion kill-chains
    POSSIBLE = "POSSIBLE"          # Realistic tactical progression or state persistence
    UNUSUAL = "UNUSUAL"            # Less common lateral step or backtracking requiring direct evidence
    UNSUPPORTED = "UNSUPPORTED"    # Lacks historical replication or structural justification
    CONTRADICTORY = "CONTRADICTORY"# Evidence directly refutes or conflicts with transition


class TransitionValidationStatus(str, Enum):
    """Formal audit status for an asserted transition."""
    VALID = "VALID"
    VALID_BUT_UNUSUAL = "VALID_BUT_UNUSUAL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    CONTRADICTORY = "CONTRADICTORY"
    INVALID = "INVALID"


@dataclass(slots=True, frozen=True)
class TransitionRule:
    """Configurable rule governing a directed stage pair (from_stage -> to_stage)."""
    semantics: TransitionSemantics
    allowed: bool
    requires_direct_evidence: bool
    confidence_modifier: float
    description: str


@dataclass(slots=True, frozen=True)
class AttackTransition:
    """Formal transition record between two analytical attack stages."""
    from_stage: AttackStage
    to_stage: AttackStage
    timestamp: float
    confidence: float
    transition_type: TransitionType = TransitionType.INFERRED
    status: TransitionValidationStatus = TransitionValidationStatus.VALID
    reason: str = ""
    supporting_evidence: tuple[Any, ...] = ()
    contradictory_evidence: tuple[Any, ...] = ()

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Transition confidence must be in [0.0, 1.0], got {self.confidence}")
        if not math.isfinite(self.timestamp):
            raise ValueError(f"Invalid timestamp '{self.timestamp}'; must be a finite float epoch.")

    @property
    def classification(self) -> str:
        return self.transition_type.value

    @property
    def validation_status(self) -> str:
        return self.status.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_stage": self.from_stage.value,
            "to_stage": self.to_stage.value,
            "timestamp": self.timestamp,
            "confidence": round(self.confidence, 4),
            "transition_type": self.transition_type.value,
            "classification": self.transition_type.value,
            "status": self.status.value,
            "validation_status": self.status.value,
            "reason": self.reason,
            "supporting_evidence": [e.to_dict() if hasattr(e, "to_dict") else str(e) for e in self.supporting_evidence],
            "contradictory_evidence": [e.to_dict() if hasattr(e, "to_dict") else str(e) for e in self.contradictory_evidence],
        }


def _build_default_transition_matrix() -> dict[tuple[AttackStage, AttackStage], TransitionRule]:
    """Construct complete, machine-readable transition matrix across all 15 stages."""
    matrix: dict[tuple[AttackStage, AttackStage], TransitionRule] = {}

    all_stages = [s for s in AttackStage if s != AttackStage.UNKNOWN]

    for s_from in all_stages:
        for s_to in all_stages:
            # 1. State Persistence (S_t == S_{t+1})
            if s_from == s_to:
                matrix[(s_from, s_to)] = TransitionRule(
                    semantics=TransitionSemantics.EXPECTED,
                    allowed=True,
                    requires_direct_evidence=False,
                    confidence_modifier=1.0,
                    description=f"State persistence within {s_from.display_name}.",
                )
                continue

            # 2. Return to Benign (Remediation / Quiescence / Session close)
            if s_to == AttackStage.BENIGN:
                matrix[(s_from, s_to)] = TransitionRule(
                    semantics=TransitionSemantics.POSSIBLE,
                    allowed=True,
                    requires_direct_evidence=False,
                    confidence_modifier=0.85,
                    description=f"Activity ceased; return to baseline from {s_from.display_name}.",
                )
                continue

            # 3. Transitions from BENIGN
            if s_from == AttackStage.BENIGN:
                if s_to in (AttackStage.RECONNAISSANCE, AttackStage.RESOURCE_DEVELOPMENT):
                    matrix[(s_from, s_to)] = TransitionRule(
                        semantics=TransitionSemantics.EXPECTED,
                        allowed=True,
                        requires_direct_evidence=True,
                        confidence_modifier=0.90,
                        description="Initial reconnaissance or resource acquisition against enterprise perimeter.",
                    )
                elif s_to == AttackStage.INITIAL_ACCESS:
                    matrix[(s_from, s_to)] = TransitionRule(
                        semantics=TransitionSemantics.POSSIBLE,
                        allowed=True,
                        requires_direct_evidence=True,
                        confidence_modifier=0.80,
                        description="Direct initial access exploit without prior observable scanning.",
                    )
                elif s_to == AttackStage.IMPACT:
                    matrix[(s_from, s_to)] = TransitionRule(
                        semantics=TransitionSemantics.POSSIBLE,
                        allowed=True,
                        requires_direct_evidence=True,
                        confidence_modifier=0.85,
                        description="Direct volumetric or service flooding from baseline.",
                    )
                else:
                    # Jumping directly to Exfiltration, C2, Lateral Movement from Benign is unusual and requires direct evidence
                    matrix[(s_from, s_to)] = TransitionRule(
                        semantics=TransitionSemantics.UNUSUAL,
                        allowed=True,
                        requires_direct_evidence=True,
                        confidence_modifier=0.55,
                        description=f"Direct transition from Benign to advanced stage {s_to.display_name} requires direct corroborated telemetry.",
                    )
                continue

            # 4. Standard Forward Attack Kinematics
            from_ord = s_from.ordinal
            to_ord = s_to.ordinal

            if to_ord == from_ord + 1:
                # Direct step forward
                matrix[(s_from, s_to)] = TransitionRule(
                    semantics=TransitionSemantics.EXPECTED,
                    allowed=True,
                    requires_direct_evidence=False,
                    confidence_modifier=0.95,
                    description=f"Sequential forward progression from {s_from.display_name} to {s_to.display_name}.",
                )
            elif to_ord > from_ord:
                # Forward leap (e.g. Initial Access -> C2, skipping execution / persistence logging)
                matrix[(s_from, s_to)] = TransitionRule(
                    semantics=TransitionSemantics.POSSIBLE,
                    allowed=True,
                    requires_direct_evidence=True,
                    confidence_modifier=0.80,
                    description=f"Forward stage acceleration from {s_from.display_name} to {s_to.display_name}.",
                )
            else:
                # Backward movement (e.g. Lateral Movement -> Discovery, or C2 -> Reconnaissance)
                # Realistic for iterative adversaries exploring new enclaves
                if s_from in (AttackStage.LATERAL_MOVEMENT, AttackStage.COMMAND_AND_CONTROL) and s_to in (AttackStage.DISCOVERY, AttackStage.CREDENTIAL_ACCESS):
                    matrix[(s_from, s_to)] = TransitionRule(
                        semantics=TransitionSemantics.POSSIBLE,
                        allowed=True,
                        requires_direct_evidence=True,
                        confidence_modifier=0.75,
                        description=f"Internal post-compromise expansion: returning to {s_to.display_name} from {s_from.display_name}.",
                    )
                else:
                    matrix[(s_from, s_to)] = TransitionRule(
                        semantics=TransitionSemantics.UNUSUAL,
                        allowed=True,
                        requires_direct_evidence=True,
                        confidence_modifier=0.60,
                        description=f"Non-linear backward step from {s_from.display_name} to earlier stage {s_to.display_name}.",
                    )

    return matrix


STAGE_TRANSITION_MATRIX: dict[tuple[AttackStage, AttackStage], TransitionRule] = _build_default_transition_matrix()


def validate_transition(
    from_stage: AttackStage,
    to_stage: AttackStage,
    timestamp: float,
    evidence: Sequence[StageEvidence] = (),
    transition_type: TransitionType = TransitionType.INFERRED,
    base_confidence: float = 0.70,
) -> AttackTransition:
    """Validate and score a candidate attack stage transition against evidentiary rules."""
    # Handle UNKNOWN cases
    if from_stage == AttackStage.UNKNOWN or to_stage == AttackStage.UNKNOWN:
        return AttackTransition(
            from_stage=from_stage,
            to_stage=to_stage,
            timestamp=timestamp,
            confidence=0.20,
            transition_type=transition_type,
            status=TransitionValidationStatus.INSUFFICIENT_EVIDENCE,
            reason="Transition involves unresolved UNKNOWN state.",
            supporting_evidence=tuple(evidence),
            contradictory_evidence=(),
        )

    # State persistence
    if from_stage == to_stage:
        supporting = [e for e in evidence if e.polarity == EvidencePolarity.SUPPORTING]
        contradictory = [e for e in evidence if e.polarity == EvidencePolarity.CONTRADICTORY]
        conf = min(1.0, max(0.05, base_confidence if not contradictory else base_confidence * 0.5))
        return AttackTransition(
            from_stage=from_stage,
            to_stage=to_stage,
            timestamp=timestamp,
            confidence=conf,
            transition_type=transition_type,
            status=TransitionValidationStatus.VALID if not contradictory else TransitionValidationStatus.CONTRADICTORY,
            reason=f"Continued persistence in stage {from_stage.display_name}.",
            supporting_evidence=tuple(supporting),
            contradictory_evidence=tuple(contradictory),
        )

    rule = STAGE_TRANSITION_MATRIX.get((from_stage, to_stage))
    if rule is None:
        return AttackTransition(
            from_stage=from_stage,
            to_stage=to_stage,
            timestamp=timestamp,
            confidence=0.10,
            transition_type=transition_type,
            status=TransitionValidationStatus.INVALID,
            reason=f"Transition ({from_stage.value} -> {to_stage.value}) not recognized in state matrix.",
            supporting_evidence=tuple(evidence),
            contradictory_evidence=(),
        )

    supporting = [e for e in evidence if e.polarity == EvidencePolarity.SUPPORTING]
    contradictory = [e for e in evidence if e.polarity == EvidencePolarity.CONTRADICTORY]

    # Evaluate contradictory signals
    if contradictory and len(contradictory) > len(supporting):
        return AttackTransition(
            from_stage=from_stage,
            to_stage=to_stage,
            timestamp=timestamp,
            confidence=round(max(0.05, base_confidence * 0.35), 4),
            transition_type=transition_type,
            status=TransitionValidationStatus.CONTRADICTORY,
            reason=f"Contradictory evidence outweighs supporting telemetry for {from_stage.value} -> {to_stage.value}.",
            supporting_evidence=tuple(supporting),
            contradictory_evidence=tuple(contradictory),
        )

    # Check direct evidence requirement for unusual transitions
    # (e.g. from BENIGN to EXFILTRATION requires direct exfiltration evidence)
    if rule.requires_direct_evidence and not supporting:
        return AttackTransition(
            from_stage=from_stage,
            to_stage=to_stage,
            timestamp=timestamp,
            confidence=round(max(0.05, base_confidence * 0.25), 4),
            transition_type=transition_type,
            status=TransitionValidationStatus.INSUFFICIENT_EVIDENCE,
            reason=(
                f"Transition from {from_stage.display_name} to {to_stage.display_name} requires "
                "direct corroborated telemetry, but no supporting evidence items were supplied."
            ),
            supporting_evidence=(),
            contradictory_evidence=tuple(contradictory),
        )

    agreement, agreement_mod = evaluate_sensor_agreement(evidence)
    final_conf = min(0.99, max(0.05, base_confidence * rule.confidence_modifier * agreement_mod))

    if rule.semantics == TransitionSemantics.UNUSUAL:
        status = TransitionValidationStatus.VALID_BUT_UNUSUAL
        reason = f"Unusual transition {from_stage.value} -> {to_stage.value} corroborated by {len(supporting)} evidence items."
    else:
        status = TransitionValidationStatus.VALID
        reason = rule.description

    return AttackTransition(
        from_stage=from_stage,
        to_stage=to_stage,
        timestamp=timestamp,
        confidence=round(final_conf, 4),
        transition_type=transition_type,
        status=status,
        reason=reason,
        supporting_evidence=tuple(supporting),
        contradictory_evidence=tuple(contradictory),
    )
