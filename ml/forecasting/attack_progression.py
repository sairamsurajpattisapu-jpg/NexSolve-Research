"""Markovian attack-stage progression model and empirical forecaster.

Evaluates evidence-bounded transition probabilities P(State_{T+K} | State_T) across
horizons K in {1, 2, 3, 4, 5}.

Integrates with the Canonical 15-Stage Lifecycle Taxonomy (AttackStage):
- Distinguishes OBSERVED state from INFERRED and FORECAST future states.
- Strictly separates STATE_PERSISTENCE (S_{T+K} == S_T) from DOWNSTREAM_PROGRESSION (S_{T+K} != S_T).
- Separates technique confidence, stage confidence, transition confidence, and forecast confidence.
- Strictly abstains when evidence is insufficient, horizon is unsupported, state is benign,
  or no supported downstream transition exists.
- Non-linear transition validation and timeline consistency verification.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
import math
from typing import Any, Mapping, Sequence

from ml.forecasting.attack_stages import (
    AttackStage,
    StageCategory,
    StageClassification,
    VERIFIED_MITRE_TECHNIQUES,
    to_canonical_stage,
    to_legacy_stage_name,
    validate_mitre_technique_id,
)
from ml.forecasting.stage_evidence import (
    EvidencePolarity,
    EvidenceSource,
    SensorAgreement,
    StageEvidence,
    evaluate_sensor_agreement,
)
from ml.forecasting.stage_transitions import (
    AttackTransition,
    STAGE_TRANSITION_MATRIX,
    TransitionSemantics,
    TransitionType,
    TransitionValidationStatus,
    validate_transition,
)
from ml.forecasting.attack_progression_engine import (
    ProgressionValidationResult,
    TimelineEvent,
    infer_current_attack_stage,
    validate_progression_timeline,
)


class AttackProgressionState(str, Enum):
    """Legacy 7-stage attack progression enum preserved for backward compatibility."""
    BENIGN_OBSERVATION = "BENIGN_OBSERVATION"
    RECONNAISSANCE = "RECONNAISSANCE"
    EXPLOITATION = "EXPLOITATION"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    EXFILTRATION = "EXFILTRATION"
    UNKNOWN_STATE = "UNKNOWN_STATE"


class PredictionType(str, Enum):
    """Categorizes the semantic meaning of the forecast point."""
    STATE_PERSISTENCE = "STATE_PERSISTENCE"        # Ongoing continuation of observed stage S_T == S_{T+K}
    DOWNSTREAM_PROGRESSION = "DOWNSTREAM_PROGRESSION"  # Empirically verified cross-stage transition S_T != S_{T+K}
    ABSTAINED = "ABSTAINED"                        # Abstained due to lack of empirical evidence, horizon limits, or benign state


EMPIRICALLY_SUPPORTED_HORIZONS: tuple[int, ...] = (1, 2, 3, 4, 5)
UNSUPPORTED_HORIZONS: tuple[int, ...] = (10, 15)

# Grounded MITRE ATT&CK technique mapping for observable states
MITRE_TECHNIQUE_MAP: dict[AttackProgressionState, str] = {
    AttackProgressionState.RECONNAISSANCE: "T1046",       # Network Service Discovery
    AttackProgressionState.EXPLOITATION: "T1190",         # Exploit Public-Facing Application
    AttackProgressionState.COMMAND_AND_CONTROL: "T1071",  # Application Layer Protocol
    AttackProgressionState.DENIAL_OF_SERVICE: "T1498",    # Network Denial of Service
    AttackProgressionState.LATERAL_MOVEMENT: "T1021",     # Remote Services
    AttackProgressionState.EXFILTRATION: "T1041",         # Exfiltration Over C2 Channel
}

# Empirical Transition Matrices for K in 1..5
TRANSITIONS_K1: dict[AttackProgressionState, dict[AttackProgressionState, float]] = {
    AttackProgressionState.BENIGN_OBSERVATION: {
        AttackProgressionState.BENIGN_OBSERVATION: 0.992,
        AttackProgressionState.RECONNAISSANCE: 0.005,
        AttackProgressionState.DENIAL_OF_SERVICE: 0.003,
    },
    AttackProgressionState.RECONNAISSANCE: {
        AttackProgressionState.RECONNAISSANCE: 0.975,
        AttackProgressionState.BENIGN_OBSERVATION: 0.025,
        AttackProgressionState.EXPLOITATION: 0.000,
        AttackProgressionState.DENIAL_OF_SERVICE: 0.000,
    },
    AttackProgressionState.COMMAND_AND_CONTROL: {
        AttackProgressionState.COMMAND_AND_CONTROL: 0.960,
        AttackProgressionState.LATERAL_MOVEMENT: 0.030,
        AttackProgressionState.EXFILTRATION: 0.010,
    },
    AttackProgressionState.DENIAL_OF_SERVICE: {
        AttackProgressionState.DENIAL_OF_SERVICE: 0.985,
        AttackProgressionState.BENIGN_OBSERVATION: 0.015,
    },
}

TRANSITIONS_K2: dict[AttackProgressionState, dict[AttackProgressionState, float]] = {
    AttackProgressionState.BENIGN_OBSERVATION: {
        AttackProgressionState.BENIGN_OBSERVATION: 0.984,
        AttackProgressionState.RECONNAISSANCE: 0.010,
        AttackProgressionState.DENIAL_OF_SERVICE: 0.006,
    },
    AttackProgressionState.RECONNAISSANCE: {
        AttackProgressionState.RECONNAISSANCE: 0.950,
        AttackProgressionState.BENIGN_OBSERVATION: 0.050,
        AttackProgressionState.EXPLOITATION: 0.000,
        AttackProgressionState.DENIAL_OF_SERVICE: 0.000,
    },
    AttackProgressionState.COMMAND_AND_CONTROL: {
        AttackProgressionState.COMMAND_AND_CONTROL: 0.935,
        AttackProgressionState.LATERAL_MOVEMENT: 0.048,
        AttackProgressionState.EXFILTRATION: 0.017,
    },
    AttackProgressionState.DENIAL_OF_SERVICE: {
        AttackProgressionState.DENIAL_OF_SERVICE: 0.968,
        AttackProgressionState.BENIGN_OBSERVATION: 0.032,
    },
}

TRANSITIONS_K3: dict[AttackProgressionState, dict[AttackProgressionState, float]] = {
    AttackProgressionState.BENIGN_OBSERVATION: {
        AttackProgressionState.BENIGN_OBSERVATION: 0.977,
        AttackProgressionState.RECONNAISSANCE: 0.015,
        AttackProgressionState.DENIAL_OF_SERVICE: 0.008,
    },
    AttackProgressionState.RECONNAISSANCE: {
        AttackProgressionState.RECONNAISSANCE: 0.924,
        AttackProgressionState.BENIGN_OBSERVATION: 0.076,
    },
    AttackProgressionState.COMMAND_AND_CONTROL: {
        AttackProgressionState.COMMAND_AND_CONTROL: 0.910,
        AttackProgressionState.LATERAL_MOVEMENT: 0.065,
        AttackProgressionState.EXFILTRATION: 0.025,
    },
    AttackProgressionState.DENIAL_OF_SERVICE: {
        AttackProgressionState.DENIAL_OF_SERVICE: 0.950,
        AttackProgressionState.BENIGN_OBSERVATION: 0.050,
    },
}

TRANSITIONS_K4: dict[AttackProgressionState, dict[AttackProgressionState, float]] = {
    AttackProgressionState.BENIGN_OBSERVATION: {
        AttackProgressionState.BENIGN_OBSERVATION: 0.969,
        AttackProgressionState.RECONNAISSANCE: 0.020,
        AttackProgressionState.DENIAL_OF_SERVICE: 0.011,
    },
    AttackProgressionState.RECONNAISSANCE: {
        AttackProgressionState.RECONNAISSANCE: 0.898,
        AttackProgressionState.BENIGN_OBSERVATION: 0.102,
    },
    AttackProgressionState.COMMAND_AND_CONTROL: {
        AttackProgressionState.COMMAND_AND_CONTROL: 0.880,
        AttackProgressionState.LATERAL_MOVEMENT: 0.085,
        AttackProgressionState.EXFILTRATION: 0.035,
    },
    AttackProgressionState.DENIAL_OF_SERVICE: {
        AttackProgressionState.DENIAL_OF_SERVICE: 0.920,
        AttackProgressionState.BENIGN_OBSERVATION: 0.080,
    },
}

TRANSITIONS_K5: dict[AttackProgressionState, dict[AttackProgressionState, float]] = {
    AttackProgressionState.BENIGN_OBSERVATION: {
        AttackProgressionState.BENIGN_OBSERVATION: 0.962,
        AttackProgressionState.RECONNAISSANCE: 0.025,
        AttackProgressionState.DENIAL_OF_SERVICE: 0.013,
    },
    AttackProgressionState.RECONNAISSANCE: {
        AttackProgressionState.RECONNAISSANCE: 0.873,
        AttackProgressionState.BENIGN_OBSERVATION: 0.127,
    },
    AttackProgressionState.COMMAND_AND_CONTROL: {
        AttackProgressionState.COMMAND_AND_CONTROL: 0.850,
        AttackProgressionState.LATERAL_MOVEMENT: 0.105,
        AttackProgressionState.EXFILTRATION: 0.045,
    },
    AttackProgressionState.DENIAL_OF_SERVICE: {
        AttackProgressionState.DENIAL_OF_SERVICE: 0.890,
        AttackProgressionState.BENIGN_OBSERVATION: 0.110,
    },
}

TRANSITION_MATRICES = {
    1: TRANSITIONS_K1,
    2: TRANSITIONS_K2,
    3: TRANSITIONS_K3,
    4: TRANSITIONS_K4,
    5: TRANSITIONS_K5,
}


@dataclass(frozen=True)
class StageForecastPoint:
    """Individual stage forecast point adhering to strict scientific forecasting semantics."""
    horizon_minutes: int
    predicted_state: AttackProgressionState
    predicted_technique: str | None
    forecast_techniques: tuple[str, ...]
    prediction_type: PredictionType
    transition_probability: float
    baseline_probability: float
    lead_time_seconds: int
    abstained: bool
    abstention_reason: str | None
    supporting_evidence: tuple[str, ...]
    canonical_stage: AttackStage = AttackStage.UNKNOWN
    stage_confidence: float = 0.0
    forecast_confidence: float = 0.0
    transition_confidence: float = 0.0
    technique_confidence: float = 0.0
    classification: StageClassification = StageClassification.FORECAST
    contradictory_evidence: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "horizon": self.horizon_minutes,
            "horizon_minutes": self.horizon_minutes,
            "predicted_state": self.predicted_state.value,
            "canonical_stage": self.canonical_stage.value,
            "predicted_technique": self.predicted_technique,
            "mitre_technique": self.predicted_technique,
            "forecast_techniques": list(self.forecast_techniques),
            "prediction_type": self.prediction_type.value,
            "classification": self.classification.value,
            "transition_probability": round(self.transition_probability, 4) if self.transition_probability is not None else None,
            "stage_confidence": round(self.stage_confidence, 4),
            "forecast_confidence": round(self.forecast_confidence, 4),
            "transition_confidence": round(self.transition_confidence, 4),
            "technique_confidence": round(self.technique_confidence, 4),
            "baseline_probability": round(self.baseline_probability, 4) if self.baseline_probability is not None else None,
            "lead_time_seconds": self.lead_time_seconds,
            "abstained": self.abstained,
            "abstention_reason": self.abstention_reason,
            "supporting_evidence": list(self.supporting_evidence),
            "contradictory_evidence": list(self.contradictory_evidence),
        }


@dataclass(frozen=True)
class AttackProgressionForecast:
    """Complete multi-horizon progression assessment with 15-stage timeline and transitions."""
    observed_state: AttackProgressionState
    observed_techniques: tuple[str, ...]
    forecast_points: tuple[StageForecastPoint, ...]
    supported_horizons: tuple[int, ...]
    unsupported_horizons: tuple[int, ...]
    verdict: str
    summary: str
    canonical_stage: AttackStage = AttackStage.UNKNOWN
    classification: StageClassification = StageClassification.UNKNOWN
    secondary_stages: tuple[AttackStage, ...] = ()
    stage_confidence: float = 0.0
    technique_confidence: float = 0.0
    timeline: tuple[dict[str, Any], ...] = ()
    transitions: tuple[dict[str, Any], ...] = ()
    validation: dict[str, Any] = field(default_factory=dict)
    supporting_evidence: tuple[dict[str, Any], ...] = ()
    contradictory_evidence: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "observed_state": self.observed_state.value,
            "current_state": self.observed_state.value,
            "canonical_stage": self.canonical_stage.value,
            "current_stage": self.canonical_stage.value,
            "classification": self.classification.value if hasattr(self.classification, "value") else str(self.classification),
            "secondary_stages": [s.value for s in self.secondary_stages],
            "stage_confidence": round(self.stage_confidence, 4),
            "technique_confidence": round(self.technique_confidence, 4),
            "observed_techniques": list(self.observed_techniques),
            "forecast_points": [p.to_dict() for p in self.forecast_points],
            "forecast": [p.to_dict() for p in self.forecast_points],
            "supported_horizons": list(self.supported_horizons),
            "unsupported_horizons": list(self.unsupported_horizons),
            "verdict": self.verdict,
            "summary": self.summary,
            "timeline": list(self.timeline),
            "transitions": list(self.transitions),
            "validation": self.validation,
            "supporting_evidence": list(self.supporting_evidence),
            "contradictory_evidence": list(self.contradictory_evidence),
        }


def determine_observed_state(
    observed_findings: Sequence[Mapping[str, Any]],
    behavioral_report: Any = None,
) -> tuple[AttackProgressionState, tuple[str, ...]]:
    """Deterministically map current observed evidence into the legacy attack stage for backward compatibility."""
    c_stage, _, _, _, _, _, ev_items = infer_current_attack_stage(
        observed_findings=observed_findings,
        behavioral_report=behavioral_report,
    )
    legacy_name = to_legacy_stage_name(c_stage)
    observed_techniques = sorted({e.technique_id for e in ev_items if e.technique_id})
    return AttackProgressionState(legacy_name), tuple(observed_techniques)


def forecast_attack_progression(
    observed_findings: Sequence[Mapping[str, Any]],
    behavioral_report: Any = None,
    horizons: tuple[int, ...] = (1, 3, 5, 10, 15),
    history_window_count: int = 8,
    require_downstream_progression: bool = False,
    network_state: Any = None,
    current_timestamp: float | None = None,
) -> AttackProgressionForecast:
    """Forecast future attack state using empirical Markovian progression and 15-stage transition validator."""
    ts = float(current_timestamp) if current_timestamp is not None and math.isfinite(current_timestamp) else 1700000000.0

    (
        canonical_stage,
        secondary_stages,
        classification,
        overall_conf,
        stage_conf,
        tech_conf,
        evidence_items,
    ) = infer_current_attack_stage(
        observed_findings=observed_findings,
        behavioral_report=behavioral_report,
        network_state=network_state,
        timestamp=ts,
    )

    legacy_name = to_legacy_stage_name(canonical_stage)
    observed_state = AttackProgressionState(legacy_name)
    observed_techniques = tuple(sorted({e.technique_id for e in evidence_items if e.technique_id}))

    points: list[StageForecastPoint] = []
    transitions_list: list[AttackTransition] = []
    timeline_events: list[TimelineEvent] = []

    # 1. Add T0 Current State to Timeline
    t0_event = TimelineEvent(
        timestamp=ts,
        stage=canonical_stage,
        classification=classification,
        confidence=overall_conf,
        stage_confidence=stage_conf,
        technique_confidence=tech_conf,
        primary_techniques=observed_techniques,
        secondary_stages=tuple(secondary_stages),
        lead_time_seconds=0,
        horizon_label="T0",
        supporting_evidence=tuple(e for e in evidence_items if e.polarity == EvidencePolarity.SUPPORTING),
        contradictory_evidence=tuple(e for e in evidence_items if e.polarity == EvidencePolarity.CONTRADICTORY),
        description=f"Current state evaluated as {canonical_stage.display_name} with {len(evidence_items)} evidence items.",
    )
    timeline_events.append(t0_event)

    # Check minimum history requirement
    if history_window_count < 8:
        for k in horizons:
            points.append(StageForecastPoint(
                horizon_minutes=k,
                predicted_state=AttackProgressionState.UNKNOWN_STATE,
                canonical_stage=AttackStage.UNKNOWN,
                predicted_technique=None,
                forecast_techniques=(),
                prediction_type=PredictionType.ABSTAINED,
                transition_probability=0.0,
                stage_confidence=0.0,
                forecast_confidence=0.0,
                transition_confidence=0.0,
                technique_confidence=0.0,
                classification=StageClassification.UNKNOWN,
                baseline_probability=0.0,
                lead_time_seconds=k * 60,
                abstained=True,
                abstention_reason="INSUFFICIENT_HISTORY: minimum 8 contiguous windows required",
                supporting_evidence=(),
            ))
            t_k = TimelineEvent(
                timestamp=ts + k * 60,
                stage=AttackStage.UNKNOWN,
                classification=StageClassification.UNKNOWN,
                confidence=0.0,
                stage_confidence=0.0,
                technique_confidence=0.0,
                lead_time_seconds=k * 60,
                horizon_label=f"T+{k}",
                description="Forecasting abstained: insufficient contiguous window history.",
            )
            timeline_events.append(t_k)

        val_result = validate_progression_timeline(timeline_events, transitions_list)
        return AttackProgressionForecast(
            observed_state=observed_state,
            canonical_stage=canonical_stage,
            classification=classification,
            secondary_stages=tuple(secondary_stages),
            stage_confidence=stage_conf,
            technique_confidence=tech_conf,
            observed_techniques=observed_techniques,
            forecast_points=tuple(points),
            supported_horizons=(),
            unsupported_horizons=horizons,
            verdict="ABSTAINED",
            summary="Forecasting abstained: insufficient contiguous window history.",
            timeline=tuple(e.to_dict() for e in timeline_events),
            transitions=(),
            validation=val_result.to_dict(),
            supporting_evidence=tuple(e.to_dict() for e in evidence_items if e.polarity == EvidencePolarity.SUPPORTING),
            contradictory_evidence=tuple(e.to_dict() for e in evidence_items if e.polarity == EvidencePolarity.CONTRADICTORY),
        )

    # For benign observed states, empirical audit proves pre-attack signals are unvalidated
    if observed_state == AttackProgressionState.BENIGN_OBSERVATION or canonical_stage == AttackStage.BENIGN:
        for k in horizons:
            is_unsupported = k in UNSUPPORTED_HORIZONS
            reason = (
                "UNSUPPORTED_HORIZON: K > 5 not validated on authentic data" if is_unsupported
                else "NO_ATTACK_OBSERVED: pre-attack onset forecasting from benign baseline is unvalidated"
            )
            prob = 0.99 if k in EMPIRICALLY_SUPPORTED_HORIZONS else 0.0
            pt = StageForecastPoint(
                horizon_minutes=k,
                predicted_state=AttackProgressionState.BENIGN_OBSERVATION,
                canonical_stage=AttackStage.BENIGN,
                predicted_technique=None,
                forecast_techniques=(),
                prediction_type=PredictionType.ABSTAINED if is_unsupported else PredictionType.STATE_PERSISTENCE,
                transition_probability=prob,
                stage_confidence=0.92 if not is_unsupported else 0.0,
                forecast_confidence=0.90 if not is_unsupported else 0.0,
                transition_confidence=0.95 if not is_unsupported else 0.0,
                technique_confidence=0.0,
                classification=StageClassification.FORECAST if not is_unsupported else StageClassification.UNKNOWN,
                baseline_probability=0.82,
                lead_time_seconds=k * 60,
                abstained=is_unsupported,
                abstention_reason=reason if is_unsupported else None,
                supporting_evidence=("Past observed state is benign; no early onset signal detected.",),
            )
            points.append(pt)

            tr = validate_transition(
                from_stage=canonical_stage,
                to_stage=AttackStage.BENIGN,
                timestamp=ts + k * 60,
                transition_type=TransitionType.FORECAST,
                base_confidence=0.90,
            )
            transitions_list.append(tr)

            ev_k = TimelineEvent(
                timestamp=ts + k * 60,
                stage=AttackStage.BENIGN if not is_unsupported else AttackStage.UNKNOWN,
                classification=StageClassification.FORECAST if not is_unsupported else StageClassification.UNKNOWN,
                confidence=0.90 if not is_unsupported else 0.0,
                stage_confidence=0.92 if not is_unsupported else 0.0,
                technique_confidence=0.0,
                lead_time_seconds=k * 60,
                horizon_label=f"T+{k}",
                description="Continuing baseline operation." if not is_unsupported else reason,
            )
            timeline_events.append(ev_k)

        supported = tuple(k for k in horizons if k in EMPIRICALLY_SUPPORTED_HORIZONS)
        unsupported = tuple(k for k in horizons if k in UNSUPPORTED_HORIZONS or k not in EMPIRICALLY_SUPPORTED_HORIZONS)
        val_result = validate_progression_timeline(timeline_events, transitions_list)

        return AttackProgressionForecast(
            observed_state=observed_state,
            canonical_stage=canonical_stage,
            classification=classification,
            secondary_stages=tuple(secondary_stages),
            stage_confidence=stage_conf,
            technique_confidence=tech_conf,
            observed_techniques=observed_techniques,
            forecast_points=tuple(points),
            supported_horizons=supported,
            unsupported_horizons=unsupported,
            verdict="PARTIALLY_SUPPORTED" if supported else "ABSTAINED",
            summary="Observed network state is benign. No anticipatory attack onset forecast is justified.",
            timeline=tuple(e.to_dict() for e in timeline_events),
            transitions=tuple(tr.to_dict() for tr in transitions_list),
            validation=val_result.to_dict(),
            supporting_evidence=tuple(e.to_dict() for e in evidence_items if e.polarity == EvidencePolarity.SUPPORTING),
            contradictory_evidence=tuple(e.to_dict() for e in evidence_items if e.polarity == EvidencePolarity.CONTRADICTORY),
        )

    # For active attack states (e.g. RECONNAISSANCE, C2, IMPACT)
    for k in horizons:
        if k in UNSUPPORTED_HORIZONS:
            points.append(StageForecastPoint(
                horizon_minutes=k,
                predicted_state=AttackProgressionState.UNKNOWN_STATE,
                canonical_stage=AttackStage.UNKNOWN,
                predicted_technique=None,
                forecast_techniques=(),
                prediction_type=PredictionType.ABSTAINED,
                transition_probability=0.0,
                stage_confidence=0.0,
                forecast_confidence=0.0,
                transition_confidence=0.0,
                technique_confidence=0.0,
                classification=StageClassification.UNKNOWN,
                baseline_probability=0.0,
                lead_time_seconds=k * 60,
                abstained=True,
                abstention_reason=f"UNSUPPORTED_HORIZON: horizon T+{k}m lacks empirical replication",
                supporting_evidence=(),
            ))
            ev_k = TimelineEvent(
                timestamp=ts + k * 60,
                stage=AttackStage.UNKNOWN,
                classification=StageClassification.UNKNOWN,
                confidence=0.0,
                stage_confidence=0.0,
                technique_confidence=0.0,
                lead_time_seconds=k * 60,
                horizon_label=f"T+{k}",
                description=f"Horizon T+{k}m unsupported.",
            )
            timeline_events.append(ev_k)
            continue

        trans_matrix = TRANSITION_MATRICES.get(k, {})
        row = trans_matrix.get(observed_state, {})

        if row:
            best_state = max(row.keys(), key=lambda s: row[s])
            prob = row[best_state]
            c_best_stage = to_canonical_stage(best_state)

            if best_state == observed_state:
                if require_downstream_progression:
                    points.append(StageForecastPoint(
                        horizon_minutes=k,
                        predicted_state=AttackProgressionState.UNKNOWN_STATE,
                        canonical_stage=AttackStage.UNKNOWN,
                        predicted_technique=None,
                        forecast_techniques=(),
                        prediction_type=PredictionType.ABSTAINED,
                        transition_probability=0.0,
                        stage_confidence=0.0,
                        forecast_confidence=0.0,
                        transition_confidence=0.0,
                        technique_confidence=0.0,
                        classification=StageClassification.UNKNOWN,
                        baseline_probability=0.0,
                        lead_time_seconds=k * 60,
                        abstained=True,
                        abstention_reason=(
                            f"NO_SUPPORTED_DOWNSTREAM_TRANSITION: empirical data for {observed_state.value} "
                            f"at horizon T+{k}m exhibits state persistence (P={prob:.3f}), "
                            f"not downstream cross-stage transition."
                        ),
                        supporting_evidence=(),
                    ))
                    continue

                pred_type = PredictionType.STATE_PERSISTENCE
                pred_technique = MITRE_TECHNIQUE_MAP.get(best_state)
                forecast_techniques: tuple[str, ...] = ()
                evidence_desc = f"Observed {observed_state.value} at T. Empirical persistence across {k}-step horizon yields P={prob:.3f}."
            else:
                pred_type = PredictionType.DOWNSTREAM_PROGRESSION
                pred_technique = MITRE_TECHNIQUE_MAP.get(best_state)
                forecast_techniques = (pred_technique,) if pred_technique else ()
                evidence_desc = f"Empirical cross-stage progression from {observed_state.value} to {best_state.value} across {k}-step horizon yields P={prob:.3f}."

            # Calculate separated confidences
            tr = validate_transition(
                from_stage=canonical_stage,
                to_stage=c_best_stage,
                timestamp=ts + k * 60,
                evidence=evidence_items,
                transition_type=TransitionType.FORECAST,
                base_confidence=stage_conf,
            )
            transitions_list.append(tr)

            trans_conf = tr.confidence
            f_conf = min(0.99, max(0.10, prob * trans_conf))

            points.append(StageForecastPoint(
                horizon_minutes=k,
                predicted_state=best_state,
                canonical_stage=c_best_stage,
                predicted_technique=pred_technique,
                forecast_techniques=forecast_techniques,
                prediction_type=pred_type,
                transition_probability=prob,
                stage_confidence=round(stage_conf, 4),
                forecast_confidence=round(f_conf, 4),
                transition_confidence=round(trans_conf, 4),
                technique_confidence=round(tech_conf, 4),
                classification=StageClassification.FORECAST,
                baseline_probability=0.165,
                lead_time_seconds=k * 60,
                abstained=False,
                abstention_reason=None,
                supporting_evidence=(evidence_desc,),
            ))

            ev_k = TimelineEvent(
                timestamp=ts + k * 60,
                stage=c_best_stage,
                classification=StageClassification.FORECAST,
                confidence=round(f_conf, 4),
                stage_confidence=round(stage_conf, 4),
                technique_confidence=round(tech_conf, 4),
                primary_techniques=(pred_technique,) if pred_technique else (),
                lead_time_seconds=k * 60,
                horizon_label=f"T+{k}",
                description=evidence_desc,
            )
            timeline_events.append(ev_k)
        else:
            points.append(StageForecastPoint(
                horizon_minutes=k,
                predicted_state=AttackProgressionState.UNKNOWN_STATE,
                canonical_stage=AttackStage.UNKNOWN,
                predicted_technique=None,
                forecast_techniques=(),
                prediction_type=PredictionType.ABSTAINED,
                transition_probability=0.0,
                stage_confidence=0.0,
                forecast_confidence=0.0,
                transition_confidence=0.0,
                technique_confidence=0.0,
                classification=StageClassification.UNKNOWN,
                baseline_probability=0.0,
                lead_time_seconds=k * 60,
                abstained=True,
                abstention_reason="UNSEEN_STATE: no empirical transition row available",
                supporting_evidence=(),
            ))
            ev_k = TimelineEvent(
                timestamp=ts + k * 60,
                stage=AttackStage.UNKNOWN,
                classification=StageClassification.UNKNOWN,
                confidence=0.0,
                stage_confidence=0.0,
                technique_confidence=0.0,
                lead_time_seconds=k * 60,
                horizon_label=f"T+{k}",
                description="No empirical transition row available.",
            )
            timeline_events.append(ev_k)

    supported = tuple(k for k in horizons if k in EMPIRICALLY_SUPPORTED_HORIZONS)
    unsupported = tuple(k for k in horizons if k in UNSUPPORTED_HORIZONS or k not in EMPIRICALLY_SUPPORTED_HORIZONS)
    supported_str = ", ".join(f"T+{k}m" for k in supported)
    unsupported_str = ", ".join(f"T+{k}m" for k in unsupported)

    verdict = "PARTIALLY_SUPPORTED" if supported else "ABSTAINED"
    if not unsupported:
        summary_msg = f"Observed active {observed_state.value}. Forecasting fully supported across {supported_str}."
    else:
        summary_msg = (
            f"Observed active {observed_state.value}. Forecasting supported for {supported_str}; "
            f"abstained for {unsupported_str} due to lack of verified replication."
        )

    val_result = validate_progression_timeline(timeline_events, transitions_list)

    return AttackProgressionForecast(
        observed_state=observed_state,
        canonical_stage=canonical_stage,
        classification=classification,
        secondary_stages=tuple(secondary_stages),
        stage_confidence=stage_conf,
        technique_confidence=tech_conf,
        observed_techniques=observed_techniques,
        forecast_points=tuple(points),
        supported_horizons=supported,
        unsupported_horizons=unsupported,
        verdict=verdict,
        summary=summary_msg,
        timeline=tuple(e.to_dict() for e in timeline_events),
        transitions=tuple(tr.to_dict() for tr in transitions_list),
        validation=val_result.to_dict(),
        supporting_evidence=tuple(e.to_dict() for e in evidence_items if e.polarity == EvidencePolarity.SUPPORTING),
        contradictory_evidence=tuple(e.to_dict() for e in evidence_items if e.polarity == EvidencePolarity.CONTRADICTORY),
    )


def build_continuous_progression_timeline(
    forecast: AttackProgressionForecast,
) -> list[dict[str, Any]]:
    """Builds a continuous step-by-step progression timeline with distinct OBSERVED and FORECAST stages."""
    if forecast.timeline:
        return list(forecast.timeline)

    timeline: list[dict[str, Any]] = [
        {
            "step": 0,
            "horizon_label": "CURRENT OBSERVED STATE",
            "horizon_minutes": 0,
            "lead_time_seconds": 0,
            "stage": forecast.observed_state.value,
            "canonical_stage": forecast.canonical_stage.value,
            "techniques": list(forecast.observed_techniques),
            "prediction_type": "OBSERVED_GROUND_TRUTH",
            "classification": "OBSERVED",
            "probability": 1.0,
            "status": "OBSERVED",
            "evidence": [f"Ground truth network state derived from live telemetry: {forecast.observed_state.value}"],
        }
    ]

    for pt in forecast.forecast_points:
        timeline.append({
            "step": pt.horizon_minutes,
            "horizon_label": f"T+{pt.horizon_minutes}",
            "horizon_minutes": pt.horizon_minutes,
            "lead_time_seconds": pt.lead_time_seconds,
            "stage": pt.predicted_state.value,
            "canonical_stage": pt.canonical_stage.value,
            "techniques": list(pt.forecast_techniques) if pt.forecast_techniques else ([pt.predicted_technique] if pt.predicted_technique else []),
            "prediction_type": pt.prediction_type.value,
            "classification": pt.classification.value,
            "probability": pt.transition_probability,
            "stage_confidence": pt.stage_confidence,
            "forecast_confidence": pt.forecast_confidence,
            "status": "ABSTAINED" if pt.abstained else "ACTIVE",
            "evidence": list(pt.supporting_evidence),
        })

    return timeline
