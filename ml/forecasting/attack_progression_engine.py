"""Dynamic Attack Progression Engine, Timeline Validator, and Multi-Horizon Lifecycle Forecaster.

Transforms NexSolve's attack progression subsystem into an evidence-grounded temporal state machine:
CURRENT NETWORK STATE
        ↓
OBSERVED ATTACK EVIDENCE
        ↓
OBSERVED ATTACK STAGE
        ↓
TEMPORAL TRANSITIONS
        ↓
FORECAST NEXT STAGES (T+1 ... T+5)
        ↓
FORECAST MITRE TECHNIQUES
        ↓
CONFIDENCE & UNCERTAINTY (Technique, Stage, Transition, Forecast)
        ↓
EVIDENTIARY AUDIT & VALIDATION
        ↓
EXPLICIT ABSTENTION IF INSUFFICIENT
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import math
from typing import Any, Mapping, Sequence

import numpy as np

from ml.forecasting.attack_stages import (
    AttackStage,
    StageClassification,
    VERIFIED_MITRE_TECHNIQUES,
    to_canonical_stage,
    to_legacy_stage_name,
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


@dataclass(slots=True, frozen=True)
class TimelineEvent:
    """Atomic event in the chronological attack progression timeline."""
    timestamp: float
    stage: AttackStage
    classification: StageClassification
    confidence: float
    stage_confidence: float
    technique_confidence: float
    primary_techniques: tuple[str, ...] = ()
    secondary_stages: tuple[AttackStage, ...] = ()
    lead_time_seconds: int = 0
    horizon_label: str = "T0"
    evidence_ids: tuple[str, ...] = ()
    transition_id: str | None = None
    supporting_evidence: tuple[Any, ...] = ()
    contradictory_evidence: tuple[Any, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Event confidence must be in [0.0, 1.0], got {self.confidence}")
        if not (0.0 <= self.stage_confidence <= 1.0):
            raise ValueError(f"Stage confidence must be in [0.0, 1.0], got {self.stage_confidence}")
        if not (0.0 <= self.technique_confidence <= 1.0):
            raise ValueError(f"Technique confidence must be in [0.0, 1.0], got {self.technique_confidence}")
        if not math.isfinite(self.timestamp):
            raise ValueError(f"Invalid timestamp '{self.timestamp}'; must be a finite float epoch.")

    def to_dict(self) -> dict[str, Any]:
        ev_ids = list(self.evidence_ids) if self.evidence_ids else [
            getattr(e, "evidence_id", str(e)) for e in self.supporting_evidence
        ]
        return {
            "timestamp": self.timestamp,
            "stage": self.stage.value,
            "display_name": self.stage.display_name,
            "category": self.stage.category.value,
            "classification": self.classification.value,
            "confidence": round(self.confidence, 4),
            "stage_confidence": round(self.stage_confidence, 4),
            "technique_confidence": round(self.technique_confidence, 4),
            "evidence_ids": ev_ids,
            "transition_id": self.transition_id,
            "primary_techniques": list(self.primary_techniques),
            "secondary_stages": [s.value for s in self.secondary_stages],
            "lead_time_seconds": self.lead_time_seconds,
            "horizon_label": self.horizon_label,
            "description": self.description,
            "supporting_evidence_count": len(self.supporting_evidence),
            "contradictory_evidence_count": len(self.contradictory_evidence),
            "supporting_evidence": [e.to_dict() if hasattr(e, "to_dict") else str(e) for e in self.supporting_evidence],
            "contradictory_evidence": [e.to_dict() if hasattr(e, "to_dict") else str(e) for e in self.contradictory_evidence],
        }


@dataclass(slots=True, frozen=True)
class AttackProgressionTimeline:
    """Canonical chronological attack progression timeline container."""
    events: tuple[TimelineEvent, ...] = ()

    @property
    def is_chronological(self) -> bool:
        if len(self.events) <= 1:
            return True
        return all(self.events[i].timestamp <= self.events[i + 1].timestamp for i in range(len(self.events) - 1))

    @property
    def stages(self) -> list[AttackStage]:
        return [e.stage for e in self.events]

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_count": len(self.events),
            "is_chronological": self.is_chronological,
            "events": [e.to_dict() for e in self.events],
        }


@dataclass(slots=True)
class ProgressionValidationResult:
    """Formal audit report for an attack progression timeline and transition history."""
    valid: bool
    issues: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    event_count: int = 0
    transition_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def validate_progression_timeline(
    timeline: Sequence[TimelineEvent],
    transitions: Sequence[AttackTransition] = (),
) -> ProgressionValidationResult:
    """Audit timeline events and transitions for temporal validity, consistency, and evidentiary ground."""
    issues: list[str] = []
    warnings: list[str] = []

    if not timeline:
        return ProgressionValidationResult(
            valid=False,
            issues=["Timeline is empty: zero events recorded."],
            warnings=[],
            event_count=0,
            transition_count=len(transitions),
        )

    # 1. Monotonicity and timestamp ordering for historical events
    prev_time: float | None = None
    seen_timestamps: dict[float, list[TimelineEvent]] = {}

    for idx, ev in enumerate(timeline):
        # Confidence bounds check
        if not (0.0 <= ev.confidence <= 1.0):
            issues.append(f"Event {idx} ({ev.stage.value}) confidence {ev.confidence} outside [0.0, 1.0].")

        # Classification check
        if ev.classification not in (StageClassification.OBSERVED, StageClassification.INFERRED, StageClassification.FORECAST, StageClassification.UNKNOWN):
            issues.append(f"Event {idx} has invalid classification '{ev.classification}'.")

        seen_timestamps.setdefault(ev.timestamp, []).append(ev)

        # For historical (non-forecast) events, timestamps must not decrease
        if ev.classification != StageClassification.FORECAST:
            if prev_time is not None and ev.timestamp < prev_time:
                issues.append(
                    f"Timestamp out of order at index {idx}: timestamp {ev.timestamp} < previous {prev_time}."
                )
            prev_time = ev.timestamp

        # Evidence existence check: active non-benign observed/inferred events should have evidence
        if ev.stage not in (AttackStage.BENIGN, AttackStage.UNKNOWN) and ev.classification in (StageClassification.OBSERVED, StageClassification.INFERRED):
            if not ev.supporting_evidence:
                warnings.append(
                    f"Event {idx} ({ev.stage.value}) assigned as {ev.classification.value} without supporting evidence items."
                )

    # Check duplicate timestamps for contradictory stages
    for ts, ev_list in seen_timestamps.items():
        if len(ev_list) > 1:
            stages = {e.stage for e in ev_list}
            if len(stages) > 1 and AttackStage.BENIGN in stages and any(s != AttackStage.BENIGN for s in stages):
                issues.append(
                    f"Contradictory simultaneous states at timestamp {ts}: {sorted([s.value for s in stages])}."
                )

    # 2. Audit Transitions
    for t_idx, tr in enumerate(transitions):
        if not (0.0 <= tr.confidence <= 1.0):
            issues.append(f"Transition {t_idx} confidence {tr.confidence} outside [0.0, 1.0].")

        if tr.status == TransitionValidationStatus.INVALID:
            issues.append(f"Transition {t_idx} ({tr.from_stage.value} -> {tr.to_stage.value}) marked INVALID: {tr.reason}")
        elif tr.status == TransitionValidationStatus.CONTRADICTORY:
            warnings.append(f"Transition {t_idx} has conflicting contradictory evidence: {tr.reason}")
        elif tr.status == TransitionValidationStatus.INSUFFICIENT_EVIDENCE:
            warnings.append(f"Transition {t_idx} lacks sufficient direct evidence: {tr.reason}")

    is_valid = len(issues) == 0
    return ProgressionValidationResult(
        valid=is_valid,
        issues=issues,
        warnings=warnings,
        event_count=len(timeline),
        transition_count=len(transitions),
    )


def infer_current_attack_stage(
    observed_findings: Sequence[Mapping[str, Any]] = (),
    behavioral_report: Any = None,
    network_state: Any = None,
    timestamp: float | None = None,
    normalized_telemetry: Any = None,
) -> tuple[AttackStage, list[AttackStage], StageClassification, float, float, float, list[StageEvidence]]:
    """Deterministically map multi-sensor evidence into canonical attack stage and corroboration metrics.

    Returns:
        (primary_stage, secondary_stages, classification, overall_confidence, stage_confidence, technique_confidence, evidence_items)
    """
    ts = float(timestamp) if timestamp is not None and math.isfinite(timestamp) else 1700000000.0
    evidence_items: list[StageEvidence] = []
    technique_counts: dict[str, int] = {}

    # 1. Harvest Findings from Heuristics / Sensors
    for idx, finding in enumerate(observed_findings):
        cat = str(finding.get("attack_category", "")).lower()
        rule_name = str(finding.get("rule_name", finding.get("detection_method", "heuristic"))).lower()
        raw_conf = finding.get("confidence")
        if raw_conf is not None:
            try:
                conf = float(raw_conf)
            except (ValueError, TypeError):
                conf = 0.80
        else:
            conf = 0.80
        conf = min(1.0, max(0.0, conf))

        # Check for Reconnaissance / Port Scan
        if "recon" in cat or "scan" in cat or "probe" in cat or "sweep" in cat or "t1046" in rule_name:
            ev = StageEvidence(
                evidence_id=f"ev_find_{idx}",
                source=EvidenceSource.HEURISTIC,
                timestamp=ts,
                description=f"Observable port scan or service discovery: {finding.get('description', cat)}",
                stage=AttackStage.RECONNAISSANCE,
                technique_id="T1046",
                feature="unique_dst_ports",
                confidence=conf,
                polarity=EvidencePolarity.SUPPORTING,
            )
            evidence_items.append(ev)
            technique_counts["T1046"] = technique_counts.get("T1046", 0) + 1

        # Check for Denial of Service / Impact
        elif "dos" in cat or "flood" in cat or "syn_flood" in cat or "t1498" in rule_name:
            ev = StageEvidence(
                evidence_id=f"ev_find_{idx}",
                source=EvidenceSource.HEURISTIC,
                timestamp=ts,
                description=f"Observable network volumetric or protocol flooding: {finding.get('description', cat)}",
                stage=AttackStage.IMPACT,
                technique_id="T1498",
                feature="tcp_syn_count",
                confidence=conf,
                polarity=EvidencePolarity.SUPPORTING,
            )
            evidence_items.append(ev)
            technique_counts["T1498"] = technique_counts.get("T1498", 0) + 1

        # Check for Initial Access / Exploit
        elif "exploit" in cat or "cve" in cat or "rce" in cat or "t1190" in rule_name:
            ev = StageEvidence(
                evidence_id=f"ev_find_{idx}",
                source=EvidenceSource.HEURISTIC,
                timestamp=ts,
                description=f"Public-facing application exploit indicators: {finding.get('description', cat)}",
                stage=AttackStage.INITIAL_ACCESS,
                technique_id="T1190",
                confidence=conf,
                polarity=EvidencePolarity.SUPPORTING,
            )
            evidence_items.append(ev)
            technique_counts["T1190"] = technique_counts.get("T1190", 0) + 1

        # Check for Brute Force / Credential Access
        elif "brute" in cat or "password" in cat or "t1110" in rule_name:
            ev = StageEvidence(
                evidence_id=f"ev_find_{idx}",
                source=EvidenceSource.HEURISTIC,
                timestamp=ts,
                description=f"Repetitive authentication or brute-force pattern: {finding.get('description', cat)}",
                stage=AttackStage.CREDENTIAL_ACCESS,
                technique_id="T1110",
                confidence=conf,
                polarity=EvidencePolarity.SUPPORTING,
            )
            evidence_items.append(ev)
            technique_counts["T1110"] = technique_counts.get("T1110", 0) + 1

    # 2. Harvest Behavioral Signals (Beaconing, C2)
    if behavioral_report and hasattr(behavioral_report, "beaconing_signals"):
        for b_idx, b in enumerate(behavioral_report.beaconing_signals):
            if getattr(b, "is_beaconing", False):
                ev = StageEvidence(
                    evidence_id=f"ev_beacon_{b_idx}",
                    source=EvidenceSource.ZEEK,
                    timestamp=ts,
                    description=f"Periodic network beaconing to remote endpoint: {getattr(b, 'destination_ip', 'unknown')}",
                    stage=AttackStage.COMMAND_AND_CONTROL,
                    technique_id="T1071",
                    confidence=0.85,
                    polarity=EvidencePolarity.SUPPORTING,
                )
                evidence_items.append(ev)
                technique_counts["T1071"] = technique_counts.get("T1071", 0) + 1

    # 3. Harvest Normalized Telemetry Alerts (Suricata / Zeek / Scapy / NFStream)
    if normalized_telemetry and hasattr(normalized_telemetry, "alerts"):
        for a_idx, alert in enumerate(normalized_telemetry.alerts):
            src_str = getattr(alert, "source", "suricata").lower()
            ev_source = EvidenceSource.SURICATA if "suricata" in src_str else (
                EvidenceSource.ZEEK if "zeek" in src_str else (
                    EvidenceSource.SCAPY if "scapy" in src_str else (
                        EvidenceSource.NFSTREAM if "nfstream" in src_str else EvidenceSource.HEURISTIC
                    )
                )
            )
            mitre_id = getattr(alert, "mitre_attack_id", None)
            alert_stage = AttackStage.UNKNOWN
            if mitre_id == "T1046":
                alert_stage = AttackStage.RECONNAISSANCE
            elif mitre_id == "T1498":
                alert_stage = AttackStage.IMPACT
            elif mitre_id == "T1071":
                alert_stage = AttackStage.COMMAND_AND_CONTROL
            elif mitre_id == "T1110":
                alert_stage = AttackStage.CREDENTIAL_ACCESS
            elif mitre_id == "T1190":
                alert_stage = AttackStage.INITIAL_ACCESS

            ev = StageEvidence(
                evidence_id=f"ev_norm_alert_{a_idx}",
                source=ev_source,
                timestamp=getattr(alert, "timestamp", ts),
                description=getattr(alert, "signature", "IDS alert signature"),
                stage=alert_stage,
                technique_id=mitre_id,
                confidence=0.85 if getattr(alert, "severity", "MEDIUM") in ("HIGH", "CRITICAL") else 0.65,
                polarity=EvidencePolarity.SUPPORTING,
            )
            evidence_items.append(ev)
            if mitre_id:
                technique_counts[mitre_id] = technique_counts.get(mitre_id, 0) + 1

    # 4. Harvest NetworkState Feature Metrics if present
    if network_state and hasattr(network_state, "flow_features"):
        flows = getattr(network_state, "flow_features", {})
        syn_ratio = flows.get("tcp_syn_count", 0.0) / max(1.0, flows.get("total_packets", 1.0))
        dst_port_diversity = flows.get("unique_dst_ports", 0.0)

        # High port count without confirmed flood -> Reconnaissance support
        if dst_port_diversity >= 15.0 and "T1046" not in technique_counts:
            ev = StageEvidence(
                evidence_id="ev_flow_ports",
                source=EvidenceSource.MODEL,
                timestamp=ts,
                description=f"Elevated destination port diversity ({dst_port_diversity:.0f} ports)",
                stage=AttackStage.RECONNAISSANCE,
                technique_id="T1046",
                feature="unique_dst_ports",
                feature_value=dst_port_diversity,
                confidence=0.75,
                polarity=EvidencePolarity.SUPPORTING,
            )
            evidence_items.append(ev)
            technique_counts["T1046"] = technique_counts.get("T1046", 0) + 1

    # 5. Determine Primary Stage and Secondary Stages
    supporting_by_stage: dict[AttackStage, list[StageEvidence]] = {}
    for ev in evidence_items:
        if ev.polarity == EvidencePolarity.SUPPORTING:
            supporting_by_stage.setdefault(ev.stage, []).append(ev)

    if not supporting_by_stage:
        # Benign baseline
        return (
            AttackStage.BENIGN,
            [],
            StageClassification.OBSERVED,
            0.92,
            0.92,
            0.0,
            [],
        )

    # Sort stages by evidence weight
    sorted_stages = sorted(
        supporting_by_stage.keys(),
        key=lambda s: sum(e.confidence for e in supporting_by_stage[s]),
        reverse=True,
    )
    primary = sorted_stages[0]
    secondary = sorted_stages[1:]

    # Check for ambiguity: if multiple non-benign candidate stages have closely balanced support
    if len(sorted_stages) > 1:
        top_weight = sum(e.confidence for e in supporting_by_stage[sorted_stages[0]])
        runner_weight = sum(e.confidence for e in supporting_by_stage[sorted_stages[1]])
        if top_weight < 0.8 and (top_weight - runner_weight) < 0.1:
            # Evidence is too weak/ambiguous to declare a definitive stage; preserve ambiguity
            primary = AttackStage.UNKNOWN

    primary_evs = supporting_by_stage.get(primary, evidence_items)
    stage_conf = float(np.mean([e.confidence for e in primary_evs])) if primary_evs else 0.5
    tech_conf = float(max([e.confidence for e in primary_evs if e.technique_id] or [0.5]))
    agreement, agreement_mod = evaluate_sensor_agreement(primary_evs)
    overall_conf = min(0.99, max(0.10, stage_conf * agreement_mod))

    classification = (
        StageClassification.OBSERVED
        if any(e.source in (EvidenceSource.PCAP, EvidenceSource.ZEEK, EvidenceSource.SURICATA) for e in primary_evs)
        else StageClassification.INFERRED
    )

    return (
        primary,
        secondary,
        classification,
        round(overall_conf, 4),
        round(stage_conf, 4),
        round(tech_conf, 4),
        evidence_items,
    )
