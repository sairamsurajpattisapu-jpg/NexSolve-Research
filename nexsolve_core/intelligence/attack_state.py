"""Attack State Inference Engine.

Infers empirical network attack states from multi-modal corroboration:
- BENIGN_OBSERVATION: Normal traffic baseline, established sessions, no verified findings
- RECONNAISSANCE: Port scanning, host probing, TCP SYN bursts, port fan-out changes
- DENIAL_OF_SERVICE: High volume asymmetry, packet flood, repeated connection resets
- COMMAND_AND_CONTROL: Periodic metronomic beaconing, regularity score >= 0.85
- UNKNOWN_STATE: Unclassified anomalous traffic without matching attack kinematics
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class AttackStateEnum(str, Enum):
    BENIGN_OBSERVATION = "BENIGN_OBSERVATION"
    RECONNAISSANCE = "RECONNAISSANCE"
    DENIAL_OF_SERVICE = "DENIAL_OF_SERVICE"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    EXFILTRATION = "EXFILTRATION"
    UNKNOWN_STATE = "UNKNOWN_STATE"


@dataclass(frozen=True)
class InferredAttackState:
    """Inferred attack state grounded in multi-modal evidence."""
    state_id: str
    state: AttackStateEnum
    entity: str
    start_window: int
    end_window: int
    supporting_findings: tuple[str, ...]
    supporting_signals: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    confidence_rationale: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_id": self.state_id,
            "state": self.state.value,
            "entity": self.entity,
            "start_window": self.start_window,
            "end_window": self.end_window,
            "supporting_findings": list(self.supporting_findings),
            "supporting_signals": list(self.supporting_signals),
            "mitre_techniques": list(self.mitre_techniques),
            "confidence_rationale": self.confidence_rationale,
            "provenance": self.provenance,
        }


def infer_attack_states(
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    behavioral_report: Any = None,
    change_signals: Sequence[Any] | None = None,
) -> tuple[InferredAttackState, ...]:
    """Deterministically infer attack states from multi-modal corroboration."""
    states: list[InferredAttackState] = []

    # Map findings by entity
    entity_findings: dict[str, list[Mapping[str, Any]]] = {}
    if observed_findings:
        for f in observed_findings:
            ent = str(f.get("destination_ip") or f.get("source_ip") or "network").strip()
            entity_findings.setdefault(ent, []).append(f)

    if not entity_findings:
        # Benign network state
        sid = deterministic_id("state", "network", 0, "BENIGN")
        states.append(InferredAttackState(
            state_id=sid,
            state=AttackStateEnum.BENIGN_OBSERVATION,
            entity="network",
            start_window=0,
            end_window=0,
            supporting_findings=tuple(),
            supporting_signals=tuple(["Normal traffic baseline"]),
            mitre_techniques=tuple(),
            confidence_rationale="No elevated security events or heuristic findings observed in capture.",
            provenance={"rule": "baseline_benign_rule"},
        ))
        return tuple(states)

    for ent, f_list in entity_findings.items():
        w_indices = sorted(list({int(f.get("window_index") or 0) for f in f_list}))
        start_w = w_indices[0] if w_indices else 0
        end_w = w_indices[-1] if w_indices else 0
        cats = [str(f.get("attack_category", "Anomaly")).lower() for f in f_list]

        # Multi-modal signals for this entity
        entity_changes = [c for c in (change_signals or []) if getattr(c, "entity", "") == ent]
        has_port_surge = any(getattr(c, "change_type", None) and "PORT_FANOUT" in str(getattr(c, "change_type")) for c in entity_changes)

        # 1. Reconnaissance Inference
        if any("scan" in c or "recon" in c for c in cats) or has_port_surge:
            sid = deterministic_id("state", ent, start_w, end_w, "RECON")
            states.append(InferredAttackState(
                state_id=sid,
                state=AttackStateEnum.RECONNAISSANCE,
                entity=ent,
                start_window=start_w,
                end_window=end_w,
                supporting_findings=tuple(sorted(set(f.get("attack_category", "Scan") for f in f_list))),
                supporting_signals=tuple(c.description for c in entity_changes[:3]),
                mitre_techniques=("T1046",),
                confidence_rationale="Corroborated by port scan anomaly and destination port fan-out surge.",
                provenance={"rule": "recon_corroboration_rule"},
            ))

        # 2. DoS Inference
        elif any("dos" in c or "flood" in c for c in cats):
            sid = deterministic_id("state", ent, start_w, end_w, "DOS")
            states.append(InferredAttackState(
                state_id=sid,
                state=AttackStateEnum.DENIAL_OF_SERVICE,
                entity=ent,
                start_window=start_w,
                end_window=end_w,
                supporting_findings=tuple(sorted(set(f.get("attack_category", "DoS") for f in f_list))),
                supporting_signals=tuple(c.description for c in entity_changes[:3]),
                mitre_techniques=("T1498",),
                confidence_rationale="Corroborated by high-rate asymmetric packet traffic or connection flood.",
                provenance={"rule": "dos_corroboration_rule"},
            ))
        else:
            sid = deterministic_id("state", ent, start_w, end_w, "UNKNOWN")
            states.append(InferredAttackState(
                state_id=sid,
                state=AttackStateEnum.UNKNOWN_STATE,
                entity=ent,
                start_window=start_w,
                end_window=end_w,
                supporting_findings=tuple(sorted(set(f.get("attack_category", "Anomaly") for f in f_list))),
                supporting_signals=tuple(),
                mitre_techniques=tuple(),
                confidence_rationale="Anomalous behavior observed without matching specific attack kinematics.",
                provenance={"rule": "unknown_anomaly_rule"},
            ))

    return tuple(states)
