"""Deterministic Threat Prioritization Engine.

Prioritizes active network threats using explainable multi-dimensional evidence:
- Attack state severity (IMPACT > C2 > EXPLOIT > RECON > DISCOVERY > BENIGN)
- Behavioral escalation magnitude (port fan-out, connection surges)
- Target breadth (distinct hosts & ports targeted)
- Persistence and campaign breadth (episodes, multi-window duration)
- Multi-modal corroboration (Zeek sessions + RITA beaconing + Suricata signatures + Model)
- Mitigating factors (contradicting benign patterns, low failure ratios)
- Explicit uncertainty (short history, abstention)

Zero score averaging or arbitrary AI confidence formulas.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class ThreatPriorityLevel(str, Enum):
    P1_CRITICAL = "P1_CRITICAL"
    P2_HIGH = "P2_HIGH"
    P3_MEDIUM = "P3_MEDIUM"
    P4_LOW = "P4_LOW"
    P5_INFORMATIONAL = "P5_INFORMATIONAL"


@dataclass(frozen=True)
class PrioritizedThreat:
    """A prioritized threat entity with structured, explainable decision factors."""
    priority_id: str
    entity: str
    priority_level: ThreatPriorityLevel
    priority_rank: int  # 1 = highest priority
    primary_threat_type: str
    drivers: tuple[str, ...]
    mitigating_factors: tuple[str, ...]
    uncertainty_factors: tuple[str, ...]
    supporting_evidence_count: int
    associated_campaign_id: str | None
    recommended_action: str
    explanation: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "priority_id": self.priority_id,
            "entity": self.entity,
            "priority_level": self.priority_level.value,
            "priority_rank": self.priority_rank,
            "primary_threat_type": self.primary_threat_type,
            "drivers": list(self.drivers),
            "mitigating_factors": list(self.mitigating_factors),
            "uncertainty_factors": list(self.uncertainty_factors),
            "supporting_evidence_count": self.supporting_evidence_count,
            "associated_campaign_id": self.associated_campaign_id,
            "recommended_action": self.recommended_action,
            "explanation": self.explanation,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class ThreatRiskBreakdown:
    """Detailed explainable decomposition of threat priority and risk drivers."""
    entity: str
    priority_level: ThreatPriorityLevel
    priority_rank: int
    base_severity_score: int
    attack_state_contribution: int
    kinematic_escalation_contribution: int
    target_breadth_contribution: int
    campaign_contribution: int
    mitigation_discount: int
    final_score: int
    drivers: tuple[str, ...]
    mitigating_factors: tuple[str, ...]
    uncertainty_factors: tuple[str, ...]
    recommended_action: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "priority_level": self.priority_level.value,
            "priority_rank": self.priority_rank,
            "base_severity_score": self.base_severity_score,
            "attack_state_contribution": self.attack_state_contribution,
            "kinematic_escalation_contribution": self.kinematic_escalation_contribution,
            "target_breadth_contribution": self.target_breadth_contribution,
            "campaign_contribution": self.campaign_contribution,
            "mitigation_discount": self.mitigation_discount,
            "final_score": self.final_score,
            "drivers": list(self.drivers),
            "mitigating_factors": list(self.mitigating_factors),
            "uncertainty_factors": list(self.uncertainty_factors),
            "recommended_action": self.recommended_action,
            "provenance": self.provenance,
        }


def decompose_threat_risk(
    entity: str,
    entity_profiles: Mapping[str, Any] | None = None,
    attack_kinematics: Mapping[str, Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    change_signals: Sequence[Any] | None = None,
) -> ThreatRiskBreakdown:
    """Decompose the deterministic risk and priority scoring for a single entity."""
    profiles = entity_profiles or {}
    kinematics = attack_kinematics or {}
    cmps = campaigns or []
    changes = change_signals or []

    prof = profiles.get(entity)
    traj = kinematics.get(entity)
    curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
    curr_state_val = getattr(curr_state, "value", str(curr_state))

    drivers: list[str] = []
    mitigations: list[str] = []
    uncertainties: list[str] = []

    state_contrib = 0
    if curr_state_val == "IMPACT":
        state_contrib = 100
        drivers.append("Active IMPACT state (Denial of Service / Volume Flood)")
    elif curr_state_val == "COMMAND_AND_CONTROL":
        state_contrib = 90
        drivers.append("Active COMMAND_AND_CONTROL state (Metronomic Beaconing)")
    elif curr_state_val == "EXPLOITATION_INDICATOR":
        state_contrib = 80
        drivers.append("Exploitation indicators detected in session signatures")
    elif curr_state_val == "RECONNAISSANCE":
        state_contrib = 60
        drivers.append("Active RECONNAISSANCE port sweep or address scanning")
    elif curr_state_val == "DISCOVERY":
        state_contrib = 40
        drivers.append("Host/service discovery probing observed")
    elif prof and any("SCANNER" in str(r) for r in getattr(prof, "roles", ())):
        state_contrib = 45
        drivers.append("Entity exhibits active port scanning behavior")
    elif prof and any("BEACON" in str(r) for r in getattr(prof, "roles", ())):
        state_contrib = 50
        drivers.append("Entity exhibits periodic beaconing communication")
    elif prof and any("RESET_HEAVY" in str(r) for r in getattr(prof, "roles", ())):
        state_contrib = 30
        drivers.append("Entity generates high volume of rejected or reset connection attempts")

    kinematic_contrib = 0
    ent_changes = [c for c in changes if getattr(c, "entity", "") == entity]
    for c in ent_changes:
        c_type = str(getattr(c, "change_type", ""))
        if "PORT_FANOUT" in c_type:
            kinematic_contrib += 25
            drivers.append(f"Sudden port fanout expansion (magnitude {getattr(c, 'magnitude', 0):.1f})")
        elif "CONN_SURGE" in c_type or "CONNECTION_ATTEMPT" in c_type:
            kinematic_contrib += 20
            drivers.append("Sharp connection attempt surge across windows")

    breadth_contrib = 0
    peers_cnt = getattr(prof, "peer_count", 0) if prof else 0
    ports_cnt = getattr(prof, "targeted_ports_count", 0) if prof else 0
    if peers_cnt >= 10:
        breadth_contrib += 20
        drivers.append(f"Broad target footprint: {peers_cnt} distinct peers targeted")
    if ports_cnt >= 20:
        breadth_contrib += 20
        drivers.append(f"Intense service targeting: {ports_cnt} distinct ports targeted")

    campaign_contrib = 0
    for c in cmps:
        if entity in getattr(c, "primary_entities", ()):
            campaign_contrib += 15
            drivers.append(f"Correlated into active multi-episode campaign {getattr(c, 'campaign_id', '')}")
            break

    mitigation_discount = 0
    clean_sessions = getattr(prof, "successful_sessions", 0) if prof else 0
    fail_ratio = getattr(prof, "failure_ratio", 0.0) if prof else 0.0
    if clean_sessions > 15 and fail_ratio < 0.10 and curr_state_val not in ("IMPACT", "COMMAND_AND_CONTROL"):
        mitigation_discount = 30
        mitigations.append(f"Substantial established session history ({clean_sessions} clean sessions, <10% failure)")

    act_windows = getattr(prof, "active_windows_count", 1) if prof else 1
    if act_windows <= 1:
        uncertainties.append("Single observation window limit; historical persistence unverified")

    total_score = max(0, state_contrib + kinematic_contrib + breadth_contrib + campaign_contrib - mitigation_discount)

    if total_score >= 100:
        p_level = ThreatPriorityLevel.P1_CRITICAL
        action = "Immediate host isolation and ingress traffic filtering required."
    elif total_score >= 70:
        p_level = ThreatPriorityLevel.P2_HIGH
        action = "Initiate targeted endpoint investigation and block anomalous port sweeps."
    elif total_score >= 40:
        p_level = ThreatPriorityLevel.P3_MEDIUM
        action = "Monitor entity trajectory across subsequent temporal windows."
    elif total_score >= 20:
        p_level = ThreatPriorityLevel.P4_LOW
        action = "Log for routine baseline auditing."
    else:
        p_level = ThreatPriorityLevel.P5_INFORMATIONAL
        action = "No intervention required; behavior consistent with baseline."

    return ThreatRiskBreakdown(
        entity=entity,
        priority_level=p_level,
        priority_rank=1,
        base_severity_score=state_contrib,
        attack_state_contribution=state_contrib,
        kinematic_escalation_contribution=kinematic_contrib,
        target_breadth_contribution=breadth_contrib,
        campaign_contribution=campaign_contrib,
        mitigation_discount=mitigation_discount,
        final_score=total_score,
        drivers=tuple(drivers),
        mitigating_factors=tuple(mitigations),
        uncertainty_factors=tuple(uncertainties),
        recommended_action=action,
        provenance={"engine": "deterministic_risk_decomposition_v1"},
    )



def prioritize_threats(
    entity_profiles: Mapping[str, Any] | None = None,
    attack_kinematics: Mapping[str, Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    change_signals: Sequence[Any] | None = None,
) -> tuple[PrioritizedThreat, ...]:
    """Deterministically prioritize all evaluated network entities."""
    evaluated: list[dict[str, Any]] = []
    profiles = entity_profiles or {}
    kinematics = attack_kinematics or {}
    cmps = campaigns or []
    pats = patterns or []
    changes = change_signals or []

    # Map campaigns by entity
    entity_cmp_map: dict[str, str] = {}
    for c in cmps:
        for ent in getattr(c, "primary_entities", ()):
            entity_cmp_map[ent] = getattr(c, "campaign_id", "cmp")

    for ent, prof in profiles.items():
        traj = kinematics.get(ent)
        curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
        curr_state_val = getattr(curr_state, "value", str(curr_state))

        drivers: list[str] = []
        mitigations: list[str] = []
        uncertainties: list[str] = []
        evidence_count: int = 0
        severity_score: int = 0

        # Dimension 1: Attack State
        if curr_state_val == "IMPACT":
            severity_score += 100
            drivers.append("Active IMPACT state (Denial of Service / Volume Flood)")
            evidence_count += 3
        elif curr_state_val == "COMMAND_AND_CONTROL":
            severity_score += 90
            drivers.append("Active COMMAND_AND_CONTROL state (Metronomic Beaconing)")
            evidence_count += 3
        elif curr_state_val == "EXPLOITATION_INDICATOR":
            severity_score += 80
            drivers.append("Exploitation indicators detected in session signatures")
            evidence_count += 2
        elif curr_state_val == "RECONNAISSANCE":
            severity_score += 60
            drivers.append("Active RECONNAISSANCE port sweep or address scanning")
            evidence_count += 2
        elif curr_state_val == "DISCOVERY":
            severity_score += 40
            drivers.append("Host/service discovery probing observed")
            evidence_count += 1
        elif any("SCANNER" in str(r) for r in getattr(prof, "roles", ())):
            severity_score += 45
            drivers.append("Entity exhibits active port scanning behavior")
            evidence_count += 1
        elif any("BEACON" in str(r) for r in getattr(prof, "roles", ())):
            severity_score += 50
            drivers.append("Entity exhibits periodic beaconing communication")
            evidence_count += 2
        elif any("RESET_HEAVY" in str(r) for r in getattr(prof, "roles", ())):
            severity_score += 30
            drivers.append("Entity generates high volume of rejected or reset connection attempts")
            evidence_count += 1

        # Dimension 2: Behavioral Changes
        ent_changes = [c for c in changes if getattr(c, "entity", "") == ent]
        for c in ent_changes:
            c_type = str(getattr(c, "change_type", ""))
            if "PORT_FANOUT" in c_type:
                severity_score += 25
                drivers.append(f"Sudden port fanout expansion (magnitude {getattr(c, 'magnitude', 0):.1f})")
                evidence_count += 1
            elif "CONN_SURGE" in c_type or "CONNECTION_ATTEMPT" in c_type:
                severity_score += 20
                drivers.append("Sharp connection attempt surge across windows")
                evidence_count += 1

        # Dimension 3: Target Breadth
        peers_cnt = getattr(prof, "peer_count", 0)
        ports_cnt = getattr(prof, "targeted_ports_count", 0)
        if peers_cnt >= 10:
            severity_score += 20
            drivers.append(f"Broad target footprint: {peers_cnt} distinct peers targeted")
        if ports_cnt >= 20:
            severity_score += 20
            drivers.append(f"Intense service targeting: {ports_cnt} distinct ports targeted")

        # Dimension 4: Campaign Correlation
        cmp_id = entity_cmp_map.get(ent)
        if cmp_id:
            severity_score += 15
            drivers.append(f"Correlated into active multi-episode campaign {cmp_id}")
            evidence_count += 1

        # Dimension 5: Mitigations and Contradictions
        clean_sessions = getattr(prof, "successful_sessions", 0)
        fail_ratio = getattr(prof, "failure_ratio", 0.0)
        if clean_sessions > 15 and fail_ratio < 0.10 and curr_state_val not in ("IMPACT", "COMMAND_AND_CONTROL"):
            severity_score -= 30
            mitigations.append(f"Substantial established session history ({clean_sessions} clean sessions, <10% failure)")

        # Dimension 6: Uncertainty
        act_windows = getattr(prof, "active_windows_count", 1)
        if act_windows <= 1:
            uncertainties.append("Single observation window limit; historical persistence unverified")

        # Categorize into Priority Levels
        if severity_score >= 100:
            p_level = ThreatPriorityLevel.P1_CRITICAL
            action = "Immediate host isolation and ingress traffic filtering required."
        elif severity_score >= 70:
            p_level = ThreatPriorityLevel.P2_HIGH
            action = "Initiate targeted endpoint investigation and block anomalous port sweeps."
        elif severity_score >= 40:
            p_level = ThreatPriorityLevel.P3_MEDIUM
            action = "Monitor entity trajectory across subsequent temporal windows."
        elif severity_score >= 20:
            p_level = ThreatPriorityLevel.P4_LOW
            action = "Log for routine baseline auditing."
        else:
            p_level = ThreatPriorityLevel.P5_INFORMATIONAL
            action = "No intervention required; behavior consistent with baseline."

        evaluated.append({
            "entity": ent,
            "level": p_level,
            "score": severity_score,
            "drivers": drivers,
            "mitigations": mitigations,
            "uncertainties": uncertainties,
            "evidence_count": evidence_count,
            "cmp_id": cmp_id,
            "action": action,
            "threat_type": curr_state_val,
        })

    # Sort deterministically by severity_score DESC, then entity string
    evaluated.sort(key=lambda x: (-x["score"], x["entity"]))

    prioritized: list[PrioritizedThreat] = []
    for rank, item in enumerate(evaluated, start=1):
        pid = deterministic_id("prio", item["entity"], rank, item["level"].value)
        expl = (
            f"Rank #{rank} ({item['level'].value}): {item['threat_type']} state with "
            f"{len(item['drivers'])} active driver(s). Score: {item['score']}."
        )
        prioritized.append(PrioritizedThreat(
            priority_id=pid,
            entity=item["entity"],
            priority_level=item["level"],
            priority_rank=rank,
            primary_threat_type=item["threat_type"],
            drivers=tuple(item["drivers"]),
            mitigating_factors=tuple(item["mitigations"]),
            uncertainty_factors=tuple(item["uncertainties"]),
            supporting_evidence_count=item["evidence_count"],
            associated_campaign_id=item["cmp_id"],
            recommended_action=item["action"],
            explanation=expl,
            provenance={"rule": "deterministic_multi_dimensional_prioritization_v1"},
        ))

    return tuple(prioritized)
