"""Deterministic Recommended Response Actions Engine for NexSolve.

Produces evidence-backed, non-automated mitigation recommendations based on observed telemetry:
- HIGH_SCAN_ACTIVITY -> Investigate and rate-limit anomalous port sweeps
- ACTIVE_PORT_SCAN -> Review targeted services and tighten firewall rules
- RESET_HEAVY_BEHAVIOR -> Inspect connection failures/reset patterns on firewall
- BEACONING -> Inspect periodic destination relationship and C2 domain/IP
- CAMPAIGN -> Correlate and investigate all participating entities concurrently
- ATTACK_STATE_ESCALATION -> Prioritize containment and endpoint memory forensics
- FORECAST_PERSISTENCE -> Maintain heightened monitoring across forward windows
- INSUFFICIENT_HISTORY -> Collect more temporal telemetry before drawing high-confidence conclusions

Never pretends NexSolve automatically executes active containment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class MitigationActionType(str, Enum):
    INVESTIGATE_ENTITY = "INVESTIGATE_ENTITY"
    REVIEW_EXPOSED_SERVICES = "REVIEW_EXPOSED_SERVICES"
    INSPECT_RESET_PATTERNS = "INSPECT_RESET_PATTERNS"
    INSPECT_PERIODIC_RELATIONSHIP = "INSPECT_PERIODIC_RELATIONSHIP"
    INVESTIGATE_CAMPAIGN = "INVESTIGATE_CAMPAIGN"
    PRIORITIZE_CONTAINMENT = "PRIORITIZE_CONTAINMENT"
    EXTEND_MONITORING = "EXTEND_MONITORING"
    COLLECT_MORE_TELEMETRY = "COLLECT_MORE_TELEMETRY"
    ISOLATE_HOST = "ISOLATE_HOST"


@dataclass(frozen=True)
class MitigationRecommendation:
    """A concrete, evidence-backed recommended security action."""
    recommendation_id: str
    action_type: MitigationActionType
    title: str
    target_entity: str
    urgency: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    reason: str
    supporting_evidence: tuple[str, ...]
    operational_guidance: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "recommendation_id": self.recommendation_id,
            "action_type": self.action_type.value,
            "title": self.title,
            "target_entity": self.target_entity,
            "urgency": self.urgency,
            "reason": self.reason,
            "supporting_evidence": list(self.supporting_evidence),
            "operational_guidance": self.operational_guidance,
            "provenance": self.provenance,
        }


def generate_mitigation_recommendations(
    entity: str,
    entity_profile: Any = None,
    attack_kinematics: Any = None,
    campaigns: Sequence[Any] | None = None,
    beaconing_signals: Sequence[Any] | None = None,
    contradictions: Sequence[Any] | None = None,
    window_count: int = 1,
) -> tuple[MitigationRecommendation, ...]:
    """Generate deterministic, explainable mitigation recommendations for an entity."""
    recommendations: list[MitigationRecommendation] = []
    cmps = campaigns or []
    beacons = beaconing_signals or []
    contras = contradictions or []

    roles = set(getattr(entity_profile, "roles", ())) if entity_profile else set()
    traj = attack_kinematics.get(entity) if isinstance(attack_kinematics, dict) else attack_kinematics
    curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
    curr_state_val = getattr(curr_state, "value", str(curr_state))

    # 1. ATTACK_STATE_ESCALATION / IMPACT / C2
    if curr_state_val in ("IMPACT", "COMMAND_AND_CONTROL", "EXPLOITATION_INDICATOR"):
        rid = deterministic_id("mitig", entity, "ESCALATION", curr_state_val)
        recommendations.append(MitigationRecommendation(
            recommendation_id=rid,
            action_type=MitigationActionType.PRIORITIZE_CONTAINMENT,
            title=f"Prioritize Containment for {entity} ({curr_state_val})",
            target_entity=entity,
            urgency="CRITICAL",
            reason=f"Entity is in an active {curr_state_val} attack state.",
            supporting_evidence=(f"state_{curr_state_val}",),
            operational_guidance="Initiate immediate SOC analyst review, quarantine communication channels, and collect memory artifacts.",
            provenance={"rule": "critical_attack_state"},
        ))

    # 2. SCANNER / ACTIVE_PORT_SCAN
    if any("SCANNER" in str(r) for r in roles) or curr_state_val in ("RECONNAISSANCE", "DISCOVERY"):
        ports_cnt = getattr(entity_profile, "targeted_ports_count", 0) if entity_profile else 0
        peers_cnt = getattr(entity_profile, "peer_count", 0) if entity_profile else 0
        rid = deterministic_id("mitig", entity, "PORT_SCAN")
        recommendations.append(MitigationRecommendation(
            recommendation_id=rid,
            action_type=MitigationActionType.REVIEW_EXPOSED_SERVICES,
            title=f"Review Exposed Services Targeted by {entity}",
            target_entity=entity,
            urgency="HIGH" if ports_cnt > 20 or peers_cnt > 5 else "MEDIUM",
            reason=f"Entity conducted horizontal or vertical port scans ({ports_cnt} port(s), {peers_cnt} peer(s)).",
            supporting_evidence=(f"ports_{ports_cnt}", f"peers_{peers_cnt}"),
            operational_guidance="Audit firewall ingress rules for targeted ports, verify service patch levels, and temporarily rate-limit source entity.",
            provenance={"rule": "active_port_scan"},
        ))

    # 3. BEACONING
    ent_beacons = [b for b in beacons if getattr(b, "src_ip", "") == entity and getattr(b, "is_beaconing", False)]
    if any("BEACON" in str(r) for r in roles) or ent_beacons:
        dst = getattr(ent_beacons[0], "dst_ip", "external_host") if ent_beacons else "destination"
        rid = deterministic_id("mitig", entity, "BEACONING")
        recommendations.append(MitigationRecommendation(
            recommendation_id=rid,
            action_type=MitigationActionType.INSPECT_PERIODIC_RELATIONSHIP,
            title=f"Inspect Periodic Destination Relationship to {dst}",
            target_entity=entity,
            urgency="HIGH",
            reason="Observed low-jitter periodic beaconing pattern indicative of C2 persistence.",
            supporting_evidence=(f"beacon_target_{dst}",),
            operational_guidance=f"Inspect DNS resolutions, TLS certificates, and parent process lineage connecting {entity} to {dst}.",
            provenance={"rule": "beaconing_mitigation"},
        ))

    # 4. RESET_HEAVY
    if any("RESET_HEAVY" in str(r) for r in roles):
        fail_ratio = getattr(entity_profile, "failure_ratio", 0.0) if entity_profile else 0.0
        rid = deterministic_id("mitig", entity, "RESET_HEAVY")
        recommendations.append(MitigationRecommendation(
            recommendation_id=rid,
            action_type=MitigationActionType.INSPECT_RESET_PATTERNS,
            title=f"Inspect High TCP Reset Pattern ({fail_ratio*100:.1f}% failure)",
            target_entity=entity,
            urgency="MEDIUM",
            reason="Excessive rejected/reset connections suggest probing closed services or network misconfiguration.",
            supporting_evidence=(f"failure_ratio_{fail_ratio:.2f}",),
            operational_guidance="Check switch ACL logs and border router drop counters to correlate dropped sessions.",
            provenance={"rule": "reset_heavy_mitigation"},
        ))

    # 5. CAMPAIGN CO-PARTICIPATION
    ent_cmps = [c for c in cmps if entity in getattr(c, "primary_entities", ()) or entity in getattr(c, "target_entities", ())]
    if ent_cmps:
        cmp = ent_cmps[0]
        cid = getattr(cmp, "campaign_id", "cmp")
        rid = deterministic_id("mitig", entity, "CAMPAIGN", cid)
        recommendations.append(MitigationRecommendation(
            recommendation_id=rid,
            action_type=MitigationActionType.INVESTIGATE_CAMPAIGN,
            title=f"Investigate Coordinated Campaign: {getattr(cmp, 'title', cid)}",
            target_entity=entity,
            urgency="HIGH",
            reason=f"Entity is a participant in a correlated campaign encompassing {len(getattr(cmp, 'primary_entities', ()))} entity(ies).",
            supporting_evidence=(cid,),
            operational_guidance="Correlate access logs across all participating endpoints concurrently rather than treating as an isolated alert.",
            provenance={"rule": "campaign_coordination_mitigation"},
        ))

    # 6. INSUFFICIENT_HISTORY
    if window_count < 8:
        rid = deterministic_id("mitig", entity, "INSUFFICIENT_HISTORY")
        recommendations.append(MitigationRecommendation(
            recommendation_id=rid,
            action_type=MitigationActionType.COLLECT_MORE_TELEMETRY,
            title="Extend Telemetry Capture Window for Trend Validation",
            target_entity=entity,
            urgency="LOW",
            reason=f"Capture length ({window_count} window(s)) is below 8-window canonical horizon.",
            supporting_evidence=(f"windows_{window_count}",),
            operational_guidance="Maintain packet capture collection across additional observation periods before applying strict containment policies.",
            provenance={"rule": "insufficient_history_guidance"},
        ))

    return tuple(recommendations)
