"""Deterministic Security Differentiation and Evidence Grounding Engine for NexSolve.

Classifies network signals into semantic threat tiers based purely on verified observations:
- NOISE: Isolated transient connection failure or background broadcast/multicast
- ANOMALY: Statistical or metric deviation without attack pattern corroboration
- SUSPICIOUS_BEHAVIOR: Multiple corroborating anomalies or unacknowledged SYN spikes
- SUPPORTED_RECONNAISSANCE: Multi-host/multi-port systematic probe verified by flow & session metrics
- ACTIVE_ATTACK_INDICATOR: Verified exploitation artifact, volume flood, or protocol corruption
- CAMPAIGN_ACTIVITY: Correlated multi-episode, multi-entity coordinated aggression
- FORECAST_ONLY: Future rollout hypothesis without present window attack indicators
- INSUFFICIENT_EVIDENCE: Ambiguous telemetry lacking lookback sequence depth

Also provides deterministic evidence state labeling:
- DIRECTLY_OBSERVED: Explicit packet/flow/session layer telemetric ground truth
- STRONGLY_SUPPORTED: Deterministic inference backed by >= 2 independent modalities
- SUPPORTED: Single modality inference matching rule constraints
- WEAKLY_SUPPORTED: Partial heuristic match without secondary corroboration
- CONTRADICTED: Actively weakened by verified counter-evidence
- INSUFFICIENT_EVIDENCE: Lookback depth or feature availability below threshold
- FORECAST_ONLY: Exclusively a future horizon projection
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class ThreatSemanticTier(str, Enum):
    NOISE = "NOISE"
    ANOMALY = "ANOMALY"
    SUSPICIOUS_BEHAVIOR = "SUSPICIOUS_BEHAVIOR"
    SUPPORTED_RECONNAISSANCE = "SUPPORTED_RECONNAISSANCE"
    ACTIVE_ATTACK_INDICATOR = "ACTIVE_ATTACK_INDICATOR"
    CAMPAIGN_ACTIVITY = "CAMPAIGN_ACTIVITY"
    FORECAST_ONLY = "FORECAST_ONLY"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class EvidenceGroundingState(str, Enum):
    DIRECTLY_OBSERVED = "DIRECTLY_OBSERVED"
    STRONGLY_SUPPORTED = "STRONGLY_SUPPORTED"
    SUPPORTED = "SUPPORTED"
    WEAKLY_SUPPORTED = "WEAKLY_SUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    FORECAST_ONLY = "FORECAST_ONLY"


@dataclass(frozen=True)
class ThreatDifferentiationResult:
    """Semantic differentiation of an evaluated subject."""
    subject: str
    semantic_tier: ThreatSemanticTier
    grounding_state: EvidenceGroundingState
    primary_rationale: str
    supporting_modalities: tuple[str, ...]
    mitigating_factors: tuple[str, ...]
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "semantic_tier": self.semantic_tier.value,
            "grounding_state": self.grounding_state.value,
            "primary_rationale": self.primary_rationale,
            "supporting_modalities": list(self.supporting_modalities),
            "mitigating_factors": list(self.mitigating_factors),
            "provenance": self.provenance,
        }


def differentiate_threat(
    entity: str,
    entity_profile: Any = None,
    attack_kinematics: Any = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    contradictions: Sequence[Any] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
    window_count: int = 1,
) -> ThreatDifferentiationResult:
    """Deterministically differentiate a threat subject into semantic tier and grounding state."""
    cmps = campaigns or []
    pats = patterns or []
    findings = [f for f in (observed_findings or []) if str(f.get("source_ip")) == entity or str(f.get("destination_ip")) == entity]
    contras = contradictions or []

    traj = attack_kinematics.get(entity) if isinstance(attack_kinematics, dict) else attack_kinematics
    curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
    curr_state_val = getattr(curr_state, "value", str(curr_state))
    roles = set(getattr(entity_profile, "roles", ())) if entity_profile else set()

    modalities: list[str] = []
    if entity_profile:
        modalities.append("CANONICAL_FLOW")
    if findings:
        modalities.append("DETECTION_HEURISTICS")
    if any(entity in getattr(p, "primary_entities", ()) for p in pats):
        modalities.append("PATTERN_ENGINE")
    if any(entity in getattr(c, "primary_entities", ()) for c in cmps):
        modalities.append("CAMPAIGN_ENGINE")
    if traj and getattr(traj, "transitions", ()):
        modalities.append("ATTACK_KINEMATICS")

    mitigations: list[str] = [str(c) for c in contras]

    # 1. CAMPAIGN_ACTIVITY
    ent_cmps = [c for c in cmps if entity in getattr(c, "primary_entities", ())]
    if ent_cmps and curr_state_val not in ("BENIGN", "DISCOVERY"):
        tier = ThreatSemanticTier.CAMPAIGN_ACTIVITY
        grounding = EvidenceGroundingState.STRONGLY_SUPPORTED if len(modalities) >= 2 else EvidenceGroundingState.SUPPORTED
        rationale = f"Entity actively participates in multi-episode campaign {getattr(ent_cmps[0], 'campaign_id', '')} across state {curr_state_val}."
        return ThreatDifferentiationResult(
            subject=entity,
            semantic_tier=tier,
            grounding_state=grounding,
            primary_rationale=rationale,
            supporting_modalities=tuple(modalities),
            mitigating_factors=tuple(mitigations),
            provenance={"rule": "campaign_membership"},
        )

    # 2. ACTIVE_ATTACK_INDICATOR
    if curr_state_val in ("IMPACT", "COMMAND_AND_CONTROL", "EXPLOITATION_INDICATOR"):
        tier = ThreatSemanticTier.ACTIVE_ATTACK_INDICATOR
        grounding = EvidenceGroundingState.STRONGLY_SUPPORTED if len(modalities) >= 2 else EvidenceGroundingState.SUPPORTED
        rationale = f"Observed verified indicators of active {curr_state_val} attack state."
        return ThreatDifferentiationResult(
            subject=entity,
            semantic_tier=tier,
            grounding_state=grounding,
            primary_rationale=rationale,
            supporting_modalities=tuple(modalities),
            mitigating_factors=tuple(mitigations),
            provenance={"rule": "active_attack_state"},
        )

    # 3. SUPPORTED_RECONNAISSANCE
    if curr_state_val == "RECONNAISSANCE" or any("SCANNER" in str(r) for r in roles):
        ports_cnt = getattr(entity_profile, "targeted_ports_count", 0) if entity_profile else 0
        peers_cnt = getattr(entity_profile, "peer_count", 0) if entity_profile else 0
        if ports_cnt >= 5 or peers_cnt >= 3:
            tier = ThreatSemanticTier.SUPPORTED_RECONNAISSANCE
            grounding = EvidenceGroundingState.DIRECTLY_OBSERVED if "CANONICAL_FLOW" in modalities else EvidenceGroundingState.SUPPORTED
            rationale = f"Systematic multi-target/multi-port reconnaissance directly observed ({ports_cnt} port(s), {peers_cnt} peer(s))."
        else:
            tier = ThreatSemanticTier.SUSPICIOUS_BEHAVIOR
            grounding = EvidenceGroundingState.WEAKLY_SUPPORTED
            rationale = f"Low-breadth probe activity ({ports_cnt} port(s), {peers_cnt} peer(s)) without verified systematic sweep breadth."
        return ThreatDifferentiationResult(
            subject=entity,
            semantic_tier=tier,
            grounding_state=grounding,
            primary_rationale=rationale,
            supporting_modalities=tuple(modalities),
            mitigating_factors=tuple(mitigations),
            provenance={"rule": "reconnaissance_breadth_evaluation"},
        )

    # 4. SUSPICIOUS_BEHAVIOR
    if findings or any("RESET_HEAVY" in str(r) for r in roles):
        tier = ThreatSemanticTier.SUSPICIOUS_BEHAVIOR
        grounding = EvidenceGroundingState.SUPPORTED
        rationale = "Multiple unacknowledged connections or anomalous failure spikes observed."
        return ThreatDifferentiationResult(
            subject=entity,
            semantic_tier=tier,
            grounding_state=grounding,
            primary_rationale=rationale,
            supporting_modalities=tuple(modalities),
            mitigating_factors=tuple(mitigations),
            provenance={"rule": "suspicious_traffic_signals"},
        )

    # 5. FORECAST_ONLY
    if forecast_points and not findings and curr_state_val == "BENIGN":
        tier = ThreatSemanticTier.FORECAST_ONLY
        grounding = EvidenceGroundingState.FORECAST_ONLY
        rationale = "Subject has future horizon state projections but zero observed present-window anomalies."
        return ThreatDifferentiationResult(
            subject=entity,
            semantic_tier=tier,
            grounding_state=grounding,
            primary_rationale=rationale,
            supporting_modalities=("WORLD_MODEL_ROLLOUT",),
            mitigating_factors=tuple(mitigations),
            provenance={"rule": "forecast_projection_only"},
        )

    # 6. NOISE vs INSUFFICIENT_EVIDENCE
    if window_count < 2:
        tier = ThreatSemanticTier.INSUFFICIENT_EVIDENCE
        grounding = EvidenceGroundingState.INSUFFICIENT_EVIDENCE
        rationale = "Single window capture snippet insufficient to distinguish persistent behavior from transient packet burst."
    else:
        tier = ThreatSemanticTier.NOISE
        grounding = EvidenceGroundingState.DIRECTLY_OBSERVED
        rationale = "Transient background communication or broadcast/multicast exchange within nominal parameters."

    return ThreatDifferentiationResult(
        subject=entity,
        semantic_tier=tier,
        grounding_state=grounding,
        primary_rationale=rationale,
        supporting_modalities=tuple(modalities),
        mitigating_factors=tuple(mitigations),
        provenance={"rule": "baseline_default"},
    )
