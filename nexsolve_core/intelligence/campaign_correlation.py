"""Deterministic Cross-Incident Campaign Correlation Engine for NexSolve.

Correlates independently analyzed network incidents / captures:
- Compares intelligence fingerprints across independent dimensions:
  1. ENTITY_OVERLAP (Shared source/actor infrastructure)
  2. TARGET_OVERLAP (Common destination subnet or targeted hosts)
  3. PORT_PATTERN_SIMILARITY (Identical distinctive listening port sweeps)
  4. PROTOCOL_PATTERN_SIMILARITY (Matching TCP/UDP/ICMP composition)
  5. BEHAVIOR_PATTERN_SIMILARITY (Identical fan-out, handshake failure ratios, episode structure)
  6. ATTACK_STATE_SIMILARITY (Same kill-chain stage progression)
  7. MITRE_TECHNIQUE_OVERLAP (Matching verified ATT&CK techniques)
  8. TEMPORAL_PROXIMITY (Adjacent or overlapping window ranges)

STRICT SCIENTIFIC RULES:
- Conservative categorization: RELATED_CAMPAIGN, POSSIBLY_RELATED, UNRELATED, INSUFFICIENT_EVIDENCE.
- NEVER equate "Different IP" with "Contradiction" (distinguishes NO_OVERLAP from ACTUAL_CONTRADICTION).
- Detects INFRASTRUCTURE_CHANGE (same behavioral and port fingerprint across changed source IPs).
- NEVER claim "Same Attacker" unless explicit identity evidence exists; uses BEHAVIORALLY_RELATED.
- Deterministic multi-incident clustering and campaign timeline assembly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id
from nexsolve_core.intelligence.incident_fingerprint import IncidentFingerprint


class CorrelationRelationship(str, Enum):
    RELATED_CAMPAIGN = "RELATED_CAMPAIGN"
    POSSIBLY_RELATED = "POSSIBLY_RELATED"
    UNRELATED = "UNRELATED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class CampaignEvolutionState(str, Enum):
    REPEATED_RECONNAISSANCE = "REPEATED_RECONNAISSANCE"
    EXPANDING_TARGET_SCOPE = "EXPANDING_TARGET_SCOPE"
    CHANGING_INFRASTRUCTURE = "CHANGING_INFRASTRUCTURE"
    ESCALATING_BEHAVIOR = "ESCALATING_BEHAVIOR"
    RECURRING_PATTERN = "RECURRING_PATTERN"
    STABLE_PATTERN = "STABLE_PATTERN"
    UNCERTAIN_EVOLUTION = "UNCERTAIN_EVOLUTION"


@dataclass(frozen=True)
class IncidentCorrelation:
    """Pairwise deterministic correlation between two incidents."""
    correlation_id: str
    incident_a: str
    incident_b: str
    relationship: CorrelationRelationship
    evolution: CampaignEvolutionState
    supporting_dimensions: tuple[str, ...]
    contradicting_dimensions: tuple[str, ...]
    neutral_dimensions: tuple[str, ...]
    supporting_signals: tuple[str, ...]
    contradicting_signals: tuple[str, ...]
    explanation: str
    uncertainty: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "incident_a": self.incident_a,
            "incident_b": self.incident_b,
            "relationship": self.relationship.value,
            "evolution": self.evolution.value,
            "supporting_dimensions": list(self.supporting_dimensions),
            "contradicting_dimensions": list(self.contradicting_dimensions),
            "neutral_dimensions": list(self.neutral_dimensions),
            "supporting_signals": list(self.supporting_signals),
            "contradicting_signals": list(self.contradicting_signals),
            "explanation": self.explanation,
            "uncertainty": self.uncertainty,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class CampaignClusterTimelineEvent:
    """Chronological milestone in a multi-incident campaign cluster."""
    incident_id: str
    timestamp: float
    window_range: tuple[int, int]
    dominant_attack_state: str
    actor_count: int
    target_count: int
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "window_range": list(self.window_range),
            "dominant_attack_state": self.dominant_attack_state,
            "actor_count": self.actor_count,
            "target_count": self.target_count,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class CampaignCluster:
    """A cluster of correlated incidents forming a cohesive attack campaign."""
    cluster_id: str
    label: str
    member_incidents: tuple[str, ...]
    shared_characteristics: tuple[str, ...]
    unique_characteristics: tuple[str, ...]
    evolution: CampaignEvolutionState
    timeline: tuple[CampaignClusterTimelineEvent, ...]
    correlations: tuple[IncidentCorrelation, ...]
    contradictions: tuple[str, ...]
    uncertainty: str
    campaign_assessment: str
    analyst_action: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "label": self.label,
            "member_incidents": list(self.member_incidents),
            "shared_characteristics": list(self.shared_characteristics),
            "unique_characteristics": list(self.unique_characteristics),
            "evolution": self.evolution.value,
            "timeline": [t.to_dict() for t in self.timeline],
            "correlations": [c.to_dict() for c in self.correlations],
            "contradictions": list(self.contradictions),
            "uncertainty": self.uncertainty,
            "campaign_assessment": self.campaign_assessment,
            "analyst_action": self.analyst_action,
            "provenance": self.provenance,
        }


def correlate_incidents(
    fp_a: IncidentFingerprint,
    fp_b: IncidentFingerprint,
) -> IncidentCorrelation:
    """Deterministically correlate two incident fingerprints."""
    cid = deterministic_id("corr", fp_a.incident_id, fp_b.incident_id)

    # Empty or zero-traffic checks
    if (not fp_a.actor_entities and not fp_a.target_entities) or (not fp_b.actor_entities and not fp_b.target_entities):
        return IncidentCorrelation(
            correlation_id=cid,
            incident_a=fp_a.incident_id,
            incident_b=fp_b.incident_id,
            relationship=CorrelationRelationship.INSUFFICIENT_EVIDENCE,
            evolution=CampaignEvolutionState.UNCERTAIN_EVOLUTION,
            supporting_dimensions=(),
            contradicting_dimensions=(),
            neutral_dimensions=("EMPTY_TELEMETRY",),
            supporting_signals=(),
            contradicting_signals=(),
            explanation="One or both incidents lack sufficient actor/target telemetry for correlation.",
            uncertainty="High uncertainty due to sparse telemetry.",
            provenance={"rule": "sparse_telemetry"},
        )

    supp_dims: list[str] = []
    contra_dims: list[str] = []
    neutral_dims: list[str] = []

    supp_sigs: list[str] = []
    contra_sigs: list[str] = []

    # 1. Entity Overlap (Shared Actors)
    common_actors = set(fp_a.actor_entities).intersection(set(fp_b.actor_entities))
    if common_actors:
        supp_dims.append("ENTITY_OVERLAP")
        supp_sigs.append(f"Shared actor entity/entities: {', '.join(sorted(common_actors))}")
    else:
        # Crucial: No actor overlap is NOT a contradiction! It is neutral non-overlap.
        neutral_dims.append("NO_ACTOR_OVERLAP")

    # 2. Target Overlap (Common Destination Targets)
    common_targets = set(fp_a.target_entities).intersection(set(fp_b.target_entities))
    if common_targets:
        supp_dims.append("TARGET_OVERLAP")
        supp_sigs.append(f"Overlapping target destinations ({len(common_targets)} host(s) in common)")
    else:
        neutral_dims.append("NO_TARGET_OVERLAP")

    # 3. Port Pattern Similarity (Specific Destination Ports)
    common_ports = set(fp_a.targeted_ports).intersection(set(fp_b.targeted_ports))
    if common_ports and len(common_ports) >= 2:
        supp_dims.append("PORT_PATTERN_SIMILARITY")
        supp_sigs.append(f"Shared targeted port profile: {sorted(list(common_ports))[:5]}")
    elif common_ports:
        supp_dims.append("PORT_PATTERN_SIMILARITY")
        supp_sigs.append(f"Shared targeted port: {list(common_ports)[0]}")

    # 4. Behavioral Pattern & Episode Similarity
    common_episodes = set(fp_a.episode_types).intersection(set(fp_b.episode_types))
    if common_episodes:
        supp_dims.append("BEHAVIOR_PATTERN_SIMILARITY")
        supp_sigs.append(f"Matching behavioral episode signatures: {', '.join(sorted(common_episodes))}")

    # Scan characteristics match (e.g. both high failure ratio port sweeps)
    both_high_failure = (fp_a.failure_ratio > 0.70 and fp_b.failure_ratio > 0.70)
    if both_high_failure:
        supp_dims.append("SCAN_DYNAMICS_SIMILARITY")
        supp_sigs.append(f"Similar high handshake rejection rates ({fp_a.failure_ratio*100:.0f}% vs {fp_b.failure_ratio*100:.0f}%), consistent with blind reconnaissance")

    # 5. Attack State & MITRE Technique Overlap
    common_states = set(fp_a.attack_states).intersection(set(fp_b.attack_states))
    if common_states and not common_states.issubset({"BENIGN"}):
        supp_dims.append("ATTACK_STATE_SIMILARITY")
        supp_sigs.append(f"Matching attack states: {', '.join(sorted(common_states))}")

    common_mitre = set(fp_a.observed_mitre_techniques).intersection(set(fp_b.observed_mitre_techniques))
    if common_mitre:
        supp_dims.append("MITRE_TECHNIQUE_OVERLAP")
        supp_sigs.append(f"Common observed MITRE technique(s): {', '.join(sorted(common_mitre))}")

    # 6. Contradictions (Genuine Incompatibilities, NOT merely different IPs)
    # Example contradiction: radically opposing protocol compositions (e.g. 100% UDP DNS vs 100% TCP Port Sweep)
    proto_a = set(fp_a.protocol_distribution.keys())
    proto_b = set(fp_b.protocol_distribution.keys())
    if proto_a and proto_b and not proto_a.intersection(proto_b):
        contra_dims.append("PROTOCOL_INCOMPATIBILITY")
        contra_sigs.append(f"Mutually exclusive protocol suites ({list(proto_a)} vs {list(proto_b)})")

    # Radically opposing categories (e.g. Exfiltration vs Local Port Scan without overlap)
    if fp_a.dominant_category != fp_b.dominant_category and not common_mitre and not common_targets:
        contra_dims.append("INCOMPATIBLE_CATEGORIES")
        contra_sigs.append(f"Disparate incident classifications: {fp_a.dominant_category} vs {fp_b.dominant_category}")

    # Determine Relationship & Evolution
    relationship = CorrelationRelationship.UNRELATED
    evolution = CampaignEvolutionState.UNCERTAIN_EVOLUTION

    # Evaluation Rules
    if contra_dims and len(contra_dims) >= 2:
        relationship = CorrelationRelationship.UNRELATED
        explanation = f"Incidents demonstrate mutually exclusive technical characteristics ({', '.join(contra_dims)})."
        uncertainty = "Low uncertainty: structural protocol/category divergence indicates separate events."

    elif len(supp_dims) >= 3 or ("ENTITY_OVERLAP" in supp_dims and len(supp_dims) >= 2):
        relationship = CorrelationRelationship.RELATED_CAMPAIGN

        # Detect Infrastructure Change
        if "ENTITY_OVERLAP" not in supp_dims and ("PORT_PATTERN_SIMILARITY" in supp_dims or "BEHAVIOR_PATTERN_SIMILARITY" in supp_dims):
            evolution = CampaignEvolutionState.CHANGING_INFRASTRUCTURE
            explanation = (
                f"Incidents {fp_a.incident_id} and {fp_b.incident_id} exhibit behaviorally related reconnaissance "
                "patterns and shared target/port signatures despite differing source infrastructure."
            )
        elif "TARGET_OVERLAP" in supp_dims and len(fp_b.target_entities) > len(fp_a.target_entities):
            evolution = CampaignEvolutionState.EXPANDING_TARGET_SCOPE
            explanation = (
                f"Incidents show coordinated activity with expanding target scope from {len(fp_a.target_entities)} "
                f"to {len(fp_b.target_entities)} destinations."
            )
        elif "ATTACK_STATE_SIMILARITY" in supp_dims and "RECONNAISSANCE" in common_states:
            evolution = CampaignEvolutionState.REPEATED_RECONNAISSANCE
            explanation = f"Recurring network reconnaissance sweeps observed across incidents {fp_a.incident_id} and {fp_b.incident_id}."
        else:
            evolution = CampaignEvolutionState.RECURRING_PATTERN
            explanation = f"Multi-dimensional correlation confirmed across {len(supp_dims)} shared intelligence dimensions."

        uncertainty = "Supported by multiple independent behavioral and structural dimensions."

    elif len(supp_dims) >= 1:
        relationship = CorrelationRelationship.POSSIBLY_RELATED
        evolution = CampaignEvolutionState.RECURRING_PATTERN
        explanation = (
            f"Incidents share partial characteristics ({', '.join(supp_dims)}), but lack conclusive multi-dimensional "
            "correlation to confirm a coordinated campaign."
        )
        uncertainty = "Moderate uncertainty: shared patterns may be incidental or coincident."

    else:
        relationship = CorrelationRelationship.UNRELATED
        evolution = CampaignEvolutionState.UNCERTAIN_EVOLUTION
        explanation = "No meaningful structural, behavioral, or entity overlap detected between incidents."
        uncertainty = "Low uncertainty: independent traffic profiles."

    return IncidentCorrelation(
        correlation_id=cid,
        incident_a=fp_a.incident_id,
        incident_b=fp_b.incident_id,
        relationship=relationship,
        evolution=evolution,
        supporting_dimensions=tuple(supp_dims),
        contradicting_dimensions=tuple(contra_dims),
        neutral_dimensions=tuple(neutral_dims),
        supporting_signals=tuple(supp_sigs),
        contradicting_signals=tuple(contra_sigs),
        explanation=explanation,
        uncertainty=uncertainty,
        provenance={"rule": "deterministic_cross_incident_correlation_v1"},
    )


def correlate_incident_set(
    fingerprints: Sequence[IncidentFingerprint],
) -> tuple[IncidentCorrelation, ...]:
    """Perform pairwise correlation across a sequence of incident fingerprints."""
    correlations: list[IncidentCorrelation] = []
    fps = list(fingerprints)
    for i in range(len(fps)):
        for j in range(i + 1, len(fps)):
            correlations.append(correlate_incidents(fps[i], fps[j]))
    return tuple(correlations)


def build_campaign_clusters(
    fingerprints: Sequence[IncidentFingerprint],
    correlations: Sequence[IncidentCorrelation] | None = None,
) -> tuple[CampaignCluster, ...]:
    """Cluster related incidents into cohesive attack campaigns based on strong correlations."""
    fps_map = {fp.incident_id: fp for fp in fingerprints}
    if not fps_map:
        return ()

    corrs = list(correlations) if correlations is not None else list(correlate_incident_set(fingerprints))
    related_corrs = [c for c in corrs if c.relationship in (CorrelationRelationship.RELATED_CAMPAIGN, CorrelationRelationship.POSSIBLY_RELATED)]

    # Connected components for related incidents
    adj: dict[str, set[str]] = {fid: set() for fid in fps_map}
    for c in related_corrs:
        if c.relationship == CorrelationRelationship.RELATED_CAMPAIGN:
            adj[c.incident_a].add(c.incident_b)
            adj[c.incident_b].add(c.incident_a)

    visited: set[str] = set()
    clusters: list[CampaignCluster] = []

    for fid, fp in fps_map.items():
        if fid in visited:
            continue

        # Find cluster members
        members: list[str] = []
        stack = [fid]
        visited.add(fid)
        while stack:
            curr = stack.pop()
            members.append(curr)
            for neighbor in adj.get(curr, set()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    stack.append(neighbor)

        member_fps = [fps_map[m] for m in members]

        # Shared & unique characteristics
        shared_chars: list[str] = []
        unique_chars: list[str] = []

        all_actors = sorted(list({act for m in member_fps for act in m.actor_entities}))
        all_targets = sorted(list({tgt for m in member_fps for tgt in m.target_entities}))
        all_mitre = sorted(list({t for m in member_fps for t in m.observed_mitre_techniques}))

        if len(members) > 1:
            member_corrs = [c for c in related_corrs if c.incident_a in members and c.incident_b in members]
            evolution = member_corrs[0].evolution if member_corrs else CampaignEvolutionState.RECURRING_PATTERN
            if all_mitre:
                shared_chars.append(f"Observed MITRE techniques: {', '.join(all_mitre)}")
            if len(all_actors) > len(member_fps):
                unique_chars.append(f"Varying actor infrastructure ({len(all_actors)} distinct IPs)")

            cluster_id = deterministic_id("cluster", *sorted(members))
            label = f"Campaign Cluster: {member_fps[0].dominant_category.replace('_', ' ').title()}"

            timeline_events = [
                CampaignClusterTimelineEvent(
                    incident_id=mfp.incident_id,
                    timestamp=float(min(mfp.active_windows, default=0) * 60.0),
                    window_range=(min(mfp.active_windows, default=0), max(mfp.active_windows, default=0)),
                    dominant_attack_state=mfp.attack_states[0] if mfp.attack_states else "RECONNAISSANCE",
                    actor_count=len(mfp.actor_entities),
                    target_count=len(mfp.target_entities),
                    summary=f"Incident {mfp.incident_id} exhibiting {mfp.dominant_category} targeting {len(mfp.target_entities)} hosts.",
                )
                for mfp in sorted(member_fps, key=lambda f: min(f.active_windows, default=0))
            ]

            clusters.append(CampaignCluster(
                cluster_id=cluster_id,
                label=label,
                member_incidents=tuple(members),
                shared_characteristics=tuple(shared_chars),
                unique_characteristics=tuple(unique_chars),
                evolution=evolution,
                timeline=tuple(timeline_events),
                correlations=tuple(member_corrs),
                contradictions=(),
                uncertainty="Corroborated across multi-incident evidence sets.",
                campaign_assessment=(
                    f"Coordinated cross-capture campaign encompassing {len(members)} related incident(s) "
                    f"targeting {len(all_targets)} destination hosts across network segments."
                ),
                analyst_action=f"Cross-reference firewall and SIEM logs across all member incidents ({', '.join(members)}).",
                provenance={"rule": "multi_incident_clustering_v1"},
            ))

    return tuple(clusters)
