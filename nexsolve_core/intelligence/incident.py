"""Deterministic Incident-Level Investigation Aggregation Engine for NexSolve.

Aggregates related:
- Entities
- Episodes
- Patterns
- Campaigns
- Attack states & transitions
- Observed MITRE techniques
- Contradictions
- Explainable risk breakdown
- Recommended response actions

Produces a coherent security incident investigation dossier, distinct from a generic alert.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id
from nexsolve_core.intelligence.mitigation import (
    MitigationRecommendation,
    generate_mitigation_recommendations,
)
from nexsolve_core.intelligence.prioritization import ThreatPriorityLevel, ThreatRiskBreakdown
from nexsolve_core.investigation_model import (
    InvestigationContext,
    InvestigationTimelineEvent,
)


@dataclass(frozen=True)
class IncidentInvestigation:
    """An end-to-end aggregated security incident dossier."""
    incident_id: str
    headline: str
    summary: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    first_seen: float | None
    last_seen: float | None
    duration_seconds: float
    primary_entities: tuple[str, ...]
    target_entities: tuple[str, ...]
    targeted_ports: tuple[int, ...]
    associated_campaign_ids: tuple[str, ...]
    associated_pattern_ids: tuple[str, ...]
    attack_states: tuple[str, ...]
    observed_mitre_techniques: tuple[str, ...]
    timeline: tuple[InvestigationTimelineEvent, ...]
    contradictions: tuple[str, ...]
    mitigating_factors: tuple[str, ...]
    risk_breakdown: ThreatRiskBreakdown | None
    recommended_actions: tuple[MitigationRecommendation, ...]
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "headline": self.headline,
            "summary": self.summary,
            "severity": self.severity,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
            "primary_entities": list(self.primary_entities),
            "target_entities": list(self.target_entities),
            "targeted_ports": list(self.targeted_ports),
            "associated_campaign_ids": list(self.associated_campaign_ids),
            "associated_pattern_ids": list(self.associated_pattern_ids),
            "attack_states": list(self.attack_states),
            "observed_mitre_techniques": list(self.observed_mitre_techniques),
            "timeline": [t.to_dict() for t in self.timeline],
            "contradictions": list(self.contradictions),
            "mitigating_factors": list(self.mitigating_factors),
            "risk_breakdown": self.risk_breakdown.to_dict() if self.risk_breakdown else None,
            "recommended_actions": [a.to_dict() for a in self.recommended_actions],
            "provenance": self.provenance,
        }


def build_incident_investigation(
    primary_entity: str,
    entity_investigation: InvestigationContext,
    entity_profiles: Mapping[str, Any] | None = None,
    attack_kinematics: Mapping[str, Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    beaconing_signals: Sequence[Any] | None = None,
    risk_breakdown: ThreatRiskBreakdown | None = None,
    window_count: int = 1,
) -> IncidentInvestigation:
    """Deterministically aggregate an entity's investigation context into an incident dossier."""
    subj = entity_investigation.subject
    cmps = campaigns or []
    pats = patterns or []
    profiles = entity_profiles or {}

    # Target entities and ports from patterns and campaigns
    target_ents: set[str] = set()
    ports: set[int] = set()
    states: set[str] = set()
    techniques: set[str] = set()

    for p in pats:
        if primary_entity in getattr(p, "primary_entities", ()):
            target_ents.update(getattr(p, "target_entities", ()))
            ports.update(getattr(p, "targeted_ports", ()))
            techniques.update(getattr(p, "mitre_techniques", ()))

    for c in cmps:
        if primary_entity in getattr(c, "primary_entities", ()):
            target_ents.update(getattr(c, "target_entities", ()))
            ports.update(getattr(c, "targeted_ports", ()))
            states.update(getattr(c, "attack_states", ()))
            techniques.update(getattr(c, "mitre_techniques", ()))

    if subj.inferred_attack_state:
        states.add(subj.inferred_attack_state)

    # Mitigation recommendations
    recs = generate_mitigation_recommendations(
        entity=primary_entity,
        entity_profile=profiles.get(primary_entity),
        attack_kinematics=attack_kinematics,
        campaigns=cmps,
        beaconing_signals=beaconing_signals,
        window_count=window_count,
    )

    t_first = subj.first_seen
    t_last = subj.last_seen
    dur = (t_last - t_first) if (t_last is not None and t_first is not None and t_last >= t_first) else 0.0

    sev = subj.current_priority.replace("P1_", "").replace("P2_", "").replace("P3_", "").replace("P4_", "").replace("P5_", "")
    if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        sev = "MEDIUM"

    headline = f"Security Incident [{subj.current_priority}]: {primary_entity} ({subj.inferred_attack_state})"
    summary = (
        f"Incident encompassing entity {primary_entity} exhibiting {subj.inferred_attack_state} state across "
        f"{len(subj.active_windows)} window(s). Targets {len(target_ents)} host(s) across {len(ports)} port(s). "
        f"Correlated into {len(subj.associated_campaign_ids)} campaign(s) and {len(subj.associated_pattern_ids)} pattern(s)."
    )

    iid = deterministic_id("inc", primary_entity, subj.current_priority)
    return IncidentInvestigation(
        incident_id=iid,
        headline=headline,
        summary=summary,
        severity=sev,
        first_seen=t_first,
        last_seen=t_last,
        duration_seconds=round(dur, 2),
        primary_entities=(primary_entity,),
        target_entities=tuple(sorted(target_ents)),
        targeted_ports=tuple(sorted(ports)),
        associated_campaign_ids=subj.associated_campaign_ids,
        associated_pattern_ids=subj.associated_pattern_ids,
        attack_states=tuple(sorted(states)),
        observed_mitre_techniques=tuple(sorted(techniques)),
        timeline=entity_investigation.timeline,
        contradictions=entity_investigation.contradictions,
        mitigating_factors=entity_investigation.mitigating_factors,
        risk_breakdown=risk_breakdown,
        recommended_actions=recs,
        provenance={"engine": "incident_investigation_v1"},
    )
