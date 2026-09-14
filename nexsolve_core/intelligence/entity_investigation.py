"""Deterministic Entity Investigation Engine for NexSolve.

Assembles the full multi-dimensional investigation context for a given entity:
- Subject identification & roles
- Concrete findings & evidence
- Chronological timeline (OBSERVED vs FORECAST)
- Multi-dimensional cross-entity relationships
- Contradiction & counter-evidence analysis
- Explainable risk & prioritization breakdown
- Recommended action and provenance
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id
from nexsolve_core.intelligence.contradictions import detect_contradictions
from nexsolve_core.intelligence.entity_relationships import discover_entity_relationships
from nexsolve_core.intelligence.prioritization import decompose_threat_risk
from nexsolve_core.intelligence.timeline import build_entity_timeline
from nexsolve_core.investigation_model import (
    InvestigationContext,
    InvestigationFinding,
    InvestigationSubject,
    InvestigationSubjectType,
)


def investigate_entity(
    entity: str,
    entity_profiles: Mapping[str, Any] | None = None,
    attack_kinematics: Mapping[str, Any] | None = None,
    change_signals: Sequence[Any] | None = None,
    baseline_deviations: Sequence[Any] | None = None,
    episodes: Sequence[Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    beaconing_signals: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
    progression_forecast: Any = None,
    window_count: int = 1,
) -> InvestigationContext:
    """Deterministically compile a complete investigation dossier for an entity."""
    profiles = entity_profiles or {}
    kinematics = attack_kinematics or {}
    cmps = campaigns or []
    pats = patterns or []
    findings_raw = observed_findings or []

    prof = profiles.get(entity)
    traj = kinematics.get(entity)
    curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
    curr_state_val = getattr(curr_state, "value", str(curr_state))

    # Associated campaigns & patterns
    ent_cmps = [c for c in cmps if entity in getattr(c, "primary_entities", ()) or entity in getattr(c, "target_entities", ())]
    ent_cmp_ids = [getattr(c, "campaign_id", "cmp") for c in ent_cmps]
    ent_pats = [p for p in pats if entity in getattr(p, "primary_entities", ()) or entity in getattr(p, "target_entities", ())]
    ent_pat_ids = [getattr(p, "pattern_id", "pat") for p in ent_pats]

    # Decompose risk
    risk_breakdown = decompose_threat_risk(
        entity=entity,
        entity_profiles=profiles,
        attack_kinematics=kinematics,
        campaigns=cmps,
        change_signals=change_signals,
    )

    # Subject
    roles = tuple(getattr(prof, "roles", ("UNKNOWN",))) if prof else ("UNKNOWN",)
    first_seen = getattr(prof, "first_seen_window", 0) * 60.0 if prof else None
    last_seen = getattr(prof, "last_seen_window", 0) * 60.0 if prof else None
    active_windows = tuple(getattr(prof, "active_windows", (0,))) if prof else (0,)

    summary = (
        f"Entity {entity} evaluated at priority {risk_breakdown.priority_level.value} (Score: {risk_breakdown.final_score}). "
        f"Attack State: {curr_state_val}. Primary Roles: {', '.join(roles)}."
    )

    subject = InvestigationSubject(
        subject_id=deterministic_id("subj", entity),
        subject_type=InvestigationSubjectType.ENTITY,
        label=entity,
        first_seen=first_seen,
        last_seen=last_seen,
        active_windows=active_windows,
        primary_roles=roles,
        inferred_attack_state=curr_state_val,
        current_priority=risk_breakdown.priority_level.value,
        associated_campaign_ids=tuple(ent_cmp_ids),
        associated_pattern_ids=tuple(ent_pat_ids),
        summary=summary,
        provenance={"engine": "investigation_subject_v1"},
    )


    # Findings
    structured_findings: list[InvestigationFinding] = []
    for f in findings_raw:
        if str(f.get("source_ip")) == entity or str(f.get("destination_ip")) == entity:
            fid = str(f.get("finding_id") or deterministic_id("find", entity, f.get("window_index", 0)))
            w = int(f.get("window_index") or 0)
            structured_findings.append(InvestigationFinding(
                finding_id=fid,
                title=str(f.get("attack_category") or "Suspicious Activity"),
                category=str(f.get("attack_category") or "Anomaly"),
                severity=str(f.get("severity") or "MEDIUM").upper(),
                window_index=w,
                timestamp=f.get("timestamp") or (w * 60.0),
                observed_or_forecast="OBSERVED",
                description=str(f.get("explanation") or f"Finding observed in window {w}."),
                supporting_evidence_keys=(fid,),
                provenance=dict(f),
            ))

    # Add kinematic transition findings if present
    if traj and hasattr(traj, "transitions"):
        for trans in traj.transitions:
            tid = deterministic_id("find_trans", entity, getattr(trans, "window_after", 0))
            structured_findings.append(InvestigationFinding(
                finding_id=tid,
                title=f"Kinematic State Transition -> {getattr(trans, 'to_state', '')}",
                category="ATTACK_KINEMATICS",
                severity="HIGH",
                window_index=getattr(trans, "window_after", 0),
                timestamp=float(getattr(trans, "window_after", 0) * 60.0),
                observed_or_forecast="OBSERVED",
                description=getattr(trans, "explanation", "Kinematic state progression detected."),
                supporting_evidence_keys=tuple(getattr(trans, "supporting_evidence_ids", ())),
                provenance=getattr(trans, "provenance", {}),
            ))


    # Timeline
    timeline_events = build_entity_timeline(
        entity=entity,
        entity_profile=prof,
        attack_kinematics=kinematics,
        change_signals=change_signals,
        baseline_deviations=baseline_deviations,
        episodes=episodes,
        campaigns=cmps,
        patterns=pats,
        observed_findings=findings_raw,
        forecast_points=forecast_points,
        progression_forecast=progression_forecast,
    )

    # Relationships
    relationships = discover_entity_relationships(
        entity=entity,
        tcp_sessions=tcp_sessions,
        patterns=pats,
        campaigns=cmps,
        beaconing_signals=beaconing_signals,
        entity_profiles=profiles,
    )

    # Contradictions
    contradictions = detect_contradictions(
        entity=entity,
        entity_profile=prof,
        attack_kinematics=kinematics,
        beaconing_signals=beaconing_signals,
        observed_findings=findings_raw,
        forecast_points=forecast_points,
        window_count=window_count,
    )
    contra_strings = tuple(f"{c.claim}: {c.contradicting_observation}" for c in contradictions)

    # Forecast summary
    fc_summary: str | None = None
    if forecast_points:
        fc_summary = f"Recursive 45-feature world model rollout across horizons K=1..{len(forecast_points)}m. Empirical persistence preserved."

    iid = deterministic_id("inv", entity, risk_breakdown.priority_level.value)
    return InvestigationContext(
        investigation_id=iid,
        subject=subject,
        findings=tuple(structured_findings),
        timeline=timeline_events,
        relationships=relationships,
        contradictions=contra_strings,
        mitigating_factors=risk_breakdown.mitigating_factors,
        forecast_context_summary=fc_summary,
        recommended_action=risk_breakdown.recommended_action,
        provenance={"risk_breakdown": risk_breakdown.to_dict()},
    )

