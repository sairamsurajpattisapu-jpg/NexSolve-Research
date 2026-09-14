"""Chronological Investigation Timeline Engine for NexSolve.

Normalizes multi-modal observations into a strictly ordered chronological sequence:
- FIRST_SEEN
- TRAFFIC_START
- BEHAVIOR_CHANGE
- BASELINE_DEVIATION
- ANOMALY
- PATTERN_START
- EPISODE_START
- ATTACK_STATE_CHANGE
- KINEMATIC_TRANSITION
- CAMPAIGN_JOIN
- OBSERVED_TECHNIQUE
- FORECAST_GENERATED
- FORECAST_ABSTAINED

Strictly isolates OBSERVED vs FORECAST events. Preserves provenance and timestamps.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id
from nexsolve_core.investigation_model import InvestigationTimelineEvent


def build_entity_timeline(
    entity: str,
    entity_profile: Any = None,
    attack_kinematics: Any = None,
    change_signals: Sequence[Any] | None = None,
    baseline_deviations: Sequence[Any] | None = None,
    episodes: Sequence[Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
    progression_forecast: Any = None,
) -> tuple[InvestigationTimelineEvent, ...]:
    """Compile a complete, chronologically sorted timeline of events for an entity."""
    events: list[InvestigationTimelineEvent] = []
    findings = observed_findings or []
    changes = change_signals or []
    deviations = baseline_deviations or []
    eps = episodes or []
    cmps = campaigns or []
    pats = patterns or []

    # 1. FIRST_SEEN / TRAFFIC_START
    if entity_profile:
        first_w = getattr(entity_profile, "first_seen_window", 0)
        t_first = float(first_w * 60.0)
        eid = deterministic_id("tl_ev", entity, "FIRST_SEEN", first_w)
        events.append(InvestigationTimelineEvent(
            event_id=eid,
            timestamp=t_first,
            window_index=first_w,
            event_type="FIRST_SEEN",
            entity=entity,
            headline=f"Initial Traffic Observed for {entity}",
            details=f"Entity first identified in capture with {getattr(entity_profile, 'connection_attempts', 0)} initial connection attempts.",
            severity="INFO",
            observed_or_forecast="OBSERVED",
            source_modality="CANONICAL_FLOW",
            supporting_evidence_keys=(f"win_{first_w}",),
            provenance={"stage": "entity_tracking"},
        ))

    # 2. BEHAVIOR_CHANGES
    for c in changes:
        if getattr(c, "entity", "") == entity:
            w_after = getattr(c, "window_after", 0)
            t_event = float(w_after * 60.0)
            eid = deterministic_id("tl_ev", entity, "BEHAVIOR_CHANGE", w_after, getattr(c, "change_type", ""))
            events.append(InvestigationTimelineEvent(
                event_id=eid,
                timestamp=t_event,
                window_index=w_after,
                event_type="BEHAVIOR_CHANGE",
                entity=entity,
                headline=f"Behavior Shift: {getattr(c, 'change_type', 'CHANGE')}",
                details=getattr(c, "description", "Abrupt change in network kinematics observed."),
                severity="HIGH" if "FANOUT" in str(getattr(c, "change_type", "")) else "MEDIUM",
                observed_or_forecast="OBSERVED",
                source_modality="CHANGE_DETECTION",
                supporting_evidence_keys=(getattr(c, "change_id", "chg"),),
                provenance=getattr(c, "provenance", {}),
            ))

    # 3. BASELINE_DEVIATIONS
    for dev in deviations:
        if getattr(dev, "entity", "") == entity:
            w = getattr(dev, "window_index", 0)
            t_event = float(w * 60.0)
            eid = deterministic_id("tl_ev", entity, "BASELINE_DEVIATION", w, getattr(dev, "metric_name", ""))
            events.append(InvestigationTimelineEvent(
                event_id=eid,
                timestamp=t_event,
                window_index=w,
                event_type="BASELINE_DEVIATION",
                entity=entity,
                headline=f"Baseline Deviation: {getattr(dev, 'metric_name', 'metric')}",
                details=getattr(dev, "explanation", "Statistically significant surge away from local baseline."),
                severity="HIGH" if getattr(dev, "z_score", 0) > 3.0 else "MEDIUM",
                observed_or_forecast="OBSERVED",
                source_modality="TEMPORAL_BASELINE",
                supporting_evidence_keys=(getattr(dev, "deviation_id", "dev"),),
                provenance=getattr(dev, "provenance", {}),
            ))

    # 4. FINDINGS / ANOMALIES
    for f in findings:
        if str(f.get("source_ip")) == entity or str(f.get("destination_ip")) == entity:
            w = int(f.get("window_index") or 0)
            t_event = float(f.get("timestamp") or (w * 60.0))
            cat = str(f.get("attack_category", "Anomaly"))
            eid = deterministic_id("tl_ev", entity, "ANOMALY", w, cat)
            events.append(InvestigationTimelineEvent(
                event_id=eid,
                timestamp=t_event,
                window_index=w,
                event_type="ANOMALY",
                entity=entity,
                headline=f"Security Anomaly: {cat}",
                details=f"Detection heuristic identified {cat} involving {entity}.",
                severity=str(f.get("severity", "MEDIUM")).upper(),
                observed_or_forecast="OBSERVED",
                source_modality="ML_DETECTION",
                supporting_evidence_keys=(str(f.get("finding_id", "find")),),
                provenance=dict(f),
            ))

    # 5. KINEMATIC_TRANSITIONS
    if attack_kinematics:
        traj = attack_kinematics.get(entity) if isinstance(attack_kinematics, dict) else attack_kinematics
        if traj and hasattr(traj, "transitions"):
            for trans in traj.transitions:
                w2 = getattr(trans, "window_after", 0)
                t_event = float(w2 * 60.0)
                eid = deterministic_id("tl_ev", entity, "KINEMATIC_TRANSITION", w2, getattr(trans, "to_state", ""))
                events.append(InvestigationTimelineEvent(
                    event_id=eid,
                    timestamp=t_event,
                    window_index=w2,
                    event_type="KINEMATIC_TRANSITION",
                    entity=entity,
                    headline=f"Kinematic State: {getattr(trans, 'to_state', 'STATE')}",
                    details=getattr(trans, "explanation", f"Transitioned to {getattr(trans, 'to_state', '')}."),
                    severity="CRITICAL" if getattr(trans, "to_state", "") in ("IMPACT", "COMMAND_AND_CONTROL") else "HIGH",
                    observed_or_forecast="OBSERVED",
                    source_modality="ATTACK_KINEMATICS",
                    supporting_evidence_keys=tuple(getattr(trans, "supporting_evidence_ids", ())),
                    provenance=getattr(trans, "provenance", {}),
                ))

    # 6. PATTERN_START
    for pat in pats:
        if entity in getattr(pat, "primary_entities", ()) or entity in getattr(pat, "target_entities", ()):
            w = getattr(pat, "time_window_range", (0, 0))[0]
            t_event = float(w * 60.0)
            eid = deterministic_id("tl_ev", entity, "PATTERN_START", w, getattr(pat, "pattern_type", ""))
            events.append(InvestigationTimelineEvent(
                event_id=eid,
                timestamp=t_event,
                window_index=w,
                event_type="PATTERN_START",
                entity=entity,
                headline=f"Attack Pattern: {getattr(pat, 'pattern_type', 'PATTERN')}",
                details=getattr(pat, "explanation", "Multi-entity pattern activity manifested."),
                severity=getattr(pat, "severity", "HIGH"),
                observed_or_forecast="OBSERVED",
                source_modality="PATTERN_ENGINE",
                supporting_evidence_keys=(getattr(pat, "pattern_id", "pat"),),
                provenance=getattr(pat, "provenance", {}),
            ))

    # 7. CAMPAIGN_JOIN
    for cmp in cmps:
        if entity in getattr(cmp, "primary_entities", ()) or entity in getattr(cmp, "target_entities", ()):
            w = getattr(cmp, "start_window", 0)
            t_event = float(w * 60.0)
            eid = deterministic_id("tl_ev", entity, "CAMPAIGN_JOIN", w, getattr(cmp, "campaign_id", ""))
            events.append(InvestigationTimelineEvent(
                event_id=eid,
                timestamp=t_event,
                window_index=w,
                event_type="CAMPAIGN_JOIN",
                entity=entity,
                headline=f"Correlated into Campaign: {getattr(cmp, 'title', 'Campaign')}",
                details=getattr(cmp, "explanation", "Associated with multi-episode attack campaign."),
                severity=getattr(cmp, "severity", "HIGH"),
                observed_or_forecast="OBSERVED",
                source_modality="CAMPAIGN_ENGINE",
                supporting_evidence_keys=(getattr(cmp, "campaign_id", "cmp"),),
                provenance=getattr(cmp, "provenance", {}),
            ))

    # 8. FORECAST EVENTS (Strictly FORECAST scope, timestamped in future windows)
    last_obs_w = max((ev.window_index for ev in events), default=0)
    if forecast_points:
        for pt in forecast_points:
            h = int(pt.get("horizon", 1))
            fc_w = last_obs_w + h
            t_fc = float(fc_w * 60.0)
            prob = pt.get("attackProbability")
            prob_str = f"({prob * 100:.1f}%)" if prob is not None else ""
            eid = deterministic_id("tl_ev", entity, "FORECAST", fc_w, h)
            events.append(InvestigationTimelineEvent(
                event_id=eid,
                timestamp=t_fc,
                window_index=fc_w,
                event_type="FORECAST_GENERATED",
                entity=entity,
                headline=f"Forecast Horizon K={h}m Projection {prob_str}",
                details=f"Model rollouts project empirical state persistence across horizon K={h}m.",
                severity="INFO",
                observed_or_forecast="FORECAST",
                source_modality="NUMPY_WORLD_MODEL_45",
                supporting_evidence_keys=(f"fc_k{h}",),
                provenance={"horizon": h, "scope": "FORECAST"},
            ))

    # 9. Deterministic chronological sort by timestamp ASC, then event_id
    events.sort(key=lambda x: (x.timestamp, x.event_id))
    return tuple(events)
