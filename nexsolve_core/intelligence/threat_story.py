"""Threat Story / Attack Narrative Engine.

Generates deterministic, evidence-backed narrative investigation stories:
- Reconstructs chronological behavioral evolution:
  Initial behavior → Behavior changes → Reconnaissance/Scans → Target expansion → Attack state → Forecast horizon
- Explicitly tracks supporting evidence, contradicting indicators, and model uncertainty
- Zero LLM dependency: Uses strictly deterministic structured composition
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


@dataclass(frozen=True)
class NarrativeStage:
    """A distinct milestone in the machine-generated investigation narrative."""
    stage_title: str
    window_index: int
    narrative_text: str
    evidence_ids: tuple[str, ...]
    is_contradiction: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage_title": self.stage_title,
            "window_index": self.window_index,
            "narrative_text": self.narrative_text,
            "evidence_ids": list(self.evidence_ids),
            "is_contradiction": self.is_contradiction,
        }


@dataclass(frozen=True)
class ThreatStory:
    """Consolidated human-readable investigation narrative for a primary entity."""
    story_id: str
    entity: str
    headline: str
    threat_verdict: str  # "BENIGN", "SUSPICIOUS", "CONFIRMED_THREAT", "ABSTAINED"
    initial_behavior: str
    behavior_changes: tuple[str, ...]
    attack_progression: str
    current_assessment: str
    forecast_projection: str
    stages: tuple[NarrativeStage, ...]
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    uncertainties: tuple[str, ...]
    full_narrative_text: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "story_id": self.story_id,
            "entity": self.entity,
            "headline": self.headline,
            "threat_verdict": self.threat_verdict,
            "initial_behavior": self.initial_behavior,
            "behavior_changes": list(self.behavior_changes),
            "attack_progression": self.attack_progression,
            "current_assessment": self.current_assessment,
            "forecast_projection": self.forecast_projection,
            "stages": [s.to_dict() for s in self.stages],
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "uncertainties": list(self.uncertainties),
            "full_narrative_text": self.full_narrative_text,
            "provenance": self.provenance,
        }


def generate_threat_stories(
    entity_profiles: Mapping[str, Any] | None = None,
    attack_kinematics: Mapping[str, Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    change_signals: Sequence[Any] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
    progression_forecast: Any = None,
) -> tuple[ThreatStory, ...]:
    """Deterministically compose structured attack narrative stories for all evaluated entities."""
    stories: list[ThreatStory] = []
    profiles = entity_profiles or {}
    kinematics = attack_kinematics or {}
    cmps = campaigns or []
    pats = patterns or []
    changes = change_signals or []

    changes_by_entity: dict[str, list[Any]] = defaultdict(list)
    for c in changes:
        ent_name = getattr(c, "entity", "")
        if ent_name:
            changes_by_entity[str(ent_name)].append(c)

    patterns_by_entity: dict[str, list[Any]] = defaultdict(list)
    for p in pats:
        for pe in getattr(p, "primary_entities", ()):
            patterns_by_entity[str(pe)].append(p)

    # Process all entities with behavioral profiles
    for ent, prof in profiles.items():
        # Check if entity exhibits non-trivial security behavior
        roles = set(getattr(prof, "roles", ()))
        is_scanner = any("SCANNER" in str(r) for r in roles)
        is_beacon = any("BEACON" in str(r) for r in roles)
        is_high_vol = any("HIGH_VOLUME" in str(r) for r in roles)
        has_episodes = bool(getattr(prof, "associated_episodes", ()))

        traj = kinematics.get(ent)
        curr_kin_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
        curr_state_val = getattr(curr_kin_state, "value", str(curr_kin_state))

        stages: list[NarrativeStage] = []
        change_texts: list[str] = []
        supporting: list[str] = []
        contradicting: list[str] = []
        uncertainties: list[str] = []

        # 1. Initial Behavior Stage
        init_w = getattr(prof, "first_seen_window", 0)
        init_text = (
            f"Entity {ent} first observed in window {init_w} with {getattr(prof, 'connection_attempts', 0)} "
            f"connection attempt(s) across {getattr(prof, 'peer_count', 0)} peer(s)."
        )
        stages.append(NarrativeStage("Initial Observation", init_w, init_text, (f"win_{init_w}",)))

        # 2. Behavior Change Signals
        ent_changes = changes_by_entity.get(ent, [])
        for c in ent_changes:
            desc = getattr(c, "description", "Significant behavioral shift observed.")
            w_after = getattr(c, "window_after", 0)
            change_texts.append(desc)
            supporting.append(f"Change: {getattr(c, 'change_type', 'CHANGE')}")
            stages.append(NarrativeStage("Behavioral Change", w_after, desc, (getattr(c, "change_id", "chg"),)))

        # 3. Kinematic Progression
        if traj and traj.transitions:
            for t in traj.transitions:
                t_expl = getattr(t, "explanation", "")
                t_w = getattr(t, "window_after", 0)
                stages.append(NarrativeStage("Kinematic Transition", t_w, t_expl, tuple(getattr(t, "supporting_evidence_ids", ()))))
                supporting.extend(getattr(t, "supporting_evidence_ids", ()))

        # 4. Multi-Entity Pattern Alignment
        ent_patterns = patterns_by_entity.get(ent, [])
        for p in ent_patterns:
            p_desc = getattr(p, "explanation", "")
            stages.append(NarrativeStage("Attack Pattern Manifestation", getattr(p, "time_window_range", (0, 0))[0], p_desc, (getattr(p, "pattern_id", "pat"),)))
            supporting.append(f"Pattern: {getattr(p, 'pattern_type', 'PATTERN')}")

        # 5. Check Contradictions
        # Legitimate established sessions or benign protocol patterns contradict malicious claims
        if getattr(prof, "successful_sessions", 0) > 20 and getattr(prof, "failure_ratio", 0) < 0.05:
            contra_text = f"Entity has high ratio of clean established sessions ({getattr(prof, 'successful_sessions', 0)}) with <5% failures, suggesting benign infrastructure."
            contradicting.append(contra_text)
            stages.append(NarrativeStage("Contradicting Evidence", init_w, contra_text, ("clean_sessions_baseline",), is_contradiction=True))

        # 6. Forecast Horizon Projection
        fc_type = getattr(progression_forecast, "prediction_type", "STATE_PERSISTENCE") if progression_forecast else "STATE_PERSISTENCE"
        fc_expl = getattr(progression_forecast, "explanation", "Empirical temporal persistence supported across evaluated horizon.") if progression_forecast else "Forecast state persistence."
        if curr_state_val in ("RECONNAISSANCE", "DISCOVERY", "IMPACT"):
            fc_proj = f"Empirical forecasting projects {fc_type} at horizon K=1..5m. {fc_expl}"
        else:
            fc_proj = "No active attack escalation projected beyond baseline persistence."

        # Verdict and Headline
        if curr_state_val in ("IMPACT", "COMMAND_AND_CONTROL"):
            verdict = "CONFIRMED_THREAT"
            headline = f"High-Severity {curr_state_val} Campaign Involving {ent}"
        elif curr_state_val in ("RECONNAISSANCE", "TARGETING", "DISCOVERY") or is_scanner or ent_changes:
            verdict = "SUSPICIOUS"
            headline = f"Active Reconnaissance and Scanning Activity by {ent}"
        else:
            verdict = "BENIGN"
            headline = f"Baseline Network Traffic for {ent}"

        # Uncertainty handling
        if not ent_changes and not ent_patterns and not has_episodes:
            uncertainties.append("Limited historical context; single observation window without established baseline.")

        # Full narrative text
        full_text = (
            f"THREAT INVESTIGATION STORY: {headline}\n"
            f"Entity: {ent} | Verdict: {verdict} | Current State: {curr_state_val}\n\n"
            f"1. Initial Behavior:\n   {init_text}\n\n"
            f"2. Observed Changes:\n   " + ("\n   ".join(change_texts) if change_texts else "No abrupt window deltas detected.") + "\n\n"
            f"3. Attack Progression:\n   " + (f"Progressed to {curr_state_val} supported by {len(supporting)} evidence point(s)." if supporting else "Remained within baseline parameters.") + "\n\n"
            f"4. Forecast Horizon:\n   {fc_proj}\n\n"
            f"5. Contradictions & Mitigations:\n   " + ("\n   ".join(contradicting) if contradicting else "No contradictory benign telemetry identified.")
        )

        sid = deterministic_id("story", ent, curr_state_val, len(stages))
        stories.append(ThreatStory(
            story_id=sid,
            entity=ent,
            headline=headline,
            threat_verdict=verdict,
            initial_behavior=init_text,
            behavior_changes=tuple(change_texts),
            attack_progression=f"Current State: {curr_state_val}",
            current_assessment=f"Assessed as {verdict} with {len(stages)} chronological stages.",
            forecast_projection=fc_proj,
            stages=tuple(stages),
            supporting_evidence=tuple(sorted(set(supporting))),
            contradicting_evidence=tuple(contradicting),
            uncertainties=tuple(uncertainties),
            full_narrative_text=full_text,
            provenance={"rule": "deterministic_narrative_synthesis_v1"},
        ))

    return tuple(stories)
