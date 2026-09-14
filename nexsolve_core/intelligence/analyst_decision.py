"""Security Analyst Decision Engine for NexSolve.

Ranks concrete investigation opportunities:
- INVESTIGATE_ENTITY: Drill down into primary actor or critical target
- INVESTIGATE_CAMPAIGN: Adjudicate multi-host coordinated aggression
- INVESTIGATE_INCIDENT: Review consolidated security incident dossier
- INVESTIGATE_PATTERN: Trace multi-entity scan or volumetric distribution
- INVESTIGATE_BEHAVIOR_CHANGE: Analyze sudden fan-out or connection surges
- REVIEW_FORECAST: Inspect empirical persistence rollouts
- REVIEW_CONTRADICTION: Reconcile evidence that actively weakens attack claim
- COLLECT_MORE_TELEMETRY: Extend temporal observation window

Builds transparent, explainable decision priorities (P0_CRITICAL .. P3_LOW, INFORMATIONAL)
grounded in actual network evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id
from nexsolve_core.intelligence.false_positive import (
    BenignHypothesis,
    evaluate_benign_hypotheses,
)
from nexsolve_core.intelligence.investigation_value import (
    InvestigationValueReport,
    compute_investigation_value,
)
from nexsolve_core.intelligence.questions import (
    InvestigationQuestion,
    generate_analyst_questions,
)
from nexsolve_core.intelligence.threat_differentiation import (
    EvidenceGroundingState,
    ThreatDifferentiationResult,
    ThreatSemanticTier,
    differentiate_threat,
)
from nexsolve_core.intelligence.what_changed import (
    WhatChangedItem,
    build_what_changed,
)


class AnalystDecisionType(str, Enum):
    INVESTIGATE_ENTITY = "INVESTIGATE_ENTITY"
    INVESTIGATE_CAMPAIGN = "INVESTIGATE_CAMPAIGN"
    INVESTIGATE_INCIDENT = "INVESTIGATE_INCIDENT"
    INVESTIGATE_PATTERN = "INVESTIGATE_PATTERN"
    INVESTIGATE_BEHAVIOR_CHANGE = "INVESTIGATE_BEHAVIOR_CHANGE"
    REVIEW_FORECAST = "REVIEW_FORECAST"
    REVIEW_CONTRADICTION = "REVIEW_CONTRADICTION"
    COLLECT_MORE_TELEMETRY = "COLLECT_MORE_TELEMETRY"


class DecisionPriority(str, Enum):
    P0_CRITICAL = "P0_CRITICAL"
    P1_HIGH = "P1_HIGH"
    P2_MEDIUM = "P2_MEDIUM"
    P3_LOW = "P3_LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass(frozen=True)
class DecisionChainItem:
    """Explicit structural trace connecting raw observation to analyst decision."""
    observation_id: str
    change_id: str | None
    behavior_role: str
    pattern_id: str | None
    attack_state: str
    campaign_id: str | None
    priority: DecisionPriority
    decision_id: str
    next_action: str

    def to_dict(self) -> dict[str, Any]:
        steps = [
            {
                "step_id": "OBSERVATION",
                "title": f"Telemetry Observation ({self.observation_id})",
                "description": f"Observed flow/finding event originating or targeting subject.",
                "grounding": "DIRECTLY_OBSERVED",
            },
        ]
        if self.change_id:
            steps.append({
                "step_id": "CHANGE",
                "title": f"Temporal State/Volume Transition ({self.change_id})",
                "description": "Validated change in transmission breadth, rate, or target profile.",
                "grounding": "STRONGLY_SUPPORTED",
            })
        steps.append({
            "step_id": "BEHAVIOR",
            "title": f"Assigned Behavioral Role ({self.behavior_role})",
            "description": f"Role classification derived deterministically from canonical flow and session statistics.",
            "grounding": "STRONGLY_SUPPORTED",
        })
        if self.pattern_id:
            steps.append({
                "step_id": "PATTERN",
                "title": f"Attack Pattern Detected ({self.pattern_id})",
                "description": "Corroborated by multi-entity structural pattern heuristic.",
                "grounding": "SUPPORTED",
            })
        steps.append({
            "step_id": "ATTACK_STATE",
            "title": f"Kinematic Attack State ({self.attack_state})",
            "description": f"Evaluated kill-chain progression stage: {self.attack_state}.",
            "grounding": "STRONGLY_SUPPORTED",
        })
        if self.campaign_id:
            steps.append({
                "step_id": "CAMPAIGN",
                "title": f"Campaign Correlation ({self.campaign_id})",
                "description": "Correlated into coordinated multi-host threat campaign.",
                "grounding": "SUPPORTED",
            })
        steps.append({
            "step_id": "DECISION",
            "title": f"Triage Decision ({self.priority.value})",
            "description": f"Recommended action: {self.next_action}",
            "grounding": "DIRECTLY_OBSERVED",
        })

        return {
            "observation_id": self.observation_id,
            "change_id": self.change_id,
            "behavior_role": self.behavior_role,
            "pattern_id": self.pattern_id,
            "attack_state": self.attack_state,
            "campaign_id": self.campaign_id,
            "priority": self.priority.value,
            "decision_id": self.decision_id,
            "next_action": self.next_action,
            "steps": steps,
        }


@dataclass(frozen=True)
class AnalystDecision:
    """A prioritized, actionable decision for a security operations analyst."""
    decision_id: str
    decision_type: AnalystDecisionType
    priority: DecisionPriority
    subject: str
    headline: str
    why_now: tuple[str, ...]
    supporting_findings: tuple[str, ...]
    supporting_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    uncertainty: tuple[str, ...]
    recommended_next_action: str
    expected_value: str
    investigation_value: InvestigationValueReport | None
    threat_differentiation: ThreatDifferentiationResult | None
    what_changed: tuple[WhatChangedItem, ...]
    benign_hypotheses: tuple[BenignHypothesis, ...]
    open_questions: tuple[InvestigationQuestion, ...]
    decision_chain: DecisionChainItem | None
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "decision_type": self.decision_type.value,
            "priority": self.priority.value,
            "subject": self.subject,
            "headline": self.headline,
            "why_now": list(self.why_now),
            "supporting_findings": list(self.supporting_findings),
            "supporting_evidence": list(self.supporting_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "uncertainty": list(self.uncertainty),
            "recommended_next_action": self.recommended_next_action,
            "expected_value": self.expected_value,
            "investigation_value": self.investigation_value.to_dict() if self.investigation_value else None,
            "threat_differentiation": self.threat_differentiation.to_dict() if self.threat_differentiation else None,
            "what_changed": [c.to_dict() for c in self.what_changed],
            "benign_hypotheses": [h.to_dict() for h in self.benign_hypotheses],
            "open_questions": [q.to_dict() for q in self.open_questions],
            "decision_chain": self.decision_chain.to_dict() if self.decision_chain else None,
            "provenance": self.provenance,
        }


def build_analyst_decisions(
    entity_investigations: Mapping[str, Any] | None = None,
    campaign_investigations: Mapping[str, Any] | None = None,
    incident_investigations: Sequence[Any] | None = None,
    prioritized_threats: Sequence[Any] | None = None,
    entity_profiles: Mapping[str, Any] | None = None,
    attack_kinematics: Mapping[str, Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    change_signals: Sequence[Any] | None = None,
    baseline_deviations: Sequence[Any] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    beaconing_signals: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
    window_count: int = 1,
) -> tuple[AnalystDecision, ...]:
    """Deterministically synthesize and rank analyst decisions across all available security intelligence."""
    decisions: list[AnalystDecision] = []

    p_threats = prioritized_threats or []
    profiles = entity_profiles or {}
    kinematics = attack_kinematics or {}
    cmps = campaigns or []
    pats = patterns or []
    signals = change_signals or []
    deviations = baseline_deviations or []
    findings = observed_findings or []

    # 1. Decisions for Prioritized Entities (Top Candidates)
    for p in p_threats[:8]:
        ent = getattr(p, "entity", "")
        prof = profiles.get(ent)
        traj = kinematics.get(ent)
        curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
        curr_state_val = getattr(curr_state, "value", str(curr_state))
        prio_lvl = getattr(p, "priority_level", "P3_MEDIUM")
        prio_val = getattr(prio_lvl, "value", str(prio_lvl))

        # Semantic Differentiation & Grounding
        diff = differentiate_threat(
            entity=ent,
            entity_profile=prof,
            attack_kinematics=kinematics,
            campaigns=cmps,
            patterns=pats,
            observed_findings=findings,
            contradictions=getattr(p, "mitigating_factors", ()),
            forecast_points=forecast_points,
            window_count=window_count,
        )

        # What Changed
        changes = build_what_changed(
            entity=ent,
            entity_profile=prof,
            attack_kinematics=kinematics,
            change_signals=signals,
            baseline_deviations=deviations,
            campaigns=cmps,
            window_count=window_count,
        )

        # Benign Hypotheses
        b_hypos = evaluate_benign_hypotheses(
            entity=ent,
            entity_profile=prof,
            attack_kinematics=kinematics,
            tcp_sessions=tcp_sessions,
            beaconing_signals=beaconing_signals,
            contradictions=getattr(p, "mitigating_factors", ()),
        )

        # Analyst Questions
        questions = generate_analyst_questions(
            entity=ent,
            entity_profile=prof,
            attack_kinematics=kinematics,
            campaigns=cmps,
            patterns=pats,
            contradictions=getattr(p, "mitigating_factors", ()),
            benign_hypotheses=b_hypos,
            window_count=window_count,
        )

        # Investigation Value
        ent_findings = [f for f in findings if str(f.get("source_ip")) == ent or str(f.get("destination_ip")) == ent]
        inv_val = compute_investigation_value(
            entity=ent,
            entity_profile=prof,
            attack_kinematics=kinematics,
            campaigns=cmps,
            contradictions=getattr(p, "mitigating_factors", ()),
            findings_count=len(ent_findings),
            window_count=window_count,
        )

        # Determine Tier
        if "CRITICAL" in prio_val or curr_state_val in ("IMPACT", "COMMAND_AND_CONTROL"):
            decision_prio = DecisionPriority.P0_CRITICAL
        elif "HIGH" in prio_val or curr_state_val in ("EXPLOITATION_INDICATOR", "RECONNAISSANCE"):
            decision_prio = DecisionPriority.P1_HIGH
        elif "MEDIUM" in prio_val:
            decision_prio = DecisionPriority.P2_MEDIUM
        else:
            decision_prio = DecisionPriority.P3_LOW

        why_now_list: list[str] = list(getattr(p, "drivers", ()))
        if not why_now_list and prof:
            why_now_list.append(f"Entity exhibited roles: {', '.join(getattr(prof, 'roles', ()))}")
        if changes:
            why_now_list.append(f"Observed {len(changes)} temporal change event(s)")

        # Structural Decision Chain
        obs_id = ent_findings[0].get("finding_id", "obs_1") if ent_findings else f"flow_{ent}"
        chg_id = changes[0].change_id if changes else None
        pat_id = pats[0].pattern_id if pats and ent in getattr(pats[0], "primary_entities", ()) else None
        cmp_id = getattr(p, "associated_campaign_id", None)
        roles_str = ", ".join(getattr(prof, "roles", ())) if prof else "UNKNOWN"
        next_act = getattr(p, "recommended_action", "Investigate endpoint and firewall logs.")

        did = deterministic_id("dec", ent, decision_prio.value)
        d_chain = DecisionChainItem(
            observation_id=str(obs_id),
            change_id=chg_id,
            behavior_role=roles_str,
            pattern_id=pat_id,
            attack_state=curr_state_val,
            campaign_id=cmp_id,
            priority=decision_prio,
            decision_id=did,
            next_action=next_act,
        )

        headline = f"Investigate Entity: {ent} ({curr_state_val})"
        decisions.append(AnalystDecision(
            decision_id=did,
            decision_type=AnalystDecisionType.INVESTIGATE_ENTITY,
            priority=decision_prio,
            subject=ent,
            headline=headline,
            why_now=tuple(why_now_list),
            supporting_findings=tuple(f.get("attack_category", "Finding") for f in ent_findings[:5]),
            supporting_evidence=tuple(f.get("finding_id", "find") for f in ent_findings[:5]),
            contradicting_evidence=tuple(getattr(p, "mitigating_factors", ())),
            uncertainty=tuple(getattr(p, "uncertainty_factors", ())),
            recommended_next_action=next_act,
            expected_value=inv_val.uncertainty_reduction_summary,
            investigation_value=inv_val,
            threat_differentiation=diff,
            what_changed=tuple(changes[:5]),
            benign_hypotheses=tuple(b_hypos),
            open_questions=tuple(questions[:5]),
            decision_chain=d_chain,
            provenance={"rule": "entity_decision_synthesis_v1"},
        ))

    # 2. Decisions for Coordinated Campaigns
    for cmp in cmps[:3]:
        cid = getattr(cmp, "campaign_id", "cmp")
        c_sev = getattr(cmp, "severity", "HIGH")
        c_prio = DecisionPriority.P1_HIGH if c_sev == "CRITICAL" else DecisionPriority.P2_MEDIUM
        did = deterministic_id("dec_cmp", cid)
        why_now = [
            f"Campaign aggregates {len(getattr(cmp, 'constituent_episodes', ()))} episode(s)",
            f"Involves {len(getattr(cmp, 'target_entities', ()))} target host(s) on ports {list(getattr(cmp, 'targeted_ports', ()))[:5]}",
            f"Correlation driven by {', '.join(getattr(cmp, 'correlation_reasons', ()))}",
        ]
        next_act = "Quarantine communication pathways across all participating entities concurrently."
        decisions.append(AnalystDecision(
            decision_id=did,
            decision_type=AnalystDecisionType.INVESTIGATE_CAMPAIGN,
            priority=c_prio,
            subject=cid,
            headline=f"Investigate Coordinated Campaign: {getattr(cmp, 'title', cid)}",
            why_now=tuple(why_now),
            supporting_findings=tuple(getattr(cmp, "attack_states", ())),
            supporting_evidence=tuple(getattr(cmp, "constituent_episodes", ())),
            contradicting_evidence=(),
            uncertainty=("Requires correlating authentication logs across all targets",),
            recommended_next_action=next_act,
            expected_value=f"Bounds multi-host blast radius across {len(getattr(cmp, 'primary_entities', ()))} entity(ies).",
            investigation_value=None,
            threat_differentiation=None,
            what_changed=(),
            benign_hypotheses=(),
            open_questions=(),
            decision_chain=None,
            provenance={"rule": "campaign_decision_synthesis_v1"},
        ))

    # 3. Decision for Lookback Telemetry Deficit (if applicable)
    if window_count < 8:
        did = deterministic_id("dec_telemetry", window_count)
        decisions.append(AnalystDecision(
            decision_id=did,
            decision_type=AnalystDecisionType.COLLECT_MORE_TELEMETRY,
            priority=DecisionPriority.P3_LOW,
            subject=f"Capture Horizon ({window_count} windows)",
            headline="Extend Network Observation Depth for Trend Validation",
            why_now=(
                f"Capture length ({window_count} window(s)) is below 8-window threshold required for calibrated LSTM forecasting",
                "Transient bursts cannot yet be definitively distinguished from long-term attack persistence",
            ),
            supporting_findings=(f"window_count_{window_count}",),
            supporting_evidence=(f"available_windows_{window_count}", "required_windows_8"),
            contradicting_evidence=(),
            uncertainty=("Short observation lookback increases false-positive risk for transient scanning",),
            recommended_next_action="Continue continuous packet capture for at least 8 full 60-second windows before applying permanent containment rules.",
            expected_value="Unlocks full 5-step recursive forecasting and verifies persistence.",
            investigation_value=None,
            threat_differentiation=None,
            what_changed=(),
            benign_hypotheses=(),
            open_questions=(),
            decision_chain=None,
            provenance={"rule": "telemetry_depth_rule"},
        ))

    # Sort deterministically by priority rank: P0 > P1 > P2 > P3 > INFORMATIONAL
    prio_order = {
        DecisionPriority.P0_CRITICAL: 0,
        DecisionPriority.P1_HIGH: 1,
        DecisionPriority.P2_MEDIUM: 2,
        DecisionPriority.P3_LOW: 3,
        DecisionPriority.INFORMATIONAL: 4,
    }
    decisions.sort(key=lambda d: (prio_order.get(d.priority, 5), d.decision_id))
    return tuple(decisions)
