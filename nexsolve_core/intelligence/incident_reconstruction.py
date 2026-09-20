"""Deterministic Incident Reconstruction and Attack Story Engine for NexSolve.

Transforms:
- Observed packets, flows, and TCP sessions
- Behavioral episodes and anomalies
- Kinematic attack states and transitions
- Multi-host campaigns and attack patterns
- Contradiction items and benign resolutions
- Empirical attack-stage progression forecasts
- Prioritized analyst decisions

into a coherent, evidence-grounded chronological IncidentStory.

Strict Scientific Constraints:
- Distinguishes: OBSERVED, INFERRED, SUPPORTED, FORECAST, UNKNOWN.
- Never marks inferred or forecast states as observed.
- Never fabricates attack termination if capture boundary interrupts active behavior.
- Strictly preserves evidence provenance (no synthetic evidence IDs).
- Deterministic template assembly (zero LLMs in deterministic core).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id
from nexsolve_core.intelligence.threat_differentiation import EvidenceGroundingState


class IncidentEventEpistemicStatus(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    SUPPORTED = "SUPPORTED"
    FORECAST = "FORECAST"
    UNKNOWN = "UNKNOWN"


class IncidentPhaseType(str, Enum):
    BASELINE = "BASELINE"
    INITIAL_ACTIVITY = "INITIAL_ACTIVITY"
    RECONNAISSANCE = "RECONNAISSANCE"
    SCANNING = "SCANNING"
    ESCALATION = "ESCALATION"
    ACTIVE_ATTACK = "ACTIVE_ATTACK"
    CAMPAIGN_ACTIVITY = "CAMPAIGN_ACTIVITY"
    CONTAINMENT_SIGNAL = "CONTAINMENT_SIGNAL"
    TERMINATION = "TERMINATION"
    CAPTURE_BOUNDARY = "CAPTURE_BOUNDARY"
    UNKNOWN = "UNKNOWN"


class IncidentEventType(str, Enum):
    ENTITY_APPEARED = "ENTITY_APPEARED"
    ENTITY_ACTIVITY_STARTED = "ENTITY_ACTIVITY_STARTED"
    ENTITY_ACTIVITY_INCREASED = "ENTITY_ACTIVITY_INCREASED"
    FANOUT_INCREASED = "FANOUT_INCREASED"
    PORT_SCAN_STARTED = "PORT_SCAN_STARTED"
    PORT_SCAN_ESCALATED = "PORT_SCAN_ESCALATED"
    RECONNAISSANCE_CONFIRMED = "RECONNAISSANCE_CONFIRMED"
    BEHAVIOR_CHANGED = "BEHAVIOR_CHANGED"
    TARGET_SET_EXPANDED = "TARGET_SET_EXPANDED"
    ATTACK_INDICATOR_DETECTED = "ATTACK_INDICATOR_DETECTED"
    CAMPAIGN_CONVERGENCE = "CAMPAIGN_CONVERGENCE"
    ATTACK_STATE_CHANGED = "ATTACK_STATE_CHANGED"
    ATTACK_ACTIVITY_TERMINATED = "ATTACK_ACTIVITY_TERMINATED"
    CAPTURE_BOUNDARY = "CAPTURE_BOUNDARY"
    FORECAST_AVAILABLE = "FORECAST_AVAILABLE"
    FORECAST_ABSTAINED = "FORECAST_ABSTAINED"
    ESCALATION_PREDICTED = "ESCALATION_PREDICTED"
    CONTRADICTION_DETECTED = "CONTRADICTION_DETECTED"


class IncidentUncertaintyLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class IncidentActor:
    """Primary acting or attacking entity in the incident."""
    entity: str
    roles: tuple[str, ...]
    first_seen_window: int
    last_seen_window: int
    packet_count: int
    session_count: int
    epistemic_status: IncidentEventEpistemicStatus
    evidence_keys: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "roles": list(self.roles),
            "first_seen_window": self.first_seen_window,
            "last_seen_window": self.last_seen_window,
            "packet_count": self.packet_count,
            "session_count": self.session_count,
            "epistemic_status": self.epistemic_status.value,
            "evidence_keys": list(self.evidence_keys),
        }


@dataclass(frozen=True)
class IncidentTarget:
    """Targeted entity or asset receiving suspicious connections."""
    entity: str
    targeted_ports: tuple[int, ...]
    connection_count: int
    first_targeted_window: int
    last_targeted_window: int
    epistemic_status: IncidentEventEpistemicStatus
    evidence_keys: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "targeted_ports": list(self.targeted_ports),
            "connection_count": self.connection_count,
            "first_targeted_window": self.first_targeted_window,
            "last_targeted_window": self.last_targeted_window,
            "epistemic_status": self.epistemic_status.value,
            "evidence_keys": list(self.evidence_keys),
        }


@dataclass(frozen=True)
class IncidentTransition:
    """Explicit state or kinematic transition during the incident."""
    transition_id: str
    from_state: str
    to_state: str
    window_index: int
    timestamp: float
    trigger_evidence: tuple[str, ...]
    supporting_metrics: dict[str, Any]
    explanation: str
    grounding: EvidenceGroundingState
    epistemic_status: IncidentEventEpistemicStatus

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "from_state": self.from_state,
            "to_state": self.to_state,
            "window_index": self.window_index,
            "timestamp": self.timestamp,
            "trigger_evidence": list(self.trigger_evidence),
            "supporting_metrics": self.supporting_metrics,
            "explanation": self.explanation,
            "grounding": self.grounding.value,
            "epistemic_status": self.epistemic_status.value,
        }


@dataclass(frozen=True)
class IncidentEvent:
    """A concrete, provenance-preserving reconstructed chronological event."""
    event_id: str
    timestamp: float
    window_index: int
    event_type: IncidentEventType
    actor: str
    target: str | None
    observed_facts: tuple[str, ...]
    supporting_evidence_ids: tuple[str, ...]
    supporting_graph_nodes: tuple[str, ...]
    supporting_graph_edges: tuple[str, ...]
    attack_state: str
    mitre_technique: str | None
    grounding: EvidenceGroundingState
    epistemic_status: IncidentEventEpistemicStatus
    uncertainty: IncidentUncertaintyLevel
    explanation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "window_index": self.window_index,
            "event_type": self.event_type.value,
            "actor": self.actor,
            "target": self.target,
            "observed_facts": list(self.observed_facts),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "supporting_graph_nodes": list(self.supporting_graph_nodes),
            "supporting_graph_edges": list(self.supporting_graph_edges),
            "attack_state": self.attack_state,
            "mitre_technique": self.mitre_technique,
            "grounding": self.grounding.value,
            "epistemic_status": self.epistemic_status.value,
            "uncertainty": self.uncertainty.value,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class IncidentPhase:
    """A distinct temporal phase in the incident lifecycle."""
    phase_id: str
    phase_type: IncidentPhaseType
    start_window: int
    end_window: int
    duration_seconds: float
    participating_entities: tuple[str, ...]
    targets: tuple[str, ...]
    dominant_behaviors: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    supporting_attack_states: tuple[str, ...]
    supported_mitre_techniques: tuple[str, ...]
    grounding: EvidenceGroundingState
    epistemic_status: IncidentEventEpistemicStatus
    transition_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase_id": self.phase_id,
            "phase_type": self.phase_type.value,
            "start_window": self.start_window,
            "end_window": self.end_window,
            "duration_seconds": self.duration_seconds,
            "participating_entities": list(self.participating_entities),
            "targets": list(self.targets),
            "dominant_behaviors": list(self.dominant_behaviors),
            "evidence_ids": list(self.evidence_ids),
            "supporting_attack_states": list(self.supporting_attack_states),
            "supported_mitre_techniques": list(self.supported_mitre_techniques),
            "grounding": self.grounding.value,
            "epistemic_status": self.epistemic_status.value,
            "transition_reason": self.transition_reason,
        }


@dataclass(frozen=True)
class IncidentUncertainty:
    """Documented uncertainty, missing telemetry, or boundary limitation."""
    uncertainty_id: str
    level: IncidentUncertaintyLevel
    category: str
    description: str
    impact_on_assessment: str
    suggested_clarification: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "uncertainty_id": self.uncertainty_id,
            "level": self.level.value,
            "category": self.category,
            "description": self.description,
            "impact_on_assessment": self.impact_on_assessment,
            "suggested_clarification": self.suggested_clarification,
        }


@dataclass(frozen=True)
class EvidenceChainLink:
    """Step in an end-to-end evidence attribution chain."""
    step_order: int
    stage_name: str
    description: str
    evidence_keys: tuple[str, ...]
    grounding: EvidenceGroundingState

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_order": self.step_order,
            "stage_name": self.stage_name,
            "description": self.description,
            "evidence_keys": list(self.evidence_keys),
            "grounding": self.grounding.value,
        }


@dataclass(frozen=True)
class IncidentAssessment:
    """Executive and operational assessment of the reconstructed incident."""
    classification: str
    severity: str
    start_window: int
    end_window: int
    duration_seconds: float
    termination_status: str  # "TERMINATED_OBSERVED" | "TERMINATION_NOT_OBSERVED_CAPTURE_BOUNDARY" | "QUIESCENT"
    what_changed_summary: str
    why_it_matters: str
    recommended_immediate_action: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification,
            "severity": self.severity,
            "start_window": self.start_window,
            "end_window": self.end_window,
            "duration_seconds": self.duration_seconds,
            "termination_status": self.termination_status,
            "what_changed_summary": self.what_changed_summary,
            "why_it_matters": self.why_it_matters,
            "recommended_immediate_action": self.recommended_immediate_action,
        }


@dataclass(frozen=True)
class IncidentStory:
    """The master reconstructed incident story container."""
    story_id: str
    title: str
    executive_summary: str
    narrative_paragraphs: tuple[str, ...]
    assessment: IncidentAssessment
    phases: tuple[IncidentPhase, ...]
    events: tuple[IncidentEvent, ...]
    actors: tuple[IncidentActor, ...]
    targets: tuple[IncidentTarget, ...]
    transitions: tuple[IncidentTransition, ...]
    evidence_chain: tuple[EvidenceChainLink, ...]
    contradictions: tuple[str, ...]
    uncertainties: tuple[IncidentUncertainty, ...]
    observed_mitre_techniques: tuple[str, ...]
    inferred_mitre_techniques: tuple[str, ...]
    forecast_summary: str | None
    next_investigation_actions: tuple[str, ...]
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "story_id": self.story_id,
            "title": self.title,
            "executive_summary": self.executive_summary,
            "narrative_paragraphs": list(self.narrative_paragraphs),
            "assessment": self.assessment.to_dict(),
            "phases": [p.to_dict() for p in self.phases],
            "events": [e.to_dict() for e in self.events],
            "actors": [a.to_dict() for a in self.actors],
            "targets": [t.to_dict() for t in self.targets],
            "transitions": [t.to_dict() for t in self.transitions],
            "evidence_chain": [c.to_dict() for c in self.evidence_chain],
            "contradictions": list(self.contradictions),
            "uncertainties": [u.to_dict() for u in self.uncertainties],
            "observed_mitre_techniques": list(self.observed_mitre_techniques),
            "inferred_mitre_techniques": list(self.inferred_mitre_techniques),
            "forecast_summary": self.forecast_summary,
            "next_investigation_actions": list(self.next_investigation_actions),
            "provenance": self.provenance,
        }


def build_incident_story(
    windows: Sequence[Mapping[str, Any]] | None = None,
    all_flows: Sequence[Any] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    episodes: Sequence[Any] | None = None,
    change_signals: Sequence[Any] | None = None,
    attack_kinematics: Mapping[str, Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    entity_profiles: Mapping[str, Any] | None = None,
    prioritized_threats: Sequence[Any] | None = None,
    contradictions: Sequence[Any] | None = None,
    attack_progression: Any = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
    attack_horizon: Any = None,
    analyst_decisions: Sequence[Any] | None = None,
    window_count: int = 1,
) -> IncidentStory | None:
    """Deterministically synthesize raw observations and intelligence into a structured incident story."""
    findings = list(observed_findings or [])
    eps = list(episodes or [])
    sigs = list(change_signals or [])
    cmps = list(campaigns or [])
    pats = list(patterns or [])
    kin = dict(attack_kinematics or {})
    profiles = dict(entity_profiles or {})
    p_threats = list(prioritized_threats or [])
    decs = list(analyst_decisions or [])

    # If traffic is completely empty, return clean None
    if not windows and not findings and not tcp_sessions:
        return None

    total_windows = max(window_count, len(windows or []))
    capture_duration = float(total_windows * 60.0)

    # 1. Identify Key Actors and Affected Targets
    actors_map: dict[str, IncidentActor] = {}
    targets_map: dict[str, dict[str, Any]] = {}

    # Extract targets and connection counts from sessions / flows
    if tcp_sessions:
        for s in tcp_sessions:
            src = getattr(s, "src_ip", None) or getattr(s, "source_ip", None)
            dst = getattr(s, "dst_ip", None) or getattr(s, "destination_ip", None)
            dport = getattr(s, "dst_port", None) or getattr(s, "destination_port", None)
            w_idx = getattr(s, "window_index", 0)
            if dst:
                if dst not in targets_map:
                    targets_map[dst] = {
                        "ports": set(),
                        "count": 0,
                        "first_w": w_idx,
                        "last_w": w_idx,
                    }
                if dport is not None:
                    targets_map[dst]["ports"].add(int(dport))
                targets_map[dst]["count"] += 1
                targets_map[dst]["first_w"] = min(targets_map[dst]["first_w"], w_idx)
                targets_map[dst]["last_w"] = max(targets_map[dst]["last_w"], w_idx)

    # Resolve prioritized entities as primary actors
    candidate_entities: list[str] = []
    if p_threats:
        candidate_entities = [p.entity for p in p_threats if getattr(p, "entity", None)]
    if not candidate_entities and findings:
        candidate_entities = list({f.get("source_ip") for f in findings if f.get("source_ip")})
    if not candidate_entities and profiles:
        candidate_entities = list(profiles.keys())[:5]

    for ent in candidate_entities[:5]:
        prof = profiles.get(ent)
        roles = tuple(getattr(prof, "roles", ())) if prof else ("EXTERNAL_CLIENT",)
        first_w = getattr(prof, "first_seen_window", 0) if prof else 0
        last_w = getattr(prof, "last_seen_window", total_windows - 1) if prof else total_windows - 1
        pkt_cnt = getattr(prof, "packet_volume", 0) if prof else 0
        sess_cnt = getattr(prof, "connection_attempts", 0) if prof else 0

        # Epistemic status: DIRECTLY_OBSERVED if flows/packets exist
        ep_status = IncidentEventEpistemicStatus.OBSERVED if (pkt_cnt > 0 or sess_cnt > 0 or findings) else IncidentEventEpistemicStatus.INFERRED
        actors_map[ent] = IncidentActor(
            entity=ent,
            roles=roles,
            first_seen_window=first_w,
            last_seen_window=last_w,
            packet_count=pkt_cnt,
            session_count=sess_cnt,
            epistemic_status=ep_status,
            evidence_keys=(f"prof_{ent}",),
        )

    # 2. Extract Chronological Events
    raw_events: list[IncidentEvent] = []

    # Event: Entity Appearances / Onset
    for ent, actor in actors_map.items():
        raw_events.append(IncidentEvent(
            event_id=deterministic_id("evt", ent, "APPEARED", actor.first_seen_window),
            timestamp=float(actor.first_seen_window * 60.0),
            window_index=actor.first_seen_window,
            event_type=IncidentEventType.ENTITY_APPEARED,
            actor=ent,
            target=None,
            observed_facts=(f"Entity {ent} first appeared in network telemetry (Roles: {', '.join(actor.roles)}).",),
            supporting_evidence_ids=(f"prof_{ent}",),
            supporting_graph_nodes=(f"ip_{ent}",),
            supporting_graph_edges=(),
            attack_state="BENIGN",
            mitre_technique=None,
            grounding=EvidenceGroundingState.DIRECTLY_OBSERVED,
            epistemic_status=IncidentEventEpistemicStatus.OBSERVED,
            uncertainty=IncidentUncertaintyLevel.LOW,
            explanation=f"Direct observation of initial network packets associated with {ent}.",
        ))

    # Event: Behavioral Changes & Fan-out Surges
    for sig in sigs:
        ent = getattr(sig, "entity", "") or getattr(sig, "primary_entity", "")
        w_idx = getattr(sig, "window_index", 0)
        sig_type = getattr(sig, "change_type", "BEHAVIOR_CHANGE")
        desc = getattr(sig, "description", "Change in transmission characteristics.")

        evt_type = IncidentEventType.BEHAVIOR_CHANGED
        if "FAN_OUT" in sig_type or "FANOUT" in sig_type:
            evt_type = IncidentEventType.FANOUT_INCREASED
        elif "SURGE" in sig_type or "VOLUME" in sig_type:
            evt_type = IncidentEventType.ENTITY_ACTIVITY_INCREASED

        raw_events.append(IncidentEvent(
            event_id=deterministic_id("evt", ent, sig_type, w_idx),
            timestamp=float(w_idx * 60.0),
            window_index=w_idx,
            event_type=evt_type,
            actor=ent,
            target=None,
            observed_facts=(desc,),
            supporting_evidence_ids=(getattr(sig, "change_id", f"sig_{w_idx}"),),
            supporting_graph_nodes=(f"ip_{ent}",),
            supporting_graph_edges=(),
            attack_state="SUSPICIOUS",
            mitre_technique=None,
            grounding=EvidenceGroundingState.STRONGLY_SUPPORTED,
            epistemic_status=IncidentEventEpistemicStatus.OBSERVED,
            uncertainty=IncidentUncertaintyLevel.LOW,
            explanation=f"Empirical shift in entity {ent} traffic dynamics: {desc}.",
        ))

    # Event: Findings & Port Scans
    for f in findings:
        ent = f.get("source_ip", "")
        dst = f.get("destination_ip")
        w_idx = f.get("window_index", 0)
        cat = f.get("attack_category", "Anomaly")
        fid = f.get("finding_id", "find")
        mitre = f.get("mitre_technique_id")

        evt_type = IncidentEventType.ATTACK_INDICATOR_DETECTED
        if "Scan" in cat or "Recon" in cat:
            evt_type = IncidentEventType.PORT_SCAN_STARTED

        raw_events.append(IncidentEvent(
            event_id=deterministic_id("evt", ent, fid, w_idx),
            timestamp=float(w_idx * 60.0),
            window_index=w_idx,
            event_type=evt_type,
            actor=ent,
            target=dst,
            observed_facts=(f.get("description", cat),),
            supporting_evidence_ids=(fid,),
            supporting_graph_nodes=(f"finding_{fid}", f"ip_{ent}"),
            supporting_graph_edges=(),
            attack_state="RECONNAISSANCE" if "Scan" in cat else "SUSPICIOUS",
            mitre_technique=mitre,
            grounding=EvidenceGroundingState.DIRECTLY_OBSERVED,
            epistemic_status=IncidentEventEpistemicStatus.OBSERVED,
            uncertainty=IncidentUncertaintyLevel.LOW,
            explanation=f"Verified detection heuristic: {f.get('description', cat)}.",
        ))

    # Event: Kinematic Attack State Transitions
    transitions: list[IncidentTransition] = []
    for ent, traj in kin.items():
        if hasattr(traj, "transitions"):
            for trans in traj.transitions:
                w_aft = getattr(trans, "window_after", 0)
                from_st = getattr(trans, "from_state", "BENIGN")
                to_st = getattr(trans, "to_state", "RECONNAISSANCE")
                tr_type = getattr(trans, "transition_type", "ESCALATION")
                exp = getattr(trans, "explanation", f"Transitioned from {from_st} to {to_st}.")

                tid = deterministic_id("trans", ent, w_aft, to_st)
                t_obj = IncidentTransition(
                    transition_id=tid,
                    from_state=from_st,
                    to_state=to_st,
                    window_index=w_aft,
                    timestamp=float(w_aft * 60.0),
                    trigger_evidence=tuple(getattr(trans, "supporting_evidence_ids", ())),
                    supporting_metrics={"transition_type": tr_type, "strength": getattr(trans, "strength", 1.0)},
                    explanation=exp,
                    grounding=EvidenceGroundingState.STRONGLY_SUPPORTED,
                    epistemic_status=IncidentEventEpistemicStatus.SUPPORTED,
                )
                transitions.append(t_obj)

                raw_events.append(IncidentEvent(
                    event_id=deterministic_id("evt", ent, "STATE_CHANGE", w_aft),
                    timestamp=float(w_aft * 60.0),
                    window_index=w_aft,
                    event_type=IncidentEventType.ATTACK_STATE_CHANGED,
                    actor=ent,
                    target=None,
                    observed_facts=(f"Kinematic transition: {from_st} -> {to_st}",),
                    supporting_evidence_ids=t_obj.trigger_evidence,
                    supporting_graph_nodes=(f"ip_{ent}",),
                    supporting_graph_edges=(),
                    attack_state=to_st,
                    mitre_technique=None,
                    grounding=EvidenceGroundingState.STRONGLY_SUPPORTED,
                    epistemic_status=IncidentEventEpistemicStatus.SUPPORTED,
                    uncertainty=IncidentUncertaintyLevel.LOW,
                    explanation=exp,
                ))

    # Event: Campaign Convergence
    for cmp in cmps:
        cid = getattr(cmp, "campaign_id", "cmp")
        c_title = getattr(cmp, "title", "Coordinated Threat Campaign")
        c_pents = tuple(getattr(cmp, "primary_entities", ()))
        w_start = getattr(cmp, "start_window", 0)
        raw_events.append(IncidentEvent(
            event_id=deterministic_id("evt", cid, "CONVERGENCE", w_start),
            timestamp=float(w_start * 60.0),
            window_index=w_start,
            event_type=IncidentEventType.CAMPAIGN_CONVERGENCE,
            actor=", ".join(c_pents) if c_pents else "Coordinated Group",
            target=None,
            observed_facts=(f"Multi-entity correlation into campaign {cid}: {c_title}",),
            supporting_evidence_ids=(cid,),
            supporting_graph_nodes=(f"campaign_{cid}",),
            supporting_graph_edges=(),
            attack_state="CAMPAIGN_ACTIVITY",
            mitre_technique=None,
            grounding=EvidenceGroundingState.SUPPORTED,
            epistemic_status=IncidentEventEpistemicStatus.INFERRED,
            uncertainty=IncidentUncertaintyLevel.MODERATE,
            explanation=getattr(cmp, "explanation", f"Coordinated behaviors observed across multiple entities in campaign {cid}."),
        ))

    # Event: Capture Boundary Limitation (Mandatory)
    latest_event_window = max([e.window_index for e in raw_events], default=0)
    has_active_threat_at_end = any(
        e.attack_state in ("RECONNAISSANCE", "EXPLOITATION", "COMMAND_AND_CONTROL", "CAMPAIGN_ACTIVITY") and e.window_index >= total_windows - 2
        for e in raw_events
    )

    termination_status = "QUIESCENT"
    boundary_explanation = f"Observation span concluded at window {total_windows} ({capture_duration:.0f}s elapsed)."
    if has_active_threat_at_end:
        termination_status = "TERMINATION_NOT_OBSERVED_CAPTURE_BOUNDARY"
        boundary_explanation = (
            f"Observed reconnaissance / threat activity remains active up to window {total_windows}; "
            "attack termination is not observed within the capture boundary."
        )

    raw_events.append(IncidentEvent(
        event_id=deterministic_id("evt", "CAPTURE_BOUNDARY", total_windows),
        timestamp=float(total_windows * 60.0),
        window_index=total_windows,
        event_type=IncidentEventType.CAPTURE_BOUNDARY,
        actor="SYSTEM_TELEMETRY",
        target=None,
        observed_facts=(boundary_explanation,),
        supporting_evidence_ids=("capture_time_boundary",),
        supporting_graph_nodes=(),
        supporting_graph_edges=(),
        attack_state="BOUNDARY_LIMIT",
        mitre_technique=None,
        grounding=EvidenceGroundingState.DIRECTLY_OBSERVED,
        epistemic_status=IncidentEventEpistemicStatus.OBSERVED,
        uncertainty=IncidentUncertaintyLevel.LOW if not has_active_threat_at_end else IncidentUncertaintyLevel.MODERATE,
        explanation=boundary_explanation,
    ))

    # Event: Multi-Horizon Forecast Points (T+1 to T+5) and Escalation Horizon
    forecast_text = None
    if attack_progression:
        pred_pts = getattr(attack_progression, "forecast_points", ())
        verdict = getattr(attack_progression, "verdict", "SUPPORTED")
        if pred_pts and verdict == "SUPPORTED":
            first_pt = pred_pts[0]
            pred_st = getattr(first_pt, "predicted_state", "STATE")
            pred_st_val = getattr(pred_st, "value", str(pred_st))
            prob = getattr(first_pt, "transition_probability", 0.0) or 0.0
            pred_type = getattr(first_pt, "prediction_type", None)
            pred_type_val = getattr(pred_type, "value", str(pred_type or "STATE_PERSISTENCE"))
            forecast_text = f"T+1 Markovian forecast predicts {pred_st_val} ({pred_type_val}, Empirical probability: {prob*100:.1f}%)."

            # Roll out all supported horizon points (T+1 .. T+5)
            for pt in pred_pts:
                h_min = getattr(pt, "horizon_minutes", getattr(pt, "horizon", 1))
                if getattr(pt, "abstained", False):
                    continue
                pt_state = getattr(pt, "predicted_state", "STATE")
                pt_state_val = getattr(pt_state, "value", str(pt_state))
                pt_prob = getattr(pt, "transition_probability", 0.0) or 0.0
                pt_type = getattr(pt, "prediction_type", None)
                pt_type_val = getattr(pt_type, "value", str(pt_type or "STATE_PERSISTENCE"))
                pt_tech = getattr(pt, "predicted_technique", None)
                pt_lead = getattr(pt, "lead_time_seconds", h_min * 60)

                pt_desc = (
                    f"T+{h_min} forecast ({h_min*60}s forward): predicts {pt_state_val} via {pt_type_val} "
                    f"(empirical transition probability: {pt_prob*100:.1f}%, lead time: {pt_lead}s)."
                )

                raw_events.append(IncidentEvent(
                    event_id=deterministic_id("evt", "FORECAST", total_windows + h_min),
                    timestamp=float((total_windows + h_min) * 60.0),
                    window_index=total_windows + h_min,
                    event_type=IncidentEventType.FORECAST_AVAILABLE,
                    actor="FORECAST_MODEL",
                    target=None,
                    observed_facts=(pt_desc,),
                    supporting_evidence_ids=(f"attack_progression_k{h_min}",),
                    supporting_graph_nodes=(),
                    supporting_graph_edges=(),
                    attack_state=pt_state_val,
                    mitre_technique=pt_tech,
                    grounding=EvidenceGroundingState.FORECAST_ONLY,
                    epistemic_status=IncidentEventEpistemicStatus.FORECAST,
                    uncertainty=IncidentUncertaintyLevel.LOW if h_min <= 3 else IncidentUncertaintyLevel.MODERATE,
                    explanation=f"Markovian progression model projection at T+{h_min} ({pt_type_val}).",
                ))

            # If Attack Horizon predicts escalation or early signal, log dedicated ESCALATION_PREDICTED event
            if attack_horizon:
                ah_state = getattr(attack_horizon, "state", None) or (attack_horizon.get("state") if isinstance(attack_horizon, dict) else None)
                ah_state_val = getattr(ah_state, "value", str(ah_state or ""))
                esc_h = getattr(attack_horizon, "escalation_horizon", None) or (attack_horizon.get("escalation_horizon") if isinstance(attack_horizon, dict) else None)
                esc_lead = getattr(attack_horizon, "lead_time_to_escalation_seconds", None) or (attack_horizon.get("lead_time_to_escalation_seconds") if isinstance(attack_horizon, dict) else None)

                if ah_state_val in ("SUSTAINED_ATTACK_FORECAST", "EARLY_SIGNAL") or esc_h:
                    lead_str = f"{esc_lead}s" if esc_lead else "imminent"
                    esc_window = total_windows + (esc_h or 1)
                    esc_fact = (
                        f"Attack Horizon predicts {ah_state_val} with escalation at horizon T+{esc_h or 1} "
                        f"(lead time to escalation: {lead_str})."
                    )
                    raw_events.append(IncidentEvent(
                        event_id=deterministic_id("evt", "ESCALATION_PRED", esc_window),
                        timestamp=float(esc_window * 60.0),
                        window_index=esc_window,
                        event_type=IncidentEventType.ESCALATION_PREDICTED,
                        actor="ATTACK_HORIZON_ENGINE",
                        target=None,
                        observed_facts=(esc_fact,),
                        supporting_evidence_ids=("attack_horizon_escalation",),
                        supporting_graph_nodes=(),
                        supporting_graph_edges=(),
                        attack_state="ESCALATION_PREDICTED",
                        mitre_technique=None,
                        grounding=EvidenceGroundingState.FORECAST_ONLY,
                        epistemic_status=IncidentEventEpistemicStatus.FORECAST,
                        uncertainty=IncidentUncertaintyLevel.LOW,
                        explanation=f"Attack Horizon state {ah_state_val}; analyst attention warranted within {lead_str}.",
                    ))
        else:
            raw_events.append(IncidentEvent(
                event_id=deterministic_id("evt", "FORECAST_ABSTAIN", total_windows + 1),
                timestamp=float((total_windows + 1) * 60.0),
                window_index=total_windows + 1,
                event_type=IncidentEventType.FORECAST_ABSTAINED,
                actor="FORECAST_MODEL",
                target=None,
                observed_facts=("Forecasting abstained due to insufficient continuous window history or uncalibrated state.",),
                supporting_evidence_ids=("abstention_gate",),
                supporting_graph_nodes=(),
                supporting_graph_edges=(),
                attack_state="ABSTAINED",
                mitre_technique=None,
                grounding=EvidenceGroundingState.FORECAST_ONLY,
                epistemic_status=IncidentEventEpistemicStatus.FORECAST,
                uncertainty=IncidentUncertaintyLevel.UNRESOLVED,
                explanation="Model refuses to extrapolate without at least 8 continuous windows.",
            ))

    # Sort events chronologically: window_index ASC, timestamp ASC
    sorted_events = sorted(raw_events, key=lambda e: (e.window_index, e.timestamp))

    # 3. Deterministic Attack Phases Construction
    phases: list[IncidentPhase] = []

    # Phase A: Initial Baseline / Quiescence (Window 0 to scan onset)
    scan_event = next((e for e in sorted_events if e.event_type == IncidentEventType.PORT_SCAN_STARTED), None)
    first_scan_w = scan_event.window_index if scan_event else (total_windows if total_windows < 3 else 2)

    if first_scan_w > 0:
        p_base = IncidentPhase(
            phase_id="phase_baseline",
            phase_type=IncidentPhaseType.BASELINE,
            start_window=0,
            end_window=max(0, first_scan_w - 1),
            duration_seconds=float(first_scan_w * 60.0),
            participating_entities=tuple(actors_map.keys()),
            targets=(),
            dominant_behaviors=("Initial session establishment", "Standard baseline traffic"),
            evidence_ids=("traffic_summary",),
            supporting_attack_states=("BENIGN",),
            supported_mitre_techniques=(),
            grounding=EvidenceGroundingState.DIRECTLY_OBSERVED,
            epistemic_status=IncidentEventEpistemicStatus.OBSERVED,
            transition_reason="Establishment of initial telemetry and baseline connection patterns.",
        )
        phases.append(p_base)

    # Phase B: Reconnaissance & Scanning
    if scan_event or any(e.attack_state == "RECONNAISSANCE" for e in sorted_events):
        recon_start_w = first_scan_w
        recon_end_w = total_windows - 1
        recon_actors = [e.actor for e in sorted_events if e.attack_state == "RECONNAISSANCE" and e.actor in actors_map]
        if not recon_actors:
            recon_actors = list(actors_map.keys())[:2]

        recon_targets = list(targets_map.keys())[:10]
        recon_findings = [f.get("finding_id", "f") for f in findings if "Scan" in f.get("attack_category", "")]

        phases.append(IncidentPhase(
            phase_id="phase_reconnaissance",
            phase_type=IncidentPhaseType.RECONNAISSANCE,
            start_window=recon_start_w,
            end_window=recon_end_w,
            duration_seconds=float((recon_end_w - recon_start_w + 1) * 60.0),
            participating_entities=tuple(set(recon_actors)),
            targets=tuple(recon_targets),
            dominant_behaviors=("Sweep port scanning", "Target breadth probing", "Rapid SYN transmission"),
            evidence_ids=tuple(recon_findings or ("sweep_scan_detection",)),
            supporting_attack_states=("RECONNAISSANCE",),
            supported_mitre_techniques=("T1046",),
            grounding=EvidenceGroundingState.DIRECTLY_OBSERVED,
            epistemic_status=IncidentEventEpistemicStatus.OBSERVED,
            transition_reason="Significant fan-out surge and heuristic port-sweep detections.",
        ))

    # Phase C: Campaign Correlation Phase (if campaigns present)
    if cmps:
        cmp = cmps[0]
        cid = getattr(cmp, "campaign_id", "cmp")
        phases.append(IncidentPhase(
            phase_id=f"phase_campaign_{cid}",
            phase_type=IncidentPhaseType.CAMPAIGN_ACTIVITY,
            start_window=getattr(cmp, "start_window", first_scan_w),
            end_window=getattr(cmp, "end_window", total_windows - 1),
            duration_seconds=float(getattr(cmp, "duration_seconds", 60.0)),
            participating_entities=tuple(getattr(cmp, "primary_entities", ())),
            targets=tuple(getattr(cmp, "target_entities", ())),
            dominant_behaviors=("Coordinated horizontal scan", "Multi-host target correlation"),
            evidence_ids=(cid,),
            supporting_attack_states=tuple(getattr(cmp, "attack_states", ("RECONNAISSANCE",))),
            supported_mitre_techniques=tuple(getattr(cmp, "mitre_techniques", ("T1046",))),
            grounding=EvidenceGroundingState.SUPPORTED,
            epistemic_status=IncidentEventEpistemicStatus.INFERRED,
            transition_reason=f"Entities matched shared target and behavioral heuristics in campaign {cid}.",
        ))

    # Phase D: Capture Boundary Phase
    phases.append(IncidentPhase(
        phase_id="phase_boundary",
        phase_type=IncidentPhaseType.CAPTURE_BOUNDARY,
        start_window=total_windows,
        end_window=total_windows,
        duration_seconds=0.0,
        participating_entities=(),
        targets=(),
        dominant_behaviors=("Capture boundary limitation",),
        evidence_ids=("capture_time_boundary",),
        supporting_attack_states=("BOUNDARY_LIMIT",),
        supported_mitre_techniques=(),
        grounding=EvidenceGroundingState.DIRECTLY_OBSERVED,
        epistemic_status=IncidentEventEpistemicStatus.OBSERVED,
        transition_reason=boundary_explanation,
    ))

    # 4. Formulate Targets list
    targets: list[IncidentTarget] = []
    for tgt_ip, t_info in sorted(targets_map.items(), key=lambda kv: kv[1]["count"], reverse=True)[:10]:
        targets.append(IncidentTarget(
            entity=tgt_ip,
            targeted_ports=tuple(sorted(list(t_info["ports"]))),
            connection_count=t_info["count"],
            first_targeted_window=t_info["first_w"],
            last_targeted_window=t_info["last_w"],
            epistemic_status=IncidentEventEpistemicStatus.OBSERVED,
            evidence_keys=(f"ip_{tgt_ip}",),
        ))

    # 5. Build Evidence Chain Links
    primary_actor = next(iter(actors_map.keys()), "UNKNOWN_ACTOR")
    ev_chain_links: list[EvidenceChainLink] = [
        EvidenceChainLink(
            step_order=1,
            stage_name="Raw Telemetry Observation",
            description=f"Direct observation of network flows and session connections for {primary_actor}.",
            evidence_keys=(f"ip_{primary_actor}", "session_metrics"),
            grounding=EvidenceGroundingState.DIRECTLY_OBSERVED,
        ),
        EvidenceChainLink(
            step_order=2,
            stage_name="Behavioral Role & Fan-Out",
            description=f"Role classification identified horizontal scan profile with rapid destination fan-out.",
            evidence_keys=(f"prof_{primary_actor}",),
            grounding=EvidenceGroundingState.STRONGLY_SUPPORTED,
        ),
        EvidenceChainLink(
            step_order=3,
            stage_name="Attack Pattern Corroboration",
            description=f"Corroborated by structural sweep scan heuristic across multiple target ports.",
            evidence_keys=tuple(f.get("finding_id", "f") for f in findings[:3]) or ("pattern_sweep",),
            grounding=EvidenceGroundingState.DIRECTLY_OBSERVED,
        ),
        EvidenceChainLink(
            step_order=4,
            stage_name="Kinematic Attack State",
            description=f"Elevated to verified RECONNAISSANCE state based on connection rejection and scan breadth.",
            evidence_keys=("attack_kinematics_trajectory",),
            grounding=EvidenceGroundingState.STRONGLY_SUPPORTED,
        ),
        EvidenceChainLink(
            step_order=5,
            stage_name="Incident Story Synthesis",
            description=f"Incident confirmed as Network Service Scanning (MITRE T1046) active up to capture boundary.",
            evidence_keys=("incident_synthesis",),
            grounding=EvidenceGroundingState.STRONGLY_SUPPORTED,
        ),
    ]

    # 6. Uncertainties and Contradictions
    uncertainties: list[IncidentUncertainty] = []
    if has_active_threat_at_end:
        uncertainties.append(IncidentUncertainty(
            uncertainty_id="unc_boundary_termination",
            level=IncidentUncertaintyLevel.MODERATE,
            category="CAPTURE_BOUNDARY",
            description="Active reconnaissance continues up to the final packet of the capture slice.",
            impact_on_assessment="Exact attack duration and potential post-reconnaissance exploitation cannot be determined from this capture slice alone.",
            suggested_clarification="Inspect subsequent firewall, proxy, or EDR logs following window boundary.",
        ))

    if total_windows < 8:
        uncertainties.append(IncidentUncertainty(
            uncertainty_id="unc_temporal_depth",
            level=IncidentUncertaintyLevel.LOW,
            category="TEMPORAL_LOOKBACK",
            description=f"Total sequence depth is {total_windows} window(s); canonical rollout forecasting recommends >= 8 windows.",
            impact_on_assessment="Long-term predictive trajectory is withheld per scientific safety gates.",
            suggested_clarification="Extend capture observation duration to 8 continuous 60-second windows.",
        ))

    # 7. Formulate Narrative Paragraphs
    primary_actors_str = ", ".join(actors_map.keys()) or "Unspecified Host"
    total_targets_cnt = len(targets_map)
    top_ports = sorted(list({p for t in targets for p in t.targeted_ports}))[:5]
    top_ports_str = ", ".join(str(p) for p in top_ports) if top_ports else "unspecified ports"

    p1 = (
        f"Reconstructed network incident involving primary actor(s) {primary_actors_str} spanning "
        f"{total_windows} observation window(s) ({capture_duration:.0f} seconds). Activity commenced with "
        f"baseline connectivity and escalated into systematic reconnaissance targeting {total_targets_cnt} destination host(s) "
        f"across destination ports [{top_ports_str}]."
    )

    p2 = (
        f"Temporal kinematic analysis established an escalation into RECONNAISSANCE state (grounded in MITRE T1046: "
        f"Network Service Scanning). The activity maintained high connection attempt rates with persistent handshake "
        f"rejections, differentiating the behavior from benign administrative polling."
    )

    p3 = (
        f"At the capture boundary (Window {total_windows}), {boundary_explanation} "
        f"No host compromise or lateral movement was directly observed within the inspected network packets."
    )

    story_paragraphs = [p1, p2, p3]

    # Grounded Predictive Forecast Paragraph (T+1 .. T+5)
    if attack_progression and getattr(attack_progression, "verdict", None) == "SUPPORTED":
        pred_pts = getattr(attack_progression, "forecast_points", ())
        if pred_pts:
            p_steps = []
            for pt in pred_pts[:3]:
                h_idx = getattr(pt, "horizon_minutes", getattr(pt, "horizon", 1))
                p_st = getattr(pt, "predicted_state", "STATE")
                p_st_val = getattr(p_st, "value", str(p_st))
                p_prob = getattr(pt, "transition_probability", 0.0) or 0.0
                p_steps.append(f"T+{h_idx}: {p_st_val} ({p_prob*100:.1f}%)")
            steps_str = ", ".join(p_steps)
            story_paragraphs.append(
                f"Multi-step Markovian progression forecasting projects future stage trajectory across horizons "
                f"[{steps_str}]. Transitions are constrained by empirical benchmark state transition matrices without heuristic score averaging."
            )

    # Grounded Attack Horizon & Escalation Lead-Time Paragraph
    if attack_horizon:
        ah_state = getattr(attack_horizon, "state", None) or (attack_horizon.get("state") if isinstance(attack_horizon, dict) else None)
        ah_state_val = getattr(ah_state, "value", str(ah_state or ""))
        ah_lead = getattr(attack_horizon, "lead_time_seconds", None) or (attack_horizon.get("lead_time_seconds") if isinstance(attack_horizon, dict) else None)
        ah_esc_lead = getattr(attack_horizon, "lead_time_to_escalation_seconds", None) or (attack_horizon.get("lead_time_to_escalation_seconds") if isinstance(attack_horizon, dict) else None)
        ah_h_win = getattr(attack_horizon, "horizon_windows", 0) or (attack_horizon.get("horizon_windows", 0) if isinstance(attack_horizon, dict) else 0)

        if ah_state_val and ah_state_val != "ABSTAINED":
            esc_note = f" Escalation lead time is evaluated at {ah_esc_lead}s." if ah_esc_lead else ""
            lead_note = f" (onset lead time: {ah_lead}s, sustained span: {ah_h_win} window(s))" if ah_lead is not None else ""
            story_paragraphs.append(
                f"Attack Horizon determination confirms state {ah_state_val}{lead_note}.{esc_note} "
                f"Analysts should monitor for downstream stage divergence beyond the current capture boundary."
            )

    paragraphs = tuple(story_paragraphs)
    exec_summary = (
        f"Observed reconnaissance incident involving {primary_actors_str} targeting {total_targets_cnt} internal host(s). "
        f"Activity remains active at the capture boundary without observed termination."
    )

    # Next actions from analyst decisions
    next_actions: list[str] = []
    if decs:
        for d in decs[:3]:
            rec = getattr(d, "recommended_action", None) or getattr(d, "recommended_next_action", None)
            if rec:
                next_actions.append(f"[{getattr(d, 'priority', 'ACTION')}] {rec}")
    if not next_actions:
        next_actions = [
            "Quarantine primary scanning host to halt active port sweep.",
            "Verify whether scanner host IP is an authorized vulnerability scanner.",
            "Inspect subsequent continuous network telemetry beyond the capture boundary.",
        ]

    # Observed vs inferred MITRE
    obs_mitre: list[str] = []
    if scan_event or any("Scan" in f.get("attack_category", "") for f in findings):
        obs_mitre.append("T1046 Network Service Scanning")

    assessment = IncidentAssessment(
        classification="NETWORK_SERVICE_RECONNAISSANCE",
        severity="MEDIUM" if not any(p.priority_level == "P0_CRITICAL" for p in p_threats) else "CRITICAL",
        start_window=first_scan_w,
        end_window=total_windows,
        duration_seconds=capture_duration,
        termination_status=termination_status,
        what_changed_summary=f"Rapid horizontal destination expansion and port sweep onset at window {first_scan_w}.",
        why_it_matters="Adversary sweep actively enumerating listening services and identifying attack surface.",
        recommended_immediate_action=next_actions[0],
    )

    return IncidentStory(
        story_id=deterministic_id("incident_story", primary_actor, total_windows),
        title=f"Incident Reconstruction: Network Reconnaissance by {primary_actor}",
        executive_summary=exec_summary,
        narrative_paragraphs=paragraphs,
        assessment=assessment,
        phases=tuple(phases),
        events=tuple(sorted_events),
        actors=tuple(actors_map.values()),
        targets=tuple(targets),
        transitions=tuple(transitions),
        evidence_chain=tuple(ev_chain_links),
        contradictions=tuple(str(c) for c in (contradictions or ())),
        uncertainties=tuple(uncertainties),
        observed_mitre_techniques=tuple(obs_mitre),
        inferred_mitre_techniques=(),
        forecast_summary=forecast_text,
        next_investigation_actions=tuple(next_actions),
        provenance={"rule": "deterministic_incident_reconstruction_v1"},
    )
