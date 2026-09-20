"""Deterministic Attack Kinematics Engine for NexSolve.

Models behavioral movement through observable network states:
BENIGN
    ↓
DISCOVERY
    ↓
RECONNAISSANCE
    ↓
TARGETING
    ↓
EXPLOITATION_INDICATOR
    ↓
EXECUTION_INDICATOR
    ↓
COMMAND_AND_CONTROL
    ↓
IMPACT

Distinguishes:
- OBSERVED_STATE
- SUPPORTED_TRANSITION
- UNSUPPORTED_TRANSITION
- UNKNOWN_STATE

Every transition is strictly evidence-backed and explainable. No manufactured transitions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from collections import defaultdict
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class KinematicState(str, Enum):
    BENIGN = "BENIGN"
    DISCOVERY = "DISCOVERY"
    RECONNAISSANCE = "RECONNAISSANCE"
    TARGETING = "TARGETING"
    EXPLOITATION_INDICATOR = "EXPLOITATION_INDICATOR"
    EXECUTION_INDICATOR = "EXECUTION_INDICATOR"
    COMMAND_AND_CONTROL = "COMMAND_AND_CONTROL"
    IMPACT = "IMPACT"
    UNKNOWN_STATE = "UNKNOWN_STATE"


class TransitionType(str, Enum):
    OBSERVED_STATE = "OBSERVED_STATE"
    SUPPORTED_TRANSITION = "SUPPORTED_TRANSITION"
    UNSUPPORTED_TRANSITION = "UNSUPPORTED_TRANSITION"
    ABSTAINED_TRANSITION = "ABSTAINED_TRANSITION"


# Deterministic admissible state machine transitions
ALLOWED_FORWARD_TRANSITIONS = {
    KinematicState.BENIGN: {KinematicState.DISCOVERY, KinematicState.RECONNAISSANCE, KinematicState.BENIGN},
    KinematicState.DISCOVERY: {KinematicState.RECONNAISSANCE, KinematicState.TARGETING, KinematicState.DISCOVERY},
    KinematicState.RECONNAISSANCE: {KinematicState.TARGETING, KinematicState.EXPLOITATION_INDICATOR, KinematicState.RECONNAISSANCE},
    KinematicState.TARGETING: {KinematicState.EXPLOITATION_INDICATOR, KinematicState.TARGETING},
    KinematicState.EXPLOITATION_INDICATOR: {KinematicState.EXECUTION_INDICATOR, KinematicState.COMMAND_AND_CONTROL, KinematicState.IMPACT, KinematicState.EXPLOITATION_INDICATOR},
    KinematicState.EXECUTION_INDICATOR: {KinematicState.COMMAND_AND_CONTROL, KinematicState.IMPACT, KinematicState.EXECUTION_INDICATOR},
    KinematicState.COMMAND_AND_CONTROL: {KinematicState.IMPACT, KinematicState.COMMAND_AND_CONTROL},
    KinematicState.IMPACT: {KinematicState.IMPACT},
    KinematicState.UNKNOWN_STATE: {KinematicState.UNKNOWN_STATE},
}


@dataclass(frozen=True)
class AttackKinematicTransition:
    """A deterministic, evidence-backed transition between attack kinematic states."""
    transition_id: str
    entity: str
    from_state: KinematicState
    to_state: KinematicState
    window_before: int
    window_after: int
    timestamp_before: float | None
    timestamp_after: float | None
    transition_type: TransitionType
    strength: float  # [0.0, 1.0] deterministic corroboration score
    supporting_evidence_ids: tuple[str, ...]
    supporting_modalities: tuple[str, ...]
    observed_or_forecast: str  # "OBSERVED" | "FORECAST"
    explanation: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "transition_id": self.transition_id,
            "entity": self.entity,
            "from_state": self.from_state.value,
            "to_state": self.to_state.value,
            "window_before": self.window_before,
            "window_after": self.window_after,
            "timestamp_before": self.timestamp_before,
            "timestamp_after": self.timestamp_after,
            "transition_type": self.transition_type.value,
            "strength": round(self.strength, 3),
            "supporting_evidence_ids": list(self.supporting_evidence_ids),
            "supporting_modalities": list(self.supporting_modalities),
            "observed_or_forecast": self.observed_or_forecast,
            "explanation": self.explanation,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class EntityKinematicTrajectory:
    """Complete temporal progression of an entity through kinematic states."""
    entity: str
    current_state: KinematicState
    trajectory: tuple[KinematicState, ...]
    transitions: tuple[AttackKinematicTransition, ...]
    first_seen_window: int
    last_seen_window: int
    total_transitions: int
    unsupported_transition_count: int
    highest_severity_state: KinematicState
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "current_state": self.current_state.value,
            "trajectory": [s.value for s in self.trajectory],
            "transitions": [t.to_dict() for t in self.transitions],
            "first_seen_window": self.first_seen_window,
            "last_seen_window": self.last_seen_window,
            "total_transitions": self.total_transitions,
            "unsupported_transition_count": self.unsupported_transition_count,
            "highest_severity_state": self.highest_severity_state.value,
            "summary": self.summary,
        }


def _classify_window_state(
    entity: str,
    window_idx: int,
    findings: Sequence[Mapping[str, Any]],
    sessions: Sequence[Any],
    change_signals: Sequence[Any],
    beaconing_signals: Sequence[Any],
) -> tuple[KinematicState, list[str], list[str], float]:
    """Deterministically map window activity for an entity into a KinematicState."""
    w_findings = [f for f in findings if int(f.get("window_index") or 0) == window_idx]
    w_sessions = [s for s in sessions if (getattr(s, "window_index", 0) or 0) == window_idx]
    w_changes = [c for c in change_signals if getattr(c, "window_after", -1) == window_idx]
    w_beacons = [b for b in beaconing_signals if getattr(b, "src_ip", "") == entity and getattr(b, "is_beaconing", False)]

    supporting_ids: list[str] = []
    modalities: list[str] = []
    strength: float = 0.0

    # Extract categories and flags
    cats = [str(f.get("attack_category", "")).lower() for f in w_findings]
    severities = [str(f.get("severity", "")).upper() for f in w_findings]

    # Check for Impact (e.g. DoS floods, service disruptions)
    if any("dos" in c or "flood" in c or "slowloris" in c or "hulk" in c for c in cats):
        supporting_ids.extend([f.get("finding_id", "find") for f in w_findings if "dos" in str(f.get("attack_category", "")).lower()])
        modalities.append("ANOMALY_DETECTION")
        strength = 0.9 if "CRITICAL" in severities else 0.75
        return KinematicState.IMPACT, supporting_ids, modalities, strength

    # Check for Command and Control (periodic beaconing)
    if w_beacons or any("c2" in c or "beacon" in c for c in cats):
        supporting_ids.extend([f"beacon_{getattr(b, 'dst_ip', '')}" for b in w_beacons])
        modalities.append("RITA_BEACONING")
        strength = max(0.7, max((getattr(b, "score", 0.7) for b in w_beacons), default=0.7))
        return KinematicState.COMMAND_AND_CONTROL, supporting_ids, modalities, strength

    # Check for Targeting / Exploit Indicator
    if any("exploit" in c or "injection" in c or "overflow" in c for c in cats):
        supporting_ids.extend([f.get("finding_id", "find") for f in w_findings])
        modalities.append("SURICATA_SIGNATURE")
        return KinematicState.EXPLOITATION_INDICATOR, supporting_ids, modalities, 0.85

    # Check for Reconnaissance / Discovery
    has_port_surge = any("PORT_FANOUT" in str(getattr(c, "change_type", "")) for c in w_changes)
    has_scan = any("scan" in c or "recon" in c or "probe" in c for c in cats)
    if has_scan or has_port_surge:
        for f in w_findings:
            if "scan" in str(f.get("attack_category", "")).lower() or "recon" in str(f.get("attack_category", "")).lower():
                supporting_ids.append(str(f.get("finding_id", "scan_find")))
        if has_port_surge:
            supporting_ids.extend([str(getattr(c, "change_id", "chg")) for c in w_changes if "PORT_FANOUT" in str(getattr(c, "change_type", ""))])
            modalities.append("BEHAVIOR_CHANGE")
        modalities.append("FLOW_RECON")
        strength = 0.85 if has_port_surge and has_scan else 0.70
        return KinematicState.RECONNAISSANCE, supporting_ids, modalities, strength

    # Check for Discovery / Initial Probing
    if any("probe" in c or "discovery" in c for c in cats) or len(w_sessions) >= 5:
        # Check failed session ratio
        failed_count = sum(1 for s in w_sessions if getattr(s, "state", "") in ("REJECTED", "RESET"))
        if failed_count >= 3:
            modalities.append("ZEEK_SESSION_STATE")
            supporting_ids.append(f"rejected_sessions_{failed_count}")
            return KinematicState.DISCOVERY, supporting_ids, modalities, 0.60

    # Default to Benign if sessions exist without finding
    if w_sessions:
        return KinematicState.BENIGN, ["established_sessions"], ["BASELINE"], 0.90

    return KinematicState.BENIGN, [], ["NO_ACTIVITY"], 0.50


def analyze_attack_kinematics(
    entity_histories: Mapping[str, Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    change_signals: Sequence[Any] | None = None,
    beaconing_signals: Sequence[Any] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, EntityKinematicTrajectory]:
    """Compute deterministic attack kinematics trajectories for all active entities."""
    trajectories: dict[str, EntityKinematicTrajectory] = {}
    findings = observed_findings or []
    sessions = tcp_sessions or []
    changes = change_signals or []
    beacons = beaconing_signals or []

    # Pre-index data by entity
    entities: set[str] = set()
    if entity_histories:
        entities.update(str(k) for k in entity_histories.keys())

    sessions_by_entity: dict[str, list[Any]] = defaultdict(list)
    for s in sessions:
        src = getattr(s, "src_ip", None)
        dst = getattr(s, "dst_ip", None)
        if src:
            src_str = str(src)
            entities.add(src_str)
            sessions_by_entity[src_str].append(s)
        if dst:
            dst_str = str(dst)
            entities.add(dst_str)
            if dst_str != src:
                sessions_by_entity[dst_str].append(s)

    findings_by_entity: dict[str, list[Any]] = defaultdict(list)
    for f in findings:
        src = f.get("source_ip")
        dst = f.get("destination_ip")
        if src:
            src_str = str(src)
            entities.add(src_str)
            findings_by_entity[src_str].append(f)
        if dst:
            dst_str = str(dst)
            entities.add(dst_str)
            if dst_str != src:
                findings_by_entity[dst_str].append(f)

    changes_by_entity: dict[str, list[Any]] = defaultdict(list)
    for c in changes:
        ent_name = getattr(c, "entity", "")
        if ent_name:
            changes_by_entity[str(ent_name)].append(c)

    beacons_by_entity: dict[str, list[Any]] = defaultdict(list)
    for b in beacons:
        src = getattr(b, "src_ip", "")
        dst = getattr(b, "dst_ip", "")
        if src:
            beacons_by_entity[str(src)].append(b)
        if dst and dst != src:
            beacons_by_entity[str(dst)].append(b)

    for ent in sorted(entities):
        ent_sessions = sessions_by_entity.get(ent, [])
        ent_findings = findings_by_entity.get(ent, [])
        ent_changes = changes_by_entity.get(ent, [])
        ent_beacons = beacons_by_entity.get(ent, [])

        if not ent_sessions and not ent_findings and not ent_changes:
            continue

        # Determine all relevant windows
        windows = set()
        for s in ent_sessions:
            windows.add(getattr(s, "window_index", 0) or 0)
        for f in ent_findings:
            windows.add(int(f.get("window_index") or 0))
        for c in ent_changes:
            windows.add(getattr(c, "window_after", 0) or 0)

        if not windows:
            windows = {0}

        sorted_windows = sorted(windows)
        first_w = sorted_windows[0]
        last_w = sorted_windows[-1]

        # Classify state per window
        window_states: list[tuple[int, KinematicState, list[str], list[str], float]] = []
        for w in sorted_windows:
            st, supp_ids, mods, strn = _classify_window_state(
                ent, w, ent_findings, ent_sessions, ent_changes, ent_beacons
            )
            window_states.append((w, st, supp_ids, mods, strn))

        # Build Transitions
        transitions: list[AttackKinematicTransition] = []
        unsupported_count = 0
        state_path: list[KinematicState] = [window_states[0][1]]

        for i in range(len(window_states) - 1):
            w1, st1, _, _, _ = window_states[i]
            w2, st2, supp2, mods2, strn2 = window_states[i + 1]

            state_path.append(st2)
            tid = deterministic_id("kin_trans", ent, w1, w2, st1.value, st2.value)

            if st1 == st2:
                # State Persistence
                t_type = TransitionType.SUPPORTED_TRANSITION
                expl = f"Entity maintained {st1.value} across window {w1} to {w2}."
            elif st2 in ALLOWED_FORWARD_TRANSITIONS.get(st1, set()):
                # Supported Forward Progression
                t_type = TransitionType.SUPPORTED_TRANSITION
                expl = f"Supported kinematic advancement from {st1.value} to {st2.value} supported by {len(supp2)} evidence item(s)."
            else:
                # Direct leap without intermediate corroboration
                t_type = TransitionType.UNSUPPORTED_TRANSITION
                unsupported_count += 1
                expl = f"Kinematic state jumped from {st1.value} to {st2.value} without corroborating intermediate stages."

            transitions.append(AttackKinematicTransition(
                transition_id=tid,
                entity=ent,
                from_state=st1,
                to_state=st2,
                window_before=w1,
                window_after=w2,
                timestamp_before=float(w1 * 60.0),
                timestamp_after=float(w2 * 60.0),
                transition_type=t_type,
                strength=strn2,
                supporting_evidence_ids=tuple(supp2),
                supporting_modalities=tuple(sorted(set(mods2))),
                observed_or_forecast="OBSERVED",
                explanation=expl,
                provenance={"rule": "deterministic_kinematics_v1"},
            ))

        # Determine highest severity state
        severity_rank = {
            KinematicState.BENIGN: 0,
            KinematicState.UNKNOWN_STATE: 1,
            KinematicState.DISCOVERY: 2,
            KinematicState.RECONNAISSANCE: 3,
            KinematicState.TARGETING: 4,
            KinematicState.EXPLOITATION_INDICATOR: 5,
            KinematicState.EXECUTION_INDICATOR: 6,
            KinematicState.COMMAND_AND_CONTROL: 7,
            KinematicState.IMPACT: 8,
        }
        highest_state = max(state_path, key=lambda s: severity_rank.get(s, 0))
        curr_state = state_path[-1]

        summary = (
            f"Entity {ent} progressed through {len(transitions)} transition(s). "
            f"Current state: {curr_state.value} (Peak: {highest_state.value}). "
            f"Unsupported transitions: {unsupported_count}."
        )

        trajectories[ent] = EntityKinematicTrajectory(
            entity=ent,
            current_state=curr_state,
            trajectory=tuple(state_path),
            transitions=tuple(transitions),
            first_seen_window=first_w,
            last_seen_window=last_w,
            total_transitions=len(transitions),
            unsupported_transition_count=unsupported_count,
            highest_severity_state=highest_state,
            summary=summary,
        )

    return trajectories
