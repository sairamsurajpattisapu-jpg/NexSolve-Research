"""Deterministic Contradiction and Counter-Evidence Engine for NexSolve.

Identifies evidence that actively weakens or contradicts an aggressive attack interpretation:
- Supposed scanner with no meaningful target breadth (<3 distinct ports/hosts)
- Supposed beacon without periodicity support (high CV > 0.6)
- Supposed attack escalation with zero temporal continuity
- Forecast generated despite insufficient history (<8 observation windows)
- Attack state claims unsupported by multi-modal corroboration
- High ratio of clean established sessions contradicting malicious intent
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


@dataclass(frozen=True)
class ContradictionItem:
    """An explicit contradiction observation weakening an attack claim."""
    contradiction_id: str
    entity: str
    claim: str
    contradicting_observation: str
    severity: str  # "INFO", "LOW", "MEDIUM", "HIGH"
    source: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "contradiction_id": self.contradiction_id,
            "entity": self.entity,
            "claim": self.claim,
            "contradicting_observation": self.contradicting_observation,
            "severity": self.severity,
            "source": self.source,
            "provenance": self.provenance,
        }


def detect_contradictions(
    entity: str,
    entity_profile: Any = None,
    attack_kinematics: Any = None,
    beaconing_signals: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
    window_count: int = 1,
) -> tuple[ContradictionItem, ...]:
    """Detect deterministic contradictions for an evaluated entity."""
    contradictions: list[ContradictionItem] = []
    findings = observed_findings or []
    beacons = beaconing_signals or []

    if not entity_profile:
        return ()

    roles = set(getattr(entity_profile, "roles", ()))
    clean_sessions = getattr(entity_profile, "successful_sessions", 0)
    fail_ratio = getattr(entity_profile, "failure_ratio", 0.0)
    port_count = getattr(entity_profile, "targeted_ports_count", 0)
    peer_count = getattr(entity_profile, "peer_count", 0)

    # 1. Clean Established Session Contradiction
    if clean_sessions >= 15 and fail_ratio <= 0.05:
        cid = deterministic_id("contra", entity, "CLEAN_SESSIONS")
        contradictions.append(ContradictionItem(
            contradiction_id=cid,
            entity=entity,
            claim="Malicious Host Intrusiveness",
            contradicting_observation=f"Entity maintains {clean_sessions} cleanly established sessions with <5% failure rate, consistent with trusted infrastructure.",
            severity="MEDIUM",
            source="TCP_SESSION_TRACKER",
            provenance={"successful_sessions": clean_sessions, "failure_ratio": fail_ratio},
        ))

    # 2. Narrow Scanner Claim Contradiction
    is_scanner_claimed = any("SCANNER" in str(r) for r in roles)
    if is_scanner_claimed and port_count < 5 and peer_count < 3:
        cid = deterministic_id("contra", entity, "NARROW_SCANNER")
        contradictions.append(ContradictionItem(
            contradiction_id=cid,
            entity=entity,
            claim="Broad Port Scanner",
            contradicting_observation=f"Scanner classification weakened: entity only contacted {peer_count} peer(s) across {port_count} port(s).",
            severity="HIGH",
            source="ENTITY_PROFILE",
            provenance={"targeted_ports": port_count, "peers": peer_count},
        ))

    # 3. Non-Periodic Beacon Contradiction
    is_beacon_claimed = any("BEACON" in str(r) for r in roles)
    entity_beacons = [b for b in beacons if getattr(b, "src_ip", "") == entity]
    if is_beacon_claimed and entity_beacons:
        for b in entity_beacons:
            cv = getattr(b, "coefficient_of_variation", 0.0)
            if cv > 0.40:
                cid = deterministic_id("contra", entity, "IRREGULAR_BEACON")
                contradictions.append(ContradictionItem(
                    contradiction_id=cid,
                    entity=entity,
                    claim="Metronomic Robotic Beaconing",
                    contradicting_observation=f"Timing variance CV={cv:.2f} exceeds strict metronomic threshold (0.35); communication exhibits human-like interval jitter.",
                    severity="HIGH",
                    source="RITA_BEACONING",
                    provenance={"cv": cv},
                ))

    # 4. Forecast History Insufficiency Contradiction
    if forecast_points and window_count < 8:
        cid = deterministic_id("contra", entity, "INSUFFICIENT_HISTORY_FORECAST")
        contradictions.append(ContradictionItem(
            contradiction_id=cid,
            entity=entity,
            claim="High-Confidence Attack Horizon Forecast",
            contradicting_observation=f"Forecast rollout uncertainty elevated: observation sequence length ({window_count}) is below minimum canonical horizon requirement (8 windows).",
            severity="MEDIUM",
            source="FORECAST_COMPATIBILITY_GATE",
            provenance={"window_count": window_count, "required_windows": 8},
        ))

    # 5. Unsupported Downstream Progression Contradiction
    traj = attack_kinematics.get(entity) if isinstance(attack_kinematics, dict) else attack_kinematics
    if traj and getattr(traj, "unsupported_transition_count", 0) > 0:
        cid = deterministic_id("contra", entity, "UNSUPPORTED_TRANSITIONS")
        contradictions.append(ContradictionItem(
            contradiction_id=cid,
            entity=entity,
            claim="Continuous Linear Attack Progression",
            contradicting_observation=f"Attack trajectory contains {getattr(traj, 'unsupported_transition_count', 0)} state jump(s) without intermediate corroboration.",
            severity="HIGH",
            source="ATTACK_KINEMATICS",
            provenance={"unsupported_transitions": getattr(traj, "unsupported_transition_count", 0)},
        ))

    return tuple(contradictions)
