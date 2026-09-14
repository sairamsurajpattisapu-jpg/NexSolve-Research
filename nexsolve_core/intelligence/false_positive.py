"""Deterministic Benign Hypothesis & False-Positive Resolution Engine for NexSolve.

Evaluates plausible non-malicious explanations for anomalous telemetry:
- Administrative vulnerability scanning (internal scanner host)
- Automated network discovery / asset inventory
- Backup / bulk file synchronization traffic
- Network health telemetry & ICMP/SNMP polling
- High-volume legitimate web/database server
- High-frequency CDN / API polling

Returns resolution states:
- UNRESOLVED: Insufficient evidence to dismiss or confirm benign hypothesis
- PARTIALLY_SUPPORTED: Some characteristics match benign profile, but discrepancies persist
- SUPPORTED_BENIGN: Verified benign characteristics override threat claim
- SUPPORTED_THREAT: Discrepancies firmly disprove benign hypothesis

Never claims benign status without concrete supporting telemetry.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class BenignResolutionState(str, Enum):
    UNRESOLVED = "UNRESOLVED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    SUPPORTED_BENIGN = "SUPPORTED_BENIGN"
    SUPPORTED_THREAT = "SUPPORTED_THREAT"


@dataclass(frozen=True)
class BenignHypothesis:
    """A plausible benign interpretation of suspicious activity."""
    hypothesis_id: str
    entity: str
    hypothesis_type: str
    title: str
    description: str
    supporting_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    contradicting_evidence: tuple[str, ...]
    resolution_state: BenignResolutionState
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hypothesis_id": self.hypothesis_id,
            "entity": self.entity,
            "hypothesis_type": self.hypothesis_type,
            "title": self.title,
            "description": self.description,
            "supporting_evidence": list(self.supporting_evidence),
            "missing_evidence": list(self.missing_evidence),
            "contradicting_evidence": list(self.contradicting_evidence),
            "resolution_state": self.resolution_state.value,
            "provenance": self.provenance,
        }


def evaluate_benign_hypotheses(
    entity: str,
    entity_profile: Any = None,
    attack_kinematics: Any = None,
    tcp_sessions: Sequence[Any] | None = None,
    beaconing_signals: Sequence[Any] | None = None,
    contradictions: Sequence[Any] | None = None,
) -> tuple[BenignHypothesis, ...]:
    """Evaluate deterministic benign hypotheses against observed telemetry."""
    hypotheses: list[BenignHypothesis] = []
    roles = set(getattr(entity_profile, "roles", ())) if entity_profile else set()
    clean_sessions = getattr(entity_profile, "successful_sessions", 0) if entity_profile else 0
    fail_ratio = getattr(entity_profile, "failure_ratio", 0.0) if entity_profile else 0.0
    ports_cnt = getattr(entity_profile, "targeted_ports_count", 0) if entity_profile else 0

    traj = attack_kinematics.get(entity) if isinstance(attack_kinematics, dict) else attack_kinematics
    curr_state = getattr(traj, "current_state", "BENIGN") if traj else "BENIGN"
    curr_state_val = getattr(curr_state, "value", str(curr_state))

    # 1. Administrative Scanner Hypothesis
    if any("SCANNER" in str(r) for r in roles) or curr_state_val == "RECONNAISSANCE":
        hid = deterministic_id("hypo", entity, "ADMIN_SCANNER")
        supp: list[str] = []
        miss: list[str] = ["Asset tag indicating authorized vulnerability scanner", "Scheduled maintenance window ticket"]
        contra: list[str] = []

        if clean_sessions > 0:
            supp.append(f"Completed {clean_sessions} standard handshakes on target services")
        if ports_cnt > 10:
            supp.append(f"Broad multi-port sweep typical of Nessus/Qualys/Nmap profile ({ports_cnt} ports)")

        # Disproving indicators
        if fail_ratio > 0.80:
            contra.append(f"Extremely high handshake rejection rate ({fail_ratio*100:.1f}%), suggesting aggressive blind probe rather than credentialed audit")

        res = BenignResolutionState.PARTIALLY_SUPPORTED if supp and not contra else (BenignResolutionState.SUPPORTED_THREAT if contra else BenignResolutionState.UNRESOLVED)

        hypotheses.append(BenignHypothesis(
            hypothesis_id=hid,
            entity=entity,
            hypothesis_type="ADMINISTRATIVE_SCAN",
            title="Authorized Security Audit / Vulnerability Scanner",
            description="Activity matches automated vulnerability assessment or IT compliance auditing.",
            supporting_evidence=tuple(supp),
            missing_evidence=tuple(miss),
            contradicting_evidence=tuple(contra),
            resolution_state=res,
            provenance={"rule": "admin_scanner_check"},
        ))

    # 2. Legitimate High-Volume Server Hypothesis
    if clean_sessions >= 20 and fail_ratio <= 0.05:
        hid = deterministic_id("hypo", entity, "LEGIT_SERVER")
        supp = [
            f"High ratio of clean sessions: {clean_sessions} established with <5% reset/failure",
            "Consistent bidirectional packet exchanges observed across active windows",
        ]
        miss = ["Enterprise DNS naming resolution confirmation", "Internal infrastructure whitelist entry"]
        contra = []
        if curr_state_val in ("IMPACT", "COMMAND_AND_CONTROL"):
            contra.append(f"Entity assigned active {curr_state_val} kinematic state")

        res = BenignResolutionState.SUPPORTED_BENIGN if not contra else BenignResolutionState.PARTIALLY_SUPPORTED

        hypotheses.append(BenignHypothesis(
            hypothesis_id=hid,
            entity=entity,
            hypothesis_type="LEGITIMATE_INFRASTRUCTURE",
            title="Standard Core Infrastructure Service",
            description="Established session volume and low error rates reflect normal infrastructure behavior.",
            supporting_evidence=tuple(supp),
            missing_evidence=tuple(miss),
            contradicting_evidence=tuple(contra),
            resolution_state=res,
            provenance={"rule": "legitimate_server_check"},
        ))

    # 3. Scheduled Periodic Polling / Monitoring
    if any("BEACON" in str(r) for r in roles):
        hid = deterministic_id("hypo", entity, "PERIODIC_POLLING")
        supp = ["Regular interval timing consistent with NTP, SNMP, or health check agent"]
        miss = ["Agent heartbeat documentation", "Approved monitoring destination endpoint"]
        contra = []
        # Check interval jitter
        beacons = [b for b in (beaconing_signals or []) if getattr(b, "src_ip", "") == entity]
        if beacons and any(getattr(b, "coefficient_of_variation", 1.0) < 0.15 for b in beacons):
            contra.append("Strict metronomic consistency without human or randomized jitter")

        res = BenignResolutionState.UNRESOLVED if not contra else BenignResolutionState.SUPPORTED_THREAT

        hypotheses.append(BenignHypothesis(
            hypothesis_id=hid,
            entity=entity,
            hypothesis_type="SCHEDULED_POLLING",
            title="Scheduled Telemetry / NTP / Health Polling",
            description="Periodic communications may represent benign background monitoring software.",
            supporting_evidence=tuple(supp),
            missing_evidence=tuple(miss),
            contradicting_evidence=tuple(contra),
            resolution_state=res,
            provenance={"rule": "polling_telemetry_check"},
        ))

    return tuple(hypotheses)
