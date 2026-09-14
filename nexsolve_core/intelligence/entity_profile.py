"""Entity Behavior Profile Engine.

Constructs rich, deterministic behavioral profiles for network entities:
- Protocol distribution, byte/packet volumes, connection success/failure ratios
- Behavioral characteristics/roles:
  SCANNER, BEACON, SERVER, CLIENT, FANOUT_SOURCE, FANIN_TARGET,
  HIGH_VOLUME_SOURCE, HIGH_VOLUME_TARGET, RESET_HEAVY, PERIODIC_COMMUNICATOR,
  BURSTY_SOURCE, QUIET_ENTITY, EMERGING_ENTITY
- Tracks behavioral evolution across observation windows
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class EntityBehavioralRole(str, Enum):
    SCANNER = "SCANNER"
    BEACON = "BEACON"
    SERVER = "SERVER"
    CLIENT = "CLIENT"
    FANOUT_SOURCE = "FANOUT_SOURCE"
    FANIN_TARGET = "FANIN_TARGET"
    HIGH_VOLUME_SOURCE = "HIGH_VOLUME_SOURCE"
    HIGH_VOLUME_TARGET = "HIGH_VOLUME_TARGET"
    RESET_HEAVY = "RESET_HEAVY"
    PERIODIC_COMMUNICATOR = "PERIODIC_COMMUNICATOR"
    BURSTY_SOURCE = "BURSTY_SOURCE"
    QUIET_ENTITY = "QUIET_ENTITY"
    EMERGING_ENTITY = "EMERGING_ENTITY"


@dataclass(frozen=True)
class EntityBehaviorProfile:
    """Rich multi-modal behavioral profile for an observed IP/entity."""
    entity: str
    roles: tuple[EntityBehavioralRole, ...]
    first_seen_window: int
    last_seen_window: int
    active_windows_count: int
    peer_count: int
    targeted_ports_count: int
    protocol_distribution: dict[str, int]
    packet_volume: int
    byte_volume: int
    connection_attempts: int
    successful_sessions: int
    failed_sessions: int
    reset_sessions: int
    failure_ratio: float
    beaconing_detected: bool
    scan_detected: bool
    volume_anomalies_detected: bool
    associated_episodes: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    role_summary: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity": self.entity,
            "roles": [r.value for r in self.roles],
            "first_seen_window": self.first_seen_window,
            "last_seen_window": self.last_seen_window,
            "active_windows_count": self.active_windows_count,
            "peer_count": self.peer_count,
            "targeted_ports_count": self.targeted_ports_count,
            "protocol_distribution": self.protocol_distribution,
            "packet_volume": self.packet_volume,
            "byte_volume": self.byte_volume,
            "connection_attempts": self.connection_attempts,
            "successful_sessions": self.successful_sessions,
            "failed_sessions": self.failed_sessions,
            "reset_sessions": self.reset_sessions,
            "failure_ratio": round(self.failure_ratio, 3),
            "beaconing_detected": self.beaconing_detected,
            "scan_detected": self.scan_detected,
            "volume_anomalies_detected": self.volume_anomalies_detected,
            "associated_episodes": list(self.associated_episodes),
            "mitre_techniques": list(self.mitre_techniques),
            "role_summary": self.role_summary,
            "provenance": self.provenance,
        }


def build_entity_behavior_profiles(
    entity_histories: Mapping[str, Any] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    episodes: Sequence[Any] | None = None,
    beaconing_signals: Sequence[Any] | None = None,
) -> dict[str, EntityBehaviorProfile]:
    """Build deterministic behavioral profiles for all network entities."""
    profiles: dict[str, EntityBehaviorProfile] = {}
    sessions = tcp_sessions or []
    findings = observed_findings or []
    eps = episodes or []
    beacons = beaconing_signals or []

    # Map sessions by IP
    src_sessions: dict[str, list[Any]] = defaultdict(list)
    dst_sessions: dict[str, list[Any]] = defaultdict(list)
    for s in sessions:
        src = getattr(s, "src_ip", None)
        dst = getattr(s, "dst_ip", None)
        if src:
            src_sessions[src].append(s)
        if dst:
            dst_sessions[dst].append(s)

    all_entities = set(src_sessions.keys()) | set(dst_sessions.keys())
    if entity_histories:
        all_entities |= set(entity_histories.keys())

    # Index beacons
    beacon_sources = {b.src_ip for b in beacons if getattr(b, "is_beaconing", False)}
    all_entities |= beacon_sources

    # Index episodes
    entity_episodes: dict[str, list[str]] = defaultdict(list)
    for ep in eps:
        primary = getattr(ep, "primary_entity", None)
        epid = getattr(ep, "episode_id", None)
        if primary and epid:
            entity_episodes[primary].append(epid)

    for ent in sorted(all_entities):
        out_s = src_sessions.get(ent, [])
        in_s = dst_sessions.get(ent, [])
        all_s = out_s + in_s

        if not all_s and ent not in beacon_sources:
            continue

        peers = {getattr(s, "dst_ip") for s in out_s if getattr(s, "dst_ip", None)} | \
                {getattr(s, "src_ip") for s in in_s if getattr(s, "src_ip", None)}
        ports = {getattr(s, "dst_port") for s in out_s if getattr(s, "dst_port", None) is not None}

        proto_counts: dict[str, int] = defaultdict(int)
        for s in all_s:
            proto = getattr(s, "protocol", "TCP") or "TCP"
            proto_counts[str(proto).upper()] += 1

        pkts = sum((getattr(s, "packet_count", 1) or 1) for s in all_s)
        byts = sum((getattr(s, "byte_count", 0) or 0) for s in all_s)

        # Connection success/failure states
        conn_attempts = len(out_s)
        success = sum(1 for s in out_s if getattr(s, "state", "") in ("ESTABLISHED", "FIN_ACK", "CLOSED"))
        failed = sum(1 for s in out_s if getattr(s, "state", "") in ("REJECTED", "ATTEMPTED"))
        resets = sum(1 for s in out_s if getattr(s, "state", "") == "RESET")
        fail_ratio = (failed + resets) / max(1, conn_attempts)

        windows = sorted({getattr(s, "window_index", 0) or 0 for s in all_s})
        first_w = windows[0] if windows else 0
        last_w = windows[-1] if windows else 0

        # Behavioral heuristics
        roles: list[EntityBehavioralRole] = []

        if len(ports) >= 10 or (conn_attempts >= 10 and len(ports) / max(1, conn_attempts) > 0.6):
            roles.append(EntityBehavioralRole.SCANNER)

        if len(peers) >= 5 and conn_attempts >= 10:
            roles.append(EntityBehavioralRole.FANOUT_SOURCE)

        if len(in_s) > 3 * max(1, len(out_s)):
            roles.append(EntityBehavioralRole.SERVER)
            if len(peers) >= 5:
                roles.append(EntityBehavioralRole.FANIN_TARGET)
        elif len(out_s) > 2 * max(1, len(in_s)):
            roles.append(EntityBehavioralRole.CLIENT)

        if ent in beacon_sources:
            roles.append(EntityBehavioralRole.BEACON)
            roles.append(EntityBehavioralRole.PERIODIC_COMMUNICATOR)

        if resets >= 5 or (conn_attempts >= 5 and fail_ratio >= 0.70):
            roles.append(EntityBehavioralRole.RESET_HEAVY)

        if pkts > 5000 or byts > 1_000_000:
            if len(out_s) >= len(in_s):
                roles.append(EntityBehavioralRole.HIGH_VOLUME_SOURCE)
            else:
                roles.append(EntityBehavioralRole.HIGH_VOLUME_TARGET)

        if len(windows) <= 1 and conn_attempts <= 2:
            roles.append(EntityBehavioralRole.QUIET_ENTITY)
        elif len(windows) == 1 and conn_attempts >= 10:
            roles.append(EntityBehavioralRole.EMERGING_ENTITY)
            roles.append(EntityBehavioralRole.BURSTY_SOURCE)

        if not roles:
            roles.append(EntityBehavioralRole.CLIENT)

        # Correlating findings
        ent_findings = [f for f in findings if str(f.get("source_ip")) == ent or str(f.get("destination_ip")) == ent]
        scan_det = any("scan" in str(f.get("attack_category", "")).lower() for f in ent_findings) or (EntityBehavioralRole.SCANNER in roles)
        vol_det = any("dos" in str(f.get("attack_category", "")).lower() for f in ent_findings)

        mitre_techs: list[str] = []
        if scan_det:
            mitre_techs.append("T1046")
        if ent in beacon_sources:
            mitre_techs.append("T1071")
        if vol_det:
            mitre_techs.append("T1498")

        role_str = ", ".join(r.value for r in roles)
        summary = f"Entity behaves as {role_str} across {len(windows)} window(s)."

        profiles[ent] = EntityBehaviorProfile(
            entity=ent,
            roles=tuple(roles),
            first_seen_window=first_w,
            last_seen_window=last_w,
            active_windows_count=len(windows),
            peer_count=len(peers),
            targeted_ports_count=len(ports),
            protocol_distribution=dict(proto_counts),
            packet_volume=pkts,
            byte_volume=byts,
            connection_attempts=conn_attempts,
            successful_sessions=success,
            failed_sessions=failed,
            reset_sessions=resets,
            failure_ratio=fail_ratio,
            beaconing_detected=(ent in beacon_sources),
            scan_detected=scan_det,
            volume_anomalies_detected=vol_det,
            associated_episodes=tuple(entity_episodes.get(ent, ())),
            mitre_techniques=tuple(sorted(set(mitre_techs))),
            role_summary=summary,
            provenance={"rule": "deterministic_entity_profile_v1"},
        )

    return profiles
