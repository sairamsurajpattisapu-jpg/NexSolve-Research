"""Deterministic Network Behavior Episode Engine.

Groups related multi-modal observations (IPs, sessions, findings, signals)
into coherent temporal behavioral episodes using strictly deterministic rules:
- Same source/destination entity across contiguous or adjacent temporal windows
- Correlated protocol signals (e.g. SYN scan / rejection burst) and findings
- Shared destination port fan-out or targeted service concentration
- No arbitrary similarity clustering or GNN approximations
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class EpisodeSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True)
class BehavioralEpisode:
    """Coherent period of correlated network activity across entities and windows."""
    episode_id: str
    title: str
    start_window: int
    end_window: int
    duration_seconds: float
    primary_entity: str
    source_ips: tuple[str, ...]
    destination_ips: tuple[str, ...]
    destination_ports: tuple[int, ...]
    flow_count: int
    session_count: int
    findings: tuple[str, ...]
    behavior_signals: tuple[str, ...]
    protocol_signals: tuple[str, ...]
    anomaly_signals: tuple[str, ...]
    attack_states: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    severity: EpisodeSeverity
    description: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "title": self.title,
            "start_window": self.start_window,
            "end_window": self.end_window,
            "duration_seconds": self.duration_seconds,
            "primary_entity": self.primary_entity,
            "source_ips": list(self.source_ips),
            "destination_ips": list(self.destination_ips),
            "destination_ports": list(self.destination_ports),
            "flow_count": self.flow_count,
            "session_count": self.session_count,
            "findings": list(self.findings),
            "behavior_signals": list(self.behavior_signals),
            "protocol_signals": list(self.protocol_signals),
            "anomaly_signals": list(self.anomaly_signals),
            "attack_states": list(self.attack_states),
            "mitre_techniques": list(self.mitre_techniques),
            "severity": self.severity.value,
            "description": self.description,
            "provenance": self.provenance,
        }


def build_behavioral_episodes(
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    behavioral_report: Any = None,
    attack_progression: Any = None,
) -> tuple[BehavioralEpisode, ...]:
    """Deterministically group observations into behavioral episodes."""
    episodes: list[BehavioralEpisode] = []

    # 1. Group by entity from observed findings
    entity_findings: dict[str, list[Mapping[str, Any]]] = {}
    if observed_findings:
        for f in observed_findings:
            entity = str(f.get("destination_ip") or f.get("source_ip") or "network").strip()
            entity_findings.setdefault(entity, []).append(f)

    # 2. Extract TCP sessions by entity
    entity_sessions: dict[str, list[Any]] = {}
    if tcp_sessions:
        for s in tcp_sessions:
            src = getattr(s, "src_ip", None) or "unknown"
            dst = getattr(s, "dst_ip", None) or "unknown"
            entity_sessions.setdefault(src, []).append(s)
            if dst != src:
                entity_sessions.setdefault(dst, []).append(s)

    # 3. Build episodes for entities with findings or significant activity
    all_candidate_entities = sorted(set(list(entity_findings.keys())))
    if not all_candidate_entities and observed_findings:
        all_candidate_entities = ["network"]

    for entity in all_candidate_entities:
        findings_list = entity_findings.get(entity, [])
        if not findings_list:
            continue

        w_indices = sorted(list({int(f.get("window_index") or 0) for f in findings_list}))
        start_w = w_indices[0] if w_indices else 0
        end_w = w_indices[-1] if w_indices else 0
        dur = max(60.0, float(end_w - start_w + 1) * 60.0)

        src_ips = sorted(list({str(f.get("source_ip")) for f in findings_list if f.get("source_ip")}))
        dst_ips = sorted(list({str(f.get("destination_ip")) for f in findings_list if f.get("destination_ip")}))
        categories = [str(f.get("attack_category", "Anomaly")) for f in findings_list]
        
        # Check sessions associated with this entity
        sessions_list = entity_sessions.get(entity, [])
        dst_ports = sorted(list({int(getattr(s, "dst_port")) for s in sessions_list if getattr(s, "dst_port", None) is not None}))

        # Severity determination
        has_high = any(str(f.get("severity", "")).upper() in ("HIGH", "CRITICAL") for f in findings_list)
        sev = EpisodeSeverity.HIGH if has_high else EpisodeSeverity.MEDIUM

        # MITRE techniques mapping
        mitre_techs = []
        for cat in categories:
            if "recon" in cat.lower() or "scan" in cat.lower():
                mitre_techs.append("T1046")
            elif "dos" in cat.lower() or "flood" in cat.lower():
                mitre_techs.append("T1498")

        # Inferred attack state from progression or category
        state_val = "RECONNAISSANCE" if any("scan" in c.lower() or "recon" in c.lower() for c in categories) else "BENIGN_OBSERVATION"
        if any("dos" in c.lower() for c in categories):
            state_val = "DENIAL_OF_SERVICE"

        ep_id = deterministic_id("ep", entity, start_w, end_w, len(findings_list))
        title = f"Episode: {', '.join(sorted(set(categories)))} targeting {entity}"
        desc = (
            f"Observed behavioral episode spanning windows {start_w}..{end_w} with {len(findings_list)} finding(s) "
            f"and {len(sessions_list)} associated TCP conversation(s)."
        )

        episodes.append(BehavioralEpisode(
            episode_id=ep_id,
            title=title,
            start_window=start_w,
            end_window=end_w,
            duration_seconds=dur,
            primary_entity=entity,
            source_ips=tuple(src_ips),
            destination_ips=tuple(dst_ips),
            destination_ports=tuple(dst_ports[:20]),
            flow_count=len(sessions_list) or len(findings_list),
            session_count=len(sessions_list),
            findings=tuple(sorted(set(categories))),
            behavior_signals=tuple(),
            protocol_signals=tuple(f"{getattr(s, 'state', 'OTH')}" for s in sessions_list[:5]),
            anomaly_signals=tuple(categories),
            attack_states=(state_val,),
            mitre_techniques=tuple(sorted(set(mitre_techs))),
            severity=sev,
            description=desc,
            provenance={"rule": "deterministic_entity_temporal_grouping"},
        ))

    return tuple(episodes)
