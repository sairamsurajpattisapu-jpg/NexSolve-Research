"""Arkime-inspired session-centric investigation data model for NexSolve.

Represents individual bidirectional communications as forensic session entities
linking 5-tuples, packet/byte counts, temporal duration, behavioral signals,
and MITRE ATT&CK techniques.

Also provides the unified deterministic InvestigationQueryEngine to query:
entity, campaign, incident, timeline, relationships, patterns, attack_states,
transitions, evidence, mitre, forecast, contradictions, risk, mitigations.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

from nexsolve_core.schemas import FlowRecord


@dataclass(frozen=True)
class SessionInvestigationRecord:
    """Arkime-style session investigation forensic unit."""
    session_id: str
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    first_seen: float
    last_seen: float
    duration_seconds: float
    forward_packets: int
    reverse_packets: int
    total_packets: int
    forward_bytes: int
    reverse_bytes: int
    total_bytes: int
    packet_rate: float | None
    byte_rate: float | None
    completeness: str
    behavioral_tags: tuple[str, ...]
    signature_alerts: tuple[str, ...]
    mitre_techniques: tuple[str, ...]
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": self.duration_seconds,
            "forward_packets": self.forward_packets,
            "reverse_packets": self.reverse_packets,
            "total_packets": self.total_packets,
            "forward_bytes": self.forward_bytes,
            "reverse_bytes": self.reverse_bytes,
            "total_bytes": self.total_bytes,
            "packet_rate": self.packet_rate,
            "byte_rate": self.byte_rate,
            "completeness": self.completeness,
            "behavioral_tags": list(self.behavioral_tags),
            "signature_alerts": list(self.signature_alerts),
            "mitre_techniques": list(self.mitre_techniques),
            "risk_level": self.risk_level,
        }


def build_session_investigation_records(
    flows: Sequence[FlowRecord],
    beaconing_signals: Sequence[Any] = (),
    max_records: int = 1000,
) -> tuple[SessionInvestigationRecord, ...]:
    """Convert flow records and behavioral findings into session investigation records."""
    # Index beaconing pairs
    beacon_set = {
        (s.src_ip, s.dst_ip, s.dst_port)
        for s in beaconing_signals
        if getattr(s, "is_beaconing", False)
    }

    records: list[SessionInvestigationRecord] = []
    for flow in flows[:max_records]:
        b_tags: list[str] = []
        mitre: list[str] = []
        key = (flow.src_ip, flow.dst_ip, flow.dst_port)

        if key in beacon_set:
            b_tags.append("PERIODIC_BEACONING")
            mitre.append("T1071 - Application Layer Protocol")

        if flow.duration_seconds >= 300.0:
            b_tags.append("LONG_LIVED_SESSION")

        if flow.protocol == "TCP" and flow.syn_count > 0 and flow.ack_count == 0:
            b_tags.append("UNACKNOWLEDGED_SYN")
            mitre.append("T1046 - Network Service Scanning")

        risk = "LOW"
        if "PERIODIC_BEACONING" in b_tags:
            risk = "HIGH"
        elif "UNACKNOWLEDGED_SYN" in b_tags or "LONG_LIVED_SESSION" in b_tags:
            risk = "MEDIUM"

        records.append(SessionInvestigationRecord(
            session_id=flow.flow_id,
            src_ip=flow.src_ip,
            src_port=flow.src_port,
            dst_ip=flow.dst_ip,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            first_seen=flow.start_timestamp,
            last_seen=flow.end_timestamp,
            duration_seconds=round(flow.duration_seconds, 3),
            forward_packets=flow.forward_packet_count,
            reverse_packets=flow.reverse_packet_count,
            total_packets=flow.total_packet_count,
            forward_bytes=flow.forward_bytes,
            reverse_bytes=flow.reverse_bytes,
            total_bytes=flow.total_bytes,
            packet_rate=round(flow.packet_rate, 2) if flow.packet_rate is not None else None,
            byte_rate=round(flow.byte_rate, 2) if flow.byte_rate is not None else None,
            completeness=flow.completeness,
            behavioral_tags=tuple(b_tags),
            signature_alerts=(),
            mitre_techniques=tuple(mitre),
            risk_level=risk,
        ))

    return tuple(records)


class InvestigationQueryEngine:
    """Unified deterministic investigation query interface for NexSolve."""

    def __init__(
        self,
        entity_profiles: Mapping[str, Any] | None = None,
        attack_kinematics: Mapping[str, Any] | None = None,
        campaigns: Sequence[Any] | None = None,
        patterns: Sequence[Any] | None = None,
        change_signals: Sequence[Any] | None = None,
        threat_stories: Sequence[Any] | None = None,
        prioritized_threats: Sequence[Any] | None = None,
        evidence_graph: Any = None,
        entity_investigations: Mapping[str, Any] | None = None,
        incident_investigations: Sequence[Any] | None = None,
        forecast_context: Mapping[str, Any] | None = None,
        mitigations: Sequence[Any] | None = None,
        contradictions: Mapping[str, Sequence[Any]] | None = None,
    ) -> None:
        self.profiles = dict(entity_profiles or {})
        self.kinematics = dict(attack_kinematics or {})
        self.campaigns = list(campaigns or [])
        self.patterns = list(patterns or [])
        self.change_signals = list(change_signals or [])
        self.stories = list(threat_stories or [])
        self.prioritized = list(prioritized_threats or [])
        self.graph = evidence_graph
        self.entity_investigations = dict(entity_investigations or {})
        self.incident_investigations = list(incident_investigations or [])
        self.forecast_context = dict(forecast_context or {})
        self.mitigations = list(mitigations or [])
        self.contradictions = dict(contradictions or {})

    def query_entity(self, entity: str) -> dict[str, Any] | None:
        """Query full investigation dossier for an entity."""
        inv = self.entity_investigations.get(entity)
        if inv and hasattr(inv, "to_dict"):
            return inv.to_dict()
        if inv:
            return dict(inv)
        return self.query_entity_profile(entity)

    def query_entity_profile(self, entity: str) -> dict[str, Any] | None:
        p = self.profiles.get(entity)
        return p.to_dict() if p and hasattr(p, "to_dict") else p

    def query_campaign(self, campaign_id: str) -> dict[str, Any] | None:
        c = next((cmp for cmp in self.campaigns if getattr(cmp, "campaign_id", "") == campaign_id), None)
        return c.to_dict() if c and hasattr(c, "to_dict") else c

    def query_incident(self, incident_id_or_entity: str) -> dict[str, Any] | None:
        for inc in self.incident_investigations:
            if getattr(inc, "incident_id", "") == incident_id_or_entity or incident_id_or_entity in getattr(inc, "primary_entities", ()):
                return inc.to_dict() if hasattr(inc, "to_dict") else dict(inc)
        return None

    def query_timeline(self, entity: str) -> list[dict[str, Any]]:
        inv = self.entity_investigations.get(entity)
        if inv and hasattr(inv, "timeline"):
            return [t.to_dict() if hasattr(t, "to_dict") else dict(t) for t in inv.timeline]
        if self.graph and hasattr(self.graph, "get_entity_timeline"):
            return self.graph.get_entity_timeline(entity)
        story = next((s for s in self.stories if getattr(s, "entity", "") == entity), None)
        if story and hasattr(story, "stages"):
            return [s.to_dict() for s in story.stages]
        return []

    def query_entity_timeline(self, entity: str) -> list[dict[str, Any]]:
        """Alias for query_timeline for backwards-compatibility."""
        return self.query_timeline(entity)

    def query_relationships(self, entity: str) -> list[dict[str, Any]]:
        inv = self.entity_investigations.get(entity)
        if inv and hasattr(inv, "relationships"):
            return [r.to_dict() if hasattr(r, "to_dict") else dict(r) for r in inv.relationships]
        return self.query_entity_neighbors(entity)

    def query_entity_neighbors(self, entity: str) -> list[dict[str, Any]]:
        if self.graph and hasattr(self.graph, "get_entity_neighbors"):
            return self.graph.get_entity_neighbors(entity)
        p = self.profiles.get(entity)
        if p:
            return [{"peer": peer} for peer in getattr(p, "peer_count", 0)]
        return []

    def query_entity_campaigns(self, entity: str) -> list[dict[str, Any]]:
        matched = [c for c in self.campaigns if entity in getattr(c, "primary_entities", ()) or entity in getattr(c, "target_entities", ())]
        return [c.to_dict() if hasattr(c, "to_dict") else dict(c) for c in matched]

    def query_patterns(self, entity: str) -> list[dict[str, Any]]:
        matched = [p for p in self.patterns if entity in getattr(p, "primary_entities", ()) or entity in getattr(p, "target_entities", ())]
        return [p.to_dict() if hasattr(p, "to_dict") else dict(p) for p in matched]

    def query_attack_states(self, entity: str) -> dict[str, Any] | None:
        k = self.kinematics.get(entity)
        return k.to_dict() if k and hasattr(k, "to_dict") else k

    def query_transitions(self, entity: str) -> list[dict[str, Any]]:
        k = self.kinematics.get(entity)
        if k and hasattr(k, "transitions"):
            return [t.to_dict() if hasattr(t, "to_dict") else dict(t) for t in k.transitions]
        return []

    def query_evidence(self, entity: str) -> list[dict[str, Any]]:
        if self.graph and hasattr(self.graph, "get_entity_evidence"):
            return self.graph.get_entity_evidence(entity)
        inv = self.entity_investigations.get(entity)
        if inv and hasattr(inv, "findings"):
            return [f.to_dict() if hasattr(f, "to_dict") else dict(f) for f in inv.findings]
        return []

    def query_mitre(self, entity: str) -> list[str]:
        techs: set[str] = set()
        p = self.profiles.get(entity)
        if p and hasattr(p, "mitre_techniques"):
            techs.update(getattr(p, "mitre_techniques", ()))
        for pat in self.patterns:
            if entity in getattr(pat, "primary_entities", ()):
                techs.update(getattr(pat, "mitre_techniques", ()))
        for cmp in self.campaigns:
            if entity in getattr(cmp, "primary_entities", ()):
                techs.update(getattr(cmp, "mitre_techniques", ()))
        return sorted(techs)

    def query_forecast(self, entity: str) -> dict[str, Any] | None:
        fc = self.forecast_context.get(entity)
        return fc.to_dict() if fc and hasattr(fc, "to_dict") else fc

    def query_contradictions(self, entity: str) -> list[str]:
        if entity in self.contradictions:
            return [str(c) for c in self.contradictions[entity]]
        inv = self.entity_investigations.get(entity)
        if inv and hasattr(inv, "contradictions"):
            return list(inv.contradictions)
        story = next((s for s in self.stories if getattr(s, "entity", "") == entity), None)
        if story and hasattr(story, "contradicting_evidence"):
            return list(story.contradicting_evidence)
        return []

    def query_risk(self, entity: str) -> dict[str, Any] | None:
        p = next((pr for pr in self.prioritized if getattr(pr, "entity", "") == entity), None)
        return p.to_dict() if p and hasattr(p, "to_dict") else None

    def query_mitigations(self, entity: str) -> list[dict[str, Any]]:
        matched = [m for m in self.mitigations if getattr(m, "target_entity", "") == entity]
        return [m.to_dict() if hasattr(m, "to_dict") else dict(m) for m in matched]

    def query_targeted_entities(self, entity: str) -> list[str]:
        targets: set[str] = set()
        for p in self.patterns:
            if entity in getattr(p, "primary_entities", ()):
                targets.update(getattr(p, "target_entities", ()))
        for c in self.campaigns:
            if entity in getattr(c, "primary_entities", ()):
                targets.update(getattr(c, "target_entities", ()))
        return sorted(targets)
