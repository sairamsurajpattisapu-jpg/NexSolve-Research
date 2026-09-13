"""Arkime-inspired session-centric investigation data model for NexSolve.

Represents individual bidirectional communications as forensic session entities
linking 5-tuples, packet/byte counts, temporal duration, behavioral signals,
and MITRE ATT&CK techniques.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Sequence

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
        return asdict(self)


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
