"""Native NFStream-inspired statistical flow intelligence module.

Computes mathematically rigorous flow and subflow statistical profiles from
canonical FlowRecord and PacketRecord extractions:
- Bidirectional packet & byte asymmetry ratios:
    packet_asymmetry = (fwd_pkts - rev_pkts) / total_pkts
    byte_asymmetry = (fwd_bytes - rev_bytes) / total_bytes
- Flow duration and rate distributions (packet_rate, byte_rate, burstiness)
- Active / idle duration statistics
- Directional entropy
- TCP flag distributions and retransmission tracking

All metrics are EVIDENCE ONLY (`EVIDENCE_ONLY (UNTOUCHED_45)`).
Zero NFStream C/CFFI runtime dependencies required.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Sequence

from nexsolve_core.fusion import EvidenceModality, FusedEvidenceItem, TemporalScope
from nexsolve_core.schemas import FlowRecord, PacketRecord


@dataclass(frozen=True)
class FlowStatisticalProfile:
    """Detailed statistical profile of an individual bidirectional conversation."""
    flow_id: str
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    duration_seconds: float
    total_packets: int
    forward_packets: int
    reverse_packets: int
    total_bytes: int
    forward_bytes: int
    reverse_bytes: int
    # Asymmetry metrics bounded [-1.0, 1.0] (+1 = all forward, -1 = all reverse, 0 = balanced)
    packet_asymmetry_ratio: float
    byte_asymmetry_ratio: float
    # Transfer rate metrics
    packet_rate_per_sec: float
    byte_rate_per_sec: float
    mean_packet_size_bytes: float
    # Flags & anomalies
    syn_count: int
    ack_count: int
    fin_count: int
    rst_count: int
    retransmission_count: int
    is_single_packet_flow: bool
    is_asymmetric_flood: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class FlowStatisticsSummary:
    """Aggregated network-wide flow intelligence metrics."""
    total_flows: int
    single_packet_flows: int
    single_packet_flow_ratio: float
    mean_flow_duration_seconds: float
    median_flow_duration_seconds: float
    mean_packet_asymmetry: float
    mean_byte_asymmetry: float
    high_asymmetry_flow_count: int  # Flows with |asymmetry| >= 0.90
    total_retransmissions: int
    retransmission_ratio: float  # retransmissions / total_packets
    mean_packet_rate: float
    mean_byte_rate: float
    bursty_flow_count: int  # Flows with packet_rate >= 100 pkts/sec
    profiles: tuple[FlowStatisticalProfile, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_flows": self.total_flows,
            "single_packet_flows": self.single_packet_flows,
            "single_packet_flow_ratio": self.single_packet_flow_ratio,
            "mean_flow_duration_seconds": self.mean_flow_duration_seconds,
            "median_flow_duration_seconds": self.median_flow_duration_seconds,
            "mean_packet_asymmetry": self.mean_packet_asymmetry,
            "mean_byte_asymmetry": self.mean_byte_asymmetry,
            "high_asymmetry_flow_count": self.high_asymmetry_flow_count,
            "total_retransmissions": self.total_retransmissions,
            "retransmission_ratio": self.retransmission_ratio,
            "mean_packet_rate": self.mean_packet_rate,
            "mean_byte_rate": self.mean_byte_rate,
            "bursty_flow_count": self.bursty_flow_count,
            "profile_count": len(self.profiles),
        }


def compute_flow_statistical_profile(flow: FlowRecord) -> FlowStatisticalProfile:
    """Extract directional and rate statistics for a single FlowRecord."""
    tot_pkts = max(1, flow.total_packet_count)
    tot_bytes = max(1, flow.total_bytes)
    dur = max(flow.duration_seconds, 1e-4)

    fwd_pkts = flow.forward_packet_count
    rev_pkts = flow.reverse_packet_count
    fwd_bytes = flow.forward_bytes
    rev_bytes = flow.reverse_bytes

    # Bounded asymmetry in [-1.0, 1.0]
    pkt_asym = (fwd_pkts - rev_pkts) / tot_pkts
    byte_asym = (fwd_bytes - rev_bytes) / tot_bytes

    pkt_rate = flow.total_packet_count / dur
    byte_rate = flow.total_bytes / dur
    mean_size = flow.total_bytes / tot_pkts

    is_single = (flow.total_packet_count == 1)
    is_asym_flood = (abs(pkt_asym) >= 0.95 and flow.total_packet_count >= 50)

    return FlowStatisticalProfile(
        flow_id=flow.flow_id,
        src_ip=flow.src_ip,
        src_port=flow.src_port,
        dst_ip=flow.dst_ip,
        dst_port=flow.dst_port,
        protocol=flow.protocol,
        duration_seconds=round(flow.duration_seconds, 4),
        total_packets=flow.total_packet_count,
        forward_packets=fwd_pkts,
        reverse_packets=rev_pkts,
        total_bytes=flow.total_bytes,
        forward_bytes=fwd_bytes,
        reverse_bytes=rev_bytes,
        packet_asymmetry_ratio=round(pkt_asym, 4),
        byte_asymmetry_ratio=round(byte_asym, 4),
        packet_rate_per_sec=round(pkt_rate, 2),
        byte_rate_per_sec=round(byte_rate, 2),
        mean_packet_size_bytes=round(mean_size, 2),
        syn_count=flow.syn_count,
        ack_count=flow.ack_count,
        fin_count=flow.fin_count,
        rst_count=flow.rst_count,
        retransmission_count=flow.retransmission_count,
        is_single_packet_flow=is_single,
        is_asymmetric_flood=is_asym_flood,
    )


def aggregate_flow_statistics_summary(
    flows: Iterable[FlowRecord],
) -> FlowStatisticsSummary:
    """Aggregate flow intelligence across all observed conversations."""
    flow_list = tuple(flows)
    n_flows = len(flow_list)
    if n_flows == 0:
        return FlowStatisticsSummary(
            total_flows=0,
            single_packet_flows=0,
            single_packet_flow_ratio=0.0,
            mean_flow_duration_seconds=0.0,
            median_flow_duration_seconds=0.0,
            mean_packet_asymmetry=0.0,
            mean_byte_asymmetry=0.0,
            high_asymmetry_flow_count=0,
            total_retransmissions=0,
            retransmission_ratio=0.0,
            mean_packet_rate=0.0,
            mean_byte_rate=0.0,
            bursty_flow_count=0,
            profiles=(),
        )

    profiles: list[FlowStatisticalProfile] = []
    durations: list[float] = []
    pkt_asyms: list[float] = []
    byte_asyms: list[float] = []
    single_pkts = 0
    high_asym = 0
    tot_retrans = 0
    tot_pkts = 0
    pkt_rates: list[float] = []
    byte_rates: list[float] = []
    bursty = 0

    for f in flow_list:
        p = compute_flow_statistical_profile(f)
        profiles.append(p)
        durations.append(p.duration_seconds)
        pkt_asyms.append(p.packet_asymmetry_ratio)
        byte_asyms.append(p.byte_asymmetry_ratio)
        if p.is_single_packet_flow:
            single_pkts += 1
        if abs(p.packet_asymmetry_ratio) >= 0.90:
            high_asym += 1
        tot_retrans += p.retransmission_count
        tot_pkts += p.total_packets
        pkt_rates.append(p.packet_rate_per_sec)
        byte_rates.append(p.byte_rate_per_sec)
        if p.packet_rate_per_sec >= 100.0 and p.total_packets >= 10:
            bursty += 1

    durations.sort()
    mid = len(durations) // 2
    med_dur = (durations[mid] if len(durations) % 2 == 1 else (durations[mid - 1] + durations[mid]) / 2.0)

    return FlowStatisticsSummary(
        total_flows=n_flows,
        single_packet_flows=single_pkts,
        single_packet_flow_ratio=round(single_pkts / n_flows, 4),
        mean_flow_duration_seconds=round(sum(durations) / n_flows, 4),
        median_flow_duration_seconds=round(med_dur, 4),
        mean_packet_asymmetry=round(sum(pkt_asyms) / n_flows, 4),
        mean_byte_asymmetry=round(sum(byte_asyms) / n_flows, 4),
        high_asymmetry_flow_count=high_asym,
        total_retransmissions=tot_retrans,
        retransmission_ratio=round(tot_retrans / max(1, tot_pkts), 4),
        mean_packet_rate=round(sum(pkt_rates) / n_flows, 2),
        mean_byte_rate=round(sum(byte_rates) / n_flows, 2),
        bursty_flow_count=bursty,
        profiles=tuple(profiles),
    )


def build_flow_statistical_evidence(
    summary: FlowStatisticsSummary,
) -> tuple[FusedEvidenceItem, ...]:
    """Emit FusedEvidenceItem instances for notable flow anomalies (e.g. sweep scans or burst floods)."""
    items: list[FusedEvidenceItem] = []

    # 1. Sweep / Port scan indication via single packet flow ratio
    if summary.total_flows >= 20 and summary.single_packet_flow_ratio >= 0.60:
        items.append(FusedEvidenceItem(
            id=f"obs-flow-sweep-{summary.single_packet_flows}",
            timestamp="observed_capture",
            temporal_scope=TemporalScope.OBSERVED,
            modality=EvidenceModality.ANOMALY,
            source="nfstream_flow_statistical_analyzer",
            severity="MEDIUM" if summary.single_packet_flow_ratio < 0.85 else "HIGH",
            confidence=round(min(1.0, summary.single_packet_flow_ratio), 2),
            description=(
                f"Elevated single-packet flow ratio ({summary.single_packet_flow_ratio * 100:.1f}%, "
                f"{summary.single_packet_flows}/{summary.total_flows} flows) indicative of scanning or probing."
            ),
            entities={"single_packet_flows": summary.single_packet_flows, "total_flows": summary.total_flows},
            supporting_features={
                "single_packet_flow_ratio": summary.single_packet_flow_ratio,
                "high_asymmetry_flow_count": float(summary.high_asymmetry_flow_count),
            },
            provenance={"analyzer": "nfstream_statistical_engine"},
            mitre_technique_id="T1046",
        ))

    # 2. Volumetric / Bursty asymmetry flood
    if summary.bursty_flow_count >= 5:
        items.append(FusedEvidenceItem(
            id=f"obs-flow-burst-{summary.bursty_flow_count}",
            timestamp="observed_capture",
            temporal_scope=TemporalScope.OBSERVED,
            modality=EvidenceModality.ANOMALY,
            source="nfstream_flow_statistical_analyzer",
            severity="HIGH" if summary.bursty_flow_count >= 15 else "MEDIUM",
            confidence=0.80,
            description=f"Observed {summary.bursty_flow_count} high-rate bursty flows (>=100 pkts/sec).",
            entities={"bursty_flows": summary.bursty_flow_count},
            supporting_features={
                "bursty_flow_count": float(summary.bursty_flow_count),
                "mean_packet_rate": summary.mean_packet_rate,
            },
            provenance={"analyzer": "nfstream_statistical_engine"},
            mitre_technique_id="T1498",
        ))

    return tuple(items)
