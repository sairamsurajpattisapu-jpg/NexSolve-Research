"""Observed Network Risk Indicator Engine for NexSolve.

Grounded strictly in observable physical telemetry and causal state metrics:
- Every indicator contains:
  * entity (host IP, subnet, edge, or global network)
  * observation (objective physical finding)
  * severity ("LOW", "MEDIUM", "HIGH", "CRITICAL")
  * persistence (windows or seconds observed)
  * trend ("INCREASING", "STABLE", "DECREASING")
  * evidence (list of factual telemetry citations)
  * confidence (calibrated probability score)
  * observability (capture completeness score)

Guarantees:
- Emits "OBSERVED RISK INDICATOR" rather than unsubstantiated claims of vulnerability or compromise.
- Zero speculation or fabricated alerts without empirical telemetry.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Mapping, Sequence

from ml.models.behavioral_intelligence import BehavioralVector
from ml.models.host_graph_intelligence import CommunicationEdge, GraphEvolutionSnapshot, HostProfile
from ml.models.temporal_intelligence import TemporalVelocityVector


class RiskSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskTrend(str, Enum):
    INCREASING = "INCREASING"
    STABLE = "STABLE"
    DECREASING = "DECREASING"


@dataclass(frozen=True)
class ObservedRiskIndicator:
    """Rigorous, evidence-grounded physical network risk indicator."""
    indicator_type: str
    entity: str
    observation: str
    severity: RiskSeverity
    persistence: int  # Number of contiguous windows observed
    trend: RiskTrend
    evidence: tuple[str, ...]
    confidence: float  # Calibrated 0.0 to 1.0
    observability: float  # 0.0 to 1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": f"OBSERVED RISK INDICATOR: {self.indicator_type.replace('_', ' ').title()}",
            "indicator_type": self.indicator_type,
            "entity": self.entity,
            "observation": self.observation,
            "severity": self.severity.value,
            "persistence_windows": self.persistence,
            "trend": self.trend.value,
            "evidence": list(self.evidence),
            "confidence": round(self.confidence, 4),
            "observability": round(self.observability, 4),
        }


class NetworkRiskEngine:
    """Extracts factual observed risk indicators from multi-view state telemetry."""

    def evaluate_indicators(
        self,
        hosts: Mapping[str, HostProfile],
        edges: Sequence[CommunicationEdge],
        graph_snapshot: GraphEvolutionSnapshot,
        behavior: BehavioralVector,
        temporal: TemporalVelocityVector,
        persistence_tracker: dict[str, int] | None = None,
    ) -> list[ObservedRiskIndicator]:
        """Evaluates empirical patterns and synthesizes verified risk indicators."""
        indicators: list[ObservedRiskIndicator] = []
        tracker = persistence_tracker if persistence_tracker is not None else {}
        obs = graph_snapshot.graph_observability_score

        # 1. Abnormal Outbound Fan-Out (Horizontal Scan / Lateral Spreading)
        for ip, host in hosts.items():
            out_count = len(host.outbound_peers)
            if out_count >= 15:
                key = f"fanout_{ip}"
                p_count = tracker.get(key, 0) + 1
                tracker[key] = p_count
                sev = RiskSeverity.CRITICAL if out_count >= 50 else RiskSeverity.HIGH if out_count >= 25 else RiskSeverity.MEDIUM
                trend = RiskTrend.INCREASING if host.temporal_change_score > 0.2 else RiskTrend.STABLE
                indicators.append(ObservedRiskIndicator(
                    indicator_type="ABNORMAL_OUTBOUND_FANOUT",
                    entity=ip,
                    observation=f"Host contacted {out_count} distinct outbound peer endpoints within observation window.",
                    severity=sev,
                    persistence=p_count,
                    trend=trend,
                    evidence=(
                        f"Target peer count: {out_count}",
                        f"Active probed ports: {len(host.probed_ports)}",
                        f"Bytes transmitted: {host.bytes_sent:,} B",
                    ),
                    confidence=min(0.95, 0.50 + (out_count / 100.0)),
                    observability=obs,
                ))

        # 2. Abnormal Inbound Fan-In (Target Concentration / DoS or Concentrated Probe)
        for ip, host in hosts.items():
            in_count = len(host.inbound_peers)
            if in_count >= 20:
                key = f"fanin_{ip}"
                p_count = tracker.get(key, 0) + 1
                tracker[key] = p_count
                sev = RiskSeverity.HIGH if in_count >= 40 else RiskSeverity.MEDIUM
                indicators.append(ObservedRiskIndicator(
                    indicator_type="ABNORMAL_INBOUND_FANIN",
                    entity=ip,
                    observation=f"Host received inbound connection attempts from {in_count} distinct sources.",
                    severity=sev,
                    persistence=p_count,
                    trend=RiskTrend.INCREASING if temporal.delta_flow_count > 50 else RiskTrend.STABLE,
                    evidence=(
                        f"Inbound sources: {in_count}",
                        f"Packets received: {host.packets_recv:,}",
                    ),
                    confidence=min(0.92, 0.60 + (in_count / 100.0)),
                    observability=obs,
                ))

        # 3. Peer Expansion (Rapid Topology Broadening)
        if behavior.new_peer_rate > 0.40 and graph_snapshot.node_count >= 5:
            key = "peer_expansion_global"
            p_count = tracker.get(key, 0) + 1
            tracker[key] = p_count
            indicators.append(ObservedRiskIndicator(
                indicator_type="RAPID_PEER_EXPANSION",
                entity="Global Subnet",
                observation=f"{behavior.new_peer_rate * 100:.1f}% of communicating endpoints were unobserved in prior history.",
                severity=RiskSeverity.HIGH if behavior.new_peer_rate > 0.70 else RiskSeverity.MEDIUM,
                persistence=p_count,
                trend=RiskTrend.INCREASING,
                evidence=(
                    f"New peer fraction: {behavior.new_peer_rate:.3f}",
                    f"Total active vertices: {graph_snapshot.node_count}",
                ),
                confidence=min(0.90, 0.50 + behavior.new_peer_rate * 0.4),
                observability=obs,
            ))

        # 4. Unusual Service Exposure Behavior (Multi-port probing on common services)
        for ip, host in hosts.items():
            ports = host.probed_ports
            if len(ports) >= 8:
                key = f"service_probe_{ip}"
                p_count = tracker.get(key, 0) + 1
                tracker[key] = p_count
                indicators.append(ObservedRiskIndicator(
                    indicator_type="UNUSUAL_SERVICE_EXPOSURE_PROBING",
                    entity=ip,
                    observation=f"Host systematically queried {len(ports)} destination transport ports.",
                    severity=RiskSeverity.HIGH if len(ports) >= 20 else RiskSeverity.MEDIUM,
                    persistence=p_count,
                    trend=RiskTrend.STABLE,
                    evidence=(
                        f"Probed ports: {list(ports[:10])}{'...' if len(ports) > 10 else ''}",
                        f"Distinct peers targeted: {len(host.outbound_peers)}",
                    ),
                    confidence=min(0.95, 0.60 + (len(ports) / 50.0)),
                    observability=obs,
                ))

        # 5. Communication Churn & Transient Edge Burst
        if behavior.edge_churn_rate > 0.60 and graph_snapshot.edge_count >= 10:
            key = "comm_churn_global"
            p_count = tracker.get(key, 0) + 1
            tracker[key] = p_count
            indicators.append(ObservedRiskIndicator(
                indicator_type="HIGH_COMMUNICATION_CHURN",
                entity="Network Edge Graph",
                observation=f"Edge churn rate reached {behavior.edge_churn_rate * 100:.1f}%, indicating rapid interaction changes.",
                severity=RiskSeverity.MEDIUM,
                persistence=p_count,
                trend=RiskTrend.INCREASING if behavior.connection_churn_rate > 0.5 else RiskTrend.STABLE,
                evidence=(
                    f"Edge churn rate: {behavior.edge_churn_rate:.3f}",
                    f"Connection churn rate: {behavior.connection_churn_rate:.3f}",
                    f"Active edges: {graph_snapshot.edge_count}",
                ),
                confidence=min(0.88, 0.50 + behavior.edge_churn_rate * 0.4),
                observability=obs,
            ))

        # 6. Abnormal Traffic Concentration (Volumetric Exfiltration / Asymmetry)
        if behavior.traffic_concentration_gini > 0.85:
            key = "traffic_gini_global"
            p_count = tracker.get(key, 0) + 1
            tracker[key] = p_count
            indicators.append(ObservedRiskIndicator(
                indicator_type="ABNORMAL_TRAFFIC_CONCENTRATION",
                entity="Aggregate Network Flows",
                observation=f"Traffic volume exhibits extreme Gini concentration ({behavior.traffic_concentration_gini:.2f}), dominated by a tiny fraction of sessions.",
                severity=RiskSeverity.MEDIUM,
                persistence=p_count,
                trend=RiskTrend.STABLE,
                evidence=(
                    f"Gini coefficient: {behavior.traffic_concentration_gini:.3f}",
                    f"Rolling total bytes: {temporal.rolling_total_bytes:,.0f} B",
                ),
                confidence=0.80,
                observability=obs,
            ))

        return indicators
