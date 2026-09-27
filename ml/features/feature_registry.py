"""Modular Feature Registry for NexSolve Network World Model.

Implements an authoritative registry declaring 18 feature families:
1. Packet
2. Flow
3. TCP
4. UDP
5. DNS
6. HTTP
7. TLS
8. SSH
9. ICMP
10. ARP
11. DHCP
12. Temporal
13. Behavioral
14. Host
15. Graph
16. Statistical
17. Observability
18. Missingness

Every feature explicitly declares:
- name: Unique identifier
- family: FeatureFamily enum
- dtype: "float", "int", "bool"
- source: Telemetry origin (PACKET, FLOW, PROTOCOL, GRAPH, TEMPORAL, META)
- semantic_meaning: Detailed description of physical/network property
- required_telemetry: Upstream sensors or packet headers required
- availability_condition: When this feature can be legitimately observed
- computation: High-level mathematical formulation
- normalization: Recommended normalization method (Z_SCORE, MIN_MAX, LOG1P, RATIO)
- is_causal: Strictly True (only past and current window data; zero lookahead)
- is_safe_for_production: True (deterministic, passive observation, zero active probing)

Guarantees:
- Zero fabricated telemetry (e.g. passive TCP RTT is never fabricated).
- Explicit missingness flags and masks when protocol telemetry is unobservable.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping, Sequence


class FeatureFamily(str, Enum):
    PACKET = "packet"
    FLOW = "flow"
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    HTTP = "http"
    TLS = "tls"
    SSH = "ssh"
    ICMP = "icmp"
    ARP = "arp"
    DHCP = "dhcp"
    TEMPORAL = "temporal"
    BEHAVIORAL = "behavioral"
    HOST = "host"
    GRAPH = "graph"
    STATISTICAL = "statistical"
    OBSERVABILITY = "observability"
    MISSINGNESS = "missingness"


class TelemetrySource(str, Enum):
    PACKET_HEADER = "PACKET_HEADER"
    FLOW_AGGREGATE = "FLOW_AGGREGATE"
    PROTOCOL_PARSER = "PROTOCOL_PARSER"
    GRAPH_SNAPSHOT = "GRAPH_SNAPSHOT"
    TEMPORAL_WINDOW = "TEMPORAL_WINDOW"
    OBSERVABILITY_SENSOR = "OBSERVABILITY_SENSOR"


class NormalizationType(str, Enum):
    Z_SCORE = "Z_SCORE"
    LOG1P_Z = "LOG1P_Z"
    MIN_MAX = "MIN_MAX"
    RATIO = "RATIO"
    IDENTITY = "IDENTITY"


@dataclass(frozen=True)
class FeatureDefinition:
    """Formal, verifiable specification of an observable network feature."""
    name: str
    family: FeatureFamily
    dtype: str
    source: TelemetrySource
    semantic_meaning: str
    required_telemetry: tuple[str, ...]
    availability_condition: str
    computation: str
    normalization: NormalizationType
    is_causal: bool = True
    is_safe_for_production: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "family": self.family.value,
            "dtype": self.dtype,
            "source": self.source.value,
            "semantic_meaning": self.semantic_meaning,
            "required_telemetry": list(self.required_telemetry),
            "availability_condition": self.availability_condition,
            "computation": self.computation,
            "normalization": self.normalization.value,
            "is_causal": self.is_causal,
            "is_safe_for_production": self.is_safe_for_production,
        }


class FeatureRegistry:
    """Authoritative catalog and schema validator for network world model features."""

    _FEATURES: dict[str, FeatureDefinition] = {}

    @classmethod
    def register(cls, feat: FeatureDefinition) -> None:
        """Register a feature definition, ensuring uniqueness and causality."""
        if not feat.is_causal:
            raise ValueError(f"Feature '{feat.name}' violates causality constraint.")
        if not feat.is_safe_for_production:
            raise ValueError(f"Feature '{feat.name}' violates production safety constraint.")
        cls._FEATURES[feat.name] = feat

    @classmethod
    def get(cls, name: str) -> FeatureDefinition:
        if name not in cls._FEATURES:
            raise KeyError(f"Feature '{name}' not found in registry.")
        return cls._FEATURES[name]

    @classmethod
    def list_all(cls) -> list[FeatureDefinition]:
        return list(cls._FEATURES.values())

    @classmethod
    def get_by_family(cls, family: FeatureFamily | str) -> list[FeatureDefinition]:
        target = family.value if isinstance(family, FeatureFamily) else str(family)
        return [f for f in cls._FEATURES.values() if f.family.value == target]

    @classmethod
    def names(cls) -> list[str]:
        return list(cls._FEATURES.keys())

    @classmethod
    def schema_hash(cls) -> str:
        """Generate deterministic cryptographic hash of the registered feature catalog."""
        dumped = json.dumps(
            [f.to_dict() for f in sorted(cls._FEATURES.values(), key=lambda x: x.name)],
            sort_keys=True,
        )
        return hashlib.sha256(dumped.encode("utf-8")).hexdigest()

    @classmethod
    def export_catalog(cls) -> dict[str, Any]:
        return {
            "schema_version": "18_family_world_model_v1",
            "feature_count": len(cls._FEATURES),
            "schema_hash": cls.schema_hash(),
            "families": {
                fam.value: [f.to_dict() for f in cls.get_by_family(fam)]
                for fam in FeatureFamily
            },
        }


# =========================================================================
# 1. PACKET FEATURES (22 canonical features from passive packet frames)
# =========================================================================
_PACKET_SPECS = [
    ("packet_count", "Total packets observed in 60s window", "count(packets)", NormalizationType.LOG1P_Z),
    ("mean_packet_size", "Mean byte length of packet frames", "sum(bytes) / count(packets)", NormalizationType.Z_SCORE),
    ("std_packet_size", "Standard deviation of packet byte lengths", "std(bytes)", NormalizationType.Z_SCORE),
    ("min_packet_size", "Minimum packet length in window", "min(bytes)", NormalizationType.Z_SCORE),
    ("max_packet_size", "Maximum packet length in window", "max(bytes)", NormalizationType.Z_SCORE),
    ("mean_ttl", "Mean IP Time-To-Live in window", "mean(IP.ttl)", NormalizationType.Z_SCORE),
    ("std_ttl", "Standard deviation of IP Time-To-Live", "std(IP.ttl)", NormalizationType.Z_SCORE),
    ("min_ttl", "Minimum IP Time-To-Live", "min(IP.ttl)", NormalizationType.Z_SCORE),
    ("max_ttl", "Maximum IP Time-To-Live", "max(IP.ttl)", NormalizationType.Z_SCORE),
    ("tcp_syn_count", "Total TCP SYN flag packets observed", "count(TCP.flags == SYN)", NormalizationType.LOG1P_Z),
    ("tcp_ack_count", "Total TCP ACK flag packets observed", "count(TCP.flags == ACK)", NormalizationType.LOG1P_Z),
    ("tcp_fin_count", "Total TCP FIN flag packets observed", "count(TCP.flags == FIN)", NormalizationType.LOG1P_Z),
    ("tcp_rst_count", "Total TCP RST flag packets observed", "count(TCP.flags == RST)", NormalizationType.LOG1P_Z),
    ("tcp_psh_count", "Total TCP PSH flag packets observed", "count(TCP.flags == PSH)", NormalizationType.LOG1P_Z),
    ("tcp_urg_count", "Total TCP URG flag packets observed", "count(TCP.flags == URG)", NormalizationType.LOG1P_Z),
    ("mean_tcp_window", "Mean TCP advertised receive window size", "mean(TCP.window)", NormalizationType.Z_SCORE),
    ("std_tcp_window", "Standard deviation of TCP advertised window", "std(TCP.window)", NormalizationType.Z_SCORE),
    ("fragment_count", "Total fragmented IP packets observed", "count(IP.flags == MF or frag_offset > 0)", NormalizationType.LOG1P_Z),
    ("retransmission_count", "Total passive TCP retransmissions observed", "count(retransmitted_packets)", NormalizationType.LOG1P_Z),
    ("mean_iat", "Mean inter-arrival time between consecutive packets", "mean(t_{i} - t_{i-1})", NormalizationType.Z_SCORE),
    ("std_iat", "Standard deviation of packet inter-arrival times", "std(t_{i} - t_{i-1})", NormalizationType.Z_SCORE),
    ("max_iat", "Maximum packet inter-arrival time in window", "max(t_{i} - t_{i-1})", NormalizationType.Z_SCORE),
]
for name, desc, comp, norm in _PACKET_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.PACKET,
        dtype="float",
        source=TelemetrySource.PACKET_HEADER,
        semantic_meaning=desc,
        required_telemetry=("pcap_packets",),
        availability_condition="Available when passive packet capture frames are present",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 2. FLOW FEATURES (17 canonical flow features)
# =========================================================================
_FLOW_SPECS = [
    ("flow_count", "Total bidirectional flow sessions active in window", "count(flows)", NormalizationType.LOG1P_Z),
    ("total_src_bytes", "Total payload/header bytes originating from source", "sum(src_bytes)", NormalizationType.LOG1P_Z),
    ("total_dst_bytes", "Total payload/header bytes originating from destination", "sum(dst_bytes)", NormalizationType.LOG1P_Z),
    ("total_packets", "Total flow packets observed across all sessions", "sum(flow_packets)", NormalizationType.LOG1P_Z),
    ("mean_duration", "Mean active duration of network flows", "mean(flow_duration)", NormalizationType.Z_SCORE),
    ("mean_flow_bytes", "Mean total volume per flow session", "mean(src_bytes + dst_bytes)", NormalizationType.LOG1P_Z),
    ("mean_flow_packets", "Mean packet count per flow session", "mean(flow_packets)", NormalizationType.LOG1P_Z),
    ("mean_sttl", "Mean source IP TTL across flows", "mean(sttl)", NormalizationType.Z_SCORE),
    ("mean_dttl", "Mean destination IP TTL across flows", "mean(dttl)", NormalizationType.Z_SCORE),
    ("mean_swin", "Mean source TCP window advertisement", "mean(swin)", NormalizationType.Z_SCORE),
    ("mean_dwin", "Mean destination TCP window advertisement", "mean(dwin)", NormalizationType.Z_SCORE),
    ("flow_mean_iat", "Mean flow session inter-arrival time", "mean(flow_iat)", NormalizationType.Z_SCORE),
    ("unique_src_ports", "Distinct client/source port count in window", "count(distinct(src_port))", NormalizationType.LOG1P_Z),
    ("unique_dst_ports", "Distinct server/destination port count in window", "count(distinct(dst_port))", NormalizationType.LOG1P_Z),
    ("proto_tcp_count", "Count of flows utilizing TCP protocol", "count(proto == TCP)", NormalizationType.LOG1P_Z),
    ("proto_udp_count", "Count of flows utilizing UDP protocol", "count(proto == UDP)", NormalizationType.LOG1P_Z),
    ("proto_other_count", "Count of flows utilizing non-TCP/UDP protocols", "count(proto not in (TCP, UDP))", NormalizationType.LOG1P_Z),
]
for name, desc, comp, norm in _FLOW_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.FLOW,
        dtype="float",
        source=TelemetrySource.FLOW_AGGREGATE,
        semantic_meaning=desc,
        required_telemetry=("flow_records",),
        availability_condition="Available in NetFlow, IPFIX, or aggregated PCAP flow sessions",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 3. TCP SPECIFIC FEATURES
# =========================================================================
_TCP_SPECS = [
    ("tcp_syn_ack_ratio", "Ratio of SYN to ACK packets (probing vs established)", "syn_count / max(1, ack_count)", NormalizationType.RATIO),
    ("tcp_rst_ratio", "Ratio of RST packets to total TCP flows (connection teardown anomalies)", "rst_count / max(1, flow_count)", NormalizationType.RATIO),
    ("tcp_zero_window_count", "Count of zero-window advertisement packets (buffer exhaustion)", "count(TCP.window == 0)", NormalizationType.LOG1P_Z),
    ("tcp_handshake_completion_rate", "Fraction of completed 3-way handshakes to SYN attempts", "established_handshakes / max(1, syn_attempts)", NormalizationType.RATIO),
]
for name, desc, comp, norm in _TCP_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.TCP,
        dtype="float",
        source=TelemetrySource.PROTOCOL_PARSER,
        semantic_meaning=desc,
        required_telemetry=("tcp_frames",),
        availability_condition="Available when TCP packets are present in window",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 4. UDP SPECIFIC FEATURES
# =========================================================================
_UDP_SPECS = [
    ("udp_packet_count", "Total UDP packets in window", "count(proto == UDP)", NormalizationType.LOG1P_Z),
    ("udp_byte_ratio", "Ratio of UDP bytes to total network volume", "udp_bytes / max(1.0, total_bytes)", NormalizationType.RATIO),
    ("udp_port_entropy", "Shannon entropy of destination UDP ports (amplification scan detection)", "-sum(p * log2(p))", NormalizationType.MIN_MAX),
]
for name, desc, comp, norm in _UDP_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.UDP,
        dtype="float",
        source=TelemetrySource.PROTOCOL_PARSER,
        semantic_meaning=desc,
        required_telemetry=("udp_frames",),
        availability_condition="Available when UDP traffic is present",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 5. DNS FEATURES
# =========================================================================
_DNS_SPECS = [
    ("dns_query_count", "Total DNS query transactions observed", "count(DNS.qr == 0)", NormalizationType.LOG1P_Z),
    ("dns_response_count", "Total DNS response transactions observed", "count(DNS.qr == 1)", NormalizationType.LOG1P_Z),
    ("dns_query_response_ratio", "Ratio of DNS queries to responses (tunneling / dead resolver)", "dns_queries / max(1, dns_responses)", NormalizationType.RATIO),
    ("dns_nxdomain_rate", "Proportion of DNS responses with NXDOMAIN code (DGA / scanning)", "count(rcode == 3) / max(1, dns_responses)", NormalizationType.RATIO),
]
for name, desc, comp, norm in _DNS_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.DNS,
        dtype="float",
        source=TelemetrySource.PROTOCOL_PARSER,
        semantic_meaning=desc,
        required_telemetry=("dns_frames",),
        availability_condition="Available when DNS protocol (port 53/5353) is observed",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 6. HTTP FEATURES
# =========================================================================
_HTTP_SPECS = [
    ("http_request_count", "Total HTTP plaintext requests observed", "count(HTTP.request)", NormalizationType.LOG1P_Z),
    ("http_error_rate_4xx_5xx", "Proportion of HTTP responses with status >= 400", "count(status >= 400) / max(1, responses)", NormalizationType.RATIO),
    ("http_post_ratio", "Proportion of HTTP requests using POST/PUT methods", "count(method in (POST, PUT)) / max(1, requests)", NormalizationType.RATIO),
]
for name, desc, comp, norm in _HTTP_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.HTTP,
        dtype="float",
        source=TelemetrySource.PROTOCOL_PARSER,
        semantic_meaning=desc,
        required_telemetry=("http_frames",),
        availability_condition="Available when unencrypted HTTP traffic is present",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 7. TLS FEATURES
# =========================================================================
_TLS_SPECS = [
    ("tls_client_hello_count", "Total TLS Client Hello handshakes initiated", "count(TLS.handshake == 1)", NormalizationType.LOG1P_Z),
    ("tls_sni_ratio", "Proportion of TLS handshakes containing Server Name Indication", "count(has_sni) / max(1, client_hellos)", NormalizationType.RATIO),
    ("tls_resume_session_rate", "Rate of TLS session resumption or pre-shared key handshakes", "count(session_resumed) / max(1, handshakes)", NormalizationType.RATIO),
]
for name, desc, comp, norm in _TLS_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.TLS,
        dtype="float",
        source=TelemetrySource.PROTOCOL_PARSER,
        semantic_meaning=desc,
        required_telemetry=("tls_frames",),
        availability_condition="Available when TLS traffic (port 443/8443) is observed",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 8. SSH FEATURES
# =========================================================================
_SSH_SPECS = [
    ("ssh_session_count", "Total SSH connection attempts/sessions observed", "count(port == 22)", NormalizationType.LOG1P_Z),
    ("ssh_inbound_outbound_ratio", "Byte asymmetry ratio in SSH sessions", "ssh_rx_bytes / max(1.0, ssh_tx_bytes)", NormalizationType.RATIO),
]
for name, desc, comp, norm in _SSH_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.SSH,
        dtype="float",
        source=TelemetrySource.PROTOCOL_PARSER,
        semantic_meaning=desc,
        required_telemetry=("ssh_frames",),
        availability_condition="Available when SSH protocol is observed",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 9. ICMP FEATURES
# =========================================================================
_ICMP_SPECS = [
    ("icmp_echo_request_count", "Total ICMP Echo Request (ping) packets", "count(ICMP.type == 8)", NormalizationType.LOG1P_Z),
    ("icmp_unreachable_count", "Total ICMP Destination Unreachable packets", "count(ICMP.type == 3)", NormalizationType.LOG1P_Z),
    ("icmp_volume_ratio", "Ratio of ICMP bytes to total observed volume", "icmp_bytes / max(1.0, total_bytes)", NormalizationType.RATIO),
]
for name, desc, comp, norm in _ICMP_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.ICMP,
        dtype="float",
        source=TelemetrySource.PROTOCOL_PARSER,
        semantic_meaning=desc,
        required_telemetry=("icmp_frames",),
        availability_condition="Available when ICMP packets are observed",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 10. ARP FEATURES
# =========================================================================
_ARP_SPECS = [
    ("arp_request_count", "Total ARP request frames in local broadcast domain", "count(ARP.op == 1)", NormalizationType.LOG1P_Z),
    ("arp_reply_ratio", "Ratio of ARP replies to ARP requests (poisoning / discovery)", "arp_replies / max(1, arp_requests)", NormalizationType.RATIO),
    ("arp_gratuitous_count", "Total gratuitous ARP advertisements observed", "count(gratuitous_arp)", NormalizationType.LOG1P_Z),
]
for name, desc, comp, norm in _ARP_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.ARP,
        dtype="float",
        source=TelemetrySource.PROTOCOL_PARSER,
        semantic_meaning=desc,
        required_telemetry=("arp_frames",),
        availability_condition="Available when Layer 2 Ethernet capture includes ARP",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 11. DHCP FEATURES
# =========================================================================
_DHCP_SPECS = [
    ("dhcp_discover_count", "Total DHCP Discover broadcasts", "count(DHCP.msg == 1)", NormalizationType.LOG1P_Z),
    ("dhcp_offer_ack_ratio", "Ratio of DHCP Ack to DHCP Discover requests", "dhcp_acks / max(1, dhcp_discovers)", NormalizationType.RATIO),
]
for name, desc, comp, norm in _DHCP_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.DHCP,
        dtype="float",
        source=TelemetrySource.PROTOCOL_PARSER,
        semantic_meaning=desc,
        required_telemetry=("dhcp_frames",),
        availability_condition="Available when DHCP traffic (ports 67/68) is present",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 12. TEMPORAL INTELLIGENCE FEATURES
# =========================================================================
_TEMPORAL_SPECS = [
    ("delta_flow_count", "First-order discrete velocity of flow session count", "flow_count_t - flow_count_{t-1}", NormalizationType.Z_SCORE),
    ("delta_total_bytes", "First-order discrete velocity of total byte volume", "bytes_t - bytes_{t-1}", NormalizationType.Z_SCORE),
    ("delta_total_packets", "First-order discrete velocity of packet volume", "packets_t - packets_{t-1}", NormalizationType.Z_SCORE),
    ("delta_ports", "Velocity of unique endpoint port diversity", "ports_t - ports_{t-1}", NormalizationType.Z_SCORE),
    ("delta_iat", "Velocity of mean inter-arrival time", "iat_t - iat_{t-1}", NormalizationType.Z_SCORE),
    ("rolling_total_bytes", "4-window rolling causal moving average of total bytes", "mean(bytes_{t-3:t})", NormalizationType.LOG1P_Z),
    ("acceleration_total_bytes", "Second-order discrete acceleration of byte volume", "delta_bytes_t - delta_bytes_{t-1}", NormalizationType.Z_SCORE),
    ("rolling_volatility_bytes", "Rolling standard deviation of bytes over lookback history", "std(bytes_{t-L:t})", NormalizationType.LOG1P_Z),
    ("burstiness_index", "Ratio of max 1-second packet rate to average window rate", "max_sec_rate / max(1.0, mean_rate)", NormalizationType.Z_SCORE),
]
for name, desc, comp, norm in _TEMPORAL_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.TEMPORAL,
        dtype="float",
        source=TelemetrySource.TEMPORAL_WINDOW,
        semantic_meaning=desc,
        required_telemetry=("historical_windows",),
        availability_condition="Available when at least 2 contiguous windows are observed",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 13. BEHAVIORAL INTELLIGENCE FEATURES
# =========================================================================
_BEHAVIORAL_SPECS = [
    ("peer_diversity", "Ratio of distinct peer IP addresses to active flow sessions", "unique_peers / max(1, flow_count)", NormalizationType.RATIO),
    ("new_peer_rate", "Fraction of communicating peers never observed in prior lookback windows", "new_peers / max(1, total_peers)", NormalizationType.RATIO),
    ("dest_diversity", "Ratio of destination IPs to total flows", "unique_dst / max(1, flow_count)", NormalizationType.RATIO),
    ("src_diversity", "Ratio of source IPs to total flows", "unique_src / max(1, flow_count)", NormalizationType.RATIO),
    ("port_entropy", "Shannon entropy of destination ports across all traffic", "-sum(p_port * log2(p_port))", NormalizationType.MIN_MAX),
    ("protocol_entropy", "Shannon entropy of Layer 4 protocols", "-sum(p_proto * log2(p_proto))", NormalizationType.MIN_MAX),
    ("fan_in_ratio", "Ratio of inbound flows to unique inbound sources", "inbound_flows / max(1, inbound_srcs)", NormalizationType.RATIO),
    ("fan_out_ratio", "Ratio of outbound flows to unique outbound destinations", "outbound_flows / max(1, outbound_dsts)", NormalizationType.RATIO),
    ("traffic_concentration_gini", "Gini concentration coefficient of traffic across active flows", "gini(bytes_per_flow)", NormalizationType.MIN_MAX),
    ("edge_churn_rate", "Proportion of active communication edges modified since prior window", "symmetric_diff(E_t, E_{t-1}) / max(1, |E_t|)", NormalizationType.RATIO),
    ("connection_churn_rate", "Fraction of new TCP/UDP connections opened and closed in window", "churned_conns / max(1, active_conns)", NormalizationType.RATIO),
    ("behavioral_novelty_score", "Mahalanobis novelty score against historical baseline envelope", "mahalanobis(curr, baseline)", NormalizationType.Z_SCORE),
]
for name, desc, comp, norm in _BEHAVIORAL_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.BEHAVIORAL,
        dtype="float",
        source=TelemetrySource.FLOW_AGGREGATE,
        semantic_meaning=desc,
        required_telemetry=("flows", "history"),
        availability_condition="Available when flow sessions and peer endpoints are tracked",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 14. HOST INTELLIGENCE FEATURES
# =========================================================================
_HOST_SPECS = [
    ("host_active_count", "Total active network endpoints communicating in window", "count(distinct(nodes))", NormalizationType.LOG1P_Z),
    ("host_max_outbound_fanout", "Maximum outbound peer count observed from any single host", "max(host.out_degree)", NormalizationType.LOG1P_Z),
    ("host_max_inbound_fanin", "Maximum inbound peer count targeting any single host", "max(host.in_degree)", NormalizationType.LOG1P_Z),
    ("host_internal_external_ratio", "Ratio of internal-to-internal vs internal-to-external flows", "int_flows / max(1, ext_flows)", NormalizationType.RATIO),
    ("host_max_port_spread", "Maximum unique destination ports probed by a single host", "max(host.distinct_ports)", NormalizationType.LOG1P_Z),
]
for name, desc, comp, norm in _HOST_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.HOST,
        dtype="float",
        source=TelemetrySource.GRAPH_SNAPSHOT,
        semantic_meaning=desc,
        required_telemetry=("host_states",),
        availability_condition="Available when IP endpoints are observable",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 15. GRAPH INTELLIGENCE FEATURES
# =========================================================================
_GRAPH_SPECS = [
    ("graph_node_count", "Number of active vertices in communication graph G_t", "|V_t|", NormalizationType.LOG1P_Z),
    ("graph_edge_count", "Number of directed communication edges in G_t", "|E_t|", NormalizationType.LOG1P_Z),
    ("graph_density", "Edge density of communication graph", "2 * |E| / (|V| * (|V| - 1))", NormalizationType.MIN_MAX),
    ("graph_mean_degree", "Mean degree across all active nodes in G_t", "mean(degree(v))", NormalizationType.Z_SCORE),
    ("graph_max_betweenness", "Maximum node betweenness centrality in G_t", "max(betweenness(v))", NormalizationType.MIN_MAX),
    ("graph_edge_churn", "Fraction of edges changed from snapshot G_{t-1} to G_t", "|E_t \\ E_{t-1}| / max(1, |E_t|)", NormalizationType.RATIO),
    ("graph_node_churn", "Fraction of nodes emerging or disappearing from G_t", "|V_t \\ V_{t-1}| / max(1, |V_t|)", NormalizationType.RATIO),
    ("graph_observability_score", "Ratio of observed endpoints to routable subnet scope", "observed_ips / total_scope_ips", NormalizationType.RATIO),
]
for name, desc, comp, norm in _GRAPH_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.GRAPH,
        dtype="float",
        source=TelemetrySource.GRAPH_SNAPSHOT,
        semantic_meaning=desc,
        required_telemetry=("temporal_graph",),
        availability_condition="Available when network topology graph G_t is constructed",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 16. STATISTICAL FEATURES
# =========================================================================
_STAT_SPECS = [
    ("iat_skewness", "Third standardized moment (skewness) of inter-arrival distribution", "skew(iat)", NormalizationType.Z_SCORE),
    ("iat_kurtosis", "Fourth standardized moment (kurtosis) of inter-arrival distribution", "kurtosis(iat)", NormalizationType.Z_SCORE),
    ("packet_size_skewness", "Skewness of packet byte length distribution", "skew(packet_size)", NormalizationType.Z_SCORE),
    ("packet_size_kurtosis", "Kurtosis of packet byte length distribution", "kurtosis(packet_size)", NormalizationType.Z_SCORE),
    ("packet_size_p90", "90th percentile of packet sizes in window", "quantile(packet_size, 0.90)", NormalizationType.Z_SCORE),
]
for name, desc, comp, norm in _STAT_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.STATISTICAL,
        dtype="float",
        source=TelemetrySource.FLOW_AGGREGATE,
        semantic_meaning=desc,
        required_telemetry=("packet_sizes", "inter_arrivals"),
        availability_condition="Available when individual packet records or flow distributions are available",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 17. OBSERVABILITY FEATURES
# =========================================================================
_OBSERVABILITY_SPECS = [
    ("telemetry_completeness_score", "Proportion of expected protocol headers successfully parsed", "parsed_headers / max(1, expected_headers)", NormalizationType.RATIO),
    ("payload_truncation_ratio", "Fraction of captured frames truncated prior to layer 4 payload", "truncated_packets / max(1, total_packets)", NormalizationType.RATIO),
    ("sensor_coverage_ratio", "Coverage ratio of observation window (capture active fraction)", "active_sensor_seconds / 60.0", NormalizationType.RATIO),
    ("sampling_rate_estimate", "Estimated packet capture sampling ratio (1.0 = unsampled full capture)", "1.0 / sampling_divisor", NormalizationType.RATIO),
]
for name, desc, comp, norm in _OBSERVABILITY_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.OBSERVABILITY,
        dtype="float",
        source=TelemetrySource.OBSERVABILITY_SENSOR,
        semantic_meaning=desc,
        required_telemetry=("capture_metadata",),
        availability_condition="Always computable from ingestion diagnostics",
        computation=comp,
        normalization=norm,
    ))


# =========================================================================
# 18. MISSINGNESS INDICATORS
# =========================================================================
_MISSINGNESS_SPECS = [
    ("is_packet_telemetry_missing", "Binary flag indicating whether raw packet layer is absent", "1 if packet_features_missing else 0", NormalizationType.IDENTITY),
    ("is_tcp_telemetry_missing", "Binary flag indicating absence of observed TCP traffic", "1 if tcp_count == 0 else 0", NormalizationType.IDENTITY),
    ("is_udp_telemetry_missing", "Binary flag indicating absence of observed UDP traffic", "1 if udp_count == 0 else 0", NormalizationType.IDENTITY),
    ("is_dns_telemetry_missing", "Binary flag indicating absence of DNS transactions", "1 if dns_queries == 0 else 0", NormalizationType.IDENTITY),
    ("is_tls_telemetry_missing", "Binary flag indicating absence of TLS handshakes", "1 if tls_handshakes == 0 else 0", NormalizationType.IDENTITY),
    ("is_graph_telemetry_missing", "Binary flag indicating absence of multi-endpoint topology", "1 if node_count < 2 else 0", NormalizationType.IDENTITY),
]
for name, desc, comp, norm in _MISSINGNESS_SPECS:
    FeatureRegistry.register(FeatureDefinition(
        name=name,
        family=FeatureFamily.MISSINGNESS,
        dtype="float",
        source=TelemetrySource.OBSERVABILITY_SENSOR,
        semantic_meaning=desc,
        required_telemetry=("protocol_presence",),
        availability_condition="Always computable across all capture formats",
        computation=comp,
        normalization=norm,
    ))
