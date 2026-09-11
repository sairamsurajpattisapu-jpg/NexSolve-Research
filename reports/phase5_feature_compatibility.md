# Phase 5 Feature Semantics and Compatibility Report

## Summary
- **Canonical Specification Features:** 46
- **UNSW-NB15 Available Features:** 24 (18 flow, 6 temporal; 22 packet placeholders are UNAVAILABLE in flow CSV)
- **TON-IoT Available Features:** 17 (12 flow, 5 temporal; 6 flow features, 1 temporal, and 22 packet features are UNAVAILABLE)
- **Shared Non-Fabricated Feature Subset:** 17 features (12 flow, 5 temporal)
- **Production PCAP Compatible Features:** 45 / 46 (mean_tcp_rtt is UNAVAILABLE in packet contract)

## Zero-Fabrication Policy
> [!IMPORTANT]
> Numerical 0.0 is a legitimate measurement (e.g., 0 bytes or 0 retransmissions) and must NOT be used to represent missing/unsupported fields.
> Models operating on TON-IoT must use the shared 17-feature subset or declare their explicit feature list.

## Feature Availability Table
| Feature | Group | UNSW Availability | TON-IoT Availability | Production PCAP Availability | Production Compatible |
|---|---|---|---|---|---|
| `flow_count` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `total_src_bytes` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `total_dst_bytes` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `total_packets` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `mean_duration` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `mean_flow_bytes` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `mean_flow_packets` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `mean_sttl` | flow_features | **AVAILABLE** | **UNAVAILABLE** | **CANONICAL_FLOW** | Yes |
| `mean_dttl` | flow_features | **AVAILABLE** | **UNAVAILABLE** | **CANONICAL_FLOW** | Yes |
| `mean_swin` | flow_features | **AVAILABLE** | **UNAVAILABLE** | **CANONICAL_FLOW** | Yes |
| `mean_dwin` | flow_features | **AVAILABLE** | **UNAVAILABLE** | **CANONICAL_FLOW** | Yes |
| `mean_iat` | flow_features | **AVAILABLE** | **UNAVAILABLE** | **CANONICAL_FLOW** | Yes |
| `mean_tcp_rtt` | flow_features | **AVAILABLE** | **UNAVAILABLE** | **UNAVAILABLE** | No |
| `unique_src_ports` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `unique_dst_ports` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `proto_tcp_count` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `proto_udp_count` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `proto_other_count` | flow_features | **AVAILABLE** | **AVAILABLE** | **CANONICAL_FLOW** | Yes |
| `packet_count` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `mean_packet_size` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `std_packet_size` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `min_packet_size` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `max_packet_size` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `mean_ttl` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `std_ttl` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `min_ttl` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `max_ttl` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `tcp_syn_count` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `tcp_ack_count` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `tcp_fin_count` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `tcp_rst_count` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `tcp_psh_count` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `tcp_urg_count` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `mean_tcp_window` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `std_tcp_window` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `fragment_count` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `retransmission_count` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `mean_iat` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `std_iat` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `max_iat` | packet_features | **UNAVAILABLE** | **UNAVAILABLE** | **PCAP** | Yes |
| `delta_flow_count` | temporal_features | **AVAILABLE** | **AVAILABLE** | **TEMPORAL** | Yes |
| `delta_total_bytes` | temporal_features | **AVAILABLE** | **AVAILABLE** | **TEMPORAL** | Yes |
| `delta_total_packets` | temporal_features | **AVAILABLE** | **AVAILABLE** | **TEMPORAL** | Yes |
| `delta_ports` | temporal_features | **AVAILABLE** | **AVAILABLE** | **TEMPORAL** | Yes |
| `delta_iat` | temporal_features | **AVAILABLE** | **UNAVAILABLE** | **TEMPORAL** | Yes |
| `rolling_total_bytes` | temporal_features | **AVAILABLE** | **AVAILABLE** | **TEMPORAL** | Yes |
