# NexSolve: Modular Feature Catalog & Metadata Registry

**Document Version:** 1.0.0  
**Date:** September 2026  
**Status:** Authoritative Feature Specification  
**Architecture:** 18 Modular Feature Families  
**Causality Guarantee:** 100% Causal (Zero Forward Lookahead)  
**Safety Guarantee:** Passive Telemetry Only (Zero Active Probing, Zero Fabricated Telemetry)  

---

## 1. Feature System Overview

The NexSolve Network World Model architecture relies on a strictly typed, modular registry containing **18 distinct feature families**. Every feature must satisfy:
1. **Causality:** Computed strictly from current ($t$) and historical ($t - 1, \dots, t - L$) observations. Zero lookahead leakage across sequence or split boundaries.
2. **Production Safety:** Derived exclusively from passive packet inspection, NetFlow/IPFIX records, or internal state graphs. Active probing features (such as synthetic TCP RTT) are strictly prohibited and excluded.
3. **Explicit Missingness:** Whenever a protocol or modality is absent (e.g., pure UDP captures lacking TCP window parameters), the feature system emits explicit missingness flags rather than zero-filling unknown semantics.

---

## 2. Catalog Summary by Feature Family

| # | Family | Feature Count | Primary Telemetry Source | Availability Condition | Normalization Scheme |
| :-: | :--- | :-: | :--- | :--- | :--- |
| 1 | **Packet** | 22 | Passive Packet Headers | Raw PCAP / Ethernet capture frames | `Z_SCORE`, `LOG1P_Z` |
| 2 | **Flow** | 17 | Bidirectional Flow Sessions | NetFlow, IPFIX, or Aggregated Flows | `Z_SCORE`, `LOG1P_Z` |
| 3 | **TCP** | 4 | L4 TCP Stream Decoders | TCP sessions active | `RATIO`, `LOG1P_Z` |
| 4 | **UDP** | 3 | L4 UDP Datagrams | UDP datagrams present | `RATIO`, `MIN_MAX`, `LOG1P_Z` |
| 5 | **DNS** | 4 | Port 53 / 5353 Transactions | DNS transactions observed | `RATIO`, `LOG1P_Z` |
| 6 | **HTTP** | 3 | L7 HTTP Parsers | Plaintext HTTP observed | `RATIO`, `LOG1P_Z` |
| 7 | **TLS** | 3 | TLS Handshake Records | Port 443 / TLS traffic | `RATIO`, `LOG1P_Z` |
| 8 | **SSH** | 2 | Port 22 Stream Sessions | SSH connections observed | `RATIO`, `LOG1P_Z` |
| 9 | **ICMP** | 3 | ICMP Header Types | ICMP traffic present | `RATIO`, `LOG1P_Z` |
| 10 | **ARP** | 3 | Layer 2 Ethernet Frames | Broadcast domain ARP packets | `RATIO`, `LOG1P_Z` |
| 11 | **DHCP** | 2 | UDP Ports 67/68 | DHCP transactions active | `RATIO`, `LOG1P_Z` |
| 12 | **Temporal** | 9 | Multi-Window State Sequences | History length $\ge 2$ windows | `Z_SCORE`, `LOG1P_Z` |
| 13 | **Behavioral** | 12 | Endpoint Interaction Matrix | Host/peer interactions tracked | `RATIO`, `MIN_MAX`, `Z_SCORE` |
| 14 | **Host** | 5 | Host Aggregation Engine | Visible IP endpoints | `LOG1P_Z`, `RATIO` |
| 15 | **Graph** | 8 | Temporal Graph Snapshot $G_t$ | Network topology constructed | `LOG1P_Z`, `MIN_MAX`, `RATIO` |
| 16 | **Statistical** | 5 | Inter-Arrival / Size Distributions | Granular packet/flow samples | `Z_SCORE` |
| 17 | **Observability**| 4 | Ingestion Engine Diagnostics | Always available from capture | `RATIO` |
| 18 | **Missingness** | 6 | Telemetry Mask Vectors | Always available across all inputs | `IDENTITY` (Binary Flag) |

**Total Registered Features:** 105 formally cataloged dimensions.

---

## 3. Detailed Specifications per Family

### Family 1: Packet Features (22 Features)
- `packet_count` ($x_1$): Total packet frames observed in 60s window. Source: `PACKET_HEADER`. Formula: $\sum \text{packets}$. Norm: `LOG1P_Z`.
- `mean_packet_size` ($x_2$): Mean byte size across frames. Source: `PACKET_HEADER`. Formula: $\mu(\text{bytes})$. Norm: `Z_SCORE`.
- `std_packet_size` ($x_3$): Standard deviation of packet byte lengths. Norm: `Z_SCORE`.
- `min_packet_size` ($x_4$): Minimum packet size. Norm: `Z_SCORE`.
- `max_packet_size` ($x_5$): Maximum packet size. Norm: `Z_SCORE`.
- `mean_ttl` ($x_6$): Mean IP Time-To-Live. Formula: $\frac{1}{N}\sum \text{TTL}_i$. Norm: `Z_SCORE`.
- `std_ttl` ($x_7$): Dispersion of IP TTL. Norm: `Z_SCORE`.
- `min_ttl` ($x_8$), `max_ttl` ($x_9$): Minimum and maximum observed TTL. Norm: `Z_SCORE`.
- `tcp_syn_count` ($x_{10}$): Total SYN frames. Norm: `LOG1P_Z`.
- `tcp_ack_count` ($x_{11}$): Total ACK frames. Norm: `LOG1P_Z`.
- `tcp_fin_count` ($x_{12}$): Total FIN frames. Norm: `LOG1P_Z`.
- `tcp_rst_count` ($x_{13}$): Total RST teardown frames. Norm: `LOG1P_Z`.
- `tcp_psh_count` ($x_{14}$): Total PSH flag frames. Norm: `LOG1P_Z`.
- `tcp_urg_count` ($x_{15}$): Total URG flag frames. Norm: `LOG1P_Z`.
- `mean_tcp_window` ($x_{16}$): Mean advertised TCP receive window. Norm: `Z_SCORE`.
- `std_tcp_window` ($x_{17}$): Standard deviation of advertised window. Norm: `Z_SCORE`.
- `fragment_count` ($x_{18}$): Total fragmented frames. Norm: `LOG1P_Z`.
- `retransmission_count` ($x_{19}$): Passive TCP sequence retransmissions. Norm: `LOG1P_Z`.
- `mean_iat` ($x_{20}$): Mean inter-arrival time between consecutive packets. Norm: `Z_SCORE`.
- `std_iat` ($x_{21}$): Standard deviation of packet inter-arrival times. Norm: `Z_SCORE`.
- `max_iat` ($x_{22}$): Maximum inter-arrival time in window. Norm: `Z_SCORE`.

### Family 2: Flow Features (17 Features)
- `flow_count` ($x_{23}$): Active bidirectional flow sessions. Norm: `LOG1P_Z`.
- `total_src_bytes` ($x_{24}$), `total_dst_bytes` ($x_{25}$): Forward and reverse payload volume. Norm: `LOG1P_Z`.
- `total_packets` ($x_{26}$): Total packets in active flows. Norm: `LOG1P_Z`.
- `mean_duration` ($x_{27}$): Mean flow lifetime duration. Norm: `Z_SCORE`.
- `mean_flow_bytes` ($x_{28}$), `mean_flow_packets` ($x_{29}$): Session volumetrics. Norm: `LOG1P_Z`.
- `mean_sttl` ($x_{30}$), `mean_dttl` ($x_{31}$): Source and destination TTL averages. Norm: `Z_SCORE`.
- `mean_swin` ($x_{32}$), `mean_dwin` ($x_{33}$): Source and destination window averages. Norm: `Z_SCORE`.
- `flow_mean_iat` ($x_{34}$): Mean session inter-arrival time. Norm: `Z_SCORE`.
- `unique_src_ports` ($x_{35}$), `unique_dst_ports` ($x_{36}$): Port cardinality. Norm: `LOG1P_Z`.
- `proto_tcp_count` ($x_{37}$), `proto_udp_count` ($x_{38}$), `proto_other_count` ($x_{39}$): L4 protocol counts. Norm: `LOG1P_Z`.

### Family 3: TCP Protocol Features (4 Features)
- `tcp_syn_ack_ratio`: $\frac{N_{\text{SYN}}}{\max(1, N_{\text{ACK}})}$. Detects asymmetric connection initiation vs establishment.
- `tcp_rst_ratio`: $\frac{N_{\text{RST}}}{\max(1, N_{\text{flow}})}$. Identifies abnormal session reset floods.
- `tcp_zero_window_count`: Advertised window exhaustion occurrences.
- `tcp_handshake_completion_rate`: Rate of established 3-way handshakes.

### Family 4: UDP Protocol Features (3 Features)
- `udp_packet_count`: Total UDP datagrams.
- `udp_byte_ratio`: $\frac{\text{Bytes}_{\text{UDP}}}{\max(1, \text{Bytes}_{\text{total}})}$.
- `udp_port_entropy`: Shannon entropy over destination UDP ports (amplification scan detector).

### Family 5: DNS Features (4 Features)
- `dns_query_count`, `dns_response_count`: Aggregate transaction volumes.
- `dns_query_response_ratio`: Detects tunneling or unresponsive resolver states.
- `dns_nxdomain_rate`: Proportion of responses indicating domain non-existence (DGA behavior).

### Family 6: HTTP Features (3 Features)
- `http_request_count`: Total unencrypted HTTP requests.
- `http_error_rate_4xx_5xx`: Ratio of client/server error responses.
- `http_post_ratio`: Ratio of data-upload requests (POST/PUT) vs retrieval (GET).

### Family 7: TLS Features (3 Features)
- `tls_client_hello_count`: Total TLS session negotiations initiated.
- `tls_sni_ratio`: Proportion with Server Name Indication present.
- `tls_resume_session_rate`: Rate of cached TLS session resumptions.

### Family 8: SSH Features (2 Features)
- `ssh_session_count`: Total SSH sessions on port 22.
- `ssh_inbound_outbound_ratio`: Asymmetry ratio of SSH traffic.

### Family 9: ICMP Features (3 Features)
- `icmp_echo_request_count`: Ping scan activity.
- `icmp_unreachable_count`: Routing/port unreachable indications.
- `icmp_volume_ratio`: Relative ICMP bandwidth saturation.

### Family 10: ARP Features (3 Features)
- `arp_request_count`: Broadcast address resolution queries.
- `arp_reply_ratio`: Reply-to-request ratio (ARP spoofing detection).
- `arp_gratuitous_count`: Gratuitous ARP announcements.

### Family 11: DHCP Features (2 Features)
- `dhcp_discover_count`: Broadcast DHCP discover attempts.
- `dhcp_offer_ack_ratio`: Lease completion confirmation ratio.

### Family 12: Temporal Intelligence Features (9 Features)
- `delta_flow_count`: $\Delta N_{\text{flow}} = N_{t} - N_{t-1}$.
- `delta_total_bytes`: First-order velocity of byte volume.
- `delta_total_packets`: First-order velocity of packet count.
- `delta_ports`: Port diversity expansion velocity.
- `delta_iat`: Inter-arrival timing acceleration.
- `rolling_total_bytes`: 4-window causal moving average.
- `acceleration_total_bytes`: Second-order acceleration $\Delta^2 \text{bytes} = \Delta \text{bytes}_t - \Delta \text{bytes}_{t-1}$.
- `rolling_volatility_bytes`: Rolling standard deviation $\sigma(\text{bytes}_{t-L:t})$.
- `burstiness_index`: Ratio of peak 1-second packet rate to average rate.

### Family 13: Behavioral Intelligence Features (12 Features)
- `peer_diversity`: Ratio of unique communicating peers to active sessions.
- `new_peer_rate`: Fraction of peers newly appearing relative to lookback history.
- `dest_diversity`, `src_diversity`: Endpoint concentration metrics.
- `port_entropy`, `protocol_entropy`: Shannon entropy across ports and L4 protocols.
- `fan_in_ratio`: Inbound flow concentration per target.
- `fan_out_ratio`: Outbound connection dispersion per source.
- `traffic_concentration_gini`: Gini coefficient measuring volume distribution across flows.
- `edge_churn_rate`: Proportion of modified communication edges vs previous window.
- `connection_churn_rate`: Rate of transient vs long-lived connections.
- `behavioral_novelty_score`: Mahalanobis distance from baseline behavioral centroid.

### Family 14: Host Intelligence Features (5 Features)
- `host_active_count`: Total visible endpoint IPs communicating in window.
- `host_max_outbound_fanout`: Maximum outbound degree observed for any single host.
- `host_max_inbound_fanin`: Maximum inbound degree observed for any single host.
- `host_internal_external_ratio`: Ratio of internal vs external endpoint communications.
- `host_max_port_spread`: Maximum port diversity scanned by any single host.

### Family 15: Graph Intelligence Features (8 Features)
- `graph_node_count` ($|V_t|$): Active graph vertices.
- `graph_edge_count` ($|E_t|$): Active directed communication edges.
- `graph_density`: Graph density $\frac{2 |E|}{|V|(|V|-1)}$.
- `graph_mean_degree`: Mean degree across vertices.
- `graph_max_betweenness`: Maximum betweenness centrality score.
- `graph_edge_churn`: Edge symmetric difference between $G_{t-1}$ and $G_t$.
- `graph_node_churn`: Vertex emergence/departure rate.
- `graph_observability_score`: Observed endpoints relative to monitored CIDR scope.

### Family 16: Statistical Distribution Features (5 Features)
- `iat_skewness`, `iat_kurtosis`: 3rd and 4th standardized moments of inter-arrival distribution.
- `packet_size_skewness`, `packet_size_kurtosis`: Moments of packet length distribution.
- `packet_size_p90`: 90th percentile packet size.

### Family 17: Observability Features (4 Features)
- `telemetry_completeness_score`: Proportion of expected headers successfully decoded.
- `payload_truncation_ratio`: Ratio of snaplen truncated frames.
- `sensor_coverage_ratio`: Fraction of 60s window actively monitored by sensor.
- `sampling_rate_estimate`: Capture sampling factor (1.0 = full line-rate capture).

### Family 18: Missingness Indicators (6 Features)
- `is_packet_telemetry_missing`: 1 if raw packet frames were unavailable; 0 otherwise.
- `is_tcp_telemetry_missing`: 1 if zero TCP packets observed; 0 otherwise.
- `is_udp_telemetry_missing`: 1 if zero UDP datagrams observed; 0 otherwise.
- `is_dns_telemetry_missing`: 1 if zero DNS queries observed; 0 otherwise.
- `is_tls_telemetry_missing`: 1 if zero TLS handshakes observed; 0 otherwise.
- `is_graph_telemetry_missing`: 1 if $< 2$ communicating endpoints observed; 0 otherwise.

---

## 4. Architectural Relationship to Candidate V2

Candidate V2 operates on a fixed 45-feature subset ($17 \text{ Flow} + 22 \text{ Packet} + 6 \text{ Temporal Velocity}$). 
The Final World Model supports both:
1. **Canonical 45-Feature Mode (Backward Compatibility):** Maps the canonical 45 features directly into the core encoders while flagging missingness on advanced protocol/graph views.
2. **Full Multi-View Mode:** Leverages the complete 18-family catalog to drive multi-view representation learning, cross-view fusion, dynamic graph propagation, and host-level risk scoring.
