# NexSolve Extended 72-Feature Scientific & Temporal Audit

## Executive Summary
This document provides the comprehensive scientific and mathematical audit of the 72-feature candidate representation for NexSolve Network Attack Forecasting. It establishes feature taxonomy, mathematical formulations, boundary/sparsity edge cases, temporal causality guarantees, and empirical validation results on real-world PCAP traffic.

---

## 1. Feature Taxonomy and Categorization (All 72 Features)

| # | Feature Key | Source | Group | Mathematical Derivation | Edge-Case Semantics | Causality & Leakage Risk | Suitability for Forecasting |
|---|---|---|---|---|---|---|---|
| 1 | flow_count | Flow | Flow Baseline | Count of active flow IDs | 0.0 if empty | Strict past window; no leakage | High (DoS, port sweeps) |
| 2 | total_src_bytes | Flow | Flow Baseline | Sum of forward packet lengths | 0.0 if empty | Strict past window; no leakage | High (Exfiltration volume) |
| 3 | total_dst_bytes | Flow | Flow Baseline | Sum of reverse packet lengths | 0.0 if empty | Strict past window; no leakage | High (C2 download volume) |
| 4 | total_packets | Flow | Flow Baseline | Sum of packets across active flows | 0.0 if empty | Strict past window; no leakage | High (Traffic volume) |
| 5 | mean_duration | Flow | Flow Baseline | Mean (end - start) per flow | 0.0 if empty | Strict past window; no leakage | Medium (Session persistence) |
| 6 | mean_flow_bytes | Flow | Flow Baseline | Mean total bytes per flow | 0.0 if empty | Strict past window; no leakage | Medium (Flow size profile) |
| 7 | mean_flow_packets | Flow | Flow Baseline | Mean packet count per flow | 0.0 if empty | Strict past window; no leakage | Medium (Flow packet density) |
| 8 | mean_sttl | Flow | Flow Baseline | Mean TTL in forward direction | None / Abstained | Strict past window; no leakage | High (Hop count, OS spoofing) |
| 9 | mean_dttl | Flow | Flow Baseline | Mean TTL in reverse direction | None / Abstained | Strict past window; no leakage | High (Remote OS fingerprinting) |
| 10 | mean_swin | Flow | Flow Baseline | Mean forward TCP window advertisement | None / Abstained | Strict past window; no leakage | Medium (TCP stack behavior) |
| 11 | mean_dwin | Flow | Flow Baseline | Mean reverse TCP window advertisement | None / Abstained | Strict past window; no leakage | Medium (TCP stack behavior) |
| 12 | mean_iat | Flow | Flow Baseline | Mean intra-flow packet IAT | None / Abstained | Strict past window; no leakage | High (Beaconing periodicity) |
| 13 | unique_src_ports | Flow | Flow Baseline | Distinct (src_ip, src_port) pairs | 0.0 if empty | Strict past window; no leakage | High (Port scanning, botnets) |
| 14 | unique_dst_ports | Flow | Flow Baseline | Distinct (dst_ip, dst_port) pairs | 0.0 if empty | Strict past window; no leakage | High (Service sweeping) |
| 15 | proto_tcp_count | Flow | Flow Baseline | Active TCP flows | 0.0 if empty | Strict past window; no leakage | High (TCP-based attacks) |
| 16 | proto_udp_count | Flow | Flow Baseline | Active UDP flows | 0.0 if empty | Strict past window; no leakage | High (UDP amplification) |
| 17 | proto_other_count | Flow | Flow Baseline | Active non-TCP/UDP flows | 0.0 if empty | Strict past window; no leakage | Medium (Tunneling, ICMP) |
| 18 | flow_duration_variance | Flow | Flow Extended | Sample variance ^2 = \frac{1}{N-1}\sum (d_i - \bar{d})^2$ | 0.0 if  \le 1$ | Strict past window; no leakage | High (C2 regularity vs manual) |
| 19 | byte_ratio_src_dst | Flow | Flow Extended | {bytes} / D_{bytes}$ | 0.0 if {bytes}=0$ | Strict past window; no leakage | Critical (Exfil vs Infil balance) |
| 20 | packet_ratio_src_dst | Flow | Flow Extended | Forward packets / Reverse packets | 0.0 if {rev}=0$ | Strict past window; no leakage | High (Asymmetric flood detection) |
| 21 | single_packet_flow_ratio | Flow | Flow Extended | Flows with {tot}=1$ / {flows}$ | 0.0 if empty | Strict past window; no leakage | Critical (Stealth port scanning) |
| 22 | active_flow_rate | Flow | Flow Extended | {flows} / \Delta T_{window}$ | 0.0 if empty | Strict past window; no leakage | High (Connection surge velocity) |
| 23 | flow_iat_variance | Flow | Flow Extended | Sample variance of flow start IATs | 0.0 if $<2$ IATs | Strict past window; no leakage | High (Automated beacon variance) |
| 24 | flow_iat_max | Flow | Flow Extended | Maximum flow start IAT | 0.0 if no IATs | Strict past window; no leakage | Medium (Idle period detection) |
| 25 | flow_iat_min | Flow | Flow Extended | Minimum flow start IAT | 0.0 if no IATs | Strict past window; no leakage | High (Burst onset detection) |
| 26 | tcp_syn_ack_ratio | Flow | Flow Extended | $\sum SYN / \sum ACK$ across flows | 0.0 if =0$ | Strict past window; no leakage | Critical (SYN flooding onset) |
| 27 | tcp_rst_ack_ratio | Flow | Flow Extended | $\sum RST / \sum ACK$ across flows | 0.0 if =0$ | Strict past window; no leakage | High (Rejected scan connections) |
| 28 | udp_flow_ratio | Flow | Flow Extended | {udp} / N_{flows}$ | 0.0 if empty | Strict past window; no leakage | High (UDP flood prevalence) |
| 29 | port_entropy | Flow | Flow Extended | Shannon entropy $-\sum p_i \log_2(p_i)$ over dst ports | 0.0 if $\le 1$ port | Strict past window; no leakage | Critical (Randomized port scanning) |
| 30 | mean_payload_bytes | Flow | Flow Extended | Mean prefix payload bytes per flow | 0.0 if empty | Strict past window; no leakage | High (Payload presence profiling) |
| 31 | packet_count | Packet | Packet Baseline | Total packets observed in window | 0.0 if empty | Strict past window; no leakage | High (Traffic volume) |
| 32 | mean_packet_size | Packet | Packet Baseline | Mean packet length | 0.0 if empty | Strict past window; no leakage | High (Packet sizing profile) |
| 33 | std_packet_size | Packet | Packet Baseline | Population std dev of packet lengths | 0.0 if empty | Strict past window; no leakage | High (Size dispersion) |
| 34 | min_packet_size | Packet | Packet Baseline | Minimum observed packet length | None if empty | Strict past window; no leakage | Medium (Small packet detection) |
| 35 | max_packet_size | Packet | Packet Baseline | Maximum observed packet length | None if empty | Strict past window; no leakage | High (MTU-sized packets) |
| 36 | mean_ttl | Packet | Packet Baseline | Mean TTL across packets | None if empty | Strict past window; no leakage | High (Hop count average) |
| 37 | std_ttl | Packet | Packet Baseline | Population std dev of TTL | 0.0 if empty | Strict past window; no leakage | High (TTL randomization) |
| 38 | min_ttl | Packet | Packet Baseline | Minimum TTL | None if empty | Strict past window; no leakage | Medium (Minimum hops) |
| 39 | max_ttl | Packet | Packet Baseline | Maximum TTL | None if empty | Strict past window; no leakage | Medium (Initial TTL bounds) |
| 40 | tcp_syn_count | Packet | Packet Baseline | Count of packets with SYN flag | 0.0 if empty | Strict past window; no leakage | Critical (Connection initiation) |
| 41 | tcp_ack_count | Packet | Packet Baseline | Count of packets with ACK flag | 0.0 if empty | Strict past window; no leakage | Critical (Established throughput) |
| 42 | tcp_fin_count | Packet | Packet Baseline | Count of packets with FIN flag | 0.0 if empty | Strict past window; no leakage | Medium (Graceful teardown) |
| 43 | tcp_rst_count | Packet | Packet Baseline | Count of packets with RST flag | 0.0 if empty | Strict past window; no leakage | High (Abrupt connection reset) |
| 44 | tcp_psh_count | Packet | Packet Baseline | Count of packets with PSH flag | 0.0 if empty | Strict past window; no leakage | Medium (Push data delivery) |
| 45 | tcp_urg_count | Packet | Packet Baseline | Count of packets with URG flag | 0.0 if empty | Strict past window; no leakage | Low (Urgent pointer activity) |
| 46 | mean_tcp_window | Packet | Packet Baseline | Mean TCP receive window | None if empty | Strict past window; no leakage | Medium (Host buffer health) |
| 47 | std_tcp_window | Packet | Packet Baseline | Population std dev of TCP window | 0.0 if empty | Strict past window; no leakage | Medium (Window variability) |
| 48 | fragment_count | Packet | Packet Baseline | Count of fragmented packets | 0.0 if empty | Strict past window; no leakage | High (Teardrop, fragmentation evasion) |
| 49 | retransmission_count | Packet | Packet Baseline | Count of overlapping sequence numbers | 0.0 if empty | Strict past window; no leakage | High (Network stress, packet loss) |
| 50 | mean_iat | Packet | Packet Baseline | Mean inter-arrival time | None if empty | Strict past window; no leakage | High (Rate timing) |
| 51 | std_iat | Packet | Packet Baseline | Population std dev of IAT | 0.0 if empty | Strict past window; no leakage | High (Jitter measurement) |
| 52 | max_iat | Packet | Packet Baseline | Maximum observed IAT | None if empty | Strict past window; no leakage | Medium (Burst silence gap) |
| 53 | packet_size_skewness | Packet | Packet Extended | Fisher-Pearson adjusted sample skewness | 0.0 if <3$ or ^2=0$ | Strict past window; no leakage | High (Bimodal packet size alert) |
| 54 | packet_rate_peak | Packet | Packet Extended | Max 1-second binned packet rate | 0.0 if empty | Strict past window; no leakage | Critical (Sub-window micro-bursts) |
| 55 | tcp_window_zero_count | Packet | Packet Extended | Count of packets with window == 0 | 0.0 if empty | Strict past window; no leakage | High (Target exhaustion) |
| 56 | tcp_cwr_count | Packet | Packet Extended | Count of packets with CWR flag (0x80) | 0.0 if empty | Strict past window; no leakage | Medium (Congestion notification) |
| 57 | tcp_ece_count | Packet | Packet Extended | Count of packets with ECE flag (0x40) | 0.0 if empty | Strict past window; no leakage | Medium (ECN signaling) |
| 58 | udp_packet_ratio | Packet | Packet Extended | UDP packets / Total packets | 0.0 if empty | Strict past window; no leakage | High (UDP flood density) |
| 59 | icmp_packet_ratio | Packet | Packet Extended | ICMP packets / Total packets | 0.0 if empty | Strict past window; no leakage | High (ICMP storm density) |
| 60 | mean_tcp_payload_size | Packet | Packet Extended | Mean payload length of TCP packets | 0.0 if no TCP | Strict past window; no leakage | High (Segment payload size) |
| 61 | max_tcp_payload_size | Packet | Packet Extended | Max payload length of TCP packets | 0.0 if no TCP | Strict past window; no leakage | High (Large data chunk transfer) |
| 62 | payload_rate_bytes_sec | Packet | Packet Extended | Total payload bytes / duration | 0.0 if empty | Strict past window; no leakage | Critical (Data exfiltration rate) |
| 63 | delta_flow_count | Temporal | Temporal Baseline | Flow count delta vs -1$ | Unavailable at =0$ | Backward-only ($ vs -1$); no leakage | Critical (Flow surge velocity) |
| 64 | delta_total_bytes | Temporal | Temporal Baseline | Total bytes delta vs -1$ | Unavailable at =0$ | Backward-only ($ vs -1$); no leakage | Critical (Byte surge velocity) |
| 65 | delta_total_packets | Temporal | Temporal Baseline | Packet count delta vs -1$ | Unavailable at =0$ | Backward-only ($ vs -1$); no leakage | Critical (Packet surge velocity) |
| 66 | delta_ports | Temporal | Temporal Baseline | Port count delta vs -1$ | Unavailable at =0$ | Backward-only ($ vs -1$); no leakage | Critical (Port sweep expansion) |
| 67 | delta_iat | Temporal | Temporal Baseline | Flow IAT delta vs -1$ | Unavailable at =0$ | Backward-only ($ vs -1$); no leakage | High (Jitter acceleration) |
| 68 | rolling_total_bytes | Temporal | Temporal Baseline | Rolling mean bytes over $\le 4$ prior windows | Uniform average | Backward-only (-3 \dots t$); no leakage | High (Traffic volume baseline) |
| 69 | delta_src_bytes | Temporal | Temporal Extended | Source bytes delta vs -1$ | Unavailable at =0$ | Backward-only ($ vs -1$); no leakage | High (Outbound flood velocity) |
| 70 | delta_dst_bytes | Temporal | Temporal Extended | Dest bytes delta vs -1$ | Unavailable at =0$ | Backward-only ($ vs -1$); no leakage | High (Inbound flood velocity) |
| 71 | delta_syn_count | Temporal | Temporal Extended | SYN count delta vs -1$ | Unavailable at =0$ | Backward-only ($ vs -1$); no leakage | Critical (SYN attack onset velocity) |
| 72 | rolling_flow_rate | Temporal | Temporal Extended | Rolling mean flow count over $\le 4$ prior windows | Uniform average | Backward-only (-3 \dots t$); no leakage | High (Connection load baseline) |

---

## 2. Temporal Causality and Leakage Audit
- **Strict Backward-Looking Scope**: At time window $, all feature calculations strictly depend on (t)$ and optionally (t-1), \dots, x(t-3)$.
- **Future Window Invariance**: Invariance test 	est_temporal_causality_and_invariance formally proves that modifying or appending windows +1, t+2$ causes zero change in candidate features for windows $\le t$.
- **Target Construction Separation**: Forecasting targets (+1 \dots T+5$) are derived strictly from forward attack labels and are never encoded or present in current network state tensors.
- **Normalization Scoping**: StandardScaler mean/scale parameters must strictly be fit on chronological training runs only.

---

## 3. Real-PCAP Empirical Validation
Tested on riday_10windows_slice.pcap (2,277 packets, 283 flows, 10 continuous 60s windows):
- 45-feature model compatibility: READY = True (45/45 available, 0 missing).
- 72-feature model compatibility: READY = True (72/72 available, 0 missing).
- Vector determinism: Identical floating-point values across multiple extractions.
