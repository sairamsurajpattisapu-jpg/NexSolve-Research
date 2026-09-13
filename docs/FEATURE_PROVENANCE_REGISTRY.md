# NexSolve Extended Feature Provenance Registry (Phase 11)

**Schema Baseline**: Canonical 45-feature model (`models/nexsolve_world_model_45`)
**Candidate Extended Set**: 72 Features (45 canonical baseline + 27 deterministic flow/temporal extensions inspired by NFStream and CICFlowMeter)
**Safety Gate Principle**: No candidate feature is admitted into the model input tensor until proven: (1) PCAP-derivable, (2) dataset-derivable, (3) leakage-free, and (4) validated to improve forecasting F1 over persistence.

---

## 1. Feature Registry & Provenance Specifications

| Feature Name | Group | Packet Source | PCAP Availability | History Req | Missing Data Semantics | Training Availability | Inference Availability | Attack Relevance | External Inspiration | License Risk | Model Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **flow_count** | Flow | FlowRecord | Deterministic | 1 Window | Abstained / 0.0 | Available (UNSW, CIC) | Available (PCAP) | High (DoS, Portscan) | Baseline | None | **ACTIVE (45)** |
| **total_src_bytes** | Flow | IP/IPv6 length | Deterministic | 1 Window | Abstained / 0.0 | Available (UNSW, CIC) | Available (PCAP) | High (Data Exfiltration) | Baseline | None | **ACTIVE (45)** |
| **total_dst_bytes** | Flow | IP/IPv6 length | Deterministic | 1 Window | Abstained / 0.0 | Available (UNSW, CIC) | Available (PCAP) | High (C2 Payload Download) | Baseline | None | **ACTIVE (45)** |
| **total_packets** | Flow | Packet Record | Deterministic | 1 Window | Abstained / 0.0 | Available (UNSW, CIC) | Available (PCAP) | High (Flood, Volume) | Baseline | None | **ACTIVE (45)** |
| **mean_duration** | Flow | Flow start/end | Deterministic | 1 Window | Abstained / 0.0 | Available (UNSW, CIC) | Available (PCAP) | Medium (C2, Scanning) | Baseline | None | **ACTIVE (45)** |
| **mean_flow_bytes** | Flow | IP/IPv6 length | Deterministic | 1 Window | Abstained / 0.0 | Available (UNSW, CIC) | Available (PCAP) | Medium (Exfil size) | Baseline | None | **ACTIVE (45)** |
| **mean_flow_packets**| Flow | Packet Record | Deterministic | 1 Window | Abstained / 0.0 | Available (UNSW, CIC) | Available (PCAP) | Medium (Protocol behavior) | Baseline | None | **ACTIVE (45)** |
| **mean_sttl** | Flow | IP TTL | Deterministic | 1 Window | None / Abstained | Available (UNSW, CIC) | Available (PCAP) | High (OS Spoofing, Hop count) | Baseline | None | **ACTIVE (45)** |
| **mean_dttl** | Flow | IP TTL | Deterministic | 1 Window | None / Abstained | Available (UNSW, CIC) | Available (PCAP) | High (Remote OS fingerprint) | Baseline | None | **ACTIVE (45)** |
| **mean_swin** | Flow | TCP Window | Deterministic | 1 Window | None / Abstained | Available (UNSW) | Available (PCAP) | Medium (TCP stack behavior) | Baseline | None | **ACTIVE (45)** |
| **mean_dwin** | Flow | TCP Window | Deterministic | 1 Window | None / Abstained | Available (UNSW) | Available (PCAP) | Medium (TCP stack behavior) | Baseline | None | **ACTIVE (45)** |
| **mean_iat** | Flow | Packet timestamp | Deterministic | 1 Window | None / Abstained | Available (UNSW, CIC) | Available (PCAP) | High (Beaconing, Rate) | Baseline | None | **ACTIVE (45)** |
| **unique_src_ports** | Flow | TCP/UDP header | Deterministic | 1 Window | 0.0 | Available (UNSW, CIC) | Available (PCAP) | High (DDoS, Botnet) | Baseline | None | **ACTIVE (45)** |
| **unique_dst_ports** | Flow | TCP/UDP header | Deterministic | 1 Window | 0.0 | Available (UNSW, CIC) | Available (PCAP) | High (Port scanning) | Baseline | None | **ACTIVE (45)** |
| **proto_tcp_count** | Flow | IP protocol | Deterministic | 1 Window | 0.0 | Available (UNSW, CIC) | Available (PCAP) | High (TCP-specific attacks) | Baseline | None | **ACTIVE (45)** |
| **proto_udp_count** | Flow | IP protocol | Deterministic | 1 Window | 0.0 | Available (UNSW, CIC) | Available (PCAP) | High (UDP amplification) | Baseline | None | **ACTIVE (45)** |
| **proto_other_count**| Flow | IP protocol | Deterministic | 1 Window | 0.0 | Available (UNSW, CIC) | Available (PCAP) | Medium (Tunneling/ICMP) | Baseline | None | **ACTIVE (45)** |
| **packet_count** (22 Packet Baseline)| Packet | Ethernet/IP | Deterministic | 1 Window | 0.0 | Available (PCAP) | Available (PCAP) | High (Traffic fingerprinting) | Baseline | None | **ACTIVE (45)** |
| **delta_flow_count** (6 Temporal Baseline)| Temporal | Candidate sequence| Deterministic | 2 Windows | Abstained / None | Available (Sequences) | Available (Sequences) | Critical (Velocity changes) | Baseline | None | **ACTIVE (45)** |
| **flow_duration_variance**| Flow Ext | Flow start/end | Deterministic | 1 Window | 0.0 (<=1 flow) | Available (CICFlowMeter) | Available (PCAP) | High (Detecting automated C2) | NFStream/CIC | None | **IMPLEMENTED (72)** |
| **byte_ratio_src_dst**| Flow Ext | IP bytes | Deterministic | 1 Window | 0.0 (if dst=0) | Derivable | Available (PCAP) | Critical (Exfiltration vs download)| NFStream | None | **IMPLEMENTED (72)** |
| **packet_ratio_src_dst**| Flow Ext | Packet counts | Deterministic | 1 Window | 0.0 (if rev=0) | Derivable | Available (PCAP) | High (Asymmetric flood) | NFStream | None | **IMPLEMENTED (72)** |
| **single_packet_flow_ratio**| Flow Ext | Flow packet counts| Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | Critical (Port/Host sweeping) | NFStream | None | **IMPLEMENTED (72)** |
| **active_flow_rate** | Flow Ext | Flow count / window_s| Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | High (Connection bursts) | NFStream | None | **IMPLEMENTED (72)** |
| **flow_iat_variance**| Flow Ext | Packet timestamp | Deterministic | 1 Window | 0.0 (<2 IATs) | Available (CICFlowMeter) | Available (PCAP) | High (Robotic beaconing) | CICFlowMeter/RITA | None | **IMPLEMENTED (72)** |
| **flow_iat_max** | Flow Ext | Packet timestamp | Deterministic | 1 Window | 0.0 (no IATs) | Available (CICFlowMeter) | Available (PCAP) | Medium (Idle session gaps) | CICFlowMeter | None | **IMPLEMENTED (72)** |
| **flow_iat_min** | Flow Ext | Packet timestamp | Deterministic | 1 Window | 0.0 (no IATs) | Available (CICFlowMeter) | Available (PCAP) | High (Rapid-fire bursts) | CICFlowMeter | None | **IMPLEMENTED (72)** |
| **tcp_syn_ack_ratio**| Flow Ext | TCP Flags | Deterministic | 1 Window | 0.0 (if ack=0) | Derivable | Available (PCAP) | Critical (SYN Flood, Half-open)| NFStream/CIC | None | **IMPLEMENTED (72)** |
| **tcp_rst_ack_ratio**| Flow Ext | TCP Flags | Deterministic | 1 Window | 0.0 (if ack=0) | Derivable | Available (PCAP) | High (Connection resets/rejection)| NFStream/CIC | None | **IMPLEMENTED (72)** |
| **udp_flow_ratio** | Flow Ext | IP protocol | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | High (UDP flood, DNS flood) | NFStream | None | **IMPLEMENTED (72)** |
| **port_entropy** | Flow Ext | TCP/UDP ports | Deterministic | 1 Window | 0.0 (<=1 port) | Derivable | Available (PCAP) | Critical (Randomized scanning) | RITA/NFStream | None | **IMPLEMENTED (72)** |
| **mean_payload_bytes**| Flow Ext | L4 payload | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | High (Zero-payload scans vs exfil)| NFStream | None | **IMPLEMENTED (72)** |
| **packet_size_skewness**| Packet Ext | PacketRecord.packet_length| Deterministic | 1 Window | 0.0 (<3 pkts or 0 var) | Derivable | Available (PCAP) | High (Packet distribution asymmetry) | NFStream | None | **IMPLEMENTED (72)** |
| **packet_rate_peak** | Packet Ext | PacketRecord.timestamp | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | Critical (Burst DDoS/micro-floods) | NFStream | None | **IMPLEMENTED (72)** |
| **tcp_window_zero_count**| Packet Ext | TCP window header | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | High (Buffer exhaustion/DDoS) | Snort/Suricata | None | **IMPLEMENTED (72)** |
| **tcp_cwr_count** | Packet Ext | TCP flags (0x80) | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | Medium (Congestion window reduced) | Baseline/RFC 3168 | None | **IMPLEMENTED (72)** |
| **tcp_ece_count** | Packet Ext | TCP flags (0x40) | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | Medium (ECN-Echo notification) | Baseline/RFC 3168 | None | **IMPLEMENTED (72)** |
| **udp_packet_ratio** | Packet Ext | PacketRecord.protocol | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | High (UDP amplification/scan) | CICFlowMeter | None | **IMPLEMENTED (72)** |
| **icmp_packet_ratio**| Packet Ext | PacketRecord.protocol | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | High (ICMP ping storms/tunneling) | CICFlowMeter | None | **IMPLEMENTED (72)** |
| **mean_tcp_payload_size**| Packet Ext | TCP payload length | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | High (Payload volume per segment) | NFStream | None | **IMPLEMENTED (72)** |
| **max_tcp_payload_size**| Packet Ext | TCP payload length | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | High (Jumbo frame exfil/download) | NFStream | None | **IMPLEMENTED (72)** |
| **payload_rate_bytes_sec**| Packet Ext | Payload / duration | Deterministic | 1 Window | 0.0 | Derivable | Available (PCAP) | Critical (Data exfiltration throughput) | NFStream | None | **IMPLEMENTED (72)** |
| **delta_src_bytes** | Temp Ext | Candidate sequence| Deterministic | 2 Windows | None (1st win) | Derivable | Available (Sequences) | High (Data spike velocity) | NexSolve | None | **IMPLEMENTED (72)** |
| **delta_dst_bytes** | Temp Ext | Candidate sequence| Deterministic | 2 Windows | None (1st win) | Derivable | Available (Sequences) | High (Download spike velocity) | NexSolve | None | **IMPLEMENTED (72)** |
| **delta_syn_count** | Temp Ext | Candidate sequence| Deterministic | 2 Windows | None (1st win) | Derivable | Available (Sequences) | Critical (Attack onset velocity) | NexSolve | None | **IMPLEMENTED (72)** |
| **rolling_flow_rate**| Temp Ext | Candidate sequence| Deterministic | 4 Windows | None (1st win) | Derivable | Available (Sequences) | High (Sustained load tracking) | NexSolve | None | **IMPLEMENTED (72)** |
| **mean_tcp_rtt** | Flow | TCP timestamp/ACK| **NON-DETERMINISTIC**| 1 Window | **ABSTAIN (NO ZERO-FILL)**| Present in UNSW raw | **UNAVAILABLE in passive PCAP**| Medium | Legacy | None | **REJECTED (46->45)** |

---

## 2. Dataset Compatibility Matrix

| Feature Subsets | UNSW-NB15 | CIC-IDS2017 | CIC-IDS2018 | TON-IoT | Arbitrary Passive PCAP | Training Compatible? | Inference Compatible? |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Canonical 45 Features** | Yes | Yes (adapted) | Yes (adapted) | Yes (adapted) | Yes | **YES** | **YES (Ready)** |
| **Legacy 46 Features (`mean_tcp_rtt`)** | Yes | No | No | No | **NO** | Research Only | **NO (Refused)** |
| **Extended 72 Features** | Partial (requires PCAP replay)| Yes (via canonical PCAP)| Yes (via canonical PCAP)| Partial | **YES** | Candidate Stage | **YES (Ready)** |
