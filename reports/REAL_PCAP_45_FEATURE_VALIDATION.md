# NexSolve — Scientific Report: 45-Feature PCAP-Compatible World Model & Real-PCAP Forecast Validation

## Executive Summary
This report formalizes the design, training, multi-horizon scientific benchmarking, and live pipeline validation of the **versioned 45-feature PCAP-compatible world model variant**.

Under passive packet capture ingestion, TCP Round-Trip Time (`flow_features.mean_tcp_rtt`) cannot be honestly derived without synthetic heuristics or protocol assumptions. In accordance with NexSolve's Zero-Fabrication Charter:
1. `mean_tcp_rtt` is omitted from the PCAP-compatible candidate feature schema.
2. The remaining 45 observable network features (17 flow, 22 packet, 6 temporal) are preserved with exact mathematical definitions.
3. A 45-feature `NumpyLSTM` model was trained and evaluated strictly on historical windows ($X_t = 8$, $Y = T+1 \dots T+5$) on UNSW-NB15 with zero lookahead leakage.
4. The model was benchmarked against the empirical Persistence champion across all 5 horizons.
5. In accordance with the promotion policy, the candidate was marked `HOLD` (as Persistence remains champion on the test episode).
6. The dual-schema compatibility gate was enabled in `model_service/pcap_upload.py` and `jobs.py`.
7. Real-world bidirectional capture `friday_10windows_slice.pcap` (2,277 packets, 10 windows, 283 flows) was executed end-to-end, producing valid multi-step rollouts ($T+1 \dots T+5$), Attack Horizon derivation, and Evidence Chaining without fabricating missing telemetry.

---

## 1. 45-Feature Schema Specification

The 45 features comprise:
- **Flow Features (17)**: `flow_count`, `total_src_bytes`, `total_dst_bytes`, `total_packets`, `mean_duration`, `mean_flow_bytes`, `mean_flow_packets`, `mean_sttl`, `mean_dttl`, `mean_swin`, `mean_dwin`, `mean_iat`, `unique_src_ports`, `unique_dst_ports`, `proto_tcp_count`, `proto_udp_count`, `proto_other_count`.
- **Packet Features (22)**: `packet_count`, `mean_packet_size`, `std_packet_size`, `min_packet_size`, `max_packet_size`, `mean_ttl`, `std_ttl`, `min_ttl`, `max_ttl`, `tcp_syn_count`, `tcp_ack_count`, `tcp_fin_count`, `tcp_rst_count`, `tcp_psh_count`, `tcp_urg_count`, `mean_tcp_window`, `std_tcp_window`, `fragment_count`, `retransmission_count`, `mean_iat`, `std_iat`, `max_iat`.
- **Temporal Features (6)**: `delta_flow_count`, `delta_total_bytes`, `delta_total_packets`, `delta_ports`, `delta_iat`, `rolling_total_bytes`.
- **Omitted Feature**: `flow_features.mean_tcp_rtt`.

---

## 2. Multi-Horizon Scientific Benchmark (UNSW-NB15)

Evaluation on the contiguous mixed-state test episode (13 independent 5-horizon forecast cases):

| Horizon | Persistence F1 | Persistence Bal. Acc. | Persistence Brier | LSTM-45 F1 | LSTM-45 Bal. Acc. | LSTM-45 Brier | Winner |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **T+1** | **0.9231** | **0.9286** | **0.0769** | 0.6316 | 0.4286 | 0.3892 | **Persistence** |
| **T+2** | **0.8571** | **0.8750** | **0.1538** | 0.7000 | 0.4375 | 0.3699 | **Persistence** |
| **T+3** | **0.8000** | **0.8333** | **0.2308** | 0.7619 | 0.4444 | 0.3228 | **Persistence** |
| **T+4** | 0.7500 | **0.8000** | 0.3077 | **0.8182** | 0.4500 | **0.2577** | Split |
| **T+5** | 0.7059 | **0.7727** | 0.3846 | **0.8696** | 0.4545 | **0.1857** | Split |

### Promotion Determination
- **Status**: `HOLD` (`production_eligible: False`)
- **Champion**: Empirical Persistence Champion Baseline
- **Scientific Defense**: Persistence demonstrates significantly higher balanced accuracy across all horizons ($0.9286 \to 0.7727$) and superior short-horizon F1. While LSTM-45 achieves strong tail-horizon probability scores, it does not beat persistence across all criteria. Holding promotion protects operational deployment.

---

## 3. Real-World Capture Validation (`friday_10windows_slice.pcap`)

Validation executed through the asynchronous pipeline:
- **Packet Count**: 2,277 parsed packets
- **Temporal Windows**: 10 contiguous 60-second windows (600s total temporal coverage)
- **Flow Reconstruction**: 283 distinct flows
- **History Requirement**: Satisfied (`READY` status, 8 contiguous lookback windows)
- **Model Compatibility**: `model_ready: True` under `MODEL_SCHEMA_45`
- **Rollout Generated**:
  - $T+1$: Attack Probability = 0.6002, Confidence = 0.2003
  - $T+2$: Attack Probability = 0.2085, Confidence = 0.5830
  - $T+3$: Attack Probability = 0.1538, Confidence = 0.6923
  - $T+4$: Attack Probability = 0.1174, Confidence = 0.7651
  - $T+5$: Attack Probability = 0.0944, Confidence = 0.8112
- **Attack Horizon**: State = `EARLY_SIGNAL`, Lead Time = 60s, Summary: "Early attack signal detected at horizon T+1 (lead time 60s); duration isolated to 60s (1 window). Temporal consistency: 1.00."
- **Evidence Chain**: 4 supporting indicators (source byte volume surge, destination byte volume surge, sequential byte volume acceleration, attack horizon signal) balanced against 8 contradictory capture signals.

