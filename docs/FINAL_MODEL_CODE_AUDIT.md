# NexSolve Final Network World Model — Comprehensive Code Audit

**Audit Date:** September 26, 2026  
**Audit Target:** Codebase implementation of `final_world_model`  
**Governing Standard:** Independent Verification & Validation (IV&V)  

---

## 1. Input Features & Canonical Schema

### 1.1 Total Features Evaluated vs Passed to Model
- **Documented in Feature Registry (`ml/features/feature_registry.py`):** 115 features across 18 declared families.
- **Canonical Model Schema (`world_model.FEATURE_NAMES_45` / `nexsolve_core/state.py`):** **45 continuous features**.
- **Model Ingestion Dimension (`model.npz` `state_dim` / `enc_flow_W` / `enc_packet_W`):** **45 continuous dimensions** (partitioned into 17 flow, 22 packet, 6 temporal base features).
- **Actual Features Fed to Model:** The model receives exactly 45 canonical features per time step. The additional 70 features defined in `FeatureRegistry` (115 total - 45 canonical) exist only as registry metadata specifications and are **not** ingested by the neural network weights.

### 1.2 Exact Feature Names (Canonical 45 Features)

| Index | Feature Name | Canonical Family | Description / Computation |
| :---: | :--- | :--- | :--- |
| `0` | `flow_count` | Flow | Total bidirectional flow sessions active in window |
| `1` | `total_src_bytes` | Flow | Sum of source transmitted bytes |
| `2` | `total_dst_bytes` | Flow | Sum of destination transmitted bytes |
| `3` | `total_packets` | Flow | Sum of all flow packets across sessions |
| `4` | `mean_duration` | Flow | Average active flow duration |
| `5` | `mean_flow_bytes` | Flow | Mean bytes per flow |
| `6` | `mean_flow_packets` | Flow | Mean packets per flow |
| `7` | `mean_sttl` | Flow | Mean source IP TTL |
| `8` | `mean_dttl` | Flow | Mean destination IP TTL |
| `9` | `mean_swin` | Flow | Mean source TCP window advertisement |
| `10`| `mean_dwin` | Flow | Mean destination TCP window advertisement |
| `11`| `flow_mean_iat` | Flow | Mean flow inter-arrival time |
| `12`| `unique_src_ports` | Flow | Number of distinct source ports |
| `13`| `unique_dst_ports` | Flow | Number of distinct destination ports |
| `14`| `proto_tcp_count` | Flow | Count of TCP flows |
| `15`| `proto_udp_count` | Flow | Count of UDP flows |
| `16`| `proto_other_count`| Flow | Count of non-TCP/UDP flows |
| `17`| `packet_count` | Packet | Total raw packets in window |
| `18`| `mean_packet_size` | Packet | Mean packet byte length |
| `19`| `std_packet_size` | Packet | Standard deviation of packet lengths |
| `20`| `min_packet_size` | Packet | Minimum packet length |
| `21`| `max_packet_size` | Packet | Maximum packet length |
| `22`| `mean_ttl` | Packet | Mean IP TTL |
| `23`| `std_ttl` | Packet | Standard deviation of IP TTL |
| `24`| `min_ttl` | Packet | Minimum IP TTL |
| `25`| `max_ttl` | Packet | Maximum IP TTL |
| `26`| `tcp_syn_count` | Packet | Count of SYN flag packets |
| `27`| `tcp_ack_count` | Packet | Count of ACK flag packets |
| `28`| `tcp_fin_count` | Packet | Count of FIN flag packets |
| `29`| `tcp_rst_count` | Packet | Count of RST flag packets |
| `30`| `tcp_psh_count` | Packet | Count of PSH flag packets |
| `31`| `tcp_urg_count` | Packet | Count of URG flag packets |
| `32`| `mean_tcp_window` | Packet | Mean TCP advertised receive window |
| `33`| `std_tcp_window` | Packet | Standard deviation of TCP window |
| `34`| `fragment_count` | Packet | Count of fragmented IP packets |
| `35`| `retransmission_count` | Packet | Count of retransmitted packets |
| `36`| `mean_iat` | Packet | Mean inter-arrival time between packets |
| `37`| `std_iat` | Packet | Standard deviation of inter-arrival times |
| `38`| `max_iat` | Packet | Maximum inter-arrival time |
| `39`| `delta_flow_count` | Temporal | 1st-order difference in flow count ($\Delta x_0$) |
| `40`| `delta_packet_count`| Temporal | 1st-order difference in packet count ($\Delta x_{17}$) |
| `41`| `delta_total_bytes`| Temporal | 1st-order difference in total bytes |
| `42`| `rolling_mean_flow_count`| Temporal | Rolling average of flow count |
| `43`| `rolling_mean_packet_count`| Temporal| Rolling average of packet count |
| `44`| `rolling_mean_total_bytes`| Temporal| Rolling average of total bytes |

---

## 2. Feature Families: Specification vs. Implementation

The system declares 18 feature families in `FeatureRegistry`:
1. `packet` (22 features) — Actually computed and passed to model.
2. `flow` (17 features) — Actually computed and passed to model.
3. `tcp` (4 features) — Documented; 2 derived heuristically in `extract_views_from_canonical_45()` (`syn_ack_ratio`, `rst_ratio`).
4. `udp` (3 features) — Documented; 2 derived heuristically (`udp_cnt`, `udp_ratio`).
5. `dns` (4 features) — Documented only; no DNS parser in model ingestion path.
6. `http` (3 features) — Documented only; no HTTP parser in model ingestion path.
7. `tls` (3 features) — Documented only; no TLS handshake parser in model ingestion path.
8. `ssh` (2 features) — Documented only; no SSH parser in model ingestion path.
9. `icmp` (3 features) — Documented only; no ICMP parser in model ingestion path.
10. `arp` (3 features) — Documented only; no ARP parser in model ingestion path.
11. `dhcp` (2 features) — Documented only; no DHCP parser in model ingestion path.
12. `temporal` (9 features) — 6 computed and passed to model; 3 extended metrics in `TemporalEngine`.
13. `behavioral` (12 features) — Heuristically computed in `BehavioralEngine` or simulated in `extract_views_from_canonical_45()`.
14. `host` (5 features) — Computed in `HostGraphIntelligenceEngine` or approximated from flow ports.
15. `graph` (8 features) — Computed in `HostGraphIntelligenceEngine` or approximated in `extract_views_from_canonical_45()`.
16. `statistical` (5 features) — Documented only (skewness, kurtosis).
17. `observability` (4 features) — Documented; approximated via flags in `extract_views_from_canonical_45()`.
18. `missingness` (6 features) — Explicit boolean flags in `extract_views_from_canonical_45()`.

---

## 3. Neural Architecture & Parameter Audit

### 3.1 Neural Dimensions & Weight Tensors (`models/final_world_model/model.npz`)

| Submodule | Tensor Key | Shape | Parameter Count | Analytical Role |
| :--- | :--- | :---: | :---: | :--- |
| **Packet Encoder** | `enc_packet_W`, `enc_packet_b` | $(16, 22)$, $(16,)$ | $352 + 16 = 368$ | Linear projection of 22 packet metrics to 16D |
| **Flow Encoder** | `enc_flow_W`, `enc_flow_b` | $(16, 17)$, $(16,)$ | $272 + 16 = 288$ | Linear projection of 17 flow metrics to 16D |
| **Protocol Encoder** | `enc_protocol_W`, `enc_protocol_b` | $(12, 16)$, $(12,)$ | $192 + 12 = 204$ | Projection of 16 derived protocol features to 12D |
| **Host Encoder** | `enc_host_W`, `enc_host_b` | $(8, 5)$, $(8,)$ | $40 + 8 = 48$ | Projection of 5 host profile metrics to 8D |
| **Temporal Encoder** | `enc_temporal_W`, `enc_temporal_b` | $(8, 10)$, $(8,)$ | $80 + 8 = 88$ | Projection of 10 temporal velocity metrics to 8D |
| **Behavior Encoder** | `enc_behavior_W`, `enc_behavior_b` | $(8, 12)$, $(8,)$ | $96 + 8 = 104$ | Projection of 12 behavioral metrics to 8D |
| **Graph Encoder** | `enc_graph_W`, `enc_graph_b` | $(8, 11)$, $(8,)$ | $88 + 8 = 96$ | Projection of 11 graph evolution metrics to 8D |
| **Observability Encoder**| `enc_observability_W`, `enc_observability_b` | $(6, 10)$, $(6,)$ | $60 + 6 = 66$ | Projection of 10 observability/missingness flags to 6D |
| **Cross-View Gating** | `W_gate`, `b_gate` | $(32, 82)$, $(32,)$ | $2,624 + 32 = 2,656$| Sigmoidal gating across concatenated 82D views |
| **Cross-View Fusion** | `W_fuse`, `b_fuse` | $(32, 82)$, $(32,)$ | $2,624 + 32 = 2,656$| Linear transformation of gated multi-view embedding |
| **Recurrent Accumulator**| `W_acc`, `b_acc` | $(128, 64)$, $(128,)$ | $8,192 + 128 = 8,320$| 4-gate LSTM cell ($4 \times 32 = 128$) over $[Z_t, h_{t-1}]$ ($32+32=64$) |
| **State Forecast Decoder**| `W_state`, `b_state` | $(45, 32)$, $(45,)$ | $1,440 + 45 = 1,485$| Linear projection from hidden state $h_t$ to 45 continuous features |
| **Attack Probability Head**| `W_attack`, `b_attack` | $(1, 32)$, $(1,)$ | $32 + 1 = 33$ | Sigmoid logit projection for binary attack classification |
| **MITRE Stage Head** | `W_stage`, `b_stage` | $(6, 32)$, $(6,)$ | $192 + 6 = 198$ | Softmax logits across 6 MITRE kill-chain stages |
| **Progression Index Head**| `W_prog`, `b_prog` | $(1, 32)$, $(1,)$ | $32 + 1 = 33$ | Sigmoidal regression for kill-chain progression index $[0, 1]$ |
| **Latent Reconstruction**| `W_recon`, `b_recon` | $(32, 32)$, $(32,)$ | $1,024 + 32 = 1,056$| Autoencoding reconstruction of $Z_t$ for residual anomaly detection |
| **Uncertainty Head** | `W_unc`, `b_unc` | $(2, 32)$, $(2,)$ | $64 + 2 = 66$ | 2D parameter output (aleatoric/epistemic variance parameterization) |
| **Scalars / Calibration**| `d_z`, `hidden_dim`, `state_dim`, `temperature`, `threshold` | $(1,)$ each | 5 | Architecture hyperparameters and calibration scalars |
| **TOTAL PARAMETERS** | | | **17,770** | Fully verifiable analytical float64 parameters |

---

## 4. Multi-Task Decoders & Reasoning Mechanisms

### 4.1 Forecast Decoder Architecture
- **Method:** Linear mapping $\hat{X}_{t+1} = W_{\text{state}} h_t + b_{\text{state}}$.
- **Multi-Step Rollout ($T+1..T+5$):** Recursive multi-step rollout. The predicted state $\hat{X}_{t+1}$ is encoded via `extract_views_from_canonical_45()` to produce $\hat{Z}_{t+1}$, which updates the recurrent accumulator to obtain $h_{t+1}$, and so forth up to $T+5$.

### 4.2 Attack Head
- **Method:** Logistic sigmoid on logit $z_{\text{attack}} = W_{\text{attack}} h_t + b_{\text{attack}}$.
- **Thresholding:** Uses calibrated decision threshold $\tau^* = 0.05$ (or nominal $\tau = 0.30$).

### 4.3 Anomaly Head
- **Method:** Latent reconstruction error:
  $$\hat{Z}_t = \tanh(W_{\text{recon}} Z_t + b_{\text{recon}}), \quad e_{\text{recon}} = \| Z_t - \hat{Z}_t \|_2$$
  Combined with state residual norm $\| X_t - \hat{X}_{t|t-1} \|_2$.

### 4.4 OOD Mechanism
- **Implementation (`ml/models/uncertainty_ood.py`):**
  - Baseline centroid $\mu_Z \in \mathbb{R}^{32}$ and pseudo-inverse covariance $\Sigma_Z^{-1} \in \mathbb{R}^{32 \times 32}$ fitted on first 200 training sequence representations.
  - Mahalanobis distance $D_M(Z) = \sqrt{(Z - \mu_Z)^\top \Sigma_Z^{-1} (Z - \mu_Z)}$.
  - `ood_score = min(1.0, D_M / 10.0)`.
  - `is_ood = bool(ood_score > 0.65)`.
- **Classification:** **Experimental OOD Heuristic** (fixed divisor 10.0 and fixed threshold 0.65).

### 4.5 Uncertainty Mechanism
- **Implementation (`ml/models/uncertainty_ood.py`):**
  - Epistemic uncertainty is computed as: `min(1.0, ood_score * 0.8 + 0.1)`.
  - Aleatoric uncertainty is computed as: `max(0.0, 1.0 - abs(attack_prob - 0.30) * 3.0)`.
  - Total uncertainty: `0.6 * epistemic + 0.4 * aleatoric`.
- **Classification:** **Deterministic Heuristic Proxy**, NOT a Bayesian variance posterior or Monte Carlo ensemble.

### 4.6 Risk Indicator Mechanism (`ml/models/risk_indicators.py`)
- Evaluates 6 deterministic operational conditions over host degree, peer expansion, port count, edge churn, and traffic Gini coefficients:
  1. `ABNORMAL_OUTBOUND_FANOUT`: `len(outbound_peers) >= 15`
  2. `ABNORMAL_INBOUND_FANIN`: `len(inbound_peers) >= 20`
  3. `RAPID_PEER_EXPANSION`: `new_peer_rate > 0.40` and `node_count >= 5`
  4. `UNUSUAL_SERVICE_EXPOSURE_PROBING`: `len(probed_ports) >= 8`
  5. `HIGH_COMMUNICATION_CHURN`: `edge_churn_rate > 0.60` and `edge_count >= 10`
  6. `ABNORMAL_TRAFFIC_CONCENTRATION`: `traffic_concentration_gini > 0.85`
- Evaluates strictly observable physical facts; never emits speculative claims of software vulnerabilities or host compromise.

### 4.7 5-Tier Abstention Mechanism (`ml/models/abstention_engine.py`)
- Evaluates input quality, lookback history length, numeric validity, timestamp continuity, and uncertainty thresholds:
  - `FULL_FORECAST`: History $\ge 8$ windows, data quality $\ge 0.70$, uncertainty $\le 0.40$, not OOD.
  - `DEGRADED_FORECAST`: History $\ge 8$ windows, but moderate uncertainty ($0.40 < u \le 0.70$) or partial sensor coverage.
  - `ANOMALY_ONLY`: OOD detected or high uncertainty ($u > 0.70$); suppresses classification, retains anomaly score.
  - `OBSERVABILITY_ONLY`: Insufficient history ($W < 8$); suppresses forward forecasts, returns current window observability metrics.
  - `ABSTAIN`: Invalid numerics (NaN/Inf), non-contiguous timestamps, or missing parseable frames.

---

## 5. Summary Code Audit Findings

1. **Input Dimensions:** Exactly 45 canonical features enter the neural weights. The 115-feature registry is an architectural taxonomy; 70 features are not ingested.
2. **Multi-View Derivation:** The 8 encoder views are derived from the 45 canonical features via `extract_views_from_canonical_45()` using heuristic ratios and constant padding.
3. **Weight Count:** Total parameter count is exactly 17,770 float64 values, fully verifiable in `models/final_world_model/model.npz`.
4. **Uncertainty & OOD:** Epistemic/aleatoric uncertainty and OOD novelty are deterministic heuristic scoring functions rather than Bayesian posteriors.
