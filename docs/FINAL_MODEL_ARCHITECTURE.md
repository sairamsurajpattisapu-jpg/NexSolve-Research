# NexSolve: Final Network World Model Architecture Specification

**Document Version:** 1.0.0  
**Date:** September 2026  
**Status:** Authoritative Architectural Design  
**Model Identifier:** `final_world_model` (`models/final_world_model/`)  
**Deployment Tier:** Multi-View Multi-Task World Model  

---

## 1. System Philosophy & Objectives

The NexSolve Final Network World Model transitions the platform from a monolithic, flat recurrent predictor (Candidate V2) to a **multi-view, representation-learning Network World Model ($Z_t$)**. 

Rather than treating network telemetry as an undifferentiated vector of 45 numbers, the Final Model models the network as an interconnected dynamic cyber-physical system across 8 distinct telemetry modalities:
1. **Packet Dynamics:** Frame length distributions, inter-arrival times, IP fragmentation, and TCP sequence metrics.
2. **Flow Aggregates:** Session volumetrics, TTL distributions, window dynamics, and port cardinality.
3. **Protocol Behaviors:** L4/L7 protocol distributions (TCP, UDP, DNS, HTTP, TLS, SSH, ICMP, ARP, DHCP).
4. **Host Intelligence:** Visible IP endpoint behaviors, outbound/inbound asymmetry, port spread, and host risk scores.
5. **Causal Temporal Dynamics:** First-order deltas, second-order accelerations, causal moving averages, rolling volatility, and burstiness indices.
6. **Interaction Behaviors:** Endpoint diversity, new peer arrival rates, destination/source dispersion, and Gini concentration.
7. **Dynamic Communication Graph ($G_t$):** Directed communication topologies ($V_t, E_t$), edge churn, node churn, and degree centrality.
8. **Observability & Missingness:** Explicit missingness masks preventing accidental zero-filling of unobserved protocol semantics.

---

## 2. End-to-End Pipeline Architecture

```
RAW PCAP / NETWORK TELEMETRY
              │
              ▼
   INGESTION & DATA QUALITY ASSESSMENT
   (FastPcapDecoder / Ingestion Gate)
              │
              ▼
   MULTI-VIEW TELEMETRY EXTRACTION
   ┌────────────────────────────────────────────────────────────────────────┐
   │ • Packet View (22 dims)        • Temporal Velocity View (10 dims)      │
   │ • Flow View (17 dims)          • Behavioral Dynamics View (12 dims)    │
   │ • Protocol View (16 dims)      • Dynamic Graph Snapshot View (11 dims) │
   │ • Host View (5 dims)           • Observability / Missingness (10 dims) │
   └────────────────────────────────────────────────────────────────────────┘
              │
              ▼
   MODULAR MULTI-VIEW ENCODERS
   ┌─────────┬─────────┬──────────┬────────┬──────────┬──────────┬─────────┬─────────┐
   │ Packet  │ Flow    │ Protocol │ Host   │ Temporal │ Behavior │ Graph   │ Obs     │
   │ Encoder │ Encoder │ Encoder  │Encoder │ Encoder  │ Encoder  │ Encoder │ Encoder │
   │ (d=16)  │ (d=16)  │ (d=12)   │ (d=8)  │ (d=8)    │ (d=8)    │ (d=8)   │ (d=6)   │
   └─────────┴─────────┴──────────┴────────┴──────────┴──────────┴─────────┴─────────┘
              │
              ▼
   CROSS-VIEW GATED FUSION
   Z_t = tanh(W_fuse [v_1, ..., v_8] + b_fuse) ⊙ σ(W_gate [v_1, ..., v_8] + b_gate)
              │
              ▼
   NETWORK WORLD STATE Z_t ∈ ℝ^32
              │
              ▼
   RECURRENT TEMPORAL ACCUMULATOR
   h_t, c_t = LSTMCell(Z_t, h_{t-1}, c_{t-1})  (Hidden Dim H=32, Lookback L=8)
              │
              ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │ MULTI-TASK PREDICTION HEADS                                            │
   │ ├── Continuous Future State Forecaster (T+1 .. T+5, D=45)               │
   │ ├── Forward Attack Probability Head (Calibrated sigmoid logit)         │
   │ ├── Attack Stage Estimation (Softmax distribution over 6 MITRE stages)  │
   │ ├── Attack Progression Trajectory Head (Progression index & velocity)  │
   │ ├── Latent Anomaly Detection Head (Reconstruction residual energy)     │
   │ ├── Novelty / Out-of-Distribution Head (Mahalanobis distance envelope) │
   │ ├── Host-Level Risk Ranking Engine                                     │
   │ ├── Directed Communication Edge Risk Ranking                           │
   │ └── Uncertainty Decomposition (Epistemic vs Aleatoric bounds)          │
   └────────────────────────────────────────────────────────────────────────┘
              │
              ▼
   EVIDENCE-BASED RISK INDICATOR ENGINE
   (Synthesizes OBSERVED RISK INDICATOR records with physical telemetry citations)
              │
              ▼
   5-TIER COMPREHENSIVE ABSTENTION ENGINE
   (FULL_FORECAST | DEGRADED_FORECAST | ANOMALY_ONLY | OBSERVABILITY_ONLY | ABSTAIN)
              │
              ▼
   AUTHORITATIVE STRUCTURED NETWORK INTELLIGENCE
```

---

## 3. Mathematical Specifications

### 3.1 Multi-View Encoders
For each observable telemetry view $m \in \{\text{packet}, \text{flow}, \text{protocol}, \text{host}, \text{temporal}, \text{behavior}, \text{graph}, \text{observability}\}$, the view vector $x^{(m)}_t \in \mathbb{R}^{d_{\text{in}}^{(m)}}$ is projected via a dedicated non-linear encoder:
$$v^{(m)}_t = \tanh\left(W^{(m)} x^{(m)}_t + b^{(m)}\right) \in \mathbb{R}^{d_{\text{out}}^{(m)}}$$
If a view is disabled or completely unobserved, $v^{(m)}_t = \mathbf{0}$, ensuring controlled scientific ablation without structural failure.

### 3.2 Cross-View Gated Fusion
The view representations are concatenated into a joint multi-modal vector:
$$\mathbf{v}_t = \left[ v^{(\text{packet})}_t, v^{(\text{flow})}_t, v^{(\text{protocol})}_t, v^{(\text{host})}_t, v^{(\text{temporal})}_t, v^{(\text{behavior})}_t, v^{(\text{graph})}_t, v^{(\text{obs})}_t \right] \in \mathbb{R}^{82}$$
The unified Network World State $Z_t \in \mathbb{R}^{32}$ is computed using candidate projection modulated by a cross-view feature gate:
$$Z_t = \tanh\left(W_{\text{fuse}} \mathbf{v}_t + b_{\text{fuse}}\right) \odot \sigma\left(W_{\text{gate}} \mathbf{v}_t + b_{\text{gate}}\right)$$

### 3.3 Recurrent Temporal World State Accumulator
Temporal world context is aggregated causally over lookback history $L = 8$ contiguous 60-second windows:
$$h_t, c_t = \text{LSTMCell}(Z_t, h_{t-1}, c_{t-1})$$
where $h_t \in \mathbb{R}^{32}$ represents the recurrent world context vector at timestamp $t$.

### 3.4 Multi-Task Decoders
From the recurrent world context $h_t$, independent linear and non-linear decoders project to specific tasks:
1. **Continuous State Forecasting:**
   $$\hat{S}_{t+1} = W_{\text{state}} h_t + b_{\text{state}} \in \mathbb{R}^{45}$$
2. **Forward Attack Probability:**
   $$\hat{p}_{t+1} = \sigma\left(\frac{W_{\text{attack}} h_t + b_{\text{attack}}}{T_{\text{cal}}}\right)$$
3. **Attack Stage Distribution:**
   $$\hat{\mathbf{y}}_{\text{stage}} = \text{Softmax}\left(W_{\text{stage}} h_t + b_{\text{stage}}\right) \in \Delta^5$$
4. **Attack Progression Index:**
   $$\hat{\gamma}_{t+1} = \sigma\left(W_{\text{prog}} h_t + b_{\text{prog}}\right) \in [0, 1]$$
5. **Latent Reconstruction Anomaly Score:**
   $$\hat{h}_t = \tanh(W_{\text{recon}} h_t + b_{\text{recon}}), \quad a_t = \min\left(1.0, 5 \cdot \frac{1}{H} \|h_t - \hat{h}_t\|_2^2\right)$$
6. **Novelty / Out-of-Distribution Head (Validation-Calibrated Mahalanobis Envelope):**
   $$d_{\text{M}}(Z_t) = \sqrt{(Z_t - \mu_Z)^T \Sigma_Z^{-1} (Z_t - \mu_Z)}$$
   $$\text{OOD}_t = \sigma\left(\frac{d_{\text{M}}(Z_t) - \tau_{95}}{\tau_{99} - \tau_{95} + \epsilon}\right)$$
   where $\tau_{95}$ and $\tau_{99}$ are empirical percentiles fit strictly on the validation partition $\mathcal{D}_{\text{val}}$, eliminating arbitrary constant divisors.

---

## 4. Architectural Ablation Matrix

The architecture supports dynamic ablation of each individual encoder view and objective:

| View / Component | Input Dimension | Latent Dimension | Primary Role |
| :--- | :---: | :---: | :--- |
| **Packet Encoder** | 22 | 16 | Volumetrics, packet sizes, TTL distribution, TCP flags |
| **Flow Encoder** | 17 | 16 | Session durations, flow volumes, bidirectional rates |
| **Protocol Encoder** | 16 | 12 | TCP/UDP ratios, DNS, HTTP, TLS, SSH, ICMP, ARP |
| **Host Encoder** | 5 | 8 | Active endpoints, outbound/inbound fan-out/fan-in |
| **Temporal Encoder** | 10 | 8 | First-order velocity, acceleration, rolling volatility |
| **Behavior Encoder** | 12 | 8 | Peer diversity, port entropy, Gini concentration, churn |
| **Graph Encoder** | 11 | 8 | Degree centrality, density, edge/node churn |
| **Observability Encoder**| 10 | 6 | Data completeness, truncation ratio, missingness masks |
| **Cross-View Fusion** | 82 | 32 | Gated latent state integration ($Z_t$) |
| **Recurrent Accumulator**| 32 | 32 | Temporal context propagation ($h_t$) |
| **Continuous Decoder** | 32 | 45 | Extensible $T+1..T+5$ state forecasting |

---

## 5. Backward Compatibility & Hardened Canonical Projection

The Final Model maintains **100% interoperability** with the canonical 45-feature format established in Candidate V2, hardened against constant padding:
1. When presented with a raw 45-feature vector (e.g. from existing datasets or basic flow sensors), `extract_views_from_canonical_45()` maps features directly into the Flow, Packet, and Temporal views.
2. In the hardened release, **all arbitrary constant paddings (e.g., 1.5, 0.05, 0.3, 2.0, 0.5, 0.1, 0.05) have been completely eliminated**. Unobserved higher-order views (Host, Graph, Protocol) are populated with mathematically grounded telemetry ratios (e.g., active flow counts, fan-out proxies, protocol indicators) accompanied by an explicit 10-dimensional missingness mask vector (`obs_vec`).
3. Both `candidate_v2` and `final_world_model` remain registered side-by-side in `ModelRegistry`, ensuring existing systems continue to execute without disruption.

