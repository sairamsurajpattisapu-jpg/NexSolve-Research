# Final System Architecture
**SIH 2026 Problem Statement 26153: AI based Network Attack Forecasting from Network Traffic Data**

## High-Level System Architecture

```
                                  DATA INGESTION
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼                                                     ▼
     Raw PCAP Capture                                   Flow CSV Telemetry
    (Live / Uploaded)                                   (UNSW-NB15 / TON-IoT)
             │                                                     │
             ▼                                                     ▼
    Canonical Packet Parser                              Temporal Binning
  (Scapy / dpkt / zero-dep)                             (60-second windows)
             │                                                     │
             ▼                                                     ▼
   Flow Aggregator & Tracking                           Observable Metric Map
   (Directional Session States)                                    │
             │                                                     │
             └──────────────────────────┬──────────────────────────┘
                                        │
                                        ▼
                           CANONICAL FEATURE CONTRACT
                          (Strict 45-Feature Interface)
                                        │
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
                 45-Feature PCAP                 46-Feature Enriched
                 Safety Contract                 Telemetry Contract
               (mean_tcp_rtt excluded)         (mean_tcp_rtt present)
                        │                               │
                        ▼                               ▼
               Active: MODEL_SCHEMA_45         Fallback / Rich Telemetry
                        │
                        ▼
                           TEMPORAL STATE BUILDER
                      S_t = [Flow_17, Packet_22, Temporal_6]
                                        │
                                        ▼
                            HISTORY BUFFER (N >= 8)
                   If N < 8: Safety Abstention (INSUFFICIENT_HISTORY)
                                        │
                                        ▼
                         TEMPORAL WORLD MODEL (NumPy LSTM)
                           Hidden Size = 24, Lookback = 8
                                        │
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
               State Transition Head             Attack Risk Head
               P(S_{t+1} | S_{t-7:t})          P(Attack_{t+1} | S_{t-7:t})
                        │                               │
                        ▼                               ▼
              AUTOREGRESSIVE ROLLOUT              PROBABILITY ESTIMATE
             S_hat_{t+1} -> ... -> S_hat_{t+5}   (100% Attack Recall)
                        │                               │
                        └───────────────┬───────────────┘
                                        │
                                        ▼
                          ATTACK PROGRESSION ENGINE
                        Empirical Markov Stage Dynamics
                                        │
                                        ▼
                         MITRE ATT&CK CONTEXTUAL MAP
                       (T1046, T1071, T1190, T1498)
                                        │
                                        ▼
                         EXPLAINABILITY ATTRIBUTION
                      (Counterfactual Feature Delta)
                                        │
                                        ▼
                               FASTAPI BACKEND
                          /api/analyze & /api/pcap
                                        │
                                        ▼
                               REACT FRONTEND UI
                    (Forward Projection Trajectory Table)
```

---

## Component Details

### 1. Ingestion & Extraction Layer
- **Input Formats**: `.pcap`, `.pcapng`, and pre-aggregated flow CSVs.
- **Processing**: Packets are parsed into canonical `PacketRecord` instances; bidirectional flows are tracked with microsecond timestamps and directional packet metrics.

### 2. Feature Contract Layer
- **Safety Gate**: Evaluates extracted fields against `MODEL_SCHEMA_45` and `MODEL_SCHEMA`.
- If `mean_tcp_rtt` cannot be reliably observed without full bi-directional state synchronization, the 45-feature pipeline activates automatically.

### 3. Forecasting & Rollout Layer
- Recursive multi-step lookahead propagates the predicted state vector forward without ground truth leakages.
- Predicts continuous network characteristics alongside malicious transition risks across horizons $T+1 \dots T+5$.

### 4. Behavioral Fusion & Presentation Layer
- Translates numerical trajectories into operational defender intelligence: MITRE techniques, progression stages, and feature rankings.
- Served through asynchronous background job workers with persistent state storage and RESTful endpoints.
