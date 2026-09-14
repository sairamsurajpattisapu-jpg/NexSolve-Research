# NexSolve Final End-to-End Production Architecture

## 1. Executive Summary & Purpose
**NexSolve** (`SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data`) is a scientifically grounded, production-grade cybersecurity forecasting product. 

This document details the complete end-to-end architecture from raw network capture (PCAP/PCAPNG) to real-time temporal feature extraction, dual-schema model gating, recursive LSTM world model rollouts, Markovian attack progression forecasting, MITRE ATT&CK evidence fusion, REST APIs, and the interactive frontend dashboard.

---

## 2. Complete End-to-End Data Pipeline

```
Raw Network Capture (.pcap / .pcapng)
               │
               ▼
[Step 1: Capture Ingestion & Validation]
  - Magic byte verification (PCAP standard/swapped, PCAPNG)
  - Scapy / DPDK parsing into RawPacket records
  - Temporal continuity & packet span evaluation
               │
               ▼
[Step 2: Flow Reconstruction & Temporal Windowing]
  - 5-tuple flow grouping (src_ip, dst_ip, src_port, dst_port, proto)
  - Bi-directional flow metric accumulation (bytes, packets, rates, TCP flags)
  - Non-overlapping 60-second contiguous TemporalWindows
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│ [Step 2b: Multi-Modal Network Intelligence] (OBSERVED ONLY) │
│                                                             │
│  - Zeek-Inspired TCP Session State Tracking                 │
│      * S0, S1, SF, REJ, RSTO, RSTR, OTH, RSTOS0             │
│      * ObservationBoundaryStatus (MIDSTREAM_JOIN, TRUNCATED)│
│  - RITA-Inspired Behavioral Periodicity                     │
│      * Median interval, MAD, Bowley skewness, CV, Entropy   │
│      * Classifications: INSUFFICIENT, IRREGULAR, PERIODIC   │
│  - NFStream-Inspired Flow Intelligence                      │
│      * Bidirectional packet & byte asymmetry ratios         │
│      * Single-packet flow ratios, burstiness, rate stats    │
│  - Suricata-Compatible Signature Ingestion                  │
│      * Normalized EVE JSON parsing (GID, SID, REV, MITRE)   │
└─────────────────────────────────────────────────────────────┘
               │
               ▼
[Step 3: Evidence Normalization & Fusion]
  - FusedEvidenceItem: Modality (PROTOCOL, BEHAVIOR, ANOMALY, SIGNATURE, ML, FORECAST)
  - Strict scope assignment: OBSERVED vs FORECAST
               │
               ▼
[Step 4: Canonical State Construction (45/46 Features)]
  - Flow features (17 PCAP-compatible or 18 with RTT)
  - Packet features (22 features: sizes, TTLs, TCP flags, IAT, retransmissions)
  - Temporal delta features (6 features: rate changes, delta counts, rolling bytes)
  - Evaluation of feature availability & candidate validation
               │
               ▼
[Step 5: Dual-Schema Model Compatibility Gate]
  - Check 46-feature schema: detects missing `mean_tcp_rtt` in passive captures
  - Safety rule: Zero feature fabrication or zero-filling permitted
  - Auto-selects MODEL_SCHEMA_45 when only `mean_tcp_rtt` is absent
  - Verifies minimum contiguous history (Lookback = 8 windows)
               │
               ▼
[Step 6: World Model Recursive Rollouts (K=1..5)]
  - LSTM / GRU state rollouts predicting future network state distributions
  - Attack probability per horizon step (T+60s to T+300s)
  - Feature contribution explanations (gradient/perturbation based)
               │
               ▼
[Step 7: Empirical Markovian Attack Progression]
  - Observed stage identification: RECONNAISSANCE, EXPLOITATION, C2, DOS, etc.
  - Markov transition matrices: P(State_{T+K} | State_T) for K in {1, 3, 5}
  - Strict semantic categorization:
      * STATE_PERSISTENCE (S_{T+K} == S_T) -> No fabricated future techniques
      * DOWNSTREAM_PROGRESSION (S_{T+K} != S_T) -> Verified downstream techniques
      * ABSTAINED -> For K in {10, 15}, benign states, or insufficient evidence
               │
               ▼
[Step 8: Threat Assessment & MITRE ATT&CK Fusion]
  - Deterministic synthesis isolating OBSERVED from FORECAST evidence
  - Observed techniques: grounded in heuristic / behavioral telemetry (e.g. T1046)
  - Forecast techniques: grounded ONLY in supported DOWNSTREAM_PROGRESSION
               │
               ▼
[Step 9: REST API & Background Job Worker]
  - Endpoints: POST /api/upload-pcap, POST /api/jobs/submit, GET /api/jobs/{id}
  - Complete JSON-serializable schema payload with camelCase and snake_case aliases
               │
               ▼
[Step 10: Interactive Frontend Dashboard]
  - NetworkIntelligenceCard: Multi-modal protocol, behavioral, and flow breakdown
  - AttackProgressionCard: Visual indicator for PERSISTENCE vs PROGRESSION vs ABSTAINED
  - AttackHorizonCard: Lead time, attack state, and certainty bounds
  - EvidenceChain & ThreatAssessment: MITRE techniques cleanly separated by temporal scope
```

---

## 3. Strict Non-Negotiable Scientific Principles

1. **Zero Feature Fabrication**:
   - `mean_tcp_rtt` is never zero-filled or fabricated when absent from passive captures.
   - The dual-schema gate safely routes passive PCAP traffic to `MODEL_SCHEMA_45` (`models/world_model_45`), preserving mathematical validity.
2. **Empirical Attack Progression Semantics**:
   - `STATE_PERSISTENCE` indicates ongoing duration of the current attack stage; it is **never** presented as future downstream progression.
   - During `STATE_PERSISTENCE`, `forecast_techniques` is strictly empty.
   - `transition_probability` represents the empirical frequency among historical sequences in benchmark data, **never** an arbitrary confidence score.
3. **Temporal Isolation in Evidence Fusion**:
   - OBSERVED signals (heuristics, RITA beaconing, flow anomalies) populate `observed_techniques`.
   - FORECAST signals appear under `forecast_techniques` **only** when downstream progression is empirically supported.
4. **Honest Abstention**:
   - Forecast horizons $K=10$ (600s) and $K=15$ (900s) are marked `ABSTAINED` (`UNSUPPORTED_HORIZON`) because they lack empirical training replication.

---

## 4. Real PCAP Validation (`friday_10windows_slice.pcap`)

The pipeline was verified end-to-end against the real capture `friday_10windows_slice.pcap` (2,277 packets, 283 flows, 10 contiguous 60s windows).

### Execution Results:
- **Packet Ingestion**: 2,277 packets parsed; duration 599.99s across 10 contiguous windows.
- **Gate Evaluation**: 46-feature schema withheld due to unobserved `mean_tcp_rtt`; 45-feature schema activated cleanly with 0 missing features.
- **World Model Rollouts**: 5-step recursive forecasting rollouts generated ($K=1..5$).
- **Attack Progression**:
  - `observed_state`: `RECONNAISSANCE`
  - `observed_techniques`: `['T1046']`
  - $K=1, 3, 5$: `STATE_PERSISTENCE` with $P \in \{0.975, 0.924, 0.873\}$, empty `forecast_techniques`
  - $K=10, 15$: `ABSTAINED` with `UNSUPPORTED_HORIZON`
- **Threat Fusion**: `observed_techniques` contains `T1046`; `forecast_techniques` is empty.

### Documented Production Limitation:
- A supervised training or evaluation pair $(X_{1..L}, Y_{L+K})$ with lookback $L=8$ and forecast step $K=5$ requires at least $L + K = 13$ windows ($780\text{ s}$).
- The slice PCAP contains 10 windows ($600\text{ s}$). It fully supports real-time deployment and recursive rollout inference ($10 \ge L=8$), but cannot form an $(L=8, K=5)$ supervised evaluation target window.

---

## 5. Verification Matrix
- **Backend Tests**: 18/18 tests passed (`tests/test_production_real_pcap_end_to_end.py`, `tests/test_attack_progression.py`, `tests/test_open_source_core_strengthening.py`, `tests/test_pcap_compatible_45.py`).
- **Frontend Tests**: 10/10 test suites passed, 53/53 tests passed (vitest).
- **Frontend Production Build**: `tsc -b && vite build` completed with zero TypeScript or packaging errors.
