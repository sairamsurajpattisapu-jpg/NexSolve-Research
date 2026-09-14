# NexSolve Product Readiness & SIH Demonstration Guide

## 1. Executive Summary & Capabilities
**NexSolve** (`SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data`) is a scientifically grounded cybersecurity forecasting platform that analyzes raw PCAP/PCAPNG network traffic and forecasts the forward temporal progression of network attacks.

### Core Capabilities:
- **PCAP Ingestion & Parsing**: Validates magic bytes, extracts packets into isolated temporary runtime directories, and reconstructs bi-directional 5-tuple flows.
- **Canonical Temporal Windowing**: Computes non-overlapping 60-second temporal windows with 45-feature and 46-feature canonical network state representations.
- **Dual-Schema Compatibility Safety Gate**: Strictly enforces that passive PCAP captures (which lack `mean_tcp_rtt`) route to `MODEL_SCHEMA_45` (`nexsolve_world_model_45`). No feature fabrication, zero-filling, or fallback heuristics are permitted.
- **World Model Recursive Forecasting**: Generates 5-step ($K=1..5$) forward state rollouts predicting attack probability and gradient-based feature explanations across $T+60\text{s}$ to $T+300\text{s}$.
- **Markovian Attack Progression Forecaster**: Distinguishes active `STATE_PERSISTENCE` (where an observed attack stage continues) from `DOWNSTREAM_PROGRESSION` (where cross-stage transition occurs), outputting strictly empirical transition frequencies without arbitrary confidence heuristics.
- **Evidence & Threat Fusion**: Strictly separates OBSERVED evidence (heuristics, RITA-style beaconing) from FORECAST predictions. During `STATE_PERSISTENCE`, `forecast_techniques` is strictly empty to prevent hallucinated MITRE techniques.
- **Interactive Cybersecurity Dashboard**: Real-time visualization with `AttackHorizonCard`, `AttackProgressionCard`, `EvidenceChain`, quick-metric strips, and structured report exports (JSON & standalone HTML).

---

## 2. Scientifically Supported vs. Unsupported Claims

| Claim | Status | Scientific Basis |
| :--- | :---: | :--- |
| **45-Feature PCAP Compatibility** | **Supported** | Passive packet capture extracts 17 flow, 22 packet, and 6 temporal features. `mean_tcp_rtt` is safely omitted from the passive contract. |
| **Real-time Forward Trajectory ($K=1..5$)** | **Supported** | 5-step recursive LSTM state rollouts evaluate trajectory evolution given at least 8 contiguous historical observation windows ($480\text{s}$). |
| **Attack State Persistence Semantics** | **Supported** | Grounded in empirical transition matrices $P(\text{State}_{T+K} \mid \text{State}_T)$ derived from ground truth benchmarks. Persistence is never claimed to be a new attack. |
| **Separation of Observed vs. Forecast MITRE Techniques** | **Supported** | MITRE techniques (such as `T1046`) only appear in `forecast_techniques` when an empirical downstream transition is supported. |
| **Long Horizon Rollouts ($K=10, 15$)** | **Unsupported (Abstained)** | Lacks empirical replication; marked `ABSTAINED` with explicit reason `UNSUPPORTED_HORIZON`. |
| **Universal 99.9% Prediction Accuracy** | **Unsupported (Rejected)** | NexSolve does not fabricate artificial certainty. Transition probabilities represent observed empirical frequency, not guaranteed forecasting accuracy. |

---

## 3. Real PCAP Ingestion Results (`friday_10windows_slice.pcap`)

The production pipeline was verified using `C:\Users\saira\Downloads\friday_10windows_slice.pcap`:
- **Packets Ingested**: 2,277 packets parsed across 599.99s.
- **Reconstructed Flows**: 283 active 5-tuple flows.
- **Canonical Windows**: 10 contiguous 60s windows.
- **Model Gate**: Safely abstains from 46-feature schema (`mean_tcp_rtt` unobserved) and engages `MODEL_SCHEMA_45` with 0 missing features.
- **World Model Rollouts**: 5-step rollouts ($K=1..5$) generated with feature contribution explanations.
- **Attack Progression**:
  - `observed_state`: `RECONNAISSANCE` (`T1046`)
  - $K=1, 3, 5$: `STATE_PERSISTENCE` with empirical transition probabilities ($0.975, 0.924, 0.873$) and empty `forecast_techniques`.
  - $K=10, 15$: `ABSTAINED` (`UNSUPPORTED_HORIZON`).
- **Limitation Note**: Supervised evaluation pairs $(L=8, K=5)$ require at least $L+K=13$ windows ($780\text{s}$). This 10-window slice validates real-time rollout inference ($10 \ge L=8$), but cannot form an $(L=8, K=5)$ evaluation pair.

---

## 4. Verification Test Status

- **Backend Pytest Suite**: **34 passed, 0 failed**
  - `tests/test_production_real_pcap_end_to_end.py`: 4 passed (real PCAP e2e, empty capture rejection, malformed capture rejection, insufficient history abstention)
  - `tests/test_attack_progression.py`: 7 passed
  - `tests/test_open_source_core_strengthening.py`: 7 passed
  - `tests/test_pcap_compatible_45.py`: 3 passed
  - `model_service/test_app.py`: 13 passed
- **Frontend Vitest Suite**: **53 passed, 0 failed** across 10 test suites.
- **Frontend Production Build**: `tsc -b && vite build` passed cleanly with 0 TypeScript errors.

---

## 5. 30-Second SIH Demonstration Walkthrough

When presenting to evaluators, execute the following flow:

1. **The Core Problem (5 seconds)**:
   - "Current network intrusion systems only tell you what attack already happened. NexSolve forecasts what the attacker will do 1 to 5 minutes into the future."
2. **Upload Real Capture (10 seconds)**:
   - Navigate to `/dashboard` (or click "Analyze PCAP").
   - Drag and drop `friday_10windows_slice.pcap`.
   - Show the deterministic pipeline status: `PARSING` $\rightarrow$ `FLOW RECONSTRUCTION` $\rightarrow$ `STATE EXTRACTION` $\rightarrow$ `FORECASTING` $\rightarrow$ `COMPLETE`.
3. **Show Scientific Gating (5 seconds)**:
   - Point to the **Model Contract: 45-DIM** badge:
   - "Notice the system did not fabricate missing TCP Round Trip Time (RTT). It safely routed to our 45-feature model contract without zero-filling."
4. **Show Attack Progression & Persistence (10 seconds)**:
   - Point to the **Attack-Stage Progression Forecaster**:
   - "The system observed `RECONNAISSANCE` (`T1046`). At $T+1\text{m}$, $T+3\text{m}$, and $T+5\text{m}$, it predicts **STATE PERSISTENCE** with empirical transition probabilities of 97.5%, 92.4%, and 87.3%."
   - "Notice that `forecast_techniques` is empty. We do not invent future exploits when the evidence only supports the attacker continuing reconnaissance."
   - Point to $T+10\text{m}$ and $T+15\text{m}$: "At longer horizons, the system honestly displays **ABSTAINED** because longer steps lack empirical replication."

---

## 6. Open-Source Intelligence & Boundary Capabilities (Phase 12)

### Supported Capabilities:
- **Deterministic Session-State Analysis (Zeek-Inspired)**:
  - 100% native Python single-pass connection lifecycle tracking (`S0`, `S1`, `SF`, `REJ`, `RSTO`, `RSTR`, `OTH`, `RSTOS0`).
  - Strict capture boundary qualification (`ObservationBoundaryStatus.MIDSTREAM_JOIN` / `TRUNCATED_AT_END`) avoiding false scan classification on truncated passive slices.
- **Behavioral Periodicity Statistics (RITA-Inspired)**:
  - Exact Bowley quartile skewness: $B = \frac{Q_3 + Q_1 - 2 Q_2}{Q_3 - Q_1}$.
  - Median Absolute Deviation (MAD) about the median: $\text{MAD} = \text{median}(|X_i - \text{median}(X)|)$.
  - Shannon entropy over binned intervals and coefficient of variation (CV).
  - Categorical classifications: `INSUFFICIENT_OBSERVATIONS`, `IRREGULAR`, `WEAKLY_PERIODIC`, `PERIODIC`, `HIGHLY_PERIODIC`.
- **Flow Statistical Intelligence (NFStream-Inspired)**:
  - Bounded bidirectional packet and byte asymmetry ratios in $[-1.0, 1.0]$.
  - Single-packet flow ratios for sweep scan identification.
  - Volumetric transfer rate and burstiness accounting.
- **Normalized Signature Evidence (Suricata-Compatible)**:
  - Decoupled parser for external Suricata EVE JSON event streams (GID, SID, REV, Category, Severity, MITRE metadata).
  - Emits `NO_SURICATA_EVIDENCE_AVAILABLE` when no external log is present, without fabricating signatures.
- **Multi-Modal Evidence Normalization & Fusion**:
  - Unifies `PROTOCOL`, `BEHAVIOR`, `ANOMALY`, `SIGNATURE`, `ML`, and `FORECAST` modalities into immutable `FusedEvidenceItem` records.
  - Strict, auditable firewall between `OBSERVED` telemetry and `FORECAST` rollouts.

### Explicitly NOT Supported (Scientific Boundaries):
- **NO automatic malware classification from periodicity**: Periodicity indicates robotic or automated cadence (e.g. NTP, telemetry, heartbeats), not inherent malice.
- **NO universal beacon detection without sufficient history**: Minimum 4 connections and 3 distinct non-zero intervals required.
- **NO universal attack forecasting**: Forecasts are conditioned on observable state history; novel unobserved vectors default to honest uncertainty.
- **NO automatic MITRE inference from generic anomalies**: MITRE techniques require strict empirical or rule-based grounding (e.g. `T1046` for port scanning; `T1498` for floods; verified rule tags for Suricata).
- **NO unsupported downstream progression**: Downstream transitions are never manufactured during persistence or when transition data is absent.
- **NO fabricated Suricata evidence**: Alerts are only presented when verified EVE JSON logs are supplied.
- **NO RTT inference from passive PCAP**: Passive captures do not infer or zero-fill `mean_tcp_rtt`.
