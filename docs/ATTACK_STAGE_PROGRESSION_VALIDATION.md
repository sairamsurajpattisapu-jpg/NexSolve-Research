# NEXSOLVE — SCIENTIFIC VALIDATION OF ATTACK-STAGE PROGRESSION
**SIH26153: AI-Based Network Attack Forecasting from Network Traffic Data**

---

## 1. Objective
This report details the rigorous scientific evaluation of **Markovian Attack-Stage Progression Modeling** on authentic network traffic from the **CIC-IDS2017** benchmark corpus.

The core research question is:
> *Can an observed attack stage or MITRE ATT&CK technique at time $T$ provide statistically defensible, evidence-bounded predictive information regarding downstream attack states at horizons $T+1\text{m}, T+3\text{m}, T+5\text{m}, T+10\text{m}$, and $T+15\text{m}$ without feature leakage or label fabrication?*

---

## 2. Existing NexSolve Forecasting Architecture
NexSolve operates an immutable 45-feature canonical PCAP-compatible inference pipeline:
```
Raw PCAP
  ↓
Scapy Streaming / PcapNgReader
  ↓
Deterministic 60-Second Window Aggregation
  ↓
Network State Vectors (45 Features: Flow, Packet, Temporal)
  ↓
NexSolve World Model (LSTM: 45 inputs, 24 hidden, 5-step recursive rollout)
  ↓
Attack Horizon & Evidence Fusion Layer
  ↓
ThreatAssessment (Strictly separating OBSERVED from FORECAST evidence)
```
### Hard Constraints Preserved:
- **Canonical 45-feature contract**: No features added, reordered, or deleted.
- **Safety Gate**: Rejects any attempt to fabricate or zero-fill `mean_tcp_rtt`.
- **Observed vs. Forecast Scope**: Observed telemetry ($t \le T$) and forecast rollouts ($t > T$) are strictly separated in `ThreatAssessment`.

---

## 3. Data Sources & Timestamp Provenance
1. **Authentic Network Capture**:
   - Path: `C:\Users\saira\Downloads\Friday-WorkingHours.pcap`
   - File Size: 8,839,309,056 bytes (~8.23 GB)
   - SHA-256: `beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0`
   - Packets: 9,997,874 packets hardware-stamped in UTC epoch microseconds.
2. **Processed Packet Windows**:
   - File: `data/processed/cic_ids2017_packet_windows.parquet` (484 contiguous 60s windows spanning `11:59:00 UTC` to `20:02:00 UTC`, July 7, 2017).
3. **Official UNB Ground-Truth Documentation**:
   - Source: University of New Brunswick (UNB) CIC-IDS2017 documentation (`https://www.unb.ca/cic/datasets/ids-2017.html`).
   - Timezone: Atlantic Daylight Time (ADT = UTC - 4).

---

## 4. Attack Episodes Analyzed

| Episode ID | Attack Category | Published Local Schedule | Verified UTC Interval | Onset Time ($T_0$) | Active Windows | Primary Signature |
| :--- | :--- | :--- | :--- | :--- | :---: | :--- |
| **Episode 1** | PortScan Phase 1 (Reconnaissance Sweep) | 13:55 – 14:35 ADT | 17:51:00 – 18:35:00 UTC | 17:51:00 UTC | 45 | SYN surged $470 \to 11,098$, RST surged $117 \to 10,976$, 15,303 unique destination ports |
| **Episode 2** | PortScan Phase 2 (Nmap Multi-Option Scan) | 14:51 – 15:29 ADT | 18:56:00 – 19:29:00 UTC | 18:56:00 UTC | 34 | SYN surged $240 \to 3,316 \to 10,287$, unique ports reached 5,962 |
| **Episode 3** | Denial of Service (LOIC Flood) | 15:56 – 16:16 ADT | 19:56:00 – 20:16:00 UTC | 19:56:00 UTC | 7 (capture truncated at 20:02) | Push flag saturation, packet rate surge |
| **Control** | Benign Enterprise Baseline | Quiescent Afternoon | 15:30:00 – 16:30:00 UTC | N/A | 61 | Mean SYN: 142.8, Mean RST: 34.2, Mean unique ports: 244.9 |

---

## 5. State / Stage Definitions & MITRE ATT&CK Grounding

The state representation maps observed evidence directly to empirical MITRE ATT&CK techniques:
- **`BENIGN_OBSERVATION`**: Normal background enterprise operations (web browsing, DNS, cloud polling).
- **`RECONNAISSANCE`** (MITRE **`T1046`** - Network Service Discovery): Systematic active probing of host IP/port address space.
- **`COMMAND_AND_CONTROL`** (MITRE **`T1071`** - Application Layer Protocol): Periodic low-jitter heartbeat beacons.
- **`DENIAL_OF_SERVICE`** (MITRE **`T1498`** - Network Denial of Service): High-volume packet flood saturating network bandwidth or socket states.
- **`UNKNOWN_STATE`**: Missing or degraded telemetry; triggers mandatory abstention.

---

## 6. Empirical Transition Methodology
For every candidate horizon $K \in \{1, 3, 5, 10, 15\}$ (corresponding to 60s, 180s, 300s, 600s, 900s), transition probability $P(S_{T+K} \mid S_T)$ was computed strictly using past-only observations:
$$P(S_{T+K} = j \mid S_T = i) = \frac{\sum_{t=1}^{N-K} \mathbb{I}(S_t = i \land S_{t+K} = j)}{\sum_{t=1}^{N-K} \mathbb{I}(S_t = i)}$$

---

## 7. Results Across Horizons $K \in \{1, 3, 5, 10, 15\}$

| Horizon ($K$) | Target Horizon Time | Transition Evaluated | Transition Probability | Baseline Rate | Statistical Lift | Replication Across Episodes | Status |
| :---: | :---: | :--- | :---: | :---: | :---: | :---: | :--- |
| **$K=1$** | $T+1\text{ min}$ (60s) | $P(\text{Recon}_{T+1} \mid \text{Recon}_T)$ | **0.975** | 0.164 | **5.96x** | Confirmed in Ep 1 & 2 | **SUPPORTED** |
| **$K=3$** | $T+3\text{ min}$ (180s) | $P(\text{Recon}_{T+3} \mid \text{Recon}_T)$ | **0.924** | 0.164 | **5.63x** | Confirmed in Ep 1 & 2 | **SUPPORTED** |
| **$K=5$** | $T+5\text{ min}$ (300s) | $P(\text{Recon}_{T+5} \mid \text{Recon}_T)$ | **0.873** | 0.165 | **5.30x** | Confirmed in Ep 1 & 2 | **SUPPORTED** |
| **$K=10$** | $T+10\text{ min}$ (600s) | $P(\text{Recon}_{T+10} \mid \text{Recon}_T)$ | **0.747** | 0.167 | 4.48x | Partial (Ep 1 only) | **INSUFFICIENT EVIDENCE (Abstained)** |
| **$K=15$** | $T+15\text{ min}$ (900s) | $P(\text{Recon}_{T+15} \mid \text{Recon}_T)$ | **0.620** | 0.168 | 3.68x | Lacks replication | **INSUFFICIENT EVIDENCE (Abstained)** |

### Cross-Stage Progression: Reconnaissance $\to$ Denial of Service
- In the authentic Friday capture, PortScan Episode 2 concluded at 19:29 UTC. The DDoS LOIC episode began at 19:56 UTC (a 27-minute gap).
- At horizons $K \in \{1, 3, 5, 10, 15\}$, $P(\text{DoS}_{T+K} \mid \text{Recon}_T) = 0.000$.
- **Finding**: While attack persistence within an ongoing active stage is strongly observed ($K=1 \dots 5$), cross-stage transitions across different attack tools (Nmap to LOIC) did not occur within a 15-minute window on this capture.

---

## 7.1. Critical Distinction: State Persistence vs. Downstream Progression

A critical scientific distinction must be maintained between two fundamentally different phenomena:
1. **`STATE_PERSISTENCE`** ($S_T = S_{T+K}$):
   - Measures the temporal persistence and duration of an already active, observed attack stage.
   - Example: $P(\text{Recon}_{T+K} \mid \text{Recon}_T) \in [0.873, 0.975]$ for $K \in \{1, 3, 5\}$.
   - **Crucial Rule**: Persistence tells the defender that an attack *remains underway*. It does **NOT** constitute a forecast of a new, downstream attack stage (e.g. Exploitation, DoS, or C2).
   - In NexSolve, `StageForecastPoint` explicitly tags this as `prediction_type = PredictionType.STATE_PERSISTENCE` and emits `forecast_techniques = ()` (empty) to ensure no downstream technique is falsely claimed as predicted.

2. **`DOWNSTREAM_PROGRESSION`** ($S_T \neq S_{T+K}$ where $S_{T+K}$ is an attack stage):
   - Measures an actual empirical transition from an earlier kill-chain stage to a distinct subsequent attack stage (e.g., Reconnaissance $\to$ Exploitation $\to$ Lateral Movement $\to$ Exfiltration).
   - In authentic Friday PCAP telemetry, the transition $P(\text{DoS}_{T+K} \mid \text{Recon}_T)$ is strictly **$0.000$** for all $K \le 15$ minutes.
   - **Crucial Rule**: Because no cross-stage transitions occur within the empirical horizons in this authentic capture, NexSolve **never fabricates** a downstream progression forecast. If no empirical transition exists, the system strictly refrains from emitting speculative downstream MITRE ATT&CK techniques, and abstains with `NO_SUPPORTED_DOWNSTREAM_TRANSITION`.

---

## 7.2. Probability vs. Confidence

A critical scientific distinction exists between empirical transition probability, statistical confidence, model accuracy, and universal attack likelihood:

$$\text{transition\_probability} \neq \text{statistical confidence} \neq \text{model accuracy} \neq \text{universal attack probability}$$

### Exact Semantic Meaning of `transition_probability`
In NexSolve attack progression forecasting, `transition_probability` means:
> *"Among evaluated historical windows in the analyzed benchmark dataset where state $i$ was observed at time $T$, the exact fraction where state $j$ was present at exactly $T+K$."*

Formally:
$$P(S_{T+K} = j \mid S_T = i) = \frac{\sum_{t=1}^{N-K} \mathbb{I}(S_t = i \land S_{t+K} = j)}{\sum_{t=1}^{N-K} \mathbb{I}(S_t = i)}$$

### What It Is NOT:
1. **NOT Model Confidence**: It does not represent the internal softmax activation, Bayesian posterior belief, or epistemic certainty of an AI model.
2. **NOT Calibrated Probability for All Networks**: It reflects empirical kinematics of the evaluated CIC-IDS2017 network environment and attacks (PortScan Episode 1 & 2). It cannot be generalized blindly to arbitrary corporate networks without site calibration.
3. **NOT Universal Attack Probability**: It is conditioned strictly on state $i$ already being active at time $T$.
4. **NOT Probability of Attack from Benign**: $P(\text{Recon}_{T+1} \mid \text{Recon}_T) = 0.975$ does **NOT** mean there is a 97.5% probability that an attack will occur when the network is benign. From benign baseline, $P(\text{Attack}_{T+K} \mid \text{Benign}_T) \le 0.025$.

### Scientific Decision on Confidence Scores
- **Removal of Arbitrary Heuristic**: The heuristic $\text{Confidence}(K) = \max(0.50, P \times (1.0 - 0.05 \times K))$ has been **completely removed**. It was an uncalibrated formula and cannot be represented as statistical confidence.
- **No Manufactured Confidence**: Rather than fabricating artificial certainty scores, NexSolve exposes **NONE** (`confidence` field omitted). The exact, bounded `transition_probability` $\in [0.0, 1.0]$ is exposed directly with its strict mathematical definition.

---

## 8. Baseline & Control Analysis
- In the 61-window benign control period (`15:30:00 – 16:30:00 UTC`), $P(\text{Attack}_{T+K} \mid \text{Benign}_T)$ remained $< 0.025$ for all $K \le 5$.
- Normal benign enterprise fluctuations do not trigger false positive progression forecasts.

---

## 9. Leakage & Safety Audit
- **Past-only dependency**: Feature vectors and observed state at time $T$ rely strictly on packets received up to timestamp $T$.
- **No target leakage**: Target state at $T+K$ is evaluated only during evaluation scoring.
- **Zero RTT fabrication**: `mean_tcp_rtt` is omitted; 46→45 safety gate remains strictly active.

---

## 10. Scientific Limitations
1. **Abrupt Attack Onset**: As proven in previous audits, pre-attack onset signals from a benign baseline do not provide anticipatory warning before $T_0$. Therefore, when $S_T = \text{BENIGN}$, NexSolve must abstain from predicting impending attacks.
2. **Limited Cross-Day PCAP Availability**: The Wednesday and Thursday CIC-IDS2017 datasets exist only as flow CSVs without packet timestamps. Authentic PCAP validation is currently limited to Friday.
3. **Horizon Horizon Decay**: Beyond $K=5$ (5 minutes), empirical confidence decays significantly and lacks multi-episode replication.
4. **Absence of Immediate Kill-Chain Chaining in Benchmark**: In CIC-IDS2017 Friday traffic, distinct attack scenarios were executed as isolated exercises separated by quiescent lulls (e.g., 27 minutes between PortScan 2 and DDoS), rather than rapid multi-stage kill-chain progressions within a 5-minute horizon.

---

## 11. Final Scientific Verdict

**PARTIALLY SUPPORTED**

- **State Persistence (`STATE_PERSISTENCE`)**: **SUPPORTED** ($K \in \{1, 3, 5\}$). Once an initial attack stage is observed ($T$), stage persistence at horizons $T+1\text{m}, T+3\text{m}$, and $T+5\text{m}$ is statistically defensible ($P \in [0.873, 0.975]$, lift $>5.3\times$, replicated across independent episodes).
- **Downstream Cross-Stage Progression (`DOWNSTREAM_PROGRESSION`)**: **NOT SUPPORTED** on authentic Friday PCAP. Cross-stage transitions (e.g. Recon $\to$ DoS) were $0.000$ within $K \le 15$ due to temporal separation between exercises. Speculative downstream MITRE technique forecasts are strictly withheld.
- **Anticipatory Onset Forecasting**: **UNSUPPORTED**. Predicting attack onset from a quiescent benign baseline ($T-10$ to $T-1$) and forecasting horizons beyond 5 minutes ($K=10, 15$) lack sufficient empirical support and are strictly abstained.

---

## 12. Implementation Result & Production Safety

### Components Updated:
1. **`ml/forecasting/attack_progression.py`**: A Markovian progression engine exposing `forecast_attack_progression` for horizons $K \in \{1, 3, 5, 10, 15\}$, with explicit `PredictionType` semantics (`STATE_PERSISTENCE`, `DOWNSTREAM_PROGRESSION`, `ABSTAINED`), zero arbitrary confidence heuristic, and strict abstention reasons (`INSUFFICIENT_HISTORY`, `UNSUPPORTED_HORIZON`, `NO_ATTACK_OBSERVED`, `NO_SUPPORTED_DOWNSTREAM_TRANSITION`, `UNSEEN_STATE`).
2. **`tests/test_attack_progression.py`**: Targeted unit test suite verifying persistence isolation, zero downstream fabrication, horizon gating, observed/forecast separation, no arbitrary confidence score, and contract preservation.

### Test Execution:
```bash
.venv\Scripts\pytest -q tests/test_attack_progression.py tests/test_pcap_compatible_45.py tests/test_short_pcap_and_evaluation_harness.py
```
**Result**: **`16 passed in 6.17s`** (100% passing).
