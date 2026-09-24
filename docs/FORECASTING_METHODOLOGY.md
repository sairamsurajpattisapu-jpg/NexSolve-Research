# NexSolve Forecasting Methodology & Scientific Integrity Specification

> **Version:** 4.0.0-PROD  
> **Status:** Ratified Standard  
> **Author:** NexSolve Engineering & Applied ML Research  
> **Audience:** Machine Learning Scientists, Cybersecurity Researchers, SOC Evaluators, Technical Judges

---

## 1. Executive Summary & Problem Formulation

Traditional network intrusion detection systems (NIDS) are reactive: they evaluate network telemetry at time $T_0$ to determine whether an observed event represents malicious behavior. 

**NexSolve addresses SIH Problem Statement ID 26153 by reformulating network security as an autoregressive, continuous-state forecasting challenge.** Rather than solely classifying past or current packet captures, NexSolve forecasts network state trajectories forward in time across discrete rollout horizons $T+1, T+2, T+3, T+5$, and $T+10$ minutes ($60\text{s}$ to $600\text{s}$ lookahead).

### Core Mathematical Objective
Given an observed sequence of $L$ chronological network states:
$$\mathcal{S}_{t-L:t} = \left( \mathbf{s}_{t-L+1}, \mathbf{s}_{t-L+2}, \dots, \mathbf{s}_t \right), \quad \mathbf{s}_k \in \mathbb{R}^D$$
NexSolve computes:
1. **Dynamic State Rollout:** $\mathbf{\hat{s}}_{t+h} \in \mathbb{R}^D$ for each horizon $h \in \{1, 2, 3, 5, 10\}$.
2. **Conditional Attack Step Probability:** $P(\text{Attack at } t+h \mid \mathcal{S}_{t-L:t})$.
3. **Cumulative Infiltration Risk:**
   $$\text{Risk}(H) = 1 - \prod_{h=1}^H \left(1 - P(\text{Attack at } t+h)\right)$$

---

## 2. Zero-Leakage Temporal Splitting & Embargo Engine

Standard cross-validation (e.g., random $k$-fold shuffle) is mathematically invalid for time-series forecasting because future state transitions leak into historical training data, producing drastically inflated, unscientific performance figures.

### 2.1 Chronological Partitioning Standard
NexSolve mandates strict chronological splitting:
$$\mathcal{T}_{\text{train}} < \mathcal{T}_{\text{val}} < \mathcal{T}_{\text{test}}$$
Where:
$$\max(t \in \mathcal{T}_{\text{train}}) < \min(t \in \mathcal{T}_{\text{val}}) \quad \text{and} \quad \max(t \in \mathcal{T}_{\text{val}}) < \min(t \in \mathcal{T}_{\text{test}})$$

### 2.2 Embargo & Purge Gap Rationale
Because recurrent models (LSTMs, GRUs) utilize a rolling lookback window ($L=8$ discrete 60-second steps = 480 seconds) and network features exhibit strong autocorrelation, observations immediately adjacent to split boundaries can induce boundary leakage.

NexSolve implements a configurable **embargo gap** (default $\ge 60.0\text{s}$):
$$\min(t \in \mathcal{T}_{\text{val}}) - \max(t \in \mathcal{T}_{\text{train}}) \ge \tau_{\text{embargo}}$$
$$\min(t \in \mathcal{T}_{\text{test}}) - \max(t \in \mathcal{T}_{\text{val}}) \ge \tau_{\text{embargo}}$$
All temporal windows falling within the embargo gap are strictly purged prior to evaluation.

### 2.3 Window Leakage Protection (`validate_temporal_windows`)
The runtime validation helper enforces five invariant mathematical checks:
1. **Strict Monotonicity:** $t_{i} < t_{i+1}$ for all historical and forecast steps. No backward jumps or duplicate timestamps.
2. **Strict Precedence:** $\max(t_{\text{history}}) < \min(t_{\text{forecast}})$. No history timestamp may equal or exceed any forecast horizon timestamp.
3. **No Overlap:** Lookback window boundaries and target prediction windows must not intersect.
4. **Scaler Isolation:** Feature scalers ($\mu, \sigma$) and decision thresholds are fit **exclusively** on $\mathcal{T}_{\text{train}}$ and never updated using validation or test observations.

---

## 3. Multi-Horizon Evaluation & Probabilistic Calibration

### 3.1 Multi-Horizon Degradation Curves
Autoregressive forecasting accumulates uncertainty over successive rollout steps. NexSolve evaluates model performance across discrete horizons:
- $T+1$ ($60\text{s}$ lookahead): Immediate transition state.
- $T+2$ ($120\text{s}$ lookahead): Early tactical development.
- $T+3$ ($180\text{s}$ lookahead): Attack phase execution.
- $T+5$ ($300\text{s}$ lookahead): Mid-range trajectory.
- $T+10$ ($600\text{s}$ lookahead): Strategic network shift.

Performance decay curves measure how Precision, Recall, F1, and Calibration degrade as a function of horizon $h$.

### 3.2 Probabilistic Scoring & Brier Score
Binary accuracy alone is insufficient for operational cybersecurity triage. NexSolve reports the **Brier Score**:
$$\text{Brier} = \frac{1}{N} \sum_{i=1}^N \left( p_i - y_i \right)^2 \in [0, 1]$$
Where $p_i \in [0, 1]$ is the forecasted attack probability and $y_i \in \{0, 1\}$ is the actual ground truth state. Lower Brier scores indicate superior probabilistic calibration.

### 3.3 Expected Calibration Error (ECE) & Reliability Diagrams
To verify that a forecasted $70\%$ probability translates to attack occurrences $70\%$ of the time in practice, predictions are partitioned into $M=10$ confidence bins $B_1, \dots, B_M \subseteq [0, 1]$:
$$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right|$$
Where:
- $\text{acc}(B_m) = \frac{1}{|B_m|} \sum_{i \in B_m} y_i$
- $\text{conf}(B_m) = \frac{1}{|B_m|} \sum_{i \in B_m} p_i$

Each bin's count, accuracy, and confidence are recorded in experiment artifacts to generate reliability diagrams.

---

## 4. Zero-Fabrication Rule for Missing Metrics

> [!IMPORTANT]
> **Strict Scientific Standard:**
> Under no circumstances does NexSolve manufacture, synthesize, or fill missing metrics with $0.0$ or default values.

When a mathematical metric cannot be formally computed due to sample distribution constraints, NexSolve explicitly assigns `None` and records a diagnostic explanation string in `undefined_reasons`:

| Metric | Condition | Value | Recorded Reason |
|---|---|---|---|
| **Precision** | $\text{TP} + \text{FP} = 0$ | `None` | `"Undefined: zero positive predictions made (TP + FP == 0)"` |
| **Recall** | $\text{TP} + \text{FN} = 0$ | `None` | `"Undefined: zero positive ground truth samples exist (TP + FN == 0)"` |
| **F1 Score** | Precision or Recall is `None` | `None` | `"Undefined: precision or recall is undefined"` |
| **False Positive Rate** | $\text{FP} + \text{TN} = 0$ | `None` | `"Undefined: zero negative ground truth samples exist (FP + TN == 0)"` |
| **False Negative Rate** | $\text{FN} + \text{TP} = 0$ | `None` | `"Undefined: zero positive ground truth samples exist (FN + TP == 0)"` |
| **ECE** | $N = 0$ | `None` | `"Undefined: empty dataset"` |

---

## 5. Standardized Baseline Benchmarking (Input-Parity)

To establish genuine scientific validity, NexSolve evaluates predictive models against two reproducible baseline models evaluated under **exact input parity**:

### 5.1 Persistence Baseline
Assumes the network environment is stationary and that future states will replicate the current observed state:
$$\mathbf{\hat{s}}_{t+h} = \mathbf{s}_t, \quad P(\text{Attack at } t+h) = P(\text{Attack at } t)$$
- **Role:** Demonstrates whether a machine learning model learns true temporal dynamics beyond static autocorrelation. In stationary conditions, Persistence can be competitive at $T+1$, but degrades rapidly during phase transitions.

### 5.2 Calibrated Logistic Regression Baseline
A linear probabilistic model operating on summary statistics of the rolling lookback window:
$$z = \mathbf{w}^T \mathbf{x}_{\text{summary}} + b, \quad p = \sigma(z)$$
Where $\mathbf{x}_{\text{summary}}$ captures volumetric rate-of-change, SYN packet ratios, and destination port diversity across the history window.

### 5.3 Comparative Reporting Principles
Benchmarking reports avoid subjective "winner/loser" hyperbole. Instead, reports present:
- Raw metrics across all horizons for each candidate.
- Exact comparative deltas: $\Delta \text{Brier} = \text{Brier}_{\text{WM}} - \text{Brier}_{\text{Persistence}}$ and $\Delta \text{ECE}$.
- Objective statements highlighting specific operating regimes where each method exhibits advantages.

---

## 6. Attack-Family Holdout Generalization Protocol

To measure real-world resilience against zero-day tactics and novel exploit campaigns, NexSolve supports attack-family holdout experiments:
1. **Isolation:** All samples belonging to a specified attack family (e.g., `Exploits`, `Backdoor`, `DDoS`) are completely excluded from $\mathcal{T}_{\text{train}}$, $\mathcal{T}_{\text{val}}$, scaler computation, and threshold calibration.
2. **In-Distribution Baseline:** Model performance is scored on in-distribution families.
3. **Out-of-Distribution Scoring:** The identical model is evaluated on the held-out family partition.
4. **Generalization Metrics:**
   - **F1 Retention Ratio:** $\frac{\text{F1}_{\text{unseen}}}{\text{F1}_{\text{known}}}$
   - **Recall Drop:** $\text{Recall}_{\text{known}} - \text{Recall}_{\text{unseen}}$
5. **Fallback Behavior:** If a dataset lacks an authentic multi-class attack taxonomy, the framework returns a structured `UNSUPPORTED` status code rather than fabricating categories.

---

## 7. Dataset Adapters & Canonical Interfaces

NexSolve provides production adapters for three primary network security benchmark corpuses without mutating source files:

| Dataset | Native Format | Canonical Dimension | Genuinely Derivable Features |
|---|---|---|---|
| **UNSW-NB15** | Flow CSV (49 columns) | 46 features | 18 Flow, 22 Packet (interface), 6 Temporal |
| **CIC-IDS2017** | Flow CSV / Parquet | 45 features | Flow duration, IAT statistics, flag counts, packet rates |
| **TON-IoT** | CSV (Zeek / Suricata) | 17 features | 12 Flow, 5 Temporal (no packet headers; explicit availability=False) |

### Non-Fabrication Guarantee:
When a dataset lacks raw packet headers (e.g., TON-IoT CSV), packet-level features are marked `packet_features_available=False` and excluded from encoding rather than silently filled with misleading zero values.

---

## 8. Reproducible Experiment Artifact Standard

Every execution of `nexsolve evaluate` or `nexsolve benchmark` creates an immutable experiment folder:
```
experiments/<experiment_id>/
├── manifest.json        # Execution metadata, parameters, git commit, checksums
├── metrics.json         # Aggregate metrics overview per model
├── horizon_metrics.json # Breakdown across T+1 to T+5, T+10
├── predictions.jsonl    # Line-delimited JSON predictions for every rollout point
├── provenance.json     # Hardware, OS, Python version, dependencies, data hashes
└── README.md            # Human-readable executive summary and comparative tables
```

### Cryptographic Integrity:
`manifest.json` computes and stores the SHA-256 hash of all companion artifact files, providing verifiable tamper-detection for research publications, regulatory compliance, and SOC audits.

---

## 9. CLI Usage Quick Reference

### Evaluate a dataset:
```bash
# Evaluate World Model on UNSW-NB15 across horizons T+1, T+2, T+3, T+5 with 60s embargo
nexsolve evaluate unsw --horizons 1,2,3,5 --embargo-seconds 60.0

# Evaluate with output to a dedicated reproducibility folder
nexsolve evaluate cic --horizons 1,2,3 -o experiments/cic_run_01
```

### Run baseline benchmark:
```bash
# Compare Persistence, Logistic Regression, and World Model on TON-IoT
nexsolve benchmark toniot --horizons 1,2,3,5

# Benchmark with attack-family holdout
nexsolve benchmark unsw --horizons 1,2,3 --holdout-family Exploits --json
```

---

## 10. Known Limitations & Research Boundaries

1. **Stationary Network States:** During periods of sustained benign network operation, Persistence baselines can be highly competitive at $T+1$. The World Model's primary advantage manifests during dynamic transitions and multi-step rollouts ($T+2$ to $T+5$).
2. **Missing Feature Disclosures:** PCAP packet features require raw capture files; when operating purely on flow-level CSV datasets, packet metrics are explicitly disabled.
3. **Execution Environment:** NexSolve is designed to execute locally with zero external telemetry leakage and complete user privacy.

---

## 11. Dynamic Attack Progression Engine (Phase 2 Lifecycle & Grounding)

### 11.1 Canonical 15-Stage Enterprise Lifecycle Taxonomy
NexSolve defines an authoritative, machine-readable 15-stage attack lifecycle taxonomy (plus `UNKNOWN`) categorized into enterprise execution phases:
- **BASELINE:** `BENIGN` (Ordinal 0)
- **PRE_ATTACK:** `RECONNAISSANCE` (1), `RESOURCE_DEVELOPMENT` (2)
- **INTRUSION:** `INITIAL_ACCESS` (3), `EXECUTION` (4), `PERSISTENCE` (5), `PRIVILEGE_ESCALATION` (6), `DEFENSE_EVASION` (7), `CREDENTIAL_ACCESS` (8)
- **EXPANSION:** `DISCOVERY` (9), `LATERAL_MOVEMENT` (10), `COLLECTION` (11)
- **OBJECTIVE:** `COMMAND_AND_CONTROL` (12), `EXFILTRATION` (13), `IMPACT` (14)
- **UNRESOLVED:** `UNKNOWN` (-1)

### 11.2 Epistemic Classification Standard
Every stage assignment is rigorously classified into one of four epistemic states:
- `OBSERVED`: Directly corroborated by telemetry or verified dataset ground truth.
- `INFERRED`: Derived from multi-signal heuristic and sensor corroboration without explicit ground-truth labels.
- `FORECAST`: Autoregressively predicted across future temporal horizons $T+1 \dots T+5$.
- `UNKNOWN`: Unresolved state or insufficient signal support.

### 11.3 Multi-Dimensional Separated Confidences
Rather than conflating sensor detection, stage assignment, and temporal forecasting into an arbitrary singular probability, NexSolve computes four distinct metrics:
1. `technique_confidence`: Sensor match certainty for verified MITRE ATT&CK techniques (in $[0, 1]$).
2. `stage_confidence`: Aggregated evidentiary telemetry support for the attack stage (in $[0, 1]$).
3. `transition_confidence`: Kinematic plausibility of moving between stages given historical observations.
4. `forecast_confidence`: Product of transition probability and stage confidence.

### 11.4 Non-Linear Transition Kinematics & Validation Matrix
Attacker behavior is inherently non-linear: adversaries skip stages, backtrack to earlier stages, or loop within a stage. The `STAGE_TRANSITION_MATRIX` validates all $15 \times 15 = 225$ stage pairs:
- **EXPECTED:** Sequential progression ($S_{t+1} = S_t + 1$) or state persistence ($S_{t+1} = S_t$).
- **POSSIBLE:** Accelerated progression ($S_{t+1} > S_t + 1$) requiring corroborated direct telemetry.
- **UNUSUAL:** Backward steps (e.g. `LATERAL_MOVEMENT -> RECONNAISSANCE`) requiring direct supporting evidence; without evidence, returns `INSUFFICIENT_EVIDENCE`.
- **CONTRADICTORY:** State transitions where conflicting or refuting evidence outweighs supporting telemetry.
- **INVALID:** Unrecognized or mathematically inconsistent transitions.

### 11.5 Progression CLI Command
```bash
# Human-readable lifecycle report
nexsolve progression <job_id_or_analysis_json>

# Raw JSON output
nexsolve progression <job_id_or_analysis_json> --json

# Quiet mode (prints canonical stage only)
nexsolve progression <job_id_or_analysis_json> --quiet
```
