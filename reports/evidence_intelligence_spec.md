# NexSolve Evidence Intelligence Specification

**Status**: PRODUCTION SPECIFICATION  
**Module**: `ml/forecasting/evidence_intelligence.py`  
**Endpoint**: `POST /forecast` (`model_service/app.py`)  
**SIH Problem Statement**: SIH26153 — AI based Network Attack Forecasting from Network Traffic Data  

---

## 1. Executive Summary & Core Principles

A fundamental limitation of black-box machine learning in network security is alert opacity: a high attack score with no verifiable physical or protocol justification cannot be acted upon by SOC operators. Conversely, conventional explainability frameworks (e.g. SHAP, LIME) frequently hallucinate or emphasize correlated noise features that lack physical ground truth.

**Evidence Intelligence** provides an evidence-backed explanatory layer that maps raw forecast predictions to observable, verifiable physical network phenomena derived directly from the canonical `NetworkState` representation.

### Core Architectural Principles:
1. **Zero Feature Fabrication**: If a feature is absent from the input state or marked unavailable by capture flags (e.g. `packet_features_available=False`), it is mathematically forbidden from appearing in evidence.
2. **Explicit Baseline Comparison**: Evidence is never evaluated in a vacuum. Observed current-window metrics ($T_0$) are strictly contrasted against historical baseline averages ($\bar{x}$) derived across the observation history ($N \ge 8$ windows).
3. **Bifurcated Evidence Channels**: Evidence is strictly segregated into **Supporting** and **Contradictory** signals relative to the forecast hypothesis.
4. **Evidence Strength $\ne$ Statistical Probability**: Evidence strength ($S_{\text{ev}} \in [0.0, 1.0]$) quantifies physical signal corroboration, distinct from model probability ($\hat{y} \in [0, 1]$) and statistical confidence ($\hat{c} \in [0, 1]$).
5. **Capture Integrity Awareness**: Degradations in packet capture (loss, truncation, timestamp reordering) actively degrade evidence reliability and populate explicit operational limitations.

---

## 2. Controlled Evidence Vocabulary

All generated evidence items must adhere to a strictly validated controlled vocabulary across type, direction, and severity.

### 2.1 Evidence Types (`EvidenceType`)
| Evidence Type | Semantic Definition | Associated State Features |
| :--- | :--- | :--- |
| `TRAFFIC_VOLUME` | Macroscopic surge or drop in packet or byte throughput | `total_packets`, `total_bytes`, `total_src_bytes`, `total_dst_bytes` |
| `FLOW_CHURN` | Abnormal rate of flow creation, termination, or concurrency | `flow_count`, `active_flows`, `delta_flow_count` |
| `PORT_DIVERSITY` | Dispersal or concentration across transport layer destination ports | `unique_dst_ports`, `unique_src_ports`, `port_entropy` |
| `SCANNING_RATE` | Horizontal or vertical probe intensity across IP targets | `flows_per_dest_ip`, `fan_out_ratio`, `unanswered_syn_ratio` |
| `PROTOCOL_ASYMMETRY` | Skew in forward vs. backward bytes or protocol distribution | `fwd_bwd_byte_ratio`, `protocol_split` |
| `TCP_FLAG_ANOMALY` | Elevated SYN, RST, or FIN flag distributions indicative of attacks | `syn_ratio`, `rst_ratio`, `fin_ratio`, `null_scan_count` |
| `PACKET_SIZE_DEVIATION` | Distinctive packet length distributions (e.g., small buffer probes) | `mean_packet_size`, `packet_size_std` |
| `CAPTURE_QUALITY_DEGRADATION` | Observable physical capture pipeline flaws impacting telemetry | `packet_loss_ratio`, `reordered_packets_ratio`, `truncated_packet_count` |

### 2.2 Directionality (`EvidenceDirection`)
- `INCREASE`: Metric increased by $\ge 10\%$ relative to historical baseline.
- `DECREASE`: Metric decreased by $\ge 10\%$ relative to historical baseline.
- `ANOMALOUS`: Metric deviates into an invalid, undefined, or contradictory regime.
- `STABLE`: Metric remains within $\pm 10\%$ baseline margin.

### 2.3 Severity Grading (`EvidenceSeverity`)
Thresholds for relative change $| \Delta_{\text{rel}} | = \left| \frac{x_{T_0} - \bar{x}}{\max(|\bar{x}|, \epsilon)} \right|$:
- `LOW`: $0.10 \le | \Delta_{\text{rel}} | < 0.25$ (10% to 25% change).
- `MEDIUM`: $0.25 \le | \Delta_{\text{rel}} | < 0.50$ (25% to 50% change).
- `HIGH`: $0.50 \le | \Delta_{\text{rel}} | < 1.00$ (50% to 100% change).
- `CRITICAL`: $| \Delta_{\text{rel}} | \ge 1.00$ ($\ge 100\%$ change, e.g. severe surge or complete collapse).

---

## 3. Mathematical Formalism & Evidence Processing

### 3.1 Baseline Derivation
Given a sequence of historical network states $S = [s_1, s_2, \dots, s_N]$ observed over $N \ge 8$ contiguous 60-second windows, the baseline for feature $f$ is computed as:

$$\bar{x}_f = \frac{1}{N-1} \sum_{i=1}^{N-1} s_i[f]$$

The current window value is $x_{T_0} = s_N[f]$. The absolute and relative deltas are:

$$\Delta_f = x_{T_0} - \bar{x}_f, \qquad \Delta_{\text{rel}, f} = \frac{\Delta_f}{\max(|\bar{x}_f|, 1.0)}$$

### 3.2 Corroboration Logic (Supporting vs. Contradictory)
Let $\hat{y} \in [0, 1]$ be the forecast attack probability. The forecast hypothesis $H$ is:

$$H = \begin{cases} \text{ATTACK} & \text{if } \hat{y} \ge 0.50 \\ \text{NORMAL} & \text{if } \hat{y} < 0.50 \end{cases}$$

Each candidate evidence item $e$ exhibits an inherent threat direction $D(e) \in \{+1, -1\}$:
- $+1$ (Threat Indication): Increases in volume, flow churn, port diversity, or flag anomalies.
- $-1$ (Benign Indication): Normal volume, low churn, uniform port distributions, or traffic collapse.

An evidence item is classified as **Supporting** if its direction aligns with the hypothesis:

$$\text{is\_supporting}(e) = \begin{cases} \text{True} & \text{if } (H = \text{ATTACK} \land D(e) = +1) \lor (H = \text{NORMAL} \land D(e) = -1) \\ \text{False} & \text{otherwise (Contradictory)} \end{cases}$$

### 3.3 Evidence Strength Formulation
Evidence Strength $S_{\text{ev}} \in [0.0, 1.0]$ measures the weighted consensus among observed signals, tempered by capture reliability $R$:

$$S_{\text{ev}} = R \times \frac{\sum_{e \in \mathcal{E}_{\text{supp}}} w(e) \cdot r(e)}{\sum_{e \in \mathcal{E}_{\text{all}}} w(e) \cdot r(e) + \alpha}$$

Where:
- $w(e) \in \{0.2, 0.5, 0.8, 1.0\}$ corresponds to severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- $r(e) \in [0.0, 1.0]$ is individual evidence reliability (e.g. $1.0$ for clean flows, $0.5$ under degraded capture).
- $R \in [0.0, 1.0]$ is overall capture quality coefficient.
- $\alpha = 0.1$ prevents extreme saturation on sparse evidence.

---

## 4. Evidence Item Data Contract

Each evidence item is rendered with full provenance tracking:

```json
{
  "evidence_id": "EV-01",
  "timestamp": "2026-09-10T06:00:00Z",
  "window_id": "w-185",
  "evidence_type": "FLOW_CHURN",
  "feature_name": "flow_count",
  "observed_value": 450.0,
  "baseline_value": 276.4,
  "delta": 173.6,
  "relative_change": 0.628,
  "direction": "INCREASE",
  "severity": "HIGH",
  "reliability": 1.0,
  "source": "state.flow_features",
  "provenance": {
    "window_index": 7,
    "lookback_windows": 8,
    "source_group": "flow_features"
  },
  "explanation": "flow_count increased +62.8% over 8-window baseline (450.0 vs 276.4).",
  "is_supporting": true
}
```

---

## 5. Capture Degradation & Telemetry Limitations

When capture anomalies are detected:
1. A dedicated `CAPTURE_QUALITY_DEGRADATION` item is injected into the evidence chain.
2. The `reliability` score of all concurrently evaluated flow and packet evidence items is discounted by $50\%$.
3. Human-readable operational limitations are appended to `evidence_chain.limitations`:
   - *"Packet loss ratio of 8.5% exceeds nominal threshold (5.0%). Volume metrics may underestimate true transmission."*
   - *"Timestamp reordering ratio 6.2% detected. Micro-burst sequence analysis degraded."*
