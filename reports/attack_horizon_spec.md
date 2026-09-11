# NexSolve Attack Horizon Specification

**Status**: PRODUCTION SPECIFICATION  
**Module**: `ml/forecasting/attack_horizon.py`  
**Endpoint**: `POST /forecast` (`model_service/app.py`)  
**SIH Problem Statement**: SIH26153 — AI based Network Attack Forecasting from Network Traffic Data  

---

## 1. Executive Summary & Objective

In classical network intrusion detection, systems output a binary alert at the current time: *"Attack detected."*  
NexSolve transitions cybersecurity operations from reactive detection to **predictive foresight**. The central operational question answered by the **Attack Horizon** engine is:

> *"Given the network state observed up to $T_0$, how far into the future does current evidence support an attack forecast, when will it begin, and how sustained is it?"*

Attack Horizon computes temporal reach, forecast lead time, attack duration, temporal consistency, and confidence bounds over multi-step rollouts ($T+1 \dots T+5$) without conflating temporal duration with statistical confidence.

---

## 2. Temporal Formalism & Mathematical Definitions

Let $T_0$ denote the current observation timestamp (UTC epoch seconds or ISO-8601).  
The world model generates forecasts across $K = 5$ discrete future temporal windows of fixed interval $\Delta W = 60\,\text{seconds}$:

$$\mathcal{H} = \{1, 2, 3, 4, 5\} \implies \Delta t \in \{60\,\text{s}, 120\,\text{s}, 180\,\text{s}, 240\,\text{s}, 300\,\text{s}\}$$

For each horizon step $h \in \mathcal{H}$:
- $\hat{y}_h \in [0, 1]$: Predicted attack probability for window $T+h$.
- $\hat{c}_h \in [0, 1]$: Predicted confidence score (uncalibrated distance from decision boundary: $2 \cdot |\hat{y}_h - 0.5|$).
- $\theta = 0.50$: Canonical decision threshold.
- $a_h = \mathbb{I}(\hat{y}_h \ge \theta)$: Binary threshold indicator.

### 2.1 Onset Horizon and Lead Time

The **attack onset** $h_{\text{onset}}$ is the earliest horizon step crossing the decision threshold:

$$h_{\text{onset}} = \min \{h \in \mathcal{H} \mid a_h = 1\}$$

If $a_h = 0 \;\forall h \in \mathcal{H}$, $h_{\text{onset}} = \text{None}$.

The **forecast lead time** $\Delta t_{\text{lead}}$ is the temporal buffer between current observation $T_0$ and predicted onset:

$$\Delta t_{\text{lead}} = h_{\text{onset}} \times \Delta W \quad (\text{seconds})$$

$$T_{\text{onset}} = T_0 + \Delta t_{\text{lead}} \quad (\text{ISO-8601 UTC timestamp})$$

### 2.2 Attack Horizon Duration

The **attack horizon span** $L$ is the number of **consecutive** windows for which the attack is predicted to persist, starting strictly from onset $h_{\text{onset}}$:

$$L = \max \left\{ k \in \{1, \dots, K - h_{\text{onset}} + 1\} \;\middle|\; \prod_{j=0}^{k-1} a_{h_{\text{onset}} + j} = 1 \right\}$$

The temporal horizon in seconds is:

$$H_{\text{seconds}} = L \times \Delta W = L \times 60\,\text{seconds}$$

The predicted end timestamp is:

$$T_{\text{end}} = T_0 + (h_{\text{onset}} + L - 1) \times \Delta W$$

---

## 3. Exhaustive State Taxonomy

The Attack Horizon engine deterministically evaluates the forecast sequence into one of five mutually exclusive states:

| State | Definition & Trigger Condition | Horizon Windows | Horizon Seconds | Lead Time |
| :--- | :--- | :---: | :---: | :---: |
| **`NO_ATTACK_FORECAST`** | All $\hat{y}_h < \theta$. No horizon indicates attack activity. Baseline network traffic expected. | `0` | `0` | `None` |
| **`EARLY_SIGNAL`** | Exactly 1 window above threshold starting from onset ($L = 1$). Represents isolated, transient, or pre-attack reconnaissance spikes. | `1` | `60` | $h_{\text{onset}} \times 60$ |
| **`SUSTAINED_ATTACK_FORECAST`** | At least 2 consecutive windows above threshold starting from onset ($L \ge 2$). Indicates ongoing multi-minute hostile campaign. | $L \ge 2$ | $L \times 60$ | $h_{\text{onset}} \times 60$ |
| **`UNCERTAIN_FORECAST`** | Contradictory alternating predictions (e.g. $[0.65, 0.35, 0.70, 0.30]$) or boundary hovering within $\theta \pm 0.03$. Evidence lacks temporal coherence. | `0` | `0` | `None` |
| **`ABSTAINED`** | Pipeline failure, insufficient sequence history ($N < 8$), gapped timestamps, missing features, or unparseable inputs. | `0` | `0` | `None` |

---

## 4. Fundamental Distinction: Horizon vs. Confidence

A critical scientific flaw in heuristic security dashboards is displaying *"85% horizon"* or equating confidence with duration. NexSolve enforces a strict separation:

1. **Attack Horizon ($L$ windows, $H$ seconds)**:
   - Measures **temporal duration and reach** into the future.
   - Units: Integer windows ($0 \dots 5$) and seconds ($0 \dots 300\text{s}$).
2. **Statistical Confidence ($\hat{c} \in [0, 1]$)**:
   - Measures model certainty or score margin.
   - **Calibration Status**: Explicitly set to `"UNSUPPORTED"` when validated on single-class regimes or when calibration guarantees do not hold.
   - Raw model scores are **never** presented to operators as calibrated posterior probabilities.

```json
{
  "horizon_windows": 3,
  "horizon_seconds": 180,
  "confidence_summary": {
    "mean_confidence": 0.68,
    "min_confidence": 0.60,
    "max_confidence": 0.76,
    "calibration_status": "UNSUPPORTED"
  }
}
```

---

## 5. Temporal Consistency & Monotonic Decay

### 5.1 Temporal Consistency

$$\text{Consistency} = \frac{L}{\sum_{h=1}^K a_h}$$

- If all predicted attack windows form an unbroken contiguous block starting from onset, $\text{Consistency} = 1.00$.
- If isolated stray spikes occur outside the main block (e.g. $[1, 0, 1]$), consistency decreases proportionally.
- Baseline non-attack sequences have $\text{Consistency} = 1.00$; abstained sequences have $\text{Consistency} = 0.00$.

### 5.2 Temporal Decay

$$\text{Decay Observed} = \forall j \in \{h_{\text{onset}}, \dots, K-1\}:\; \hat{y}_{j+1} \le \hat{y}_j + \epsilon$$

Indicates whether attack intensity decays monotonically over time (e.g. burst exhaustion or automated rate limiting) versus accelerating/escalating activity.

---

## 6. Service Integration & Payload Schema

### 6.1 `POST /forecast` Integration

The `/forecast` endpoint in `model_service/app.py` attaches the full Attack Horizon payload under both `attack_horizon` (snake_case) and `attackHorizon` (camelCase) to ensure zero breaking changes for existing consumers:

```json
{
  "currentState": {
    "timestamp": "2026-09-10T06:00:00Z",
    "attackProbability": null
  },
  "forecasts": [
    { "horizon": 1, "attackProbability": 0.82, "predictedStage": "Reconnaissance", "confidence": 0.64, "uncertainty": 0.36, "explanation": [...] },
    { "horizon": 2, "attackProbability": 0.85, "predictedStage": "Reconnaissance", "confidence": 0.70, "uncertainty": 0.30, "explanation": [...] },
    { "horizon": 3, "attackProbability": 0.79, "predictedStage": "Reconnaissance", "confidence": 0.58, "uncertainty": 0.42, "explanation": [...] },
    { "horizon": 4, "attackProbability": 0.35, "predictedStage": null, "confidence": 0.30, "uncertainty": 0.70, "explanation": [...] },
    { "horizon": 5, "attackProbability": 0.20, "predictedStage": null, "confidence": 0.60, "uncertainty": 0.40, "explanation": [...] }
  ],
  "attack_horizon": {
    "state": "SUSTAINED_ATTACK_FORECAST",
    "onset_horizon": 1,
    "onset_timestamp": "2026-09-10T06:01:00Z",
    "lead_time_seconds": 60,
    "horizon_windows": 3,
    "horizon_seconds": 180,
    "end_horizon": 3,
    "end_timestamp": "2026-09-10T06:03:00Z",
    "decision_threshold": 0.5,
    "temporal_consistency": 1.0,
    "decay_observed": false,
    "confidence_summary": {
      "mean_confidence": 0.564,
      "min_confidence": 0.3,
      "max_confidence": 0.7,
      "calibration_status": "UNSUPPORTED"
    },
    "evidence_chain": [
      {
        "horizon": 1,
        "horizon_seconds": 60,
        "predicted_timestamp": "2026-09-10T06:01:00Z",
        "attack_probability": 0.82,
        "confidence": 0.64,
        "predicted_stage": "Reconnaissance",
        "above_threshold": true,
        "abstained": false,
        "reason": null
      }
    ],
    "abstention_reason": null,
    "summary": "Sustained attack forecast spanning 3 windows (180s) starting at horizon T+1 (lead time 60s) through T+3. Temporal consistency: 1.00."
  }
}
```

---

## 7. Verification Matrix

The test suite in `tests/test_attack_horizon.py` covers all 19 boundary, onset, lead time, uncertainty, decay, and abstention criteria:

| Test Case | Inputs ($\hat{y}_{1 \dots 5}$) | Expected State | Horizon | Onset | Lead Time |
| :--- | :--- | :--- | :---: | :---: | :---: |
| Scenario 1 | $[0.10, 0.15, 0.20, 0.18, 0.12]$ | `NO_ATTACK_FORECAST` | 0s (0w) | `None` | `None` |
| Scenario 2 | $[0.75, 0.20, 0.15, 0.10, 0.05]$ | `EARLY_SIGNAL` | 60s (1w) | T+1 | 60s |
| Scenario 3 | $[0.80, 0.85, 0.82, 0.30, 0.10]$ | `SUSTAINED_ATTACK_FORECAST` | 180s (3w) | T+1 | 60s |
| Scenario 4 | $[0.70, 0.75, 0.80, 0.85, 0.90]$ | `SUSTAINED_ATTACK_FORECAST` | 300s (5w) | T+1 | 60s |
| Scenario 5 | $[0.10, 0.20, 0.85, 0.15, 0.10]$ | `EARLY_SIGNAL` | 60s (1w) | T+3 | 180s |
| Scenario 6 | $[0.15, 0.75, 0.85, 0.80, 0.20]$ | `SUSTAINED_ATTACK_FORECAST` | 180s (3w) | T+2 | 120s |
| Scenario 7 | $[0.65, 0.35, 0.70, 0.30, 0.75]$ | `UNCERTAIN_FORECAST` | 0s (0w) | `None` | `None` |
| Scenario 8 | $[0.51, 0.49, 0.505, 0.495, 0.502]$ | `UNCERTAIN_FORECAST` | 0s (0w) | `None` | `None` |
| Scenario 9 | $[0.50, 0.50, 0.20, 0.10, 0.10]$ | `SUSTAINED_ATTACK_FORECAST` | 120s (2w) | T+1 | 60s |
| Scenario 10 | Explicit `INSUFFICIENT_HISTORY` | `ABSTAINED` | 0s (0w) | `None` | `None` |
| Scenario 11 | `[None, None, None, None, None]` | `ABSTAINED` | 0s (0w) | `None` | `None` |
| Scenario 12 | Explicit `GAPPED_HISTORY` | `ABSTAINED` | 0s (0w) | `None` | `None` |
| Scenario 13 | ISO timestamp string input | Verifies UTC ISO strings for onset/end | - | - | - |
| Scenario 14 | Epoch integer input | Verifies conversion to UTC ISO | - | - | - |
| Scenario 15 | Onset at T+4 | `SUSTAINED_ATTACK_FORECAST` | 120s (2w) | T+4 | 240s |
| Scenario 16 | Monotonic decreasing tail | Verifies `decay_observed == True` | - | - | - |
| Scenario 17 | Statistical confidence vs horizon | Verifies separation of units & calibration status | - | - | - |
| Scenario 18 | Repeated evaluation | Deterministic bit-for-bit repeatability | - | - | - |
| Scenario 19 | Object & camelCase input | Verifies Pydantic/dataclass compatibility | - | - | - |
