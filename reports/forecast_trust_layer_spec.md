# NexSolve Forecast Trust Layer Specification

**Status**: PRODUCTION SPECIFICATION  
**Module**: `ml/forecasting/forecast_intelligence.py`  
**Endpoint**: `POST /forecast` (`model_service/app.py`)  
**SIH Problem Statement**: SIH26153 — AI based Network Attack Forecasting from Network Traffic Data  

---

## 1. Architectural Architecture & Objective

The **Forecast Trust Layer** serves as the scientific and operational gateway between raw machine learning inference and cybersecurity operators. In adversarial, safety-critical environments such as network attack forecasting, raw probabilities cannot be accepted unconditionally. 

The Trust Layer binds four core sub-systems into a unified deterministic pipeline:
1. **Evidence Intelligence** (`ml/forecasting/evidence_intelligence.py`): Extracts observable, non-hallucinated physical corroboration from sequence history.
2. **Unknown Behavior Detection** (`ml/forecasting/unknown_behavior.py`): Verifies domain validity, physical invariants, and protocol boundaries.
3. **Forecast Confidence & Uncertainty Representation** (`ml/forecasting/forecast_confidence.py`): Explicitly distinguishes between raw score margin, statistical confidence, and uncertainty.
4. **Forecast Abstention Engine** (`ml/forecasting/forecast_abstention.py`): Enforces rigorous data preconditions and halts forecast generation when inputs are compromised.

```
+-------------------------------------------------------------------------+
|                       POST /forecast Request                             |
|  [Sequence of N >= 8 contiguous 60s NetworkStates + Model Metadata]      |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                  1. Forecast Abstention Gate                            |
|  - Sequence Length >= 8?                                                |
|  - Timestamps Monotonic & Contiguous (60s +- 10s)?                      |
|  - Required Semantic Features Present?                                  |
|  - Capture Quality Sufficient (Loss < 20%, Reorder < 25%)?              |
+-------------------------------------------------------------------------+
         | (Hard Failure)                                   | (Pass)
         v                                                  v
[FORECAST_UNAVAILABLE]                     +-------------------------------+
(Forecasts suppressed,                     | 2. Evidence Intelligence      |
 abstention reason populated)              | - Baseline derivation         |
                                           | - Supporting vs Contradictory |
                                           | - Evidence Strength (0.0-1.0) |
                                           +-------------------------------+
                                                            |
                                                            v
                                           +-------------------------------+
                                           | 3. Unknown Behavior Detection |
                                           | - Physical invariant check    |
                                           | - Disagreement rules          |
                                           | - Feature coverage (0.0-1.0)  |
                                           +-------------------------------+
                                                            |
                                                            v
                                           +-------------------------------+
                                           | 4. Forecast Confidence Engine |
                                           | - Calibration Status Check    |
                                           | - Confidence Value (or NULL)  |
                                           | - Epistemic Uncertainty       |
                                           +-------------------------------+
                                                            |
                                                            v
+-------------------------------------------------------------------------+
|                  Unified Forecast Intelligence Result                   |
|  { forecasts, attack_horizon, evidence_chain, confidence,               |
|    unknown_behavior, abstention }                                       |
+-------------------------------------------------------------------------+
```

---

## 2. Fundamental Scientific Distinctions

NexSolve strictly decouples four statistical and operational concepts that are frequently conflated in naive machine learning systems:

| Metric | Symbol | Range | Definition & Mathematical Formulation | Calibration Requirement |
| :--- | :---: | :---: | :--- | :---: |
| **Forecast Score** | $\hat{y}$ | $[0.0, 1.0]$ | Raw model output or heuristic margin indicating attack likelihood. | Uncalibrated |
| **Statistical Confidence** | $\hat{c}$ | $[0.0, 1.0]$ | Calibrated empirical posterior probability $P(Y = 1 \mid \hat{y})$. When calibration guarantees are absent, this is strictly `null`. | **MANDATORY** |
| **Evidence Strength** | $S_{\text{ev}}$ | $[0.0, 1.0]$ | Normalized weighted corroboration of physical network state features relative to the forecast hypothesis. | N/A (Observed telemetry) |
| **Epistemic Uncertainty** | $U$ | $[0.0, 1.0]$ | Distance from the certainty boundaries: $U = 1.0 - 2 \cdot |\hat{y} - 0.5|$. Reaches maximum ($1.0$) at decision boundary ($0.50$). | N/A (Mathematical bound) |

> [!IMPORTANT]
> **Scientific Integrity Policy**:  
> In accordance with Phase 5 validation findings, where models evaluated across temporal splits exhibited single-class regimes or insufficient isotonic calibration curves, the production calibration status is explicitly declared as `"UNSUPPORTED"`.  
> Consequently, `confidence.confidence_value` is set to `null` (None), and `confidence.confidence_state` is set to `"UNCALIBRATED"`. Raw model scores are **never** deceptively relabeled as calibrated confidence.

---

## 3. Forecast Abstention Taxonomy & Invariant Checks

The abstention engine evaluates incoming state sequences against five mandatory preconditions:

### 3.1 Preconditions
1. **Sequence Length ($N \ge 8$)**: A minimum of 8 continuous observation windows (480 seconds) is required to compute reliable temporal baselines.
2. **Timestamp Contiguity ($\Delta t \approx 60\text{s}$)**: Inter-window timestamp delta must satisfy $45\text{s} \le \Delta t \le 75\text{s}$. If a gap $\ge 90\text{s}$ is detected, sequence temporal continuity is broken.
3. **Required Feature Semantics**: Flow feature dictionaries must contain `flow_count`, `total_packets`, and `total_bytes`.
4. **Capture Quality Floor**: Capture telemetry must not exceed critical failure levels (`packet_loss_ratio < 0.20`, `reordered_packets_ratio < 0.25`).
5. **Unknown Behavior Veto**: If `unknown_behavior.abstain_recommended == true`, the abstention engine elevates the state to protect downstream automations.

### 3.2 Output Statuses
- **`FORECAST_AVAILABLE`**: All preconditions met and model calibration is mathematically verified.
- **`FORECAST_AVAILABLE_BUT_UNCALIBRATED`**: All data and sequence preconditions met, but model calibration is `UNSUPPORTED`. Operational forecasts are rendered with uncalibrated score transparency.
- **`FORECAST_UNAVAILABLE`**: One or more preconditions failed. Forecasts are suppressed or cleared, and `abstention_reason` detailing the exact structural deficiency is returned.

---

## 4. REST API Integration (`POST /forecast`)

The `POST /forecast` endpoint in `model_service/app.py` exposes the unified trust layer. To guarantee 100% backward compatibility with legacy dashboards and external consumers, all fields are provided in snake_case with camelCase aliases.

```json
{
  "currentState": {
    "timestamp": "2026-09-10T06:00:00Z",
    "attackProbability": null
  },
  "forecasts": [
    {
      "horizon": 1,
      "attackProbability": 0.82,
      "predictedStage": "Reconnaissance",
      "confidence": null,
      "uncertainty": 0.36,
      "explanation": ["flow_count contributed +0.14"]
    }
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
      "mean_confidence": null,
      "min_confidence": null,
      "max_confidence": null,
      "calibration_status": "UNSUPPORTED"
    },
    "evidence_chain": [],
    "abstention_reason": null,
    "summary": "Sustained attack forecast spanning 3 windows (180s)."
  },
  "evidence_chain": {
    "current_window_id": "w-185",
    "current_timestamp": "2026-09-10T06:00:00Z",
    "forecast_horizon": 1,
    "supporting": [
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
        "provenance": { "lookback_windows": 8 },
        "explanation": "flow_count surged +62.8% over 8-window baseline.",
        "is_supporting": true
      }
    ],
    "contradictory": [],
    "evidence_strength": 0.86,
    "evidence_quality": "HIGH",
    "supporting_feature_count": 1,
    "contradictory_feature_count": 0,
    "provenance_complete": true,
    "explanation": "Flow churn strongly supports forecast onset.",
    "limitations": []
  },
  "confidence": {
    "forecast_score": 0.82,
    "confidence_value": null,
    "confidence_state": "UNCALIBRATED",
    "evidence_strength": 0.86,
    "calibration_status": "UNSUPPORTED",
    "uncertainty_level": "LOW",
    "explanation": "Raw forecast score is 0.82. Model calibration is UNSUPPORTED."
  },
  "unknown_behavior": {
    "classification": "KNOWN_PATTERN",
    "reason": "Traffic conforms cleanly to supported multi-step attack progression patterns.",
    "supporting_evidence": ["Active concurrent flow count increased 62.8%"],
    "contradictory_evidence": [],
    "coverage": 0.92,
    "abstain_recommended": false
  },
  "abstention": {
    "abstained": false,
    "reason": null,
    "severity": "LOW",
    "status": "FORECAST_AVAILABLE_BUT_UNCALIBRATED",
    "missing_requirements": [],
    "explanation": "Forecast available and corroborated, but model calibration is UNSUPPORTED."
  }
}
```
