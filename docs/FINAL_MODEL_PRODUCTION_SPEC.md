# NexSolve Final Network World Model — Production Specification

**Specification Version:** 2.0.0-PROD  
**Target Model:** `final_world_model`  
**Reference Implementation:** `ml/final_production_inference.py`  
**Registry Reference:** `ml/registry.py`  
**Artifact Directory:** `models/final_world_model/`  

---

## 1. Overview & Operational Scope

This specification defines the strict production interface, operational parameters, data contracts, and runtime behavior for the NexSolve Final Network World Model.

The model consumes a temporal sequence of passive network summary windows and emits multi-horizon continuous state forecasts ($T+1$ through $T+5$), discrete attack progression probabilities, MITRE ATT&CK taxonomical classifications, calibrated uncertainty estimates, distributional novelty scores, and observed risk indicators.

---

## 2. Input Schema & Data Ingestion

### 2.1 Window Definitions
- **Window Length ($\Delta t$):** 10.0 seconds nominal.
- **Sequence Context ($W$):** Minimum 5 windows ($50\text{s}$), optimal 10–32 windows ($100\text{s}–320\text{s}$).
- **Batch Dimension:** 1 (real-time stream inference) or $B$ (offline PCAP batch evaluation).

### 2.2 Feature Dimension & Schema
The input tensor per window is a 1D vector of shape `(45,)` or a 2D matrix of shape `(W, 45)`, where $W \ge 1$.

The 45 dimensions are grouped into 4 primary views across 18 specialized feature families:
1. **Flow Statistics View** (indices `[0..13]`): `flow_count`, `active_flows`, `flow_duration_mean`, `flow_duration_std`, `flow_duration_max`, `fwd_packets_per_flow_mean`, `bwd_packets_per_flow_mean`, `fwd_bytes_per_flow_mean`, `bwd_bytes_per_flow_mean`, `flow_bytes_per_sec_mean`, `flow_packets_per_sec_mean`, `mean_iat_flow`, `std_iat_flow`, `max_iat_flow`.
2. **Packet Dynamics View** (indices `[14..23]`): `packet_count`, `packet_rate`, `packet_size_mean`, `packet_size_std`, `packet_size_min`, `packet_size_max`, `mean_iat_packet`, `std_iat_packet`, `min_iat_packet`, `max_iat_packet`.
3. **Behavioral & Transport Ratios View** (indices `[24..34]`): `syn_count`, `ack_count`, `fin_count`, `rst_count`, `psh_count`, `urg_count`, `syn_ack_ratio`, `rst_rate`, `byte_ratio_in_out`, `packet_ratio_in_out`, `transport_protocol_entropy`.
4. **Host & Subnet Graph View** (indices `[35..44]`): `unique_src_ips`, `unique_dst_ips`, `unique_src_ports`, `unique_dst_ports`, `src_ip_entropy`, `dst_ip_entropy`, `src_port_entropy`, `dst_port_entropy`, `fan_out_ratio`, `fan_in_ratio`.

### 2.3 Input Formats Accepted
The engine accepts any of the following input formats via `FinalProductionInferenceEngine.predict()`:
1. **Dictionary of Feature Name to Value:** Dict with 44/45 feature keys (e.g. from live stream aggregator).
2. **1D NumPy Array / Sequence:** Shape `(45,)` representing the current instantaneous window.
3. **2D NumPy Array:** Shape `(W, 45)` representing an explicit sequence of historical windows up to the current time $T$.

### 2.4 Preprocessing, Normalization & Clamping
- **Mean & Standard Deviation:** Precomputed and stored in `preprocessing.npz`:
  $$x_{\text{norm}, i} = \frac{x_i - \mu_i}{\sigma_i + \epsilon}$$
  where $\epsilon = 10^{-6}$.
- **Outlier Clamping:** Normalized features are clamped to $[-10.0, 10.0]$:
  $$x_{\text{clamped}, i} = \text{clip}(x_{\text{norm}, i}, -10.0, 10.0)$$
- **Zero-filling Prohibition:** Missing telemetry keys default to reference mean $\mu_i$ ($x_{\text{norm}} = 0.0$) with epistemic uncertainty penalty; unobserved semantics are never zero-filled.

---

## 3. Output Contract & Response Schema

Every invocation returns a JSON-serializable dictionary with exactly the following 15 top-level contract keys:

| Key | Type | Description | Range / Values |
| :--- | :--- | :--- | :--- |
| `timestamp` | `float` | Unix timestamp of evaluation | $\ge 0.0$ |
| `window_index` | `int` | Sequential counter of evaluated windows | $\ge 0$ |
| `predicted_state_mean` | `list[float]` | Vector of forecasted state means at $T+1$ | Length 10, continuous |
| `predicted_state_variance` | `list[float]` | Vector of forecasted state variances at $T+1$ | Length 10, $\ge 0.0$ |
| `attack_probability` | `float` | Calibrated probability of malicious activity at $T+1$ | $[0.0, 1.0]$ |
| `attack_stage` | `str` | Predicted MITRE ATT&CK taxonomy stage | `benign`, `reconnaissance`, `initial_access`, `lateral_movement`, `data_exfiltration`, `command_and_control` |
| `stage_probabilities` | `dict[str, float]` | Full probability distribution across all 6 stages | Values sum to $1.0 \pm 10^{-4}$ |
| `progression_index` | `float` | Estimated attack progression metric along kill-chain | $[0.0, 1.0]$ |
| `forecast_horizon` | `int` | Target lead horizon for primary prediction | Standard default: 1 |
| `multi_horizon_forecasts` | `dict[str, dict]` | Comprehensive forecasts for horizons $T+1$ through $T+5$ | Keys `'T+1'` to `'T+5'`, each containing `predicted_state`, `attack_probability`, `anomaly_score`, `uncertainty` |
| `anomaly_detected` | `bool` | Flag indicating anomalous state deviation | `True` if `anomaly_score > threshold` |
| `anomaly_score` | `float` | Continuous state residual anomaly metric | $[0.0, \infty)$ |
| `uncertainty_score` | `float` | Total predictive uncertainty ($\sigma^2_{\text{epistemic}} + \sigma^2_{\text{aleatoric}}$) | $[0.0, 1.0]$ |
| `abstention_level` | `str` | Active decision tier from 5-Tier Abstention Engine | `FULL_FORECAST`, `DEGRADED_FORECAST`, `ANOMALY_ONLY`, `OBSERVABILITY_ONLY`, `ABSTAIN` |
| `observed_risk_indicators`| `list[dict]` | Observable telemetry risk indicators (NOT predictive claims) | List of indicator records with `indicator_name`, `severity`, `rationale`, `telemetry_source` |

---

## 4. Multi-Horizon Forecast Structure

Inside `multi_horizon_forecasts`, each horizon entry (`T+1`, `T+2`, `T+3`, `T+4`, `T+5`) conforms to:
```json
{
  "predicted_state": [0.12, -0.45, 1.20, ...], // 10 continuous state dimensions
  "attack_probability": 0.034,                  // Calibrated probability
  "anomaly_score": 0.28,                       // Residual norm against expected state
  "uncertainty": 0.041                         // Horizon-adjusted predictive uncertainty
}
```

---

## 5. Performance Benchmarks & Runtime Latency

Empirically benchmarked on Python 3.11 / AMD/Intel x86_64 architecture (pure NumPy forward pass):

| Inference Pipeline Stage | Budget Target | Empirical Latency (Measured) |
| :--- | :--- | :--- |
| Model 5-Step Forward Pass (`predict_k_steps`) | $< 5.00$ ms | Mean: **1.90 ms**, P50: **1.83 ms**, P95: **2.41 ms**, P99: **2.64 ms** |
| Full Pipeline Ingestion & Multi-Task Synthesis (`run_inference`) | $< 10.00$ ms | Mean: **2.70 ms**, P50: **2.64 ms**, P95: **3.10 ms**, P99: **3.61 ms** |
| Real PCAP Ingestion & Full Ingestion (`predict_pcap`, 3.16M packets) | $< 100.00$ ms | Total: **51.52 ms** |

### Throughput & Concurrency
- **Single-Core Capacity:** $> 370$ full pipeline inferences per second ($370\times$ faster than the 1-second streaming target, and $> 22,000\times$ faster than the 60-second window interval).
- **Memory & Storage Footprint:** 
  - `model.npz`: **141.9 KB**
  - Total artifact directory (`models/final_world_model/`): **~220 KB**
  - Active runtime memory per engine instance: $< 8.5$ MB.
  - Scaling: Stateless weights can be shared across multiple threads; each thread maintains its own recurrent buffer $H$ ($< 50$ KB).

---

## 6. Failure Modes & Graceful Fallbacks

| Failure Condition | Detection Trigger | Fallback Action & Output Contract |
| :--- | :--- | :--- |
| **Insufficient Warmup** | History length $W < 5$ | Abstention level = `OBSERVABILITY_ONLY`. Emits current window risk indicators and zero-padded state; suppresses $T+1..T+5$ attack probability. |
| **Corrupted / NaN Features** | Any feature value is NaN or Inf | Feature is imputed with reference mean $\mu_i$; uncertainty is inflated by $+0.50$; logged as `IMPUTED_TELEMETRY`. |
| **High Novelty / Out of Distribution** | Mahalanobis Distance $D_M(z) > 12.0$ | Abstention level = `ANOMALY_ONLY`. Attack classification is suppressed; anomaly score is reported with OOD warning flag. |
| **Extreme Model Uncertainty** | Total Uncertainty $> 0.70$ | Abstention level = `DEGRADED_FORECAST`. Forecasts include elevated variance bounds; SOC alert is flagged with `HIGH_UNCERTAINTY`. |
| **Missing Model File** | `model.npz` unreadable or corrupted SHA-256 | Engine raises `ModelLoadError` on startup; never silent failure. Factory fallback loads verified `candidate_v2` baseline. |

---

## 7. Integration Guide for Inference Callers

### 7.1 Python API Usage

```python
from ml.registry import ModelRegistry
from ml.final_production_inference import FinalProductionInferenceEngine

# 1. Resolve and load the production final world model
engine = ModelRegistry.load_production_model()
print(f"Loaded: {engine.get_model_id()}")

# 2. Ingest continuous telemetry stream (window by window)
for window_idx, window_features in enumerate(telemetry_stream):
    response = engine.predict(window_features)
    
    # Check decision abstention tier
    if response["abstention_level"] == "FULL_FORECAST":
        if response["attack_probability"] > 0.30:
            print(f"[{response['attack_stage'].upper()}] Lead horizon T+{response['forecast_horizon']} alert! "
                  f"Prob: {response['attack_probability']:.2f}, Uncertainty: {response['uncertainty_score']:.3f}")
    
    elif response["abstention_level"] == "ANOMALY_ONLY":
        print(f"Volumetric Anomaly: Score {response['anomaly_score']:.2f} (OOD Noveltly)")

    # Inspect observable network risk indicators
    for indicator in response["observed_risk_indicators"]:
        print(f"Risk Indicator: {indicator['name']} [{indicator['severity']}] - {indicator['rationale']}")
```

### 7.2 Safe Reset
To transition between distinct network captures, segments, or episodes without state leakage, invoke:
```python
engine.reset()
```
This reinitializes the recurrent accumulator $h_0 = \mathbf{0}$, clears sliding window history, and resets window counters.
