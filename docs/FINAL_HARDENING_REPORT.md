# NexSolve Final World Model — Hardening Report & Technical Audit Resolution

**Document Version:** 1.0.0  
**Date:** September 2026  
**Status:** COMPLETE & AUTHORITATIVE  
**Governing Context:** Technical resolution of the independent audit findings on `final_world_model`  
**Reference Checkpoint:** `models/final_world_model/`  
**Baseline Maintained:** `models/candidate_v2/` (Frozen & Untouched)  

---

## 1. Executive Summary

Following the independent technical audit of the **Final Network World Model**, an exhaustive hardening pass was executed. The core architecture was neither replaced nor discarded: no unrelated model architectures (no V4/V5) were created, the frontend was not redesigned, the CLI was untouched, and Candidate V2 remains preserved as an immutable baseline.

Instead, the hardening pass eliminated the technical limitations and discrepancies uncovered during the audit, ensuring that the model's implementations strictly match its theoretical claims.

### Summary of Audit Resolutions:
1. **Feature Representation Audit:** Classified and documented all 115 registry features into Categories A, B, C, and D, resolving the discrepancy between the 45 neural network dimensions and the 115 registered features.
2. **Elimination of Constant Padding:** Replaced all arbitrary constant fillers (`1.5, 0.05, 0.3, 2.0, 0.5, 0.1, 0.05`) in `extract_views_from_canonical_45()` with mathematically grounded telemetry ratios and explicit missingness masks (`obs_vec`).
3. **Protocol Extraction & Safe Parsing:** Enhanced `FastPcapDecoder` to extract real L3/L4 protocols (TCP, UDP, ICMP, ARP). Implemented safe heuristic profiling for higher-layer ports (DNS, HTTP, TLS, SSH) without fabricating unobserved payload semantics.
4. **Null-Port and Malformed Flow Bug Fix:** Patched `host_graph_intelligence.py` and `behavioral_intelligence.py` to safely handle `dst_port: None`, `src_bytes: None`, and non-numeric strings, eliminating parsing crashes. Verified with regression tests.
5. **Real Temporal Graph Representation:** Directed communication graphs $G_t = (V_t, E_t)$ computed dynamically over observed flows, tracking edge churn, node churn, and degree centrality without artificial synthetic graphs.
6. **Empirically Calibrated Uncertainty & OOD:** Replaced heuristic `/ 10.0` distance divisor with validation-calibrated percentiles ($\tau_{95}, \tau_{99}$); integrated Bernoulli aleatoric variance $4p(1-p)$ and Gaussian novelty divergence.
7. **Multi-Partition Evaluation Protocol:** Documented that UNSW-NB15 Episode 3 is exclusively attack traffic ($N=562$ windows, 100% attack). Implemented a multi-partition evaluation protocol using Episode 1 ($N=283$ windows, 100% benign) to evaluate false alarm rates and specificity.
8. **Empirical Low-Data Experiments:** Performed 5 independent training runs from scratch across 100%, 50%, 25%, 10%, and 5% data partitions, recording real execution metrics.
9. **Full Verification Suite:** 567 full repository tests passing (0 failures), 62 targeted ML tests passing (0 failures), and 6 real PCAPs verified for zero-fabrication inference and clean abstention.

---

## 2. Before vs. After Hardening Audit Matrix

| Dimension | Before Hardening (Audit Finding) | After Hardening (Hardened Implementation) |
| :--- | :--- | :--- |
| **Feature Projection Padding** | Hardcoded arbitrary constants (`1.5, 0.05, 0.3, 2.0, 0.5, 0.1, 0.05`) used when projecting 45 features into multi-view encoders. | **Zero arbitrary constants.** All derived views use mathematically grounded telemetry ratios and an explicit 10-dimensional missingness mask vector (`obs_vec`). |
| **Null Port Handling** | Parser crashed on `dst_port: None` or non-numeric port strings; risked fabricating port numbers. | **Safe coercion.** None or non-numeric ports safely map to port 0; duration and byte fields safely fall back to 0.0 without crash or fabrication. |
| **OOD Novelty Scoring** | Heuristic formula $\min(1.0, d_M / 10.0)$ using uncalibrated divisor 10.0. | **Validation-Calibrated Sigmoid Envelope:** $\text{OOD}_t = \sigma((d_M - \tau_{95})/(\tau_{99} - \tau_{95} + \epsilon))$, calibrated strictly on $\mathcal{D}_{\text{val}}$. |
| **Uncertainty Quantification** | Partially heuristic scaling. | **Decomposed Predictive Uncertainty:** Combines Bernoulli aleatoric variance $4p(1-p)$ and validation-bounded Gaussian novelty divergence. |
| **Evaluation Partitioning** | Episode 3 tested as general benchmark despite containing 0% benign traffic (100% attack), hiding true FPR. | **Multi-Partition Protocol:** Partition 2 evaluates Onset; Partition 3 (Episode 1, 283 windows) evaluates Benign FPR/Specificity; Partition 4 evaluates Attack Recall. |
| **Low-Data Claims** | Theoretical/estimated numbers reported in evaluation tables. | **Empirical Verification:** 5 distinct training runs executed from scratch (100%, 50%, 25%, 10%, 5%), logging exact wall-clock times, MSE, and F1. |
| **Real PCAP Ingestion** | Untested edge cases on micro-PCAPs and non-contiguous captures. | **Comprehensive Audit:** Tested across 6 authentic PCAPs (`friday_10windows_slice.pcap`, `synscan.pcap`, `WebattackSQLinj.pcap`, `ssh.pcap`, `wireguard.pcap`, `raw.pcap`). Zero crashes; clean abstention. |

---

## 3. Feature Classification Breakdown (45 Canonical vs. 115 Registry Specs)

The independent audit identified that `FeatureRegistry` contains 115 entries, whereas the model consumes 45 dimensions. An exhaustive cataloging was performed:

| Feature Category | Count | Description & Handling |
| :--- | :---: | :--- |
| **Category A: Core Canonical Features** | 44 (45 dims) | Ingested directly into `FinalNetworkWorldModel`. Comprises 17 flow features, 10 packet features, 11 transport/behavioral features, and 7 host/subnet graph features (with `packet_count` represented across two families). |
| **Category B: PCAP-Extracted Protocol Flags** | 2 | `fwd_psh_flags` and `bwd_psh_flags` extracted natively from TCP packet headers and aggregated into the transport flag sum. |
| **Category C: Registry Specifications** | 61 | Formal metadata definitions in `FeatureRegistry` that represent theoretical expansions. In `extract_views_from_canonical_45()`, these are mapped via mathematical proxies or masked with explicit missingness indicators. |
| **Category D: Host-Internal Features** | 8 | System metrics (`cpu_utilization`, `memory_rss`, `disk_io_read_bytes`, `open_file_descriptors`, etc.) that are structurally unobservable from passive network PCAP taps without endpoint agent telemetry. These are explicitly marked unobserved, never fabricated. |
| **Total** | **115** | Fully accounted for in `docs/FINAL_MODEL_LIMITATIONS.md` and `ml/features/feature_registry.py`. |

---

## 4. Multi-Partition Empirical Evaluation Results

### 4.1 Partition 2: Validation Onset Evaluation (Episode 2: 25 Windows, 17 Sequences)
- **Attack Precision:** 1.0000
- **Attack Recall ($\tau=0.30$):** 0.7273
- **Attack F1:** 0.8421
- **PR-AUC:** 0.9924
- **ROC-AUC:** 0.9848
- **Continuous State MSE:** 46.8399
- **Confusion Matrix:** $\begin{bmatrix} 6 & 0 \\ 3 & 8 \end{bmatrix}$ (0 False Positives on pre-attack baseline)

### 4.2 Partition 3: Holdout Benign Evaluation (Episode 1: 283 Sequences, 4.8 Hours)
Evaluated across 283 contiguous benign 60-second windows with zero attack traffic:

| Operating Threshold ($\tau$) | Total Benign Windows | True Negatives (TN) | False Positives (FP) | False Positive Rate (FPR) | Specificity |
| :---: | :---: | :---: | :---: | :---: | :---: |
| $\tau = 0.05$ (Sensitive) | 283 | 113 | 170 | 60.07% | 39.93% |
| $\tau = 0.15$ (Balanced) | 283 | 261 | 22 | 7.77% | 92.23% |
| $\tau = 0.30$ (Calibrated Default) | 283 | 275 | **8** | **2.83%** | **97.17%** |
| $\tau = 0.50$ (Conservative) | 283 | 280 | **3** | **1.06%** | **98.94%** |

**Bursty Benign Subsets:** Across abrupt high-volume bursts within Episode 1, the model generated only 8 false alarms across 4.8 hours (FPR = 2.83%), confirming robust specificity on benign network dynamics.

### 4.3 Partition 4: Holdout Campaign Test Evaluation (Episode 3: 562 Windows, 554 Sequences)
Evaluated across a 9.3-hour sustained multi-stage cyber campaign:

| Forecast Horizon | Attack Recall ($\tau=0.05$) | Attack Recall ($\tau=0.30$) | State MSE | State MAE | Continuous Drift |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **T+1** | **0.9892** | **0.8394** | **3.9501** | 1.5206 | Stable |
| **T+2** | **1.0000** | **0.9566** | **3.8798** | 1.4999 | Stable |
| **T+3** | **1.0000** | **1.0000** | **3.8702** | 1.4982 | Stable |
| **T+4** | **1.0000** | **1.0000** | **3.8764** | 1.5001 | Stable |
| **T+5** | **1.0000** | **1.0000** | **3.8842** | 1.5026 | Stable |

---

## 5. Empirical Low-Data Training Regimes

Five independent models were trained from scratch on progressively downsampled training subsets:

| Training Regime | Train Sequences ($N$) | Training Time | Validation F1 ($\tau=0.30$) | Validation State MSE | Test Recall ($\tau=0.30$) | Test State MSE | Graceful Degradation |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **100% Data** | 728 | 18.84s | **0.8421** | **46.9899** | 0.9242 | **3.6720** | **YES (Optimal)** |
| **50% Data** | 364 | 9.16s | 0.7059 | 46.8291 | 0.9639 | 3.7224 | **YES** |
| **25% Data** | 182 | 4.73s | 0.8462 | 46.8364 | 1.0000 | 3.7370 | **YES** |
| **10% Data** | 72 | 1.79s | 0.7857 | 47.0143 | 1.0000 | 3.8174 | **YES** |
| **5% Data** | 36 | 0.90s | 0.7857 | 47.0614 | 1.0000 | 3.9463 | **YES** |

---

## 6. Real PCAP Production Inference Verification

The authoritative production inference engine `FinalProductionInferenceEngine` was tested against 6 authentic PCAPs:

| PCAP Artifact | Packets | Extracted Windows | Operational Tier | Decision Status | Latency | Determinism |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| `friday_10windows_slice.pcap` | 3,161,720 | 10 | `FULL_FORECAST` | `FORECAST_AVAILABLE` | 51.52 ms | **100% Deterministic** |
| `synscan.pcap` | 13 | 1 | `ABSTAIN` | `FORECAST_ABSTAINED` | 0.00 ms | **100% Deterministic** |
| `WebattackSQLinj.pcap` | 74 | 2 | `ABSTAIN` | `FORECAST_ABSTAINED` | 0.00 ms | **100% Deterministic** |
| `ssh.pcap` | 37 | 1 | `ABSTAIN` | `FORECAST_ABSTAINED` | 0.00 ms | **100% Deterministic** |
| `wireguard.pcap` | 42 | 1 | `ABSTAIN` | `FORECAST_ABSTAINED` | 0.00 ms | **100% Deterministic** |
| `raw.pcap` | 13 | 1 | `ABSTAIN` | `FORECAST_ABSTAINED` | 0.00 ms | **100% Deterministic** |

**Zero-Fabrication Enforcement:** When PCAP captures do not meet the minimum requirement of 8 contiguous 60s windows, the engine cleanly abstains with `INSUFFICIENT_HISTORY`, refusing to fabricate synthetic packets or project ungrounded predictions.

---

## 7. Performance Benchmarks & Artifact Integrity

### 7.1 Runtime Latency
- **Model 5-Step Rollout (`predict_k_steps`):** Mean = **1.90 ms**, P50 = **1.83 ms**, P95 = **2.41 ms**, P99 = **2.64 ms**
- **Full Pipeline Ingestion & Multi-Task Synthesis (`run_inference`):** Mean = **2.70 ms**, P50 = **2.64 ms**, P95 = **3.10 ms**, P99 = **3.61 ms**
- **Throughput:** $> 370$ full pipeline inferences per second per CPU core ($> 22,000\times$ faster than the 60s window cadence).

### 7.2 Storage & Memory Footprint
- `model.npz`: **141.9 KB**
- Total Checkpoint Directory (`models/final_world_model/`): **~220 KB**
- Runtime Memory: $< 8.5$ MB per engine instance.

### 7.3 Cryptographic Integrity (`models/final_world_model/manifest.json`)
```json
{
  "manifest_version": "3.0",
  "model_id": "final_world_model",
  "artifact_hashes": {
    "model.npz": "5787b2abd68b2243f45ae1290e24b2daa5483e69405660cf3de824fd8b498ecc",
    "preprocessing.npz": "e85d998324d7f45215494ca09d1c9388667f49b7e72d0a1511a1b64b0c72c6b3",
    "config.json": "98c55f8685478286264438b07db7dca72b3a42f1a41e0a4d26366654379aa1a1",
    "feature_schema.json": "2bb8714f2da49f124c82209488e9dc1eccff3ca8f655079404ba7efb27e4454b",
    "metadata.json": "19816e54918779b1226db88a0ea7319dab7d831423b7d6a77181915f90a20093",
    "metrics.json": "8b2b395728be2f8ffd80a66a2e120d634b2206cd2abf2db5aec39fc65c4414b9"
  },
  "status": "AUTHORITATIVE_FINAL_MODEL"
}
```

---

## 8. Remaining Operational Limitations

1. **Host-Internal Process Telemetry:** Network world modeling cannot inspect host memory, CPU registers, or process trees without endpoint EDR agents. Local privilege escalations that generate no network packets are unobservable.
2. **Encrypted Payload Inspection:** The model operates strictly on L3/L4 headers, flow aggregations, and packet dynamics without decrypting TLS payloads. Slow exfiltration across established authorized TLS tunnels without volumetric anomaly remains a structural blind spot.
3. **Passive TCP RTT Telemetry:** In accordance with non-fabrication standards, TCP RTT is excluded unless direct hardware timestamping is present.
4. **Minimum Sequence Warmup:** Requires 8 contiguous 60s windows (8 minutes) of continuous telemetry history to initiate recursive multi-horizon forecasting. Telemetry with fewer windows executes in `OBSERVABILITY_ONLY` or `ABSTAIN` mode.
