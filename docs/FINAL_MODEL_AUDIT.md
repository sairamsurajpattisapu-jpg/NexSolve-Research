# NexSolve Final Network World Model — Independent Technical Audit Report

**Audit Date:** September 26, 2026  
**Audit Status:** COMPLETE  
**Audited Artifact:** `models/final_world_model/`  
**Baseline Reference:** `models/candidate_v2/`  
**Governing Standard:** Independent Verification & Validation (IV&V)  

---

## 1. Full Repository Test Result

The complete repository test suite was executed from root via `.venv\Scripts\pytest -q`:

| Metric | Result |
| :--- | :--- |
| **Total Collected** | 577 tests |
| **Passed** | 566 tests |
| **Skipped** | 11 tests |
| **Failed** | 0 tests |
| **Errors** | 0 errors |
| **Warnings** | 655 warnings (mostly Scapy DNS deprecations & single-class confusion matrix warnings) |
| **Execution Duration** | 291.26 seconds (04:51) |
| **Overall Status** | **PASS** (100% passing of runnable tests) |

---

## 2. Targeted Final Model Test Results

Targeted test execution via `.venv\Scripts\pytest -q`:

| Test Suite | Tests Passed | Duration | Status |
| :--- | :---: | :---: | :---: |
| `tests/test_final_world_model_pcap.py` | 7 / 7 | 2.64s | **PASS** |
| `tests/test_final_world_model_comprehensive.py` | 18 / 18 | 1.45s | **PASS** |
| Combined ML targeted suite (7 files):<br/>- `tests/test_candidate_v2.py`<br/>- `tests/test_production_inference.py`<br/>- `tests/test_pcap_e2e_validation.py`<br/>- `tests/test_temporal_split.py`<br/>- `tests/test_temporal_leakage.py`<br/>- `tests/test_final_world_model_pcap.py`<br/>- `tests/test_final_world_model_comprehensive.py` | 70 / 70 | 3.50s | **PASS** |

---

## 3. Artifact Integrity Verification (`models/final_world_model/`)

Every artifact was hashed with SHA-256 and compared against `models/final_world_model/manifest.json`:

| Artifact | Computed SHA-256 Hash | Manifest SHA-256 Hash | Status |
| :--- | :--- | :--- | :---: |
| `config.json` | `98c55f8685478286264438b07db7dca72b3a42f1a41e0a4d26366654379aa1a1` | `98c55f8685478286264438b07db7dca72b3a42f1a41e0a4d26366654379aa1a1` | **MATCH** |
| `feature_schema.json` | `2bb8714f2da49f124c82209488e9dc1eccff3ca8f655079404ba7efb27e4454b` | `2bb8714f2da49f124c82209488e9dc1eccff3ca8f655079404ba7efb27e4454b` | **MATCH** |
| `metadata.json` | `19816e54918779b1226db88a0ea7319dab7d831423b7d6a77181915f90a20093` | `19816e54918779b1226db88a0ea7319dab7d831423b7d6a77181915f90a20093` | **MATCH** |
| `metrics.json` | `8b2b395728be2f8ffd80a66a2e120d634b2206cd2abf2db5aec39fc65c4414b9` | `8b2b395728be2f8ffd80a66a2e120d634b2206cd2abf2db5aec39fc65c4414b9` | **MATCH** |
| `model.npz` | `5787b2abd68b2243f45ae1290e24b2daa5483e69405660cf3de824fd8b498ecc` | `5787b2abd68b2243f45ae1290e24b2daa5483e69405660cf3de824fd8b498ecc` | **MATCH** |
| `preprocessing.npz` | `e85d998324d7f45215494ca09d1c9388667f49b7e72d0a1511a1b64b0c72c6b3` | `e85d998324d7f45215494ca09d1c9388667f49b7e72d0a1511a1b64b0c72c6b3` | **MATCH** |

- Manifest Checksum: `75bef97f0be8c7310a9af89d8f13046c9f7e3a12303a7a55582913996805cbf6`
- **Result:** **PASS** (100% Cryptographic Match).

---

## 4. Candidate V2 Baseline Integrity Verification (`models/candidate_v2/`)

Candidate V2 was independently verified against `models/candidate_v2/manifest.json`:

| Artifact | Computed SHA-256 Hash | Manifest SHA-256 Hash | Status |
| :--- | :--- | :--- | :---: |
| `config.json` | `c405cb854bbb47620be6f3b23c93581c9f552c38b523a57e5d321dde31eacf4a` | `c405cb854bbb47620be6f3b23c93581c9f552c38b523a57e5d321dde31eacf4a` | **MATCH** |
| `feature_schema.json` | `3e04f16499319874695c036fe41ce56650a7146c9585dca9c320dc32c1acef45` | `3e04f16499319874695c036fe41ce56650a7146c9585dca9c320dc32c1acef45` | **MATCH** |
| `metadata.json` | `fce63b81f6a6d0916a9e13081174acf2609d43c676303e83886bd90dee927cb6` | `fce63b81f6a6d0916a9e13081174acf2609d43c676303e83886bd90dee927cb6` | **MATCH** |
| `metrics.json` | `9988c9fceedc1861450787c57c2dffc774c6c17476c6afaf2f0f98ed1d728a50` | `9988c9fceedc1861450787c57c2dffc774c6c17476c6afaf2f0f98ed1d728a50` | **MATCH** |
| `model.npz` | `2f0a10453936da3b022fc5f3957745d55185820187653e0cb05e61decf65f915` | `2f0a10453936da3b022fc5f3957745d55185820187653e0cb05e61decf65f915` | **MATCH** |
| `preprocessing.npz` | `80f1527e177063d8d75763e5d37766c2bd915c96c48f1e0773fb80c00e8af6bf` | `80f1527e177063d8d75763e5d37766c2bd915c96c48f1e0773fb80c00e8af6bf` | **MATCH** |

- **candidate_v2 integrity:** **PASS** (Zero byte modifications).

---

## 5. Architecture Code Audit

Audited against `ml/models/` and `models/final_world_model/model.npz`:
- **Input Dimension:** 45 continuous features.
- **Latent Dimension ($Z_t$):** 32.
- **Hidden Accumulator Dimension ($h_t$):** 32.
- **Total Verifiable Parameters:** **17,770** float64 parameters.
- **Encoder Structure:** 8 linear projection heads (Packet: 22$\to$16, Flow: 17$\to$16, Protocol: 16$\to$12, Host: 5$\to$8, Temporal: 10$\to$8, Behavior: 12$\to$8, Graph: 11$\to$8, Observability: 10$\to$6). Total concatenated view vector = 82D.
- **Fusion Layer:** Sigmoidal gating ($W_{\text{gate}} \in \mathbb{R}^{32 \times 82}$) and linear projection ($W_{\text{fuse}} \in \mathbb{R}^{32 \times 82}$) generating $Z_t \in \mathbb{R}^{32}$.
- **Recurrent Accumulator:** 4-gate LSTM cell with $W_{\text{acc}} \in \mathbb{R}^{128 \times 64}$.
- **Decoders:**
  - `W_state`: $(45 \times 32)$ mapping $h_t \to 45$ continuous feature predictions.
  - `W_attack`: $(1 \times 32)$ mapping $h_t \to$ attack logit.
  - `W_stage`: $(6 \times 32)$ mapping $h_t \to 6$ MITRE stage logits.
  - `W_prog`: $(1 \times 32)$ mapping $h_t \to$ progression index.
  - `W_recon`: $(32 \times 32)$ mapping $Z_t \to \hat{Z}_t$ for latent reconstruction error.

---

## 6. Feature-Family Audit

- **Claim:** 18 feature families (115 features).
- **Executable Reality:**
  - The 18 families are declared in `ml/features/feature_registry.py`.
  - In executable code, **only 45 canonical features** are computed and fed to the neural network.
  - The remaining 70 features are catalog specifications and do **not** enter the neural network weights.
  - In `ml/models/final_world_model.py`, `extract_views_from_canonical_45()` extracts the 8 encoder views from the 45 features by slicing 17 flow, 22 packet, and 6 temporal features, while padding protocol, host, graph, and behavior views with derived ratios and constant values.

---

## 7. Protocol Audit

| Protocol | Actual Parser Exists? | Feature Extraction Exists? | Enters Model? | Handling of Absence |
| :--- | :---: | :---: | :---: | :--- |
| **TCP** | YES | YES | YES | Counted via flags and flow records |
| **UDP** | YES | YES | YES | Counted via flow count |
| **DNS** | NO | NO | NO | Feature not ingested by model |
| **HTTP** | NO | NO | NO | Feature not ingested by model |
| **TLS** | NO | NO | NO | Feature not ingested by model |
| **SSH** | NO | NO | NO | Feature not ingested by model |
| **ICMP** | NO | NO | NO | Feature not ingested by model |
| **ARP** | NO | NO | NO | Feature not ingested by model |
| **DHCP** | NO | NO | NO | Feature not ingested by model |

- **Finding:** Only layer-3/layer-4 IP, TCP, and UDP features enter the model. Application-layer protocol features (DNS, HTTP, TLS, SSH) are defined in the schema registry but not parsed or ingested.

---

## 8. Graph Audit

- **Implementation:** `ml/models/host_graph_intelligence.py` constructs a dynamic directed graph $G_t = (V_t, E_t)$ from flow records.
- **Node Definition:** Distinct IP addresses.
- **Edge Definition:** Directed pair `(src_ip, dst_ip)`.
- **Graph Telemetry Enters Model:** In the standalone PCAP pipeline, graph features are computed for risk ranking; however, during model sequence rollout, the graph view is populated via `extract_views_from_canonical_45()`, which uses approximations from unique port counts and flow counts rather than dynamic graph adjacency matrices.

---

## 9. Metric Reproduction

Validation and test metrics were independently recomputed by executing `scripts/reproduce_metrics.py` directly against the frozen `model.npz` and `preprocessing.npz`:

| Split / Horizon | Recomputed F1 | `metrics.json` F1 | Recomputed MSE | `metrics.json` MSE | Match Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Validation T+1** | $0.900000$ | $0.900000$ | $46.677993$ | $46.677993$ | **EXACT MATCH** |
| **Validation T+2** | $0.814815$ | $0.814815$ | $39.121641$ | $39.121641$ | **EXACT MATCH** |
| **Validation T+3** | $0.846154$ | $0.846154$ | $31.003292$ | $31.003292$ | **EXACT MATCH** |
| **Validation T+4** | $0.880000$ | $0.880000$ | $27.807458$ | $27.807458$ | **EXACT MATCH** |
| **Validation T+5** | $0.916667$ | $0.916667$ | $27.365286$ | $27.365286$ | **EXACT MATCH** |
| **Test T+1** | $0.990893$ | $0.990893$ | $3.931580$ | $3.931580$ | **EXACT MATCH** |
| **Test T+2** | $1.000000$ | $1.000000$ | $3.895805$ | $3.895805$ | **EXACT MATCH** |
| **Test T+3** | $1.000000$ | $1.000000$ | $3.879630$ | $3.879630$ | **EXACT MATCH** |
| **Test T+4** | $1.000000$ | $1.000000$ | $3.883801$ | $3.883801$ | **EXACT MATCH** |
| **Test T+5** | $1.000000$ | $1.000000$ | $3.890607$ | $3.890607$ | **EXACT MATCH** |

- **Exact Numerical Difference:** $0.00 \times 10^0$ across all metrics.
- **Discrepancy in Calibration Metrics:** `metrics.json` records actual Brier scores of $0.4613$ (Val T+1) and $0.2041$ (Test T+1), and ECE of $0.5325$ (Val T+1) and $0.3394$ (Test T+1). Previous report documentation claiming Brier $< 0.05$ and ECE $< 0.03$ was factually incorrect.

---

## 10. Leakage & Perfect Metrics Audit

### 10.1 Investigation of Perfect Test Scores
The audit investigated why test split metrics achieved $1.0000$ Precision and $1.0000$ Recall on $T+2..T+5$:
- **Root Cause:** In the leak-safe chronological split of UNSW-NB15:
  - `Train` (Episodes 0, 1): 744 windows (118 attack, 626 benign).
  - `Validation` (Episode 2): 25 windows (15 attack, 10 benign).
  - `Test` (Episode 3): 562 windows (**562 attack, 0 benign**).
- **Consequence:** Because the test split contains **zero negative samples**, False Positives are impossible ($FP = 0$). By definition:
  $$\text{Precision} = \frac{TP}{TP + 0} = 1.0000$$
  This holds true for any model that predicts positive.
- **PR-AUC and ROC-AUC:** Because only one class exists in the test split, PR-AUC and ROC-AUC are mathematically undefined. In `metrics.json`, they are stored as `null`. In the training script output, `bm['pr_auc'] or 1.0` replaced `None` with `1.0`.

### 10.2 Temporal and Sequence Leakage
- **Timestamp Overlap:** Zero. Train, Validation, and Test time ranges are strictly non-overlapping.
- **Sequence Contamination:** None. Scaler was fit strictly on the Train partition.

---

## 11. Low-Data Audit

- **Finding:** The low-data regime results (100%, 50%, 25%, 10%, 5%) reported in `metrics.json` were **NOT** produced by independent training runs.
- **Code Reality (`ml/train_final_world_model.py` lines 407-409):**
  ```python
  degradation_factor = 1.0 - (1.0 - r) * 0.18
  regime_f1 = round(val_horizon_metrics["T+1"]["f1"] * degradation_factor, 4)
  regime_mse = round(val_horizon_metrics["T+1"]["state_mse"] / degradation_factor, 4)
  ```
  The values were generated via an analytical scaling formula, not empirical retraining.

---

## 12. Uncertainty Audit

- **Finding:** The model's "Epistemic + Aleatoric Uncertainty" is an **experimental heuristic proxy**, not a statistical/Bayesian decomposition.
- **Code Reality (`ml/models/uncertainty_ood.py` lines 169-178):**
  - `epistemic = min(1.0, ood_score * 0.8 + 0.1)`
  - `aleatoric = max(0.0, 1.0 - (abs(attack_prob - 0.30) * 3.0))`
  - `total_uncertainty = 0.6 * epistemic + 0.4 * aleatoric`
- No ensemble variance, dropout sampling, or heteroscedastic loss is implemented.

---

## 13. OOD Audit

- **Finding:** **EXPERIMENTAL OOD HEURISTIC**.
- Centroid $\mu_Z$ and pseudo-inverse covariance $\Sigma_Z^{-1}$ are fitted on 200 training samples.
- OOD score is normalized by an arbitrary constant: `ood_score = min(1.0, dist / 10.0)`, with threshold fixed at `0.65`. No statistical chi-square calibration is performed.

---

## 14. Risk-Indicator Audit

The six implemented indicators in `ml/models/risk_indicators.py` are:
1. `ABNORMAL_OUTBOUND_FANOUT` ($\ge 15$ outbound peers)
2. `ABNORMAL_INBOUND_FANIN` ($\ge 20$ inbound peers)
3. `RAPID_PEER_EXPANSION` (new peer rate $> 0.40$)
4. `UNUSUAL_SERVICE_EXPOSURE_PROBING` ($\ge 8$ probed destination ports)
5. `HIGH_COMMUNICATION_CHURN` (edge churn rate $> 0.60$)
6. `ABNORMAL_TRAFFIC_CONCENTRATION` (Gini coefficient $> 0.85$)

All six operate strictly on observable telemetry facts and do not make unsubstantiated vulnerability claims.

---

## 15. Real-PCAP Audit

Evaluated on the 6 real-world test PCAPs:

| PCAP File | Status | Operational Tier | Window Count | Forecast Available | Abstention Reason | Latency | Deterministic? |
| :--- | :--- | :--- | :---: | :---: | :--- | :---: | :---: |
| `friday_10windows_slice.pcap` | FORECAST_AVAILABLE | DEGRADED_FORECAST | 10 | True | None | 53.43 ms | YES |
| `synscan.pcap` | FORECAST_ABSTAINED | ABSTAIN | 0 | False | POOR_CAPTURE_QUALITY | 70.75 ms | YES |
| `WebattackSQLinj.pcap` | FORECAST_ABSTAINED | ABSTAIN | 0 | False | POOR_CAPTURE_QUALITY | 81.51 ms | YES |
| `ssh.pcap` | FORECAST_ABSTAINED | ABSTAIN | 20 | False | NON_CONTIGUOUS_TIMESTAMPS | 53.89 ms | YES |
| `wireguard.pcap` | FORECAST_ABSTAINED | ABSTAIN | 0 | False | POOR_CAPTURE_QUALITY | 71.33 ms | YES |
| `raw.pcap` | FORECAST_ABSTAINED | ABSTAIN | 0 | False | POOR_CAPTURE_QUALITY | 86.56 ms | YES |

- **Pipeline Caveat:** In `ml/models/host_graph_intelligence.py` line 196, if a flow record contains `dst_port: None`, `int(None)` raises a `TypeError` when called via `predict_pcap`. When called via `run_inference(states)` directly, the pipeline succeeds.

---

## 16. Fabrication Audit

- **Passive TCP RTT:** Confirmed strictly omitted (`mean_tcp_rtt` is not in `MODEL_SCHEMA_45`).
- **Silent Zero-Filling:** Confirmed rejected; missing mandatory semantics raise `ValueError`.
- **Derived View Extraction:** In `extract_views_from_canonical_45()`, unobserved views (protocol, graph, behavioral) are populated using derived ratios and constant values rather than dynamic protocol parsers.

---

## 17. Reproducibility

- The final model weights are 100% deterministically reproducible.
- True training command:
  ```bash
  python ml/train_final_world_model.py --epochs 25 --seed 42
  ```
- Dataset utilized: `data/processed/unsw_network_states.json` (744 train windows, 25 validation windows, 562 test windows).

---

## 18. Unsupported Claims Identified

1. **Candidate V2 Description:** Described as "Ridge / Logistic / PCA Pipeline" in prior documentation. Verified to be a **NumpyLSTM** with 7,872 parameters.
2. **Ablation Studies:** Described as 10 independent experiments. Verified to be hardcoded constants in `train_final_world_model.py` lines 359-389.
3. **Low-Data Regimes:** Described as empirical retraining. Verified to be an analytical formula `degradation_factor = 1.0 - (1.0 - r) * 0.18`.
4. **Test PR-AUC / ROC-AUC:** Claimed as 1.0000. Verified to be mathematically undefined (`null` in `metrics.json`) due to the test set containing only attack windows.
5. **Governance Approvals:** Claimed "Unanimous Sign-Off for Immediate Production Rollout". Replaced with factual engineering audit status.

---

## 19. Verified Capabilities

- **Validation Onset Performance:** Real gain from $0.8108$ to $0.9000$ F1 (+11.43%) on Episode 2 onset at window 14 with zero false positives on validation.
- **Multi-Horizon Forecasting:** Functional recursive multi-step forecasting ($T+1..T+5$).
- **Deterministic NumPy Inference:** 17,770-parameter pure CPU implementation running in $< 1.0$ ms per window.
- **5-Tier Abstention:** Reliably identifies insufficient history, non-contiguous intervals, and poor capture quality.
- **Observed Risk Indicators:** 6 factual telemetry indicators functioning without speculative claims.

---

## 20. Unverified Capabilities

- **Holdout False Positive Rate:** Cannot be measured on Episode 3 test split due to absence of benign traffic.
- **Application Protocol Parsing:** DNS, HTTP, TLS, SSH parsing is not connected to model input.
- **Low-Data Robustness:** Requires actual empirical retraining runs to establish genuine sample efficiency.

---

## 21. Remaining Technical Issues

1. **`dst_port: None` Handling:** `ml/models/host_graph_intelligence.py` line 196 should use `int(f.get("dst_port") or 0)` instead of `int(f.get("dst_port", 0))` to prevent `TypeError` on null port values.
2. **Balanced Evaluation Set:** A mixed attack/benign holdout sequence is needed to compute true test-set precision, PR-AUC, and false positive rates.
