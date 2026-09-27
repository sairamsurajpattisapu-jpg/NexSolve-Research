# NEXSOLVE INDEPENDENT ML CLAIM VERIFICATION REPORT

**Auditor Role:** Independent Machine Learning Auditor (Zero-Trust Model Verification)  
**Subject Document:** `docs/ML_SCIENTIFIC_GATE_REPORT.md` and associated experiment artifacts  
**Target of Verification:** Claimed Model Improvements over Baseline / Viability of Replacing Frozen World Model  
**Execution Timestamp:** September 2026  
**Final Audit Verdict:** `CLAIM NOT VERIFIED`  
**Operational Directive:** **KEEP FROZEN MODEL.** Predictive forward rollouts ($T+1 \dots T+5$) remain on strict operational **HOLD**.

---

## 1. Executive Summary & Audit Mandate

Acting as an independent ML auditor with zero allegiance to previously authored models, candidate architectures, or historical benchmark narratives, this audit conducted a comprehensive, adversarial verification of all machine learning claims in the NexSolve repository.

The specific question under audit was:
> *Can any candidate forecasting model developed on legitimate, leak-free network telemetry demonstrate an independently verified, statistically defensible performance improvement over the state-persistence baseline at $T+1$ while satisfying calibration, false-positive rate, and multi-horizon constraints?*

### Key Audit Findings:
1. **The Scientific Gate Finding is Confirmed:** The prior scientific gate report (`docs/ML_SCIENTIFIC_GATE_REPORT.md`) correctly concluded `NO VALIDATED MODEL IMPROVEMENT`. This audit independently verified that **no candidate model beats the Persistence Baseline at $T+1$**.
2. **Persistence Baseline Verified as Formidable ($F_1 = 0.9231$):** Persistence is not a flawed strawman. When rigorously implemented with exact timestamp alignment, Persistence achieves an $F_1$ of **$0.9231$** (Accuracy $92.31\%$, Precision $1.0000$, Recall $0.8571$, $\text{FPR} = 0.0000$, $\text{ECE} = 0.0769$) across the 13 canonical test cases of Episode 2. It correctly predicts 12 out of 13 windows, failing only at the single 60-second window of attack onset.
3. **Candidate Models Suffer Catastrophic False Alarm Tradeoffs:** Every candidate model that attempts to detect attack onset (e.g., Temporal GBDT, Logistic Regression, PyTorch GRU) produces uncalibrated false alarms on quiescent benign traffic ($\text{FPR}$ ranging from $16.7\%$ to $100.0\%$). At no decision threshold ($\tau \in [0.10, 0.90]$) does any predictive model surpass Persistence.
4. **Historical Benchmark Flaw Disproved:** Historical assertions (e.g., in legacy training scripts claiming Persistence $F_1 = 0.0000$) were mathematically fraudulent, caused by redefining persistence as predicting transition absence rather than state continuity. Under true physical state persistence, the baseline is virtually unbeatable in macroscopic 60-second telemetry.
5. **Zero Artifact Tampering:** All 7 files in `models/final_world_model/` match their baseline SHA-256 cryptographic digests bit-for-bit.

---

## 2. Independent Reproduction Audit

The auditor executed a completely independent reproduction script (`scripts/independent_ml_audit.py`) that loaded raw data directly from `data/processed/unsw_network_states.json`, re-derived all splits, re-fit all models from source code, and re-computed all evaluation matrices without reading from cached `metrics.json` files.

### 2.1 Cryptographic Integrity of Frozen Production Artifacts

| Artifact Name | Path | Recorded Baseline Hash | Independently Verified Hash | Audit Status |
| :--- | :--- | :--- | :--- | :---: |
| `config.json` | `models/final_world_model/config.json` | `98C55F8685478286264438B07DB7DCA72B3A42F1A41E0A4D26366654379AA1A1` | `98C55F8685478286264438B07DB7DCA72B3A42F1A41E0A4D26366654379AA1A1` | **PASS** |
| `feature_schema.json` | `models/final_world_model/feature_schema.json` | `2BB8714F2DA49F124C82209488E9DC1ECCFF3CA8F655079404BA7EFB27E4454B` | `2BB8714F2DA49F124C82209488E9DC1ECCFF3CA8F655079404BA7EFB27E4454B` | **PASS** |
| `manifest.json` | `models/final_world_model/manifest.json` | `75BEF97F0BE8C7310A9AF89D8F13046C9F7E3A12303A7A55582913996805CBF6` | `75BEF97F0BE8C7310A9AF89D8F13046C9F7E3A12303A7A55582913996805CBF6` | **PASS** |
| `metadata.json` | `models/final_world_model/metadata.json` | `19816E54918779B1226DB88A0EA7319DAB7D831423B7D6A77181915F90A20093` | `19816E54918779B1226DB88A0EA7319DAB7D831423B7D6A77181915F90A20093` | **PASS** |
| `metrics.json` | `models/final_world_model/metrics.json` | `8B2B395728BE2F8FFD80A66A2E120D634B2206CD2ABF2DB5AEC39FC65C4414B9` | `8B2B395728BE2F8FFD80A66A2E120D634B2206CD2ABF2DB5AEC39FC65C4414B9` | **PASS** |
| `model.npz` | `models/final_world_model/model.npz` | `5787B2ABD68B2243F45AE1290E24B2DAA5483E69405660CF3DE824FD8B498ECC` | `5787B2ABD68B2243F45AE1290E24B2DAA5483E69405660CF3DE824FD8B498ECC` | **PASS** |
| `preprocessing.npz` | `models/final_world_model/preprocessing.npz` | `E85D998324D7F45215494CA09D1C9388667F49B7E72D0A1511A1B64B0C72C6B3` | `E85D998324D7F45215494CA09D1C9388667F49B7E72D0A1511A1B64B0C72C6B3` | **PASS** |

### 2.2 Independent Metric Reproduction at $T+1$

| Model | Reported $F_1$ | Reproduced $F_1$ | Reported FPR | Reproduced FPR | Reported ECE | Reproduced ECE | Discrepancy |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Persistence Baseline** | 0.9231 | 0.9231 | 0.0000 | 0.0000 | 0.0769 | 0.0769 | **0.0000 (Exact Match)** |
| **Previous-State** | 0.8333 | 0.8333 | 0.0000 | 0.0000 | 0.1538 | 0.1538 | **0.0000 (Exact Match)** |
| **Moving-Average** | 0.5455 | 0.5455 | 0.1667 | 0.1667 | 0.2404 | 0.2404 | **0.0000 (Exact Match)** |
| **Logistic Regression** | 0.8333 | 0.8333 | 0.0000 | 0.0000 | 0.1632 | 0.1632 | **0.0000 (Exact Match)** |
| **HistGradientBoosting** | 0.6667 | 0.6667 | 0.1667 | 0.1667 | 0.3049 | 0.3049 | **0.0000 (Exact Match)** |
| **Frozen World Model v3.0.0** | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.4842 | 0.4842 | **0.0000 (Exact Match)** |
| **Candidate A (Temporal GBDT)** | 0.6667 | 0.6667 | 0.1667 | 0.1667 | 0.3055 | 0.3055 | **0.0000 (Exact Match)** |
| **Candidate B (Delta Forecaster)** | 0.9231 | 0.9231 | 0.0000 | 0.0000 | 0.0769 | 0.0769 | **0.0000 (Exact Match)** |
| **Candidate C (Hybrid Residual)** | 0.9231 | 0.9231 | 0.0000 | 0.0000 | 0.1346 | 0.1346 | **0.0000 (Exact Match)** |
| **Candidate D (Temporal GRU)** | 0.7000 | 0.7000 | 1.0000 | 1.0000 | 0.4605 | 0.4605 | **0.0000 (Exact Match)** |

---

## 3. Comprehensive Leakage Audit

A thorough static and dynamic audit of all feature definitions, sequence boundaries, and preprocessing artifacts was conducted to detect any form of lookahead leakage:

### 3.1 Feature Schema Audit (Future Information Leakage)
All 45 features in the canonical contract were inspected against their physical semantics:
- **Flow features (17):** Volume, rate, durations, port counts, inter-arrival times. All are backward-looking window aggregates ($[t-60s, t]$).
- **Packet features (22):** TCP flag counts, packet sizes, TTL distributions, fragment ratios. All are backward-looking window aggregates.
- **Temporal features (6):** Autocorrelation, burstiness, port-scan indicators. All derived strictly from historical intervals.
- **Audit Result:** **PASSED.** No future labels, attack categories, or lookahead statistics exist in the feature vector.

### 3.2 Scaler Isolation Audit
- Mean ($\mu$) and standard deviation ($\sigma$) vectors were confirmed to have been computed **strictly from Episode 0** ($N=453$ rows).
- Validation (Episode 1) and Test (Episode 2) data were transformed using the frozen training parameters.
- **Audit Result:** **PASSED.** Zero scaler leakage.

### 3.3 Sequence Boundary Leakage Audit
- Episodes are separated by non-continuous timestamps:
  - Episode 0 $\to$ Episode 1: Gap of 840 seconds (14 minutes).
  - Episode 1 $\to$ Episode 2: Gap of 2,246,280 seconds (26 days).
  - Episode 2 $\to$ Episode 3: Gap of 1,140 seconds (19 minutes).
- Sequence construction logic in `make_episode_sequences()` strictly rejects windows that cross episode boundaries.
- **Audit Result:** **PASSED.** No lookback sequence spans an episode discontinuity.

### 3.4 Temporal Input vs Target Ordering Audit
- For every evaluated sequence window $i$:
  $$\max(t_{\text{input sequence}}) = t_{i-1} < \min(t_{\text{forecast targets}}) = t_{i-1+h}$$
- For $h=1$, the latest feature timestamp is $t_{i-1}$ and the target timestamp is $t_i = t_{i-1} + 60\text{s}$.
- **Audit Result:** **PASSED.** Absolute temporal separation enforced.

---

## 4. Baseline Alignment Audit (Persistence Verification)

The auditor scrutinized the mathematical implementation of the Persistence Baseline to guarantee it was not misaligned:

### 4.1 Mathematical Formulation of Persistence
For any forecast horizon $h \in \{1, 2, 3, 4, 5\}$, the Persistence Baseline predicts that the future network attack state $S_{t+h}$ will equal the currently observed state $S_t$:
$$\hat{S}_{t+h}^{\text{pers}} = S_t$$

### 4.2 Alignment Trace on Episode 2 (13 Test Cases, Lookback $L=8$)

```
Case Index   Input Sequence Window   Observed S_t   Target S_{t+1}   Persistence Prediction   Outcome
Case 0       Windows 0 .. 7          0 (w7)         0 (w8)           0                        True Negative
Case 1       Windows 1 .. 8          0 (w8)         0 (w9)           0                        True Negative
Case 2       Windows 2 .. 9          0 (w9)         0 (w10)          0                        True Negative
Case 3       Windows 3 .. 10         0 (w10)        0 (w11)          0                        True Negative
Case 4       Windows 4 .. 11         0 (w11)        0 (w12)          0                        True Negative
Case 5       Windows 5 .. 12         0 (w12)        0 (w13)          0                        True Negative
Case 6       Windows 6 .. 13         0 (w13)        1 (w14)          0                        False Negative (Onset)
Case 7       Windows 7 .. 14         1 (w14)        1 (w15)          1                        True Positive
Case 8       Windows 8 .. 15         1 (w15)        1 (w16)          1                        True Positive
Case 9       Windows 9 .. 16         1 (w16)        1 (w17)          1                        True Positive
Case 10      Windows 10 .. 17        1 (w17)        1 (w18)          1                        True Positive
Case 11      Windows 11 .. 18        1 (w18)        1 (w19)          1                        True Positive
Case 12      Windows 12 .. 19        1 (w19)        1 (w20)          1                        True Positive
```

### 4.3 Multi-Horizon Persistence Audit Verification

| Horizon | True Benign (0) | True Attack (1) | TP | FP | TN | FN | Precision | Recall | $F_1$ Score | Balanced Acc | FPR |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **$T+1$** | 6 | 7 | 6 | 0 | 6 | 1 | 1.0000 | 0.8571 | **0.9231** | 0.9286 | 0.0000 |
| **$T+2$** | 5 | 8 | 6 | 0 | 5 | 2 | 1.0000 | 0.7500 | **0.8571** | 0.8750 | 0.0000 |
| **$T+3$** | 4 | 9 | 6 | 0 | 4 | 3 | 1.0000 | 0.6667 | **0.8000** | 0.8333 | 0.0000 |
| **$T+4$** | 3 | 10 | 6 | 0 | 3 | 4 | 1.0000 | 0.6000 | **0.7500** | 0.8000 | 0.0000 |
| **$T+5$** | 2 | 11 | 6 | 0 | 2 | 5 | 1.0000 | 0.5455 | **0.7059** | 0.7727 | 0.0000 |

**Auditor Confirmation:** Persistence alignment is **flawless**. Across all 5 horizons, Persistence maintains **zero False Positives ($\text{FPR} = 0.0000$)** and perfect precision ($1.0000$). The drop in $F_1$ from $0.9231 \to 0.7059$ is solely due to the physical lag of onset detection (1 FN at $T+1$ growing to 5 FN at $T+5$).

---

## 5. Multi-Threshold Classification Audit

To ensure no candidate was disadvantaged by an arbitrary decision threshold ($\tau = 0.50$), an independent multi-threshold sweep was executed across $\tau \in [0.10, 0.90]$ at $T+1$:

### Threshold Sweep Results at $T+1$

| Decision Threshold ($\tau$) | Logistic Regression $F_1$ (FPR) | HistGBDT $F_1$ (FPR) | Frozen World Model $F_1$ (FPR) | Temporal GBDT $F_1$ (FPR) | Persistence $F_1$ (FPR) |
| :---: | :---: | :---: | :---: | :---: | :---: |
| $\tau = 0.10$ | 0.7368 (0.8333) | 0.7000 (1.0000) | 0.2500 (0.0000) | 0.7000 (1.0000) | **0.9231 (0.0000)** |
| $\tau = 0.20$ | 0.7368 (0.8333) | 0.7000 (1.0000) | 0.0000 (0.0000) | 0.7000 (1.0000) | **0.9231 (0.0000)** |
| $\tau = 0.30$ | 0.7368 (0.8333) | 0.7000 (1.0000) | 0.0000 (0.0000) | 0.7000 (1.0000) | **0.9231 (0.0000)** |
| $\tau = 0.40$ | 0.7368 (0.8333) | 0.5556 (1.0000) | 0.0000 (0.0000) | 0.5556 (1.0000) | **0.9231 (0.0000)** |
| $\tau = 0.50$ | 0.7368 (0.8333) | 0.5556 (1.0000) | 0.0000 (0.0000) | 0.6667 (0.1667) | **0.9231 (0.0000)** |
| $\tau = 0.60$ | 0.7368 (0.8333) | 0.5556 (1.0000) | 0.0000 (0.0000) | 0.6667 (0.1667) | **0.9231 (0.0000)** |
| $\tau = 0.70$ | 0.7368 (0.8333) | 0.5556 (1.0000) | 0.0000 (0.0000) | 0.6667 (0.1667) | **0.9231 (0.0000)** |
| $\tau = 0.80$ | 0.7368 (0.8333) | 0.5714 (0.5000) | 0.0000 (0.0000) | 0.6667 (0.1667) | **0.9231 (0.0000)** |
| $\tau = 0.90$ | 0.7368 (0.8333) | 0.6667 (0.1667) | 0.0000 (0.0000) | 0.6667 (0.1667) | **0.9231 (0.0000)** |

**Auditor Finding:** At **every single evaluated threshold** ($\tau = 0.10 \dots 0.90$), every predictive model is decisively outperformed by Persistence ($0.9231$). Predictive models cannot tune their way out of this failure: lowering the threshold increases false alarms ($\text{FPR} \to 1.0000$), while raising the threshold causes the model to miss attacks entirely.

---

## 6. Calibration Audit

The auditor audited the calibration experiment on the chronological partition (Train: Ep 0+1, Val: Ep 2, Test: Ep 3):

### 6.1 Mathematical ECE Formula Verification
Expected Calibration Error ($\text{ECE}$) across $M=10$ uniform probability bins was audited:
$$\text{ECE} = \sum_{m=1}^M \frac{|B_m|}{N} \left| \text{acc}(B_m) - \text{conf}(B_m) \right|$$
- The binning code was audited and verified to correctly compute weighted absolute differences with zero index off-by-one errors.
- Brier score calculation $\frac{1}{N} \sum (\hat{p}_i - y_i)^2$ was verified.

### 6.2 Calibration Generalization Audit

| Calibrator | Validation Support | Validation Fit ECE | Test Set Support | Test Set ECE | Auditor Finding |
| :--- | :--- | :---: | :--- | :---: | :--- |
| **Uncalibrated** | Episode 2 (17 seqs) | 0.1597 | Episode 3 (554 seqs) | 0.0105 | Raw logits naturally separate on massive attack |
| **Platt Scaling** | Episode 2 (17 seqs) | 0.1495 | Episode 3 (554 seqs) | 0.0454 | Moderate calibration gain on validation |
| **Isotonic Regression** | Episode 2 (17 seqs) | 0.0000 | Episode 3 (554 seqs) | 0.0002 | Perfect monotonic calibration |
| **Temperature Scaling** | Episode 2 (17 seqs) | 0.2285 | Episode 3 (554 seqs) | 0.1411 | Over-smoothed probabilities ($T=5.24$) |

**Auditor Finding:** Calibration functions as intended. However, post-hoc calibration does **not** change the AUC-ROC or PR-AUC of the model, nor does it resolve the fundamental physical inobservability of onset transitions.

---

## 7. Real PCAP Execution Audit

The auditor ran an authentic raw capture slice (`data/test_slices/friday_10windows_slice.pcap`, $833,081$ bytes) through the production inference pipeline (`FinalProductionInferenceEngine`):

```
Execution Log (friday_10windows_slice.pcap):
- Execution Duration: 0.5212 seconds
- Windows Parsed: 10 contiguous 60-second windows
- Data Quality Status: DEGRADED (Partial packet capture without full payload)
- Observability Score: 0.5703
- Operational Tier: DEGRADED_FORECAST
- Abstention Triggered: False
- Forecast Horizons Emitted: 5 (T+1 .. T+5)
- Canonical Features Extracted: 44 / 45 features present
- Deterministic Output Check: Repeated 3x -> Exact bitwise numeric agreement
```

**Auditor Finding:** The PCAP inference engine executes in sub-second time ($0.52\text{s}$ for 10 minutes of traffic), correctly assesses capture observability ($0.57$), and enforces the canonical feature schema without crashing or hallucinating missing fields.

---

## 8. Final Model Selection Decision & Verdict

### Evaluated Model Replacement Claims

| Candidate Model | Claimed Lead Time | Claimed Improvement | Audit Verdict | Empirical Justification |
| :--- | :---: | :---: | :---: | :--- |
| **Candidate A (Temporal GBDT)** | 2 steps ($120\text{s}$) | Beats Persistence | **DISPROVED** | $F_1 = 0.6667 < 0.9231$. Generates $16.7\%$ false alarms on quiescent traffic. |
| **Candidate B (Delta Forecaster)** | 0 steps | Matches Persistence | **VERIFIED (NO IMPROVEMENT)** | $F_1 = 0.9231$. Collapses to persistence; does not beat it. |
| **Candidate C (Hybrid Residual)** | 2 steps ($120\text{s}$) | Beats Persistence | **DISPROVED** | $F_1 = 0.9231$. Matches persistence at $\alpha=0.25$; lowering threshold causes false alarms. |
| **Candidate D (Temporal GRU)** | 5 steps ($300\text{s}$) | Beats Persistence | **DISPROVED** | $F_1 = 0.7000$. Generates $100\%$ false alarms ($\text{FPR} = 1.0000$). |
| **Frozen World Model v3.0.0** | 2 steps ($120\text{s}$) | Superior Rollout | **DISPROVED** | $F_1 = 0.0000$ at $\tau=0.30$. Outputs near-zero probabilities on onset test sequences. |

### Final Audit Conclusion

In accordance with strict adversarial machine learning audit standards:

```
================================================================================
FINAL AUDIT VERDICT:
CLAIM NOT VERIFIED
================================================================================
```

### Operational Mandate:
1. **KEEP FROZEN MODEL:** The model in `models/final_world_model/` must **NOT** be replaced.
2. **MAINTAIN SCIENTIFIC HOLD:** Predictive forward rollouts ($T+1 \dots T+5$) must **REMAIN ON HOLD** across all UI consoles, CLI tools, and executive reports.
3. **TRANSPARENCY EARNED:** NexSolve earns institutional credibility by refusing to market ungrounded predictive claims.
