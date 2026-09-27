# NexSolve: Next-Generation Forecasting Scientific Revalidation Results (v2.0)

**Evaluation Date:** September 2026  
**Experimental Status:** SCIENTIFIC REVALIDATION CONCLUDED  
**Zero-Leakage Revalidation Script:** [experiments/next_generation_forecasting_v2/run_revalidation.py](file:///c:/Users/saira/OneDrive/Desktop/NexSolve-Research/experiments/next_generation_forecasting_v2/run_revalidation.py)  
**Master Results Dataset:** [experiments/next_generation_forecasting_v2/revalidation_results.json](file:///c:/Users/saira/OneDrive/Desktop/NexSolve-Research/experiments/next_generation_forecasting_v2/revalidation_results.json)  
**Independent Audit Execution:** [scripts/audit_next_gen_forecasting_v2.py](file:///c:/Users/saira/OneDrive/Desktop/NexSolve-Research/scripts/audit_next_gen_forecasting_v2.py)  
**Final Scientific Verdict:** `RESEARCH CANDIDATE — NOT YET VERIFIED`  

---

## 1. Executive Summary & Contrast with Leaked Baseline

This evaluation completely replaces the preliminary next-generation forecasting claims. All test-snooped heuristic rules (`flow_count >= 20/30`, `dst_bytes == 0`, `asymmetry >= 0.8`, `memory span = 4`, `hazard decay alpha = 0.3`, and hardcoded `3 - steps_ago`) were completely expunged.

Under a strictly causal, leak-free protocol:
1. **The $F_1 = 1.0000$ Myth Disproven**: The previous claim of $F_1 = 1.0000$ across $T+1 \dots T+3$ was entirely an artifact of hardcoding the exact 3-minute gap from Episode 2. Under clean revalidation, the candidate forecaster matches persistence at $T+1$ ($F_1 = 0.9231$) and $T+2$ ($F_1 = 0.8571$), and **surpasses persistence at $T+3$ ($F_1 = 0.8750$, $\text{FVP} = \mathbf{+0.0750}$)**, $T+4$ ($\text{FVP} = \mathbf{+0.0735}$), and $T+5$ ($\text{FVP} = \mathbf{+0.0719}$).
2. **True Early-Warning Capability**: At Window 11 ($t=1424219640$), the causal change-point model detects a genuine physical surge ($zscore\_flows = +2.64$), providing **$180.0\text{ seconds}$ (3.0 minutes) advance lead time** prior to the weaponized attack onset at Window 14 ($t=1424219820$). On the primary onset target, it achieves $F_1 = 0.5000$ with **$100.0\%$ Precision** and **$0.0\%$ False Positive Rate** on the quiet baseline.
3. **Immediate Pre-Onset Blindness**: Because the probe was a transient 1-window burst followed by a 2-minute quiet pause ($w_{12}, w_{13}$ had only 4 and 7 flows), an un-leaked causal forecaster without test-fitted memory decay misses the onset at $T+1$ and $T+2$.
4. **Low-Data Vulnerability Revealed**: Supervised models trained on $\le 25\%$ of training data collapse to $F_1 = 0.0000$ because the early training slice lacks sufficient benign samples to establish a normal baseline. The previous claim of $F_1 = 1.0000$ at $5\%$ data is mathematically refuted.
5. **Limited-Event Generalization**: Because the entire UNSW-NB15 processed corpus contains only **one** test attack onset event, multi-event generalizability cannot be established. In strict adherence to the promotion gate, the model **cannot be promoted to production**.

---

## 2. Primary Research Target: Attack Onset Forecasting

### 2.1 Target Definition
$$\mathbf{P(attack\ onset\ occurs\ within\ T+h \mid attack\_state_t = 0), \quad h \in \{1, 2, 3, 4, 5\}}$$

Evaluated across the 10 contiguous benign windows in Episode 2 ($t=4 \dots 13$):
- $T+1$: Positive case at $t=13$ ($1 / 10$ positive).
- $T+2$: Positive cases at $t \in \{12, 13\}$ ($2 / 10$ positive).
- $T+3$: Positive cases at $t \in \{11, 12, 13\}$ ($3 / 10$ positive).
- $T+4$: Positive cases at $t \in \{10, 11, 12, 13\}$ ($4 / 10$ positive).
- $T+5$: Positive cases at $t \in \{9, 10, 11, 12, 13\}$ ($5 / 10$ positive).

### 2.2 Comprehensive Onset Benchmark Table (All 9 Models)

| Model Family | Horizon | Precision | Recall | $F_1$ Score | Brier Score | ECE | Lead Time | Forecast Value over Persistence (FVP) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **1. Persistence Baseline** | $T+1$ | 0.0000 | 0.0000 | 0.0000 | 0.1000 | 0.1000 | 0s | 0.0000 |
| | $T+2$ | 0.0000 | 0.0000 | 0.0000 | 0.2000 | 0.2000 | 0s | 0.0000 |
| | $T+3$ | 0.0000 | 0.0000 | 0.0000 | 0.3000 | 0.3000 | 0s | 0.0000 |
| | $T+4$ | 0.0000 | 0.0000 | 0.0000 | 0.4000 | 0.4000 | 0s | 0.0000 |
| | $T+5$ | 0.0000 | 0.0000 | 0.0000 | 0.5000 | 0.5000 | 0s | 0.0000 |
| **2. Always-Benign** | $T+1 \dots T+5$ | 0.0000 | 0.0000 | 0.0000 | $0.10 \dots 0.50$ | $0.10 \dots 0.50$ | 0s | 0.0000 |
| **3. Historical Prior** ($\pi=0.003$) | $T+1 \dots T+5$ | 0.0000 | 0.0000 | 0.0000 | $0.099 \dots 0.497$ | $0.097 \dots 0.497$ | 0s | 0.0000 |
| **4. Logistic Regression** | $T+1$ | 0.1111 | 1.0000 | 0.2000 | 0.8000 | 0.8064 | 180s | +0.2000 |
| | $T+2$ | 0.2222 | 1.0000 | 0.3636 | 0.6999 | 0.7054 | 180s | +0.3636 |
| | $T+3$ | 0.2222 | 0.6667 | 0.3333 | 0.7892 | 0.7943 | 180s | +0.3333 |
| | $T+4$ | 0.3333 | 0.7500 | 0.4615 | 0.6873 | 0.6931 | 180s | +0.4615 |
| | $T+5$ | 0.4444 | 0.8000 | 0.5714 | 0.5855 | 0.5922 | 180s | +0.5714 |
| **5. HistGBDT** | $T+1$ | 0.1000 | 1.0000 | 0.1818 | 0.8646 | 0.8806 | 180s | +0.1818 |
| | $T+2$ | 0.2000 | 1.0000 | 0.3333 | 0.7647 | 0.7792 | 180s | +0.3333 |
| | $T+3$ | 0.3000 | 1.0000 | 0.4615 | 0.6831 | 0.6790 | 180s | +0.4615 |
| | $T+4$ | 0.4000 | 1.0000 | 0.5714 | 0.5849 | 0.5789 | 180s | +0.5714 |
| | $T+5$ | 0.5000 | 1.0000 | 0.6667 | 0.4875 | 0.4788 | 180s | +0.6667 |
| **6. PyTorch Temporal GRU** | $T+1$ | 0.1000 | 1.0000 | 0.1818 | 0.8924 | 0.8955 | 180s | +0.1818 |
| | $T+3$ | 0.3000 | 1.0000 | 0.4615 | 0.6951 | 0.6955 | 180s | +0.4615 |
| | $T+5$ | 0.5000 | 1.0000 | 0.6667 | 0.4970 | 0.4954 | 180s | +0.6667 |
| **7. PyTorch Temporal LSTM** | $T+1$ | 0.1000 | 1.0000 | 0.1818 | 0.8668 | 0.8812 | 180s | +0.1818 |
| | $T+3$ | 0.3000 | 1.0000 | 0.4615 | 0.6867 | 0.6807 | 180s | +0.4615 |
| | $T+5$ | 0.5000 | 1.0000 | 0.6667 | 0.4920 | 0.4807 | 180s | +0.6667 |
| **8. Change-Point Hazard Model** | $T+1$ | 0.0000 | 0.0000 | 0.0000 | 0.1095 | 0.1360 | 0s | 0.0000 |
| | $T+2$ | 0.0000 | 0.0000 | 0.0000 | 0.1849 | 0.2115 | 0s | 0.0000 |
| | $T+3$ | 1.0000 | 0.3333 | 0.5000 | 0.1378 | 0.1554 | 180s | **+0.5000** |
| | $T+4$ | 1.0000 | 0.2500 | 0.4000 | 0.2085 | 0.2256 | 180s | **+0.4000** |
| | $T+5$ | 1.0000 | 0.2000 | 0.3333 | 0.2791 | 0.3005 | 180s | **+0.3333** |
| **9. Clean Hybrid Forecaster** | $T+1$ | 0.0000 | 0.0000 | 0.0000 | 0.1703 | 0.1760 | 0s | 0.0000 |
| | $T+2$ | 0.0000 | 0.0000 | 0.0000 | 0.2683 | 0.2760 | 0s | 0.0000 |
| | **$T+3$** | **1.0000** | **0.3333** | **0.5000** | **0.1983** | **0.2060** | **180s** | **+0.5000** |
| | **$T+4$** | **1.0000** | **0.2500** | **0.4000** | **0.2963** | **0.3060** | **180s** | **+0.4000** |
| | **$T+5$** | **1.0000** | **0.2000** | **0.3333** | **0.3943** | **0.4060** | **180s** | **+0.3333** |

### 2.3 Scientific Insights on the Onset Target
1. **The Supervised Failure**: Supervised ML models (Logistic Regression, HistGBDT, GRU, LSTM) trained on Train (Episode 0) achieved high recall ($1.0000$) only by predicting positive on almost every benign window. Their Precision is abysmal ($0.10 \dots 0.33$) and Brier scores are unacceptable ($0.68 \dots 0.89$), proving that supervised classifiers overfit to the single onset window in Episode 0.
2. **The Change-Point / Hybrid Victory**: The Clean Hybrid Precursor model and Change-Point Hazard model achieve **$100.0\%$ Precision** with **$0.0\%$ False Positive Rate** on quiet network telemetry. When Window 11 surges to $zscore\_flows = 2.64$, it triggers an advance warning for $h \ge 3$, securing an advance lead time of $180\text{ seconds}$ and outperforming Persistence by $\text{FVP} = \mathbf{+0.5000}$ at $T+3$.
3. **The Immediate Onset Gap**: At $T+1$ and $T+2$, because the attacker went silent during $w_{12}$ and $w_{13}$ ($flows = 4$ and $7$), no instantaneous anomaly was present in those two windows. Without test-snooped temporal offsets, the model correctly remained silent, yielding Recall = $0.0000$ at those immediate horizons.

---

## 3. Secondary Benchmark: Full State Forecasting ($S_{t+h}$)

Evaluated across the 13 standard test sequences in Episode 2 ($t=7 \dots 19$):

| Horizon | Baseline Persistence ($F_1$ / Rec / Prec / FPR) | Clean Hybrid Forecaster ($F_1$ / Rec / Prec / FPR) | Net FVP Gain ($\Delta F_1$) | Status |
| :---: | :---: | :---: | :---: | :---: |
| **$T+1$** | **0.9231** / 0.8571 / 1.0000 / 0.0000 | **0.9231** / 0.8571 / 1.0000 / 0.0000 | **+0.0000** | Matches Persistence |
| **$T+2$** | **0.8571** / 0.7500 / 1.0000 / 0.0000 | **0.8571** / 0.7500 / 1.0000 / 0.0000 | **+0.0000** | Matches Persistence |
| **$T+3$** | 0.8000 / 0.6667 / 1.0000 / 0.0000 | **0.8750** / **0.7778** / 1.0000 / 0.0000 | **+0.0750** | **Beats Persistence** |
| **$T+4$** | 0.7500 / 0.6000 / 1.0000 / 0.0000 | **0.8235** / **0.7000** / 1.0000 / 0.0000 | **+0.0735** | **Beats Persistence** |
| **$T+5$** | 0.7059 / 0.5455 / 1.0000 / 0.0000 | **0.7778** / **0.6364** / 1.0000 / 0.0000 | **+0.0719** | **Beats Persistence** |

### 3.1 Side-by-Side Comparison: Leaked vs Revalidated

```
========================================================================================
HORIZON    PERSISTENCE F1     PRELIMINARY LEAKED F1     REVALIDATED ZERO-LEAKAGE F1
========================================================================================
T+1           0.9231                1.0000 (Leaked)              0.9231 (FVP: +0.0000)
T+2           0.8571                1.0000 (Leaked)              0.8571 (FVP: +0.0000)
T+3           0.8000                1.0000 (Leaked)              0.8750 (FVP: +0.0750)
T+4           0.7500                0.9474 (Leaked)              0.8235 (FVP: +0.0735)
T+5           0.7059                0.9000 (Leaked)              0.7778 (FVP: +0.0719)
========================================================================================
```

---

## 4. Probability Calibration Audit

Calibration was fit strictly on Validation (Episode 1: 291 benign states) and evaluated on Test at $T+3$:
- **Validation Sample Count**: $N_{\text{val}} = 291$ (100% benign baseline).
- **Test Sample Count**: $N_{\text{test}} = 13$ sequences.
- **Raw Expected Calibration Error (ECE)**: $0.1654$ (Brier: $0.1498$).
- **Platt Calibrated ECE**: $0.4879$ (Brier: $0.3686$).
- **Isotonic Calibrated ECE**: $0.2923$ (Brier: $0.2390$).

### 4.1 Forensic Calibration Diagnosis
Because Validation contained exclusively benign windows ($y=0$), fitting post-hoc calibration models (Platt or Isotonic) pulled predicted probabilities downward toward $0$. When evaluated on Test (which contains 7 attack windows), this downward probability shift increased calibration error on positive attack states, resulting in calibrated $\text{ECE} > 0.10$. Post-hoc calibration fails Gate 8.

---

## 5. Low-Data Regime Stress Testing

Testing across $100\%, 50\%, 25\%, 10\%, 5\%$ of the Train partition (Episode 0):

| Data Fraction | Total Train States | Benign States | Attack States | Supervised LR $F_1$ | Clean Hybrid $F_1$ ($T+3$) | Status | Earlier $F_1=1.0$ Reproduced? |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **100%** | 453 | 335 | 118 | 0.8696 | 0.8750 | SUFFICIENT | No ($0.8750$) |
| **50%** | 226 | 108 | 118 | 0.8696 | 0.8750 | SUFFICIENT | No ($0.8750$) |
| **25%** | 113 | 1 | 112 | 0.0000 | 0.8750 | INSUFFICIENT BENIGN | **Refuted** ($0.0000$) |
| **10%** | 45 | 1 | 44 | 0.0000 | 0.8750 | INSUFFICIENT BENIGN | **Refuted** ($0.0000$) |
| **5%** | 22 | 1 | 21 | 0.0000 | 0.8750 | INSUFFICIENT BENIGN | **Refuted** ($0.0000$) |

### 5.1 Forensic Finding on Low-Data Claims
In Episode 0, attack traffic dominates the first 118 windows. When Train is sliced at $25\%$ ($113$ states) or $5\%$ ($22$ states), the training slice contains **only one single benign window** ($t=0$). Any supervised classifier trained on this data receives 99% attack samples and completely fails to learn benign traffic patterns ($F_1 = 0.0000$). The earlier claim of $F_1 = 1.0000$ at $5\%$ data was 100% caused by applying a static, test-snooped heuristic directly to the test set without training.

---

## 6. Real PCAP Execution Audit

The clean candidate engine was evaluated against the physical PCAP slice:
- **PCAP File**: `data/test_slices/friday_10windows_slice.pcap`
- **File Size**: $833,081\text{ bytes}$
- **Execution Time**: $0.5411\text{ seconds}$
- **Pipeline Status**: `FORECAST_AVAILABLE`
- **Extracted Feature Count**: $44\text{ canonical features}$
- **Selective Abstention**: Not abstained (`is_abstained = False`)
- **Crash-Free Execution**: **VERIFIED**

---

## 7. Statistical Caution & Multi-Event Generalization

- **Evaluated Test Sequences**: $N = 13$
- **Evaluated Benign Windows**: $N_{\text{benign}} = 10$
- **Independent Attack Onset Events**: **$N = 1$** (Episode 2, $w_{13} \to w_{14}$)
- **Wilson Score 95% Confidence Interval for Onset Recall at $T+3$**:
  $$p = \frac{1}{3} \implies \mathbf{95\%\ CI = [0.0615, 0.7923]}$$

Because the sample size of independent attack onsets in the held-out test data is $N=1$, statistical confidence intervals are wide. Describing single-sequence performance as definitive proof of general capability is scientifically unwarranted.

---

## 8. Final 10-Point Model Promotion Gate Evaluation

| Gate # | Promotion Criterion | Evaluation Result | Verdict |
| :---: | :--- | :--- | :---: |
| **Gate 1** | Frozen production model SHA-256 intact | All 7 files match baseline digests | **PASS** |
| **Gate 2** | Zero test leakage in rules/thresholds | Expunged all Episode 2 test heuristics | **PASS** |
| **Gate 3** | Beats persistence on defined targets | $\text{FVP} = +0.0750$ ($T+3$), $\text{FVP} = +0.5000$ (Onset) | **PASS** |
| **Gate 4** | Independent reproduction verified | Reproduced by `audit_next_gen_forecasting_v2.py` | **PASS** |
| **Gate 5** | Multi-event generalization across episodes | Only 1 attack onset event exists in test corpus | **FAIL** |
| **Gate 6** | Operational FPR $\le 5.0\%$ | Validation $\text{FPR} = 2.41\% \le 5.0\%$ | **PASS** |
| **Gate 7** | Advance lead time $\ge 60\text{s}$ | $+180.0\text{ seconds}$ verified lead time | **PASS** |
| **Gate 8** | Validated calibration ($\text{ECE} \le 0.10$) | $\text{ECE} = 0.1654 > 0.10$ due to validation skew | **FAIL** |
| **Gate 9** | Low-data robustness validated | Refuted earlier leakage artifact; true limits mapped | **PASS** |
| **Gate 10** | Production safety preserved | Zero production files or services modified | **PASS** |

### Definitive Promotion Decision
$$\mathbf{\text{FINAL VERDICT: RESEARCH CANDIDATE — NOT YET VERIFIED}}$$
$$\mathbf{\text{OPERATIONAL ACTION: RETAIN FROZEN PRODUCTION MODEL (models/final_world_model/)}}$$

The candidate model demonstrates genuine precursor detection and beats persistence at $T+3 \dots T+5$, but fails Gates 5 and 8. It remains preserved in [`models/research_candidates/next_gen_v2/`](file:///c:/Users/saira/OneDrive/Desktop/NexSolve-Research/models/research_candidates/next_gen_v2/) for future multi-capture research.
