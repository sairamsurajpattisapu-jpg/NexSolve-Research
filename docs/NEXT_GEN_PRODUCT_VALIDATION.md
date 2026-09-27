# NexSolve Next-Gen Forecasting Engine: Real Product Validation Report

**Execution Timestamp:** 2026-09-27 06:25:26 UTC  
**Evaluation Pipeline:** End-to-End Product Pipeline (`ingestion` -> `flow_reconstruction` -> `windowing` -> `feature_extraction` -> `central_gate` -> `reporting`)  
**Forecasting Engine:** `NextGenResearchForecastEngine` (`models/research_candidates/next_gen_v2/`)  
**Operational Baseline:** `FrozenWorldModelForecastEngine` (`models/final_world_model/`)  
**Final Scientific Verdict:** **`NEXT-GEN RESEARCH VALIDATED BUT GENERALIZATION LIMITED`**  

---

## 1. Executive Summary & Promotion Adjudication

The Next-Generation Causal Precursor Forecaster was evaluated strictly through the **live NexSolve product pipeline** across nine diverse capture scenarios, including multi-window attack captures, quiet baselines, short captures, malformed files, temporal discontinuities, PCAPNG containers, and varied protocol distributions.

### Key Scientific Determinations:
1. **Zero Test Contamination Verified:** The $z_{\text{flows}} \ge 2.20$ change-point threshold was selected strictly from the 97.5th percentile of Episode 1 (Validation partition, 291 contiguous benign windows) and frozen prior to test evaluation. No test data from Episode 2 influenced threshold or parameter selection.
2. **Real Pipeline Lead Time Demonstrated:** On the held-out test sequence, the research engine successfully triggers an advance early warning at Window 11, delivering **+180 seconds advance lead time** prior to attack manifestation at Window 14, yielding an Onset $F_1$ gain of $+0.0750$ over Persistence at $T+3$.
3. **Zero Fake Forecasts / Strict Abstention Contract:** On captures with insufficient history ($< 8$ windows) or non-contiguous timestamp gaps ($> 300$s), the engine cleanly abstains (`status = FORECAST_ABSTAINED`). Forecast probabilities and predicted stages are withheld (`None`), and future progression states remain `UNKNOWN`.
4. **Generalization Constraint (N=1 Attack Transition):** An exhaustive census of all 1,441 network states reveals that the entire UNSW corpus contains only two attack onset transitions, meaning the held-out test partition contains **exactly one independent attack onset event ($N=1$)**.

> [!IMPORTANT]
> **GENERALIZATION NOT ESTABLISHED — SINGLE ATTACK TRANSITION**  
> Because the test data contains only $N=1$ attack transition, broad operational generalization across heterogeneous enterprise environments is not yet proven. The model is therefore designated as **NEXT-GEN RESEARCH VALIDATED BUT GENERALIZATION LIMITED** and will remain in research tier.

---

## 2. End-to-End PCAP Validation Matrix

Nine distinct capture cases were submitted directly to `model_service.pcap_upload.analyze_uploaded_capture` under research mode:

| Case ID | Capture Scenario | File | Runtime | Data Quality | Abstention Status | Forecast Availability | Horizon T+1..T+5 Summary |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :--- |
| **friday_10windows_slice** | Friday 10Windows Slice | `friday_10windows_slice.pcap` | 2.0554s | DEGRADED (Score: 1.0) | `abstained=False` | `True` | T+1: 0.02; T+2: 0.02; T+3: 0.02; T+4: 0.02; T+5: 0.02 |
| **benign_low_activity** | Benign Low Activity | `benign_low_activity.pcap` | 0.0389s | GOOD (Score: 1.0) | `abstained=True` | `False` | ABSTAINED (All P(Atk)=None, Stages=UNKNOWN) |
| **insufficient_history** | Insufficient History | `insufficient_history.pcap` | 0.0368s | DEGRADED (Score: 1.0) | `abstained=True` | `False` | ABSTAINED (All P(Atk)=None, Stages=UNKNOWN) |
| **malformed** | Malformed | `malformed.pcap` | 0.0015s | REJECTED (Invalid Magic/Header) | `abstained=True` | `False` | WITHHELD (Pipeline Rejected Malformed Input) |
| **non_contiguous** | Non Contiguous | `non_contiguous.pcap` | 0.0356s | DEGRADED (Score: 1.0) | `abstained=True` | `False` | ABSTAINED (All P(Atk)=None, Stages=UNKNOWN) |
| **pcapng** | Pcapng | `vlan-pcp-dei.pcapng` | 0.0329s | DEGRADED (Score: 1.0) | `abstained=True` | `False` | ABSTAINED (All P(Atk)=None, Stages=UNKNOWN) |
| **tcp_heavy** | Tcp Heavy | `tcp_heavy.pcap` | 0.3917s | DEGRADED (Score: 1.0) | `abstained=False` | `True` | T+1: 0.02; T+2: 0.02; T+3: 0.02; T+4: 0.02; T+5: 0.02 |
| **udp_heavy** | Udp Heavy | `udp_heavy.pcap` | 0.3287s | GOOD (Score: 1.0) | `abstained=True` | `False` | ABSTAINED (All P(Atk)=None, Stages=UNKNOWN) |
| **mixed_protocol** | Mixed Protocol | `mixed_protocol.pcap` | 0.3524s | DEGRADED (Score: 1.0) | `abstained=True` | `False` | ABSTAINED (All P(Atk)=None, Stages=UNKNOWN) |

### Detailed Case Observations:
#### Case: `friday_10windows_slice` (`friday_10windows_slice.pcap`)
- **Engine**: `Next-Gen Causal Precursor Forecaster` (next_gen_v2_revalidated (RESEARCH CANDIDATE))
- **Operational Tier**: `RESEARCH_UNVERIFIED`
- **Feature Availability**: `45 / 45`
- **Abstention Details**: `abstained=False` (Reason: `None`)
  - *Explanation*: Forecast is available and supported by lookback history, but model calibration is UNSUPPORTED. Raw scores should not be treated as calibrated probabilities.
- **Evidence & Diagnostics**: 10 items, Uncertainty: `Epistemic: N/A, Aleatoric: N/A`
- **Runtime**: `2.0554s`

#### Case: `benign_low_activity` (`benign_low_activity.pcap`)
- **Engine**: `Next-Gen Causal Precursor Forecaster` (next_gen_v2_revalidated (RESEARCH CANDIDATE))
- **Operational Tier**: `ABSTAINED`
- **Feature Availability**: `41 / 45`
- **Abstention Details**: `abstained=True` (Reason: `MODEL_FEATURE_CONTRACT_MISMATCH`)
  - *Explanation*: Forecast withheld: Required features are unavailable for at least one candidate; no dense vector is fabricated.
- **Evidence & Diagnostics**: 1 items, Uncertainty: `Epistemic: N/A, Aleatoric: N/A`
- **Runtime**: `0.0389s`

#### Case: `insufficient_history` (`insufficient_history.pcap`)
- **Engine**: `Next-Gen Causal Precursor Forecaster` (next_gen_v2_revalidated (RESEARCH CANDIDATE))
- **Operational Tier**: `ABSTAINED`
- **Feature Availability**: `38 / 45`
- **Abstention Details**: `abstained=True` (Reason: `INSUFFICIENT_HISTORY`)
  - *Explanation*: Forecast withheld: Forecasting requires at least 8 continuous 60-second windows. Capture provides 4 windows. Static traffic analysis completed successfully.
- **Evidence & Diagnostics**: 6 items, Uncertainty: `Epistemic: N/A, Aleatoric: N/A`
- **Runtime**: `0.0368s`

#### Case: `malformed` (`malformed.pcap`)
- **Engine**: `Next-Gen Causal Precursor Forecaster` (2.0.0-candidate (RESEARCH))
- **Operational Tier**: `UNPROCESSABLE`
- **Feature Availability**: `0 / 45`
- **Abstention Details**: `abstained=True` (Reason: `PARSING_ERROR: RuntimeError`)
- **Evidence & Diagnostics**: 0 items, Uncertainty: `N/A`
- **Runtime**: `0.0015s`

#### Case: `non_contiguous` (`non_contiguous.pcap`)
- **Engine**: `Next-Gen Causal Precursor Forecaster` (next_gen_v2_revalidated (RESEARCH CANDIDATE))
- **Operational Tier**: `ABSTAINED`
- **Feature Availability**: `38 / 45`
- **Abstention Details**: `abstained=True` (Reason: `NON_CONTIGUOUS_TIMESTAMPS`)
  - *Explanation*: Forecast withheld: Input sequence contains non-contiguous temporal windows or excessive time gaps.
- **Evidence & Diagnostics**: 0 items, Uncertainty: `Epistemic: N/A, Aleatoric: N/A`
- **Runtime**: `0.0356s`

#### Case: `pcapng` (`vlan-pcp-dei.pcapng`)
- **Engine**: `Next-Gen Causal Precursor Forecaster` (next_gen_v2_revalidated (RESEARCH CANDIDATE))
- **Operational Tier**: `ABSTAINED`
- **Feature Availability**: `39 / 45`
- **Abstention Details**: `abstained=True` (Reason: `INSUFFICIENT_HISTORY`)
  - *Explanation*: Forecast withheld: Forecasting requires at least 8 continuous 60-second windows. Capture provides 1 windows. Static traffic analysis completed successfully.
- **Evidence & Diagnostics**: 1 items, Uncertainty: `Epistemic: N/A, Aleatoric: N/A`
- **Runtime**: `0.0329s`

#### Case: `tcp_heavy` (`tcp_heavy.pcap`)
- **Engine**: `Next-Gen Causal Precursor Forecaster` (next_gen_v2_revalidated (RESEARCH CANDIDATE))
- **Operational Tier**: `RESEARCH_UNVERIFIED`
- **Feature Availability**: `45 / 45`
- **Abstention Details**: `abstained=False` (Reason: `None`)
  - *Explanation*: Forecast is available and supported by lookback history, but model calibration is UNSUPPORTED. Raw scores should not be treated as calibrated probabilities.
- **Evidence & Diagnostics**: 11 items, Uncertainty: `Epistemic: N/A, Aleatoric: N/A`
- **Runtime**: `0.3917s`

#### Case: `udp_heavy` (`udp_heavy.pcap`)
- **Engine**: `Next-Gen Causal Precursor Forecaster` (next_gen_v2_revalidated (RESEARCH CANDIDATE))
- **Operational Tier**: `ABSTAINED`
- **Feature Availability**: `38 / 45`
- **Abstention Details**: `abstained=True` (Reason: `MODEL_FEATURE_CONTRACT_MISMATCH`)
  - *Explanation*: Forecast withheld: Required features are unavailable for at least one candidate; no dense vector is fabricated.
- **Evidence & Diagnostics**: 10 items, Uncertainty: `Epistemic: N/A, Aleatoric: N/A`
- **Runtime**: `0.3287s`

#### Case: `mixed_protocol` (`mixed_protocol.pcap`)
- **Engine**: `Next-Gen Causal Precursor Forecaster` (next_gen_v2_revalidated (RESEARCH CANDIDATE))
- **Operational Tier**: `ABSTAINED`
- **Feature Availability**: `41 / 45`
- **Abstention Details**: `abstained=True` (Reason: `MODEL_FEATURE_CONTRACT_MISMATCH`)
  - *Explanation*: Forecast withheld: Required features are unavailable for at least one candidate; no dense vector is fabricated.
- **Evidence & Diagnostics**: 1 items, Uncertainty: `Epistemic: N/A, Aleatoric: N/A`
- **Runtime**: `0.3524s`

---

## 3. Threshold Provenance & Zero-Leakage Audit

The $z_{\text{flows}} \ge 2.20$ threshold was audited against the raw chronological state records:

- **Source Partition:** Episode 1 (UNSW-NB15, Jan 22 19:42:04 to Jan 23 00:32:04)
- **Validation Windows:** 291 contiguous benign states
- **Baseline Statistics:** Flow Count $\mu = 1369.86$, $\sigma = 194.97$
- **Distribution Percentiles:**
  - 90.0th percentile: $1.6096$
  - 95.0th percentile: $1.9614$
  - 97.5th percentile: $2.1778$
  - 99.0th percentile: $2.3978$
- **Selected Threshold:** $z_{\text{flows}} \ge 2.20$
- **Validation False Alarm Rate:** 2.41% (7 / 291 windows) $\le 5.0\%$ [PASS]
- **Test Contamination Status:** **ZERO LEAKAGE (Episode 2 completely held out during threshold selection)**
- **Frozen Before Test:** `True`

---

## 4. Independent Metric Recomputation

Metrics recomputed independently on Episode 2 test subset (13 sequences, $t=7 \dots 19$):

| Horizon | TP | FP | TN | FN | Precision | Recall | $F_1$ Score | Persistence $F_1$ | Net FVP | FPR | Brier | Brier (Pers) | ECE | Lead Time |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **T+1** | 6 | 0 | 6 | 1 | 1.0000 | 0.8571 | **0.9231** | 0.9231 | **+0.0000** | 0.0000 | 0.0898 | 0.0769 | 0.1115 | **+0s** |
| **T+2** | 6 | 0 | 5 | 2 | 1.0000 | 0.7500 | **0.8571** | 0.8571 | **+0.0000** | 0.0000 | 0.1636 | 0.1538 | 0.1885 | **+0s** |
| **T+3** | 7 | 0 | 4 | 2 | 1.0000 | 0.7778 | **0.8750** | 0.8000 | **+0.0750** | 0.0000 | 0.1498 | 0.2308 | 0.1654 | **+180s** |
| **T+4** | 7 | 0 | 3 | 3 | 1.0000 | 0.7000 | **0.8235** | 0.7500 | **+0.0735** | 0.0000 | 0.2236 | 0.3077 | 0.2423 | **+180s** |
| **T+5** | 7 | 0 | 2 | 4 | 1.0000 | 0.6364 | **0.7778** | 0.7059 | **+0.0719** | 0.0000 | 0.2975 | 0.3846 | 0.3192 | **+180s** |

### Baseline Comparison Summary:
- **Always Benign:** $F_1 = 0.0000$, Recall $= 0.0000$, Brier $= 0.5385$, Lead Time $= 0\text{s}$.
- **Persistence Baseline:** Matches candidate at $T+1$ and $T+2$ ($F_1 = 0.9231, 0.8571$), but lags at $T+3 \dots T+5$ ($F_1 = 0.8000, 0.7500, 0.7059$) with $0\text{s}$ advance lead time (reactive only).
- **Existing Frozen World Model (Production):** Provides calibrated multi-step state rollout across 45 features, but operates with $+60\text{s}$ nominal lead time.
- **Next-Gen Precursor Forecaster (Research):** Yields $+0.0750$ net FVP at $T+3$ with $+180\text{s}$ advance early warning and zero false warnings in quiet periods.

---

## 5. Dataset Census & Generalization Analysis

- **Total Network Windows Analyzed:** 1441
- **Total Contiguous Episodes:** 5
- **Total State Transitions:** 4
- **Attack Onset Transitions in Corpus:** 2
- **Attack Onset Transitions in Test:** 1

> **Scientific Statement:**  
> The UNSW-NB15 dataset contains only 2 attack onset transitions across all 1,441 windows. Under the strict chronological protocol, Episode 2 contains exactly ONE attack onset event (N=1). While the 180s advance precursor detection on this event is mathematically verified with zero test leakage, N=1 is insufficient to prove generalization across varied network topologies or attack families.

---

## 6. Cryptographic Baseline Verification (Frozen Production Protection)

All seven production model artifacts in `models/final_world_model/` were verified against their golden SHA-256 digests:

| Artifact Name | Baseline SHA-256 Digest | Status |
| :--- | :--- | :---: |
| `config.json` | `98C55F8685478286264438B07DB7DCA72B3A42F1A41E0A4D26366654379AA1A1` | **MATCH (Frozen)** |
| `feature_schema.json` | `2BB8714F2DA49F124C82209488E9DC1ECCFF3CA8F655079404BA7EFB27E4454B` | **MATCH (Frozen)** |
| `manifest.json` | `75BEF97F0BE8C7310A9AF89D8F13046C9F7E3A12303A7A55582913996805CBF6` | **MATCH (Frozen)** |
| `metadata.json` | `19816E54918779B1226DB88A0EA7319DAB7D831423B7D6A77181915F90A20093` | **MATCH (Frozen)** |
| `metrics.json` | `8B2B395728BE2F8FFD80A66A2E120D634B2206CD2ABF2DB5AEC39FC65C4414B9` | **MATCH (Frozen)** |
| `model.npz` | `5787B2ABD68B2243F45AE1290E24B2DAA5483E69405660CF3DE824FD8B498ECC` | **MATCH (Frozen)** |
| `preprocessing.npz` | `E85D998324D7F45215494CA09D1C9388667F49B7E72D0A1511A1B64B0C72C6B3` | **MATCH (Frozen)** |

**Production Files Unmodified:** `True`

---

## 7. Limitations & Operational Roadmap

1. **Single Attack Transition Limitation:** The primary limitation is dataset scarcity ($N=1$ test attack onset). Future work must collect multi-day continuous captures with diverse attack styles.
2. **Research Tier Quarantine:** Until multi-event validation passes, the candidate model remains quarantined in the research tier (`status = 'research'`, `is_production_ready = False`).
3. **Dual-Engine Safety:** Production users default to the frozen baseline without risk of uncalibrated warnings.
