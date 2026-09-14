# Production PCAP Forecast Integration Audit
**System:** NexSolve AI-Based Network Attack Forecasting (`SIH26153`)  
**Audit Target:** End-to-End Production Path & Hardened Attack-Progression Forecasting  
**Baseline Commit:** `f388fb084384c28eb56f80c39336782090eb88e1` (`origin/main`)  
**Audit Date:** 2026-09-14  

---

## 1. Audit Objective

The objective of this audit is to conduct an empirical, non-speculative production integration audit of the hardened attack-progression forecasting system on authentic network capture telemetry. Specifically, this audit validates:
1. The end-to-end production path from raw PCAP upload to frontend presentation.
2. The operational integrity of the 46->45 feature safety gate without fabrication or zero-filling of `mean_tcp_rtt`.
3. Contiguous temporal history extraction across 60-second observation windows.
4. The behavior and semantics of the attack progression forecasting engine (`STATE_PERSISTENCE` vs `DOWNSTREAM_PROGRESSION` vs `ABSTAINED`).
5. Complete adherence to scientific rules: zero label leakage, zero synthetic history, past-only feature construction, strict distinction between observed telemetry and forward forecast, and empirical conditional probabilities without arbitrary confidence heuristics.

---

## 2. Exact Production Call Chain

The execution path across the production repository was traced directly from source entrypoints through imports and function invocations:

```
[User Browser / Frontend UI]
  │
  ├─ POST /api/pcap/analyze (multipart/form-data)
  │    │
  │    ▼
[model_service/app.py: analyze_pcap()]
  │  ├─ Validates filename, extension (.pcap/.pcapng), and max file size (64MB)
  │  │
  │  ▼
[model_service/pcap_upload.py: analyze_uploaded_capture()]
  │  ├─ Magic byte validation (PCAP_MAGICS: pcap / pcapng)
  │  ├─ Tempfile extraction buffer in runtime/
  │  │
  │  ▼
[ml/data/pcap_extractor.py: extract_canonical_capture()]
  │  ├─ Streaming packet extraction (Scapy / PcapReader fallback)
  │  ├─ L2/L3/L4 packet parsing (`packet_features.py: parse_packet_summary`)
  │  ├─ Deterministic 60-second window binning (`assign_packet_to_window`)
  │  ├─ Bi-directional 5-tuple flow reconstruction (`flow_key`, `extract_flow_features`)
  │  └─ Quality evaluation (`evaluate_capture_quality`)
  │  │
  │  ▼
[nexsolve_core/state.py: build_network_state_candidates()]
  │  ├─ Flow aggregate computation (total bytes, packets, durations, ports, protocol counts)
  │  ├─ L3/L4 packet distribution statistics (packet size moments, TTL moments, TCP flags, window sizes, IAT)
  │  └─ Strictly past-only temporal feature construction (`delta_flow_count`, `delta_total_bytes`, `delta_total_packets`, `delta_ports`, `delta_iat`, `rolling_total_bytes`)
  │  │
  │  ▼
[nexsolve_core/state.py: build_state_history()]
  │  ├─ Checks capture boundary consistency and temporal contiguity ($T_{i,\text{start}} == T_{i-1,\text{end}}$)
  │  └─ Validates lookback threshold (requires >= 8 contiguous windows)
  │  │
  │  ▼
[nexsolve_core/state.py: evaluate_model_compatibility()]
  │  ├─ Primary Gate: Evaluates candidate features against canonical 46-feature schema (`MODEL_SCHEMA`)
  │  ├─ Safety Gate: When missing features == `{"flow_features.mean_tcp_rtt"}`, evaluates candidate features against canonical 45-feature schema (`MODEL_SCHEMA_45`)
  │  └─ Verifies zero missing features, zero zero-fills, and verified quality
  │  │
  │  ▼
[world_model.py: forecast_k_steps() & explain()]
  │  ├─ Converts candidates to `NetworkState` objects (`candidates_to_network_states`)
  │  ├─ Model weights loaded from `models/nexsolve_world_model_45`
  │  ├─ LSTM recursive forward rollouts across horizons K in {1, 2, 3, 4, 5}
  │  └─ First-order feature attribution explanations (`explain()`)
  │  │
  │  ▼
[ml/forecasting/forecast_intelligence.py: assemble_forecast_intelligence()]
  │  ├─ Pre-rollout abstention check (`evaluate_forecast_abstention`)
  │  ├─ Attack horizon determination (`compute_attack_horizon`)
  │  ├─ Evidence chain extraction (`build_evidence_chain`)
  │  └─ Unknown behavior classification (`classify_unknown_behavior`)
  │  │
  │  ▼
[nexsolve_core/behavior/ & nexsolve_core/fusion.py]
  │  ├─ Behavioral analysis (`analyze_behavioral_intelligence`: beaconing detection)
  │  ├─ Session investigation records (`build_session_investigation_records`)
  │  └─ Evidence fusion (`fuse_threat_assessment`: strictly separates OBSERVED evidence from FORECAST predictions)
  │  │
  │  ▼
[ml/forecasting/attack_progression.py: forecast_attack_progression()]
  │  ├─ Deterministic observed state mapping (`determine_observed_state`)
  │  ├─ Markovian empirical transition kinematics across K in {1, 3, 5, 10, 15}
  │  ├─ Explicit classification: `STATE_PERSISTENCE` vs `DOWNSTREAM_PROGRESSION` vs `ABSTAINED`
  │  └─ Strict isolation: zero arbitrary confidence formula, zero downstream fabrication
  │  │
  │  ▼
[model_service/pcap_upload.py / model_service/jobs.py / app.py]
  │  ├─ Response dictionary assembly & database persistence (`persist_analysis`)
  │  └─ JSON serialization to client
  │  │
  │  ▼
[Frontend UI: React + Vite + TypeScript]
     ├─ `stores/productionStore.ts` & `hooks/useProductionData.ts`
     ├─ `pages/Forecast.tsx` (renders provenance banner, abstention banner, `AttackHorizonCard`, `AttackProgressionCard`, rollout table)
     ├─ `pages/Threats.tsx` (renders `ForecastTrustPanel`, findings list)
     └─ `components/AttackProgressionCard.tsx` (renders observed state anchor, stage persistence metrics, empirical probabilities, and abstention reasons)
```

---

## 3. Real PCAP Integration Test

### 3.1 PCAP Metadata
- **File:** `C:\Users\saira\Downloads\friday_10windows_slice.pcap`
- **File Size:** 833,081 bytes (~813.5 KB)
- **Origin:** Authentic physical capture slice from the UNB CIC-IDS2017 dataset (`Friday-WorkingHours.pcap`).
- **Modification:** Unmodified original slice.

### 3.2 Reconstruction & Extraction Results
Executing the production pipeline against `friday_10windows_slice.pcap` yielded the following measured telemetry:

| Metric | Measured Value | Validation Status |
| :--- | :--- | :--- |
| **PCAP Upload & Validation** | `VALID` | PASS |
| **Packets Parsed** | 2,277 | Exact hardware count matched |
| **Flows Reconstructed** | 283 | Bi-directional flows reconstructed |
| **Contiguous Windows Generated** | 10 windows | Exactly 10 contiguous 60-second windows |
| **Temporal Span Covered** | 600.0 seconds | Contiguous, zero gap ($T_i = T_{i-1} + 60\text{s}$) |
| **Protocol Breakdown** | TCP: 1,617, UDP: 519, ARP: 56, ICMPv6: 21, IPv4 Proto 2: 4, Unsupported: 60 | Valid L3/L4 distribution |
| **Capture Quality Status** | `SUFFICIENT` | PASS (no blockers, valid timing) |

---

## 4. 45-Feature Compatibility & Gate Verification

1. **46->45 Dual Schema Safety Gate:**
   - On initial evaluation against the 46-feature schema (`MODEL_SCHEMA`), `flow_features.mean_tcp_rtt` was identified as absent from the PCAP flow statistics.
   - The safety gate intercepted the failure: because the **only** missing feature was `flow_features.mean_tcp_rtt`, it evaluated compatibility against `MODEL_SCHEMA_45` (`nexsolve_world_model_45`).
   - All 45 required features were fully present in the real PCAP candidate stream:
     - 17 Flow features (all present, zero fabricated)
     - 22 Packet features (all present, extracted from packet headers)
     - 6 Temporal features (strictly derived from past window delta)
   - `model_ready` resolved to `True`.
   - `missing_features`: `[]` (empty list).
   - `unreliable_features`: `[]` (empty list).
   - `reasons`: `All required feature semantics and evidence gates passed.`

2. **Invariant Invariance:**
   - `mean_tcp_rtt` was **never** fabricated, mocked, or zero-filled.
   - Zero synthetic fallback vectors were injected.

---

## 5. Temporal-History & Model Rollout Result

- **History Windows Available:** 10 continuous 60s windows.
- **Lookback Requirement:** 8 continuous windows.
- **Contiguity Check:** All 10 windows are strictly contiguous without boundary jumps.
- **History Result Status:** `READY` (last 8 windows selected for rollout input sequence).
- **World-Model Execution:** The 45-dimensional NumPy LSTM world model executed forward rollouts across horizons $K \in \{1, 2, 3, 4, 5\}$:
  - $K=1$ ($T+60\text{s}$): Attack Probability = $0.6002$, Confidence = $0.2003$
  - $K=2$ ($T+120\text{s}$): Attack Probability = $0.2085$, Confidence = $0.5830$
  - $K=3$ ($T+180\text{s}$): Attack Probability = $0.1538$, Confidence = $0.6923$
  - $K=4$ ($T+240\text{s}$): Attack Probability = $0.1174$, Confidence = $0.7651$
  - $K=5$ ($T+300\text{s}$): Attack Probability = $0.0944$, Confidence = $0.8112$
- **Feature Attribution:** Top contributors calculated by `explain()`: `mean_tcp_window` (+0.5197), `packet_count` (+0.3066), `mean_swin` (+0.3066), `mean_packet_size` (+0.2496).

---

## 6. Actual Attack Progression Forecaster Result

When evaluated against the observed telemetry and heuristic findings extracted from `friday_10windows_slice.pcap`:

- **Observed Heuristic Findings:** 9 findings total (7 `traffic_anomaly`, 2 `network_reconnaissance`).
- **Observed Stage Inferred:** `AttackProgressionState.RECONNAISSANCE`
- **Observed Techniques:** `('T1046',)` (Network Service Discovery)
- **Progression Forecaster Verdict:** `PARTIALLY_SUPPORTED`
- **Summary:** `"Observed active RECONNAISSANCE. Forecasting supported for T+1m, T+3m, T+5m; abstained for T+10m, T+15m due to lack of verified replication."`

### Detailed Horizon Rollout Points:

| Horizon ($K$) | Prediction Type | Predicted State | Predicted Technique | Forecast Techniques | Empirical Transition Probability | Baseline Probability | Abstained | Abstention Reason |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **$T+1\text{m}$** (60s) | `STATE_PERSISTENCE` | `RECONNAISSANCE` | `T1046` | `()` (Empty) | **0.9750** (97.5%) | 0.1650 | `False` | `None` |
| **$T+3\text{m}$** (180s) | `STATE_PERSISTENCE` | `RECONNAISSANCE` | `T1046` | `()` (Empty) | **0.9240** (92.4%) | 0.1650 | `False` | `None` |
| **$T+5\text{m}$** (300s) | `STATE_PERSISTENCE` | `RECONNAISSANCE` | `T1046` | `()` (Empty) | **0.8730** (87.3%) | 0.1650 | `False` | `None` |
| **$T+10\text{m}$** (600s) | `ABSTAINED` | `UNKNOWN_STATE` | `None` | `()` (Empty) | **0.0000** | 0.0000 | `True` | `UNSUPPORTED_HORIZON: horizon T+10m lacks empirical replication` |
| **$T+15\text{m}$** (900s) | `ABSTAINED` | `UNKNOWN_STATE` | `None` | `()` (Empty) | **0.0000** | 0.0000 | `True` | `UNSUPPORTED_HORIZON: horizon T+15m lacks empirical replication` |

### Critical Progression Scientific Confirmations:
1. **Persistence Confirmation:** The module returned `STATE_PERSISTENCE`, denoting active persistence of ongoing reconnaissance across $K=1, 3, 5$.
2. **Forecast Technique Isolation:** `forecast_techniques` is strictly empty `()` for all persistence points. The ongoing observed technique `T1046` was **never** duplicated into `forecast_techniques`.
3. **No Unwarranted Downstream Progression:** Unobserved downstream attacks (e.g. `T1498` Denial of Service or `T1071` C2) were **not** fabricated.
4. **No Arbitrary Numerical Confidence:** No artificial confidence multiplier or confidence formula was generated; only empirical conditional transition probabilities ($P=0.975, 0.924, 0.873$) were returned.
5. **Strict Abstention on Horizons > 5:** Horizons $K=10\text{m}$ and $K=15\text{m}$ were explicitly marked `ABSTAINED` with reason `UNSUPPORTED_HORIZON`.

---

## 7. API Serialization & Frontend Contract Verification

- **Payload Serialization:** Complete payload containing traffic, detection, quality, world-model forecasts, attack horizon, behavioral intelligence, investigation sessions, threat assessment, and attack progression was serialized via `json.dumps()` without errors (total payload size: 207,679 bytes).
- **Frontend Type Contract:** The payload adheres to `UploadedAnalysisResponse`, `AttackProgressionForecast`, and `StageForecastPoint` defined in `frontend/src/types/api.ts`.
- **UI Component Rendering:** `AttackProgressionCard` and `ForecastTrustPanel` consume this exact structure.
  - Correctly distinguishes `STATE_PERSISTENCE` from `DOWNSTREAM_PROGRESSION`.
  - Accurately renders percentage transition probability (`97.5%`, `92.4%`, `87.3%`).
  - Displays abstention reasons for $K=10\text{m}$ and $K=15\text{m}$.
  - Contains zero confidence labels or multipliers.

---

## 8. Leakage & Safety Invariant Audit

| Invariant Checked | Audit Mechanism | Result | Notes |
| :--- | :--- | :--- | :--- |
| **Future-window access** | Temporal calculation code inspected in `nexsolve_core/state.py` lines 515-538 | **CLEAN** | Temporal deltas are computed strictly between candidate $i$ and previous candidate $i-1$. Candidate 0 temporal features are withheld (`UNAVAILABLE`). |
| **Label leakage** | Feature extraction code in `ml/data/pcap_extractor.py` and `nexsolve_core/state.py` | **CLEAN** | Labels are excluded from feature vectors. Raw PCAPs are unlabeled; ground-truth labels are never passed to model input. |
| **Fabricated feature values** | `state.py: evaluate_model_compatibility` | **CLEAN** | Any missing required feature results in `model_ready = False`. No synthetic values or zeros are substituted. |
| **Hidden RTT fallback** | `ml/data/packet_features.py` and `model_service/pcap_upload.py` | **CLEAN** | `mean_tcp_rtt` is omitted from `MODEL_SCHEMA_45`; neither scapy heuristics nor dummy RTT numbers are generated. |
| **Zero-fill fallback** | `candidates_to_network_states` in `state.py` | **CLEAN** | Strict gate: raises `ValueError` if features are missing; no zero-fill exists in conversion pipeline. |
| **Synthetic history** | History building in `build_state_history` | **CLEAN** | Rejects gapped or cross-capture histories. Windows are constructed only from genuine parsed packet timestamps. |
| **Arbitrary confidence formulas** | `attack_progression.py` dataclasses & methods | **CLEAN** | `StageForecastPoint` contains no `confidence` field; only `transition_probability` and `baseline_probability`. |
| **Observed vs forecast separation** | `fuse_threat_assessment` in `nexsolve_core/fusion.py` | **CLEAN** | Ingested evidence items are explicitly tagged `TemporalScope.OBSERVED` ($t \le T_0$) vs `TemporalScope.FORECAST` ($t > T_0$). |

---

## 9. Test Suite Execution & Measured Results

### 9.1 Targeted Progression & PCAP Suite
Executed command:
```powershell
.venv\Scripts\pytest -v tests/test_attack_progression.py tests/test_pcap_compatible_45.py tests/test_short_pcap_and_evaluation_harness.py
```
**Results:** **16 passed in 5.74s** (100% pass rate)

### 9.2 Complete Backend Test Suite
Executed command:
```powershell
.venv\Scripts\pytest -q
```
**Results:** **241 passed, 7 warnings in 139.54s** (100% pass rate, 0 failures)

### 9.3 Frontend Contract & Unit Tests
Executed command:
```powershell
npm test -- --run
```
**Results:** **10 test files passed, 53 tests passed in 7.22s** (100% pass rate, 0 failures)

### 9.4 Frontend Production Build & Typecheck
Executed command:
```powershell
npm run build
```
**Results:** TypeScript check (`tsc -b`) and Vite production bundle succeeded cleanly in 1.18s (`dist/` generated with 0 errors).

---

## 10. Scientific Limitations

1. **Window Requirement for Supervised Model Evaluation:**
   - The 10-window slice (`friday_10windows_slice.pcap`) contains 10 contiguous 60s windows ($600\text{s}$).
   - Because a full supervised evaluation pair for $L=8$ lookback and $K=5$ forward forecast requires at least $L+K=13$ contiguous windows ($780\text{s}$), this 10-window slice validates real production inference rollouts, feature compatibility, and abstention semantics, but cannot provide an empirical ground-truth $K=5$ evaluation pair without the full 484-window dataset.
2. **Transition Probability Dataset Scope:**
   - Empirical Markovian transition probabilities ($P(\text{State}_{T+K} \mid \text{State}_T)$) are derived from verified ground-truth attack kinematics in the CIC-IDS2017 corpus (specifically Friday Working Hours Episodes 1 and 2).
   - They represent historical conditional frequencies within this verified benchmark, and should not be interpreted as universal prior probabilities across all arbitrary enterprise network environments.
3. **Absence of Pre-Attack Predictors:**
   - When an observed window is benign, empirical evaluation has demonstrated that baseline traffic fluctuations do not provide statistically significant early onset signals for future attack inception. The system correctly abstains from predicting future attacks from quiescent benign baselines.

---

## 11. Final Verdict

# VERDICT: PASS WITH LIMITATIONS

### Justification:
- **PASS:** The real PCAP (`friday_10windows_slice.pcap`) successfully traversed the authentic end-to-end production path without modification. All 10 windows were reconstructed, 45-feature extraction succeeded cleanly, the 46->45 safety gate activated strictly as intended without fabricating `mean_tcp_rtt`, contiguous past-only temporal history was validated, world-model rollouts executed deterministically, and the attack progression engine returned `STATE_PERSISTENCE` with empirical transition probabilities and zero fabricated downstream techniques. API serialization and frontend contract tests passed with zero failures.
- **LIMITATIONS:** The 10-window PCAP provides $L=8$ inference rollout and $K=1, 3, 5$ progression assessment, but at 10 windows it cannot support a supervised $L=8, K=5$ evaluation pair (requiring 13 windows). Progression transition probabilities are empirically derived conditional frequencies from CIC-IDS2017 kinematics rather than universal probabilities.
