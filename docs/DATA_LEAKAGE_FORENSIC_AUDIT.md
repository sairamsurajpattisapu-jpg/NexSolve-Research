# NexSolve Data Leakage Forensic Audit (Adversarial Pass)

Generated: 2026-09-14
Auditor: Forensic Scientific Claim Verification Pass
Scope: Adversarial Leakage Verification across 14 Audit Checks

| Check | Leakage Category | Verification Test | Code Reference | Status | Forensic Evidence & Notes |
|:---:|---|---|---|:---:|---|
| **A** | Future-Window Leakage | Verify feature extraction at window T strictly uses packets <= T | pcap_extractor.py:270-310 | **SAFE** | Packet slicing strictly enforces window_start <= ts < window_end. No subsequent packet enters aggregation. |
| **B** | Target Leakage | Verify forecasting target states (T+1..T+K) are withheld at inference time | world_model.py:203-218 | **SAFE** | Model performs autoregressive multi-step rollout using its own predictions; true future states are never fed in. |
| **C** | Label-Derived Feature Leakage | Verify labels (ttack_state, is_attack) are not encoded into model inputs | world_model.py:50-75 | **SAFE** | NetworkState.encode explicitly selects only FLOW_NAMES, PACKET_NAMES, and TEMPORAL_NAMES. ttack_state is omitted. |
| **D** | Random Split Leakage | Verify time-series splits do not randomly shuffle windows across time | world_model.py:130-147 | **SAFE** | Episodes are split chronologically (pre-test contiguous runs split 80/20 train/val; future mixed run used for test). |
| **E** | Same-Episode Train/Test Contamination | Verify training sequences do not cross episode boundaries into test sequences | world_model.py:145-146 | **SAFE** | Contiguous-run boundaries prevent lookback sequences from straddling train and test episodes. |
| **F** | Same-PCAP Train/Test Contamination | Verify if the model was trained on the same PCAP used for evaluation | **RISK** | **UNVERIFIED / MIXED**: Model was trained on UNSW-NB15 flow CSVs, while PCAP validation uses CIC-IDS2017 Friday PCAP. Cross-domain generalization was not formally validated. |
| **G** | Normalization Leakage | Verify scaler mean and variance were fit strictly on the training partition | world_model.py:244-245 | **SAFE** | preprocessing.npz stores frozen parameters fit on the pre-test training set only. |
| **H** | Rolling-Statistic Leakage | Verify rolling features (t-3..t) do not look ahead into t+1 | state.py:260-310 | **SAFE** | Rolling metrics strictly average historical windows [max(0, t-3), t]. |
| **I** | Lookahead in Sequence Construction | Verify window sequences do not include future windows | world_model.py:149-154 | **SAFE** | Sequence slicing uses X[i - lookback : i] to predict Y[i]. |
| **J** | Forecast Recursion State Pollution | Verify recursive rollout does not accidentally pull ground truth future states | world_model.py:214-217 | **SAFE** | olling.append(NetworkState(..., predicted, ...)) appends the model's own output. |
| **K** | Attack Schedule Leakage | Verify published UNB schedule times are not hardcoded into detection features | pcap_extractor.py, state.py | **SAFE** | Extraction is purely passive; timestamps are hardware epoch floats. |
| **L** | Timestamp Target Leakage | Verify wall-clock time does not act as a direct proxy for attack occurrence | world_model.py:50-75 | **SAFE** | Timestamps are converted to relative window deltas; absolute time of day is excluded from FEATURE_NAMES_45. |
| **M** | Dataset Duplicate Leakage | Verify identical duplicate flows do not leak across train and test | world_model.py:88-120 | **SAFE** | Aggregation bins flows by 60s epoch minute; distinct temporal buckets form non-overlapping samples. |
| **N** | Repeated Windows Across Splits | Verify identical temporal windows do not appear in both train and test splits | world_model.py:140-147 | **SAFE** | Train and test partitions are disjoint sets of integer window buckets. |

---

## Summary Verdict

Overall Leakage Risk Status: **SAFE FOR TEMPORAL CAUSALITY; UNVERIFIED FOR CROSS-DATASET GENERALIZATION**.
All feature extraction, sequence generation, scaler fitting, and autoregressive rollout mechanisms are strictly past-looking ( \le T$) and leakage-free. However, because the model was trained on UNSW-NB15 and evaluated on CIC-IDS2017, cross-dataset transferability remains scientifically unproven.
