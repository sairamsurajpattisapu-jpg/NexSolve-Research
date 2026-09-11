# Phase 5 Scientific Leakage and Integrity Audit

## Overall Leakage Status
- **Status:** ALL CHECKS PASSED
- **Passed Checks:** 10 / 10

## Detailed Checks
| Check Name | Status | Detail |
|---|---|---|
| `unsw_target_timestamp_strictly_after_input` | **PASS** | Asserts case.target_timestamps[0] > case.input_timestamps[-1] for all cases |
| `unsw_target_timestamp_strictly_increasing` | **PASS** | Asserts target timestamps increase monotonically across all 5 horizons |
| `toniot_target_timestamp_strictly_after_input` | **PASS** | Asserts case.target_timestamps[0] > case.input_timestamps[-1] on TON-IoT |
| `toniot_target_timestamp_strictly_increasing` | **PASS** | Asserts monotonic horizon ordering on TON-IoT |
| `no_sequence_crosses_episode_boundary` | **PASS** | contiguous_episodes partitions at gaps > 60s; build_forecast_cases operates strictly within a single episode |
| `no_sequence_crosses_dataset_boundary` | **PASS** | UNSW and TON-IoT pipelines run in isolated modules without concatenation |
| `scaler_fitted_on_train_only` | **PASS** | StandardScaler is fitted exclusively on train cases and applied via .transform() to test |
| `single_class_training_rejected` | **PASS** | check_model_eligibility halts model fitting when train cases have zero variance in labels |
| `single_class_calibration_rejected` | **PASS** | Platt calibrator refuses single-class validation data and returns CALIBRATION_UNSUPPORTED |
| `synthetic_future_feature_rejection` | **PASS** | Audits feature dictionaries against blacklisted target/future token names ('label', 'target', 'future') |

## Evaluation Guarantees
1. **Temporal Horizon Guard:** $t_{target} > t_{input\_end}$ is strictly asserted for every sequence.
2. **Chronological Horizon Ordering:** $t_{T+1} < t_{T+2} < t_{T+3} < t_{T+4} < t_{T+5}$ is strictly asserted.
3. **Boundary Integrity:** No sequences cross 60-second temporal discontinuities, capture files, or dataset boundaries.
4. **Zero-Fabrication:** Missing features are kept empty or rejected by compatibility gates; no zero-filling allowed.
5. **Strict Preprocessor Isolation:** Scalers and model parameters are fit exclusively on training data.
6. **Test Isolation:** The test split is never used for hyperparameter tuning, feature selection, or threshold tuning.
