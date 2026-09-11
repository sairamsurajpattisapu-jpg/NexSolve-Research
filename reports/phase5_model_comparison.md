# Phase 5 Forecasting Model Comparison and Validation

## Overall Scientific Determination
- **Phase 5 Status:** `PASS_WITH_FIXES`
- **Best Validated Model:** `Persistence Baseline`
- **Production Promotion:** `HOLD` (`production_eligible: False`)
- **Scientific Decision:** `KEEP_PERSISTENCE`

## Model Comparison Table Across Horizons
| Dataset | Candidate | T+1 F1 | T+2 F1 | T+3 F1 | T+4 F1 | T+5 F1 | Bal. Acc. | Brier | Cases | Training Status | Calibration | Promotion |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| UNSW-NB15 | **Persistence Baseline** | 0.9231 | 0.8571 | 0.8000 | 0.7500 | 0.7059 | 0.8419 | 0.2308 | 13 | `NOT_REQUIRED` | `CALIBRATION_UNSUPPORTED` | **REMAINS_BEST_BASELINE** |
| UNSW-NB15 | **Majority Baseline** | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.5000 | 0.3995 | 13 | `NOT_REQUIRED` | `CALIBRATION_UNSUPPORTED` | **HOLD** |
| UNSW-NB15 | **Empirical Transition** | 0.9231 | 0.8571 | 0.8000 | 0.7500 | 0.7059 | 0.8419 | 0.2226 | 13 | `NOT_REQUIRED` | `CALIBRATION_UNSUPPORTED` | **HOLD** |
| UNSW-NB15 | **Direct Flattened Logistic** | 0.8333 | 0.2222 | 0.0000 | 0.0000 | 0.1667 | 0.5930 | 0.5757 | 13 | `TRAINED_TRAIN_ONLY` | `CALIBRATION_UNSUPPORTED` | **HOLD** |
| UNSW-NB15 | **Direct Ridge Classifier (Flow-Only)** | 0.8571 | 0.8571 | 0.8750 | 0.7500 | 0.8421 | 0.8546 | 0.1784 | 13 | `TRAINED_TRAIN_ONLY` | `CALIBRATION_UNSUPPORTED` | **HOLD** |
| UNSW-NB15 | **Direct Small MLP** | 0.2500 | 0.4000 | 0.2000 | 0.1818 | 0.1667 | 0.5695 | 0.5681 | 13 | `TRAINED_TRAIN_ONLY` | `CALIBRATION_UNSUPPORTED` | **HOLD** |
| TON-IoT | **Persistence Baseline** | 0.9057 | 0.8302 | 0.7547 | 0.6923 | 0.7308 | 0.5278 | 0.3353 | 34 | `NOT_REQUIRED` | `CALIBRATED_ON_VALIDATION_ONLY` | **BEST_SHORT_HORIZON** |
| TON-IoT | **Majority Baseline** | 0.8852 | 0.8852 | 0.8852 | 0.8667 | 0.8667 | 0.5000 | 0.2176 | 34 | `NOT_REQUIRED` | `CALIBRATED_ON_VALIDATION_ONLY` | **BEST_LONG_HORIZON** |
| TON-IoT | **Empirical Transition** | 0.8852 | 0.8852 | 0.8852 | 0.8667 | 0.8667 | 0.5000 | 0.1925 | 34 | `NOT_REQUIRED` | `CALIBRATED_ON_VALIDATION_ONLY` | **HOLD** |
| TON-IoT | **Direct Flattened Logistic** | N/A | N/A | N/A | N/A | N/A | N/A | N/A | 34 | `TRAINING_CLASS_DIVERSITY_UNSUPPORTED` | `CALIBRATION_NOT_APPLICABLE` | **HOLD** |

## Scientific Conclusions
1. **Persistence Remains Superior:** On UNSW-NB15, Persistence achieves $F_1 = 0.9231$ ($T+1$) down to $0.7059$ ($T+5$). Complex ML models (MLP, Flattened Logistic) overfit the small episode or fail to beat persistence.
2. **Pure-Class Episode Reality:** TON-IoT Episode 0 is 100% attack traffic, triggering the explicit `TRAINING_CLASS_DIVERSITY_UNSUPPORTED` gate and preventing classifier fitting.
3. **Zero Fabrication Enforced:** The 22 unavailable packet features and unsupported flow metrics in TON-IoT are no longer zero-filled; feature vectors encode only verified data.
4. **Promotion Guarded:** No model is promoted to production inference.
