# Model Comparison

Status: **PARTIALLY_AVAILABLE**.

| Model | T+1 F1 | T+2 F1 | T+3 F1 | T+4 F1 | T+5 F1 | Coverage | Calibration |
|---|---:|---:|---:|---:|---:|---:|---|
| Persistence | N/A | N/A | N/A | N/A | N/A | N/A | BLOCKED_BY_DATA |
| Empirical Transition | N/A | N/A | N/A | N/A | N/A | N/A | BLOCKED_BY_DATA |
| Logistic Regression | N/A | N/A | N/A | N/A | N/A | N/A | BLOCKED_BY_DATA |
| Current LSTM | N/A | N/A | N/A | N/A | N/A | N/A | BLOCKED_BY_DATA |
| Future Packet+Flow LSTM | N/A | N/A | N/A | N/A | N/A | N/A | PENDING_PCAP |

The existing measured aggregate evaluation is preserved in `world_model_final_evaluation.json`: LSTM macro-F1 0.5607843137254902 versus persistence macro-F1 0.9142857142857144 on one eligible mixed-state UNSW episode. Horizon-specific metrics are not available, so no model is promoted. Selection status: **HOLD**.
