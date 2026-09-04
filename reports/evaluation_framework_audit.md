# Evaluation Framework Audit

Existing reusable components: `world_model.build_network_states`, `chronological_split`, `make_sequences`, `forecast_k_steps`, `metrics`, and the existing persistence/transition evaluation artifacts. The active model has 46 inputs, 60-second windows, lookback 8, and recursive horizon 5.

Current evidence: one eligible mixed-state UNSW episode; LSTM macro-F1 0.5608 versus persistence 0.9143, with 66.7% LSTM coverage. CIC flow CSVs have no timestamps.

New infrastructure adds strict horizon metrics, split validation, validation-only calibration, model selection, leakage checks, fusion interfaces, and deterministic demo execution. No final model was retrained or promoted.
