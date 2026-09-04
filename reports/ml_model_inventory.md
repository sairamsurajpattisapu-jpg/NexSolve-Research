# ML Model Inventory

Run date (UTC): `2026-09-03`

## Existing Components

| Component | Type | Dataset | Input and output | Task | Metrics/artifact | Reusable? |
|---|---|---|---|---|---|---|
| Logistic Regression | `sklearn.linear_model.LogisticRegression` | CIC-IDS2017 | Numeric flow CSV columns except `Label`; hard label and probability | Static detection | `results/detection_baseline.json`; validation macro-F1 0.3843, test macro-F1 0.5595 | Yes for CIC detection only; not a temporal world model |
| Current-state/persistence | Deterministic baseline | UNSW-NB15 | Current binary window state; next binary state | Next-window baseline | `results/forecast_baseline_comparison.json`; macro-F1 0.9143, coverage 1.0 on 24 test pairs | Yes as forecasting baseline |
| Empirical transition | Deterministic conditional mode | UNSW-NB15 | Training transition counts by binary state | Next-window baseline | Same artifact; tied with persistence on the sole eligible episode | Yes as forecasting baseline |
| NumPy LSTM world model | Custom NumPy recurrent model | UNSW-NB15 | 8 previous 60-second numeric states; continuous next-state decoder plus attack head | State transition and attack forecasting | `reports/world_model_evaluation.json`; test macro-F1 0.5608 at 66.7% coverage; no improvement over persistence | Yes through `world_model.py`; packet fields remain unavailable |

## Existing Pipeline and Preprocessing

`run_research.py` contains the validated 60-second window reconstruction and chronological contiguous-run split. `world_model.py` reconstructs numeric window states from the same UNSW files and fits mean/scale preprocessing on training windows only. Existing preprocessing artifacts are `results/world_model_scaler.npz`; no pre-trained CIC or UNSW external weights exist.

## Artifacts

The LSTM package is `results/world_model_lstm.npz` plus `results/world_model_scaler.npz`. It is independently loadable by `NumpyLSTM.load()` and the module inference functions. A PyTorch `model.pt` is not produced because PyTorch is not installed and no framework download was justified for this small presentation prototype.

## Licenses and Limitations

The local dataset licensing/citation terms remain those documented by CIC/UNSW source pages. The research implementation has no separate external model license. The LSTM result is extremely limited: one mixed-state future episode, 24 forecast cases, 8 abstentions, no verified raw PCAP packet features, and no claim of superiority.
