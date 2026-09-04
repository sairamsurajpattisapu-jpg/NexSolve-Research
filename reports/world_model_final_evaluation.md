# World Model Final Evaluation

## Status

**PARTIALLY_DONE**. Existing measurements are preserved; no retraining was performed.

## Model

NumPy LSTM, 46 inputs, hidden size 24, lookback 8, 60-second windows, recursive horizon 5, seed 7. Dataset: UNSW-NB15.

## Measured Result

The eligible future evaluation contains one mixed-state episode and 24 forecast cases. LSTM: precision `1.0`, recall `0.36363636363636365`, F1 `0.5333333333333333`, macro-F1 `0.5607843137254902`, balanced accuracy `0.6818181818181819`, ROC-AUC `0.6363636363636364`, PR-AUC `0.8485791985791986`, coverage `0.6666666666666666`, abstention rate `0.3333333333333333`.

Persistence: precision `0.9285714285714286`, recall `0.9285714285714286`, F1 `0.9285714285714286`, macro-F1 `0.9142857142857144`, balanced accuracy `0.9142857142857144`, coverage `1.0`.

**Conclusion:** persistence outperforms the LSTM on this measured episode. This is not evidence of AI improvement or generalization.

Full machine-readable details are in `world_model_final_evaluation.json`.
