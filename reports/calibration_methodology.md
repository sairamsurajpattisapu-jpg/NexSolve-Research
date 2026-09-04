# Calibration Methodology

The framework supports deterministic Platt scaling and reliability metrics. Calibration parameters are fitted only on validation probabilities and labels; test labels are never used during fitting. A one-class validation set is rejected as `BLOCKED_BY_DATA`. The current UNSW validation split is benign-only, so no calibrated result is claimed.
