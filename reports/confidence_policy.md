# Confidence Policy

`INSUFFICIENT_EVIDENCE` applies when history, required features, model output, calibration support, or mapping evidence is missing. Otherwise confidence is reported as the model's documented uncalibrated margin, not certainty. Suggested presentation bands are HIGH_CONFIDENCE >= 0.80, MEDIUM_CONFIDENCE >= 0.60, LOW_CONFIDENCE below 0.60; these are display policy thresholds, not calibrated probabilities.
