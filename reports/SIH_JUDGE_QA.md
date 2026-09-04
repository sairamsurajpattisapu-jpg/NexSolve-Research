# SIH Judge Q&A

## 1. What is novel about NexSolve?

It adds temporal next-state forecasting and contextual progression interpretation to traffic analysis. It does not claim to replace an IDS or guarantee attack prediction.

## 2. How is this different from an IDS?

An IDS primarily detects current suspicious activity. NexSolve adds a forecast of future network-state behavior from a past-only sequence.

## 3. Why use a World Model?

The World Model represents network state transitions, allowing the system to forecast more than a single current label.

## 4. Why LSTM?

The current prototype uses a compact NumPy LSTM because it is suitable for ordered sequences and keeps the experiment reproducible and execution-simple.

## 5. Why not Transformer?

There is no measured evidence here that a Transformer would improve the task. The project avoids adding complexity without a demonstrated benefit.

## 6. What datasets are used?

UNSW-NB15 provides the timestamped temporal prototype. CIC-IDS2017 provides audited flow CSVs and static detection evidence. The CIC PCAP packet branch is pending.

## 7. Why CIC-IDS2017?

It contains multiple labeled traffic scenarios and useful flow aggregates. Its current local CSVs do not contain event timestamps, so they cannot support the final chronological claim alone.

## 8. Why UNSW-NB15?

The local UNSW data provides timestamped rows suitable for the existing 60-second temporal prototype and chronological evaluation.

## 9. How do you prevent data leakage?

Labels are target metadata only, temporal order is preserved, preprocessing is fitted on training windows, and scenario/IP/tuple identifiers are excluded from the model state.

## 10. How do you prevent future information entering the model?

Each sequence uses only states before its target. Future labels are read only for evaluation, never inference or preprocessing.

## 11. What are your features?

The protected contract has 18 flow features, 22 packet-interface features, and 6 temporal features. Packet features are currently unavailable placeholders, not claimed observations.

## 12. Why 60-second windows?

It is the existing documented research contract and provides a consistent compromise between fine-grained traffic changes and sparse windows. It has not been proven optimal.

## 13. What does T+5 mean?

It is the fifth future 60-second state in the recursive forecast, approximately five minutes after the current state under the current contract.

## 14. How do you map predictions to MITRE ATT&CK?

Only supported contextual behaviors are mapped, and technique metadata is validated against the local ATT&CK STIX bundle. The result is contextual, not confirmed ground truth.

## 15. How do you explain predictions?

The current model uses deterministic feature ablation. It reports association with the forecast, not causality. SHAP and attention values are not claimed.

## 16. What happens when the model is uncertain?

The system reports low confidence or insufficient evidence and abstains when history, features, or mappings are inadequate.

## 17. What is your current accuracy?

On the sole eligible mixed-state UNSW episode, the LSTM balanced accuracy is `0.6818` and F1 is `0.5333`. This is prototype evidence, not the final CIC benchmark.

## 18. Does your model outperform the baseline?

No. The stored evaluation reports LSTM macro-F1 `0.5608` versus persistence macro-F1 `0.9143`, so no improvement claim is justified.

## 19. What are the current limitations?

One eligible mixed-state episode, no local PCAP, unavailable packet observations, uncalibrated probabilities, limited generalization evidence, and no final CIC temporal evaluation.

## 20. How would this scale to enterprise/CII traffic?

Use streaming window aggregation, bounded state retention, versioned schemas, service health monitoring, and retraining only after leakage-safe multi-site evaluation. Scale is not yet experimentally demonstrated.

## 21. Is this real-time?

The architecture can support near-real-time windows, but real-time operational performance has not been measured or claimed.

## 22. What happens if the packet branch is unavailable?

The system marks packet features unavailable and continues only with supported flow/state analysis. It does not substitute flow aggregates for packet observations.

## 23. What happens if the model fails?

The service reports `MODEL_NOT_AVAILABLE` or an explicit error. The UI shows `MODEL OFFLINE` and never displays fallback probabilities.

## 24. How will you evaluate unseen attacks?

Use genuinely future, scenario-separated data and report per-episode, per-horizon performance with coverage, calibration, and abstention. That evidence is not available yet.

## 25. How would you deploy this?

Keep the Python model service behind the Node/Express API boundary, expose health and forecast contracts, isolate uploads, protect secrets, and promote only a versioned model that passes the documented evaluation and leakage gates.
