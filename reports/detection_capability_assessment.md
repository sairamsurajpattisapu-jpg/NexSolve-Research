# NexSolve Detection Capability Assessment

## Production Packet Path

The production path reads the completed, read-only CIC packet-window Parquet. It contains 484 chronological 60-second aggregate windows and packet-derived fields such as packet counts, protocol counts, TCP retransmission rate, port-scan score, fragmentation, SYN/ACK counts, and endpoint cardinalities.

Those windows contain no attack labels, attack categories, or independent ground truth. The active production detector is therefore `traffic_heuristics`, implemented by `ml.detection.HeuristicDetector`. It combines bounded traffic indicators into an explainable risk score and emits findings only when a rule fires.

Each finding exposes the method, category, severity, risk score, fired rule identifiers, measured metric, threshold, explanation, and recommendation. Confidence is intentionally unavailable. `model_prediction_available` is explicitly `false`.

## Existing ML Artifacts

- `models/nexsolve_world_model/model.npz` is a real NumPy LSTM trained on UNSW-NB15-derived 46-feature temporal states. It is exposed by `/forecast`, not by the packet-analysis routes.
- The LSTM packet inputs are unavailable placeholders and do not represent the production packet windows.
- `results/detection_baseline.json` records a CIC Logistic Regression static baseline trained from labeled CIC flow CSVs. Its weak results are not a validated model for the production packet Parquet and are not served by the product API.

## Feasibility Decision

A supervised model cannot be legitimately trained on the production Parquet because it has no target labels. An unsupervised anomaly model could be explored later, but there is currently no benign reference, incident ground truth, or independent evaluation protocol that would justify calling anomaly scores attack predictions.

The current SIH claim is consequently limited and defensible: NexSolve performs evidence-bounded traffic heuristic detection over verified packet-window telemetry. Future ML integration requires labeled packet/flow fusion, a leakage-safe split, independent evaluation, and promotion gates before it can replace or augment this detector.