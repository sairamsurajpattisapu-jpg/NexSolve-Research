# NexSolve Final Status

## COMPLETED

- CIC-IDS2017 flow audit and deterministic adapter.
- Protected NumPy LSTM research model with a 46-feature contract and recursive T+1 through T+5 rollout.
- Research model service, attack progression layer, local ATT&CK context validation, explanation primitives, and abstention handling.
- Completed CIC packet-window Parquet validation, read-only adapter, traffic aggregation, and evidence-bounded API analysis routes.
- SIH technical story, five-slide deck, two-minute script, judge Q&A, claims audit, architecture, demo state machine, API audit, README, and reproducibility guide.
- Evaluation, calibration, fusion, alignment, leakage, provenance, model-selection, registry, and deterministic demo infrastructure.

## MEASURED

- Active model: one-layer NumPy LSTM, hidden size 24, sequence length 8, 60-second windows, seed 7.
- UNSW prototype LSTM balanced accuracy: `68.18%`.
- UNSW prototype LSTM F1: `53.33%`.
- Stored persistence baseline F1: `92.86%` and macro-F1 `91.43%`.
- LSTM coverage: `66.67%`; abstention rate: `33.33%`.
- Evaluation contains one eligible mixed-state future episode and 24 forecast cases.
- Note: a prior task statement cited persistence F1 `89.66%`; the current authoritative `world_model_evaluation.json` records `92.86%`, which is the value used here.
- Validation: research tests `27 passed`; production backend tests `15 passed`; production ML tests `20 passed`; frontend lint/typecheck passed.

## PACKET_INTEGRATED

- Packet/flow fusion, packet-level SIH model training, and final CIC packet+flow model.

## BLOCKED_BY_DATA

- CIC chronological training is blocked because the local CIC flow CSVs have no exact event timestamps.
- Calibration is blocked because the available validation split is one-class.
- Horizon-specific T+1 through T+5 benchmark metrics are not present in the existing stored prediction records.
- Unseen-attack generalization and enterprise-scale performance are not evidenced.

## HOLD

- Model selection and final model promotion remain `HOLD`.
- The current LSTM is not promoted over persistence.

## NOT_YET_VALIDATED

- Final CIC performance.
- Packet-only detection calibration and labeled packet-level performance.
- Calibrated probabilities.
- Production-ready model status.
- Real-time operational performance.

## Protected Artifacts

The active `models/nexsolve_world_model/` package and trained NPZ weights were not overwritten. The completed production PCAP extraction was not rerun or modified, and the production Parquet was treated as read-only.
