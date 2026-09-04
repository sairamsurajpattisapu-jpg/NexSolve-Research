# Demo State Machine

## Success Path

```text
IDLE
  -> INGESTING
  -> VALIDATING
  -> ANALYZING
  -> CURRENT_STATE_READY
  -> FORECASTING
  -> FORECAST_READY
  -> ATTACK_PROGRESSION
  -> MITRE_CONTEXT
  -> EXPLANATION
  -> DEFENDER_DECISION
```

## State Semantics

- `IDLE`: no input or active analysis.
- `INGESTING`: authorized CSV input is being received.
- `VALIDATING`: file type, size, schema, rows, and numeric values are checked.
- `ANALYZING`: valid flow data is summarized or temporal states are constructed.
- `CURRENT_STATE_READY`: observed state and evidence are available.
- `FORECASTING`: a validated model-ready temporal sequence is sent to the model service.
- `FORECAST_READY`: real T+1 through T+5 model outputs are available.
- `ATTACK_PROGRESSION`: contextual stage hypotheses are computed without target labels.
- `MITRE_CONTEXT`: only locally validated contextual ATT&CK metadata is attached.
- `EXPLANATION`: associated model features and limitations are displayed.
- `DEFENDER_DECISION`: non-autonomous guidance is displayed.

## Failure States

- `INVALID_INPUT`: file or request fails validation.
- `MODEL_UNAVAILABLE`: service or model is unavailable; display `MODEL OFFLINE` and `MODEL_NOT_AVAILABLE`.
- `INSUFFICIENT_EVIDENCE`: missing temporal history, features, or supported evidence.
- `PACKET_FEATURES_UNAVAILABLE`: packet branch is not populated; do not substitute flow features.
- `INTERNAL_ERROR`: safe structured error without predictions.

The current CSV upload can reach analysis and current-state metadata, but it must stop at `INSUFFICIENT_EVIDENCE` for forecasting unless a valid temporal state sequence is supplied.
