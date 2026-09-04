# SIH API And Error Summary

The research and production API contracts are audited in `API_CONTRACT_AUDIT.md`. The stable states are:

- `MODEL_NOT_AVAILABLE`: model service unavailable; no forecast returned.
- `INVALID_FORECAST_REQUEST` / `INVALID_REQUEST`: input fails schema or numeric validation.
- `INSUFFICIENT_EVIDENCE`: insufficient temporal history or supported features; explicit abstention.
- `INVALID_MODEL_RESPONSE`: model service returns malformed horizons, probabilities, stages, evidence, or techniques.
- `MODEL_ERROR`: upstream model service fails with a non-validation error.

The frontend must display `MODEL OFFLINE`, `INSUFFICIENT EVIDENCE`, or a useful validation message rather than a generic successful result.
