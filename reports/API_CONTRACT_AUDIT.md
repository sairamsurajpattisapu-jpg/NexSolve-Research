# API Contract Audit

## Research Model Service

### `GET /health`

Returns actual model metadata: service status, model loaded flag, model version, feature count `46`, sequence length `8`, forecast horizon `5`, and `packet_features_available: false`.

### `POST /forecast`

Accepts `states`, each with an ISO-8601 timestamp, exact flow/packet/temporal feature maps, and packet availability. Values must be finite numbers. State count is 1–256. Invalid requests return HTTP `422` with `INVALID_FORECAST_REQUEST`.

A successful response returns `completed`, current state, five forecast points, defender guidance, evidence, limitations, and model metadata. Short history returns five explicit abstentions rather than fabricated probabilities.

## Production API

### `GET /api/health`

Returns the existing backend service health contract.

### `GET /api/forecast/health`

Returns model adapter availability and metadata. An unavailable adapter returns HTTP `200` with `{status: "unavailable", code: "MODEL_NOT_AVAILABLE"}` so the UI can show a truthful offline state.

### `POST /api/forecast`

The Express backend validates the request, forwards it through the thin forecast adapter, validates the complete response, and returns the enriched canonical contract. It rejects duplicate or invalid horizons, probabilities outside `[0,1]`, malformed stages, and invalid ATT&CK IDs. Adapter failures map to `MODEL_NOT_AVAILABLE`, `INVALID_REQUEST`, `MODEL_ERROR`, or `INVALID_MODEL_RESPONSE`.

### `POST /api/traffic/analyze`

Accepts a validated CSV upload and returns flow-analysis metadata. It rejects missing, oversized, unsupported, empty, or malformed files. This endpoint does not claim packet extraction or automatically create model-ready temporal states.

## Error Boundary

No endpoint returns successful forecast data after a model failure. No browser fallback probabilities, techniques, or stages are generated.
