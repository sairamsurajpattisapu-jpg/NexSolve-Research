# NexSolve World Model V1 Local Service

## Status

The service is a local FastAPI wrapper around the existing research model. It performs inference only. It does not train, download data, or fabricate predictions. The current model reports `packet_features_available: false` until the Friday CIC PCAP has been audited.

## Install

From `NexSolve-Research`:

```powershell
python -m pip install -r model_service/requirements.txt
```

FastAPI and Uvicorn were already available in the active environment.

## Start

```powershell
python -m uvicorn model_service.app:app --host 127.0.0.1 --port 8001
```

Port: `8001` on loopback only.

## Health

`GET /health` returns service status, model-loaded state, model version, feature count, sequence length, K, and packet-feature availability.

Current values: model loaded, 46 features, sequence length 8, K=5, packet features false.

## Forecast API

`POST /forecast` accepts:

```json
{
  "states": [
    {
      "timestamp": "2026-01-01T00:00:00Z",
      "flowFeatures": {},
      "packetFeatures": {},
      "temporalFeatures": {},
      "packetFeaturesAvailable": false
    }
  ]
}
```

Each feature group must contain exactly the keys in `models/nexsolve_world_model/feature_schema.json`. Values must be finite numbers. The model requires eight historical states for a forecast. Short input produces five explicit abstentions with null prediction values. Invalid input returns HTTP 422 with `INVALID_FORECAST_REQUEST`.

A successful response contains `currentState` and exactly five points with `horizon`, `attackProbability`, `predictedStage`, `confidence`, `uncertainty`, and `explanation`. Probabilities and confidence are produced by the loaded model. Uncertainty is the documented deterministic complement of margin confidence and is not calibrated probability. ATT&CK stages are contextual signal mappings, never technique-level ground truth.

## Artifact Location

The service loads from `models/nexsolve_world_model/`:

- `model.npz`
- `preprocessing.npz`
- `config.json`
- `feature_schema.json`
- `metadata.json`

## Tests

```powershell
pytest -q model_service/test_app.py
pytest -q tests/test_world_model.py model_service/test_app.py
```

## Limitations

This is the UNSW-NB15 research V1 model with one limited mixed-state test episode. Packet-level fields are an explicit interface placeholder, not verified packet observations. The service must not be represented as production NexSolve inference until the PCAP audit, packet-feature integration, and adapter validation are complete.
