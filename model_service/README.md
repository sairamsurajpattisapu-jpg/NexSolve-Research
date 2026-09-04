# NexSolve World Model V1 Service

Small local FastAPI wrapper around `models/nexsolve_world_model/`. It loads the existing NumPy model and does not train, download, or create predictions outside that model.

`POST /api/pcap/analyze` accepts `.pcap` and `.pcapng` uploads up to 64 MB. Uploads are written to unique temporary directories under `runtime/`, processed by the existing packet-window extractor and `traffic_heuristics` detector, then cleaned up. Production Parquet and PCAP assets are never used as upload destinations.

The upload response is the current analysis contract: `analysis_id`, `status`, `source`, `upload`, `validation`, `traffic`, `detection`, and extraction `quality`. The frontend then reads `GET /api/analysis/{analysis_id}/status`, `GET /api/analysis/{analysis_id}/results`, and `GET /api/reports/{analysis_id}`. Production continues to use the same routes with `production-cic-ids2017`; uploaded analyses are in-memory session records and are never merged with that production ID.

## Install

From the research workspace:

```powershell
python -m pip install -r model_service/requirements.txt
```

The current environment already has FastAPI and Uvicorn available.

## Start

From the research workspace:

```powershell
python -m uvicorn model_service.app:app --host 127.0.0.1 --port 8001
```

The service listens on `http://127.0.0.1:8001`.

## Health

```powershell
Invoke-RestMethod http://127.0.0.1:8001/health
```

Health includes model status, version, 46-feature count, sequence length 8, K=5, and `packet_features_available: false`.

## Forecast Contract

`POST /forecast` accepts a non-empty sequence of normalized states. Each state must contain exactly the feature keys in `models/nexsolve_world_model/feature_schema.json`: 18 flow, 22 packet-interface, and 6 temporal features. Values must be finite numbers. This remains the protected UNSW research model contract and is separate from the packet-only production analysis.

The response contains `currentState` and exactly five forecast points. Attack probability, predicted state, confidence, contextual stage, and explanation originate from the loaded model and existing research signal/attribution functions. Uncertainty is the deterministic complement of the model's margin confidence and is not calibrated probability.

With fewer than eight states, the service returns five explicit abstentions with null prediction fields. Malformed requests return `422 INVALID_FORECAST_REQUEST`.

## Artifact

The service loads:

- `models/nexsolve_world_model/model.npz`
- `models/nexsolve_world_model/preprocessing.npz`
- `models/nexsolve_world_model/config.json`
- `models/nexsolve_world_model/feature_schema.json`
- `models/nexsolve_world_model/metadata.json`

## Production Packet Analysis

The completed `data/processed/cic_ids2017_packet_windows.parquet` is read-only and contains 484 validated aggregated windows. `POST /api/analysis` returns the production analysis identifier; `GET /api/analysis/production-cic-ids2017/results` exposes validation, traffic totals, and evidence-bounded findings. `GET /api/traffic`, `GET /api/alerts`, and `GET /api/reports/production-cic-ids2017` provide the corresponding views.

Those findings use traffic heuristics from measured port-scan, retransmission, fragmentation, and SYN-pressure fields. They do not expose model probabilities or claim labeled attack classification.

Each finding also exposes `detection_method`, fired rule identifiers, measured metric/threshold pairs, and an explanation derived from the active rule. The active implementation is `HeuristicDetector`; the existing UNSW LSTM remains a separate `/forecast` research endpoint.

## Limitations

The forecast endpoint is the UNSW-trained research prototype. It has one small mixed-state test episode and is not a production packet forecast model. ATT&CK stages are contextual signals, not technique-level ground truth. Packet-only production findings are evidence-bounded heuristics, not supervised classifications or calibrated probabilities.
