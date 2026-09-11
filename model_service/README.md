# NexSolve World Model V1 Service

Small local FastAPI wrapper around `models/nexsolve_world_model/`. It loads the existing NumPy model and does not train, download, or create predictions outside that model.

`POST /api/pcap/analyze` accepts `.pcap` and `.pcapng` uploads up to 64 MB. Uploads are written to unique temporary directories under `runtime/`, processed by the existing packet-window extractor and `traffic_heuristics` detector, then cleaned up. Production Parquet and PCAP assets are never used as upload destinations.

The upload response is the current analysis contract: `analysis_id`, `status`, `source`, `upload`, `validation`, `traffic`, `detection`, and extraction `quality`. The frontend then reads `GET /api/analysis/{analysis_id}/status`, `GET /api/analysis/{analysis_id}/results`, and `GET /api/reports/{analysis_id}`. Production continues to use the same routes with `production-cic-ids2017`; uploaded analyses are persisted database records and are never merged with that production ID.

## Canonical capture foundation

The live capture path uses the typed contracts in `nexsolve_core.schemas`: `PacketRecord` preserves packet observations and provenance, `FlowRecord` groups bidirectional TCP/UDP and non-port traffic without claiming incomplete TCP sessions are complete, and `TemporalWindow` records deterministic 60-second packet/flow membership and aggregate features. `CaptureQuality` records parsing, support, ordering, duplicate, protocol, VLAN, fragmentation, and incomplete-flow quality signals with `GOOD`, `DEGRADED`, or `INSUFFICIENT` status. `Provenance` links every object to capture IDs, packet indexes, flow/window IDs, source timestamps, and transformation stage.

The packet foundation is intentionally not a model adapter. The compatibility report lists the existing world-model feature contract as unavailable when PCAP windows cannot provide it. Missing features remain missing; no zero-filled `NetworkState` is produced by the capture path.

## PCAP NetworkState bridge

Each uploaded canonical `TemporalWindow` is converted into a `NetworkStateCandidate` by `nexsolve_core.state`. The candidate preserves flow, packet, protocol, detection, quality, label, and provenance metadata. A central group-qualified registry documents all 46 existing model features, including duplicate names that belong to different groups such as flow and packet `mean_iat`.

The bridge uses only packets observed at or before the current window end. Flow-spanning windows use the observed packet prefix, not the eventual flow termination or future bytes. Candidate history is chronological, contiguous, capture-scoped, and lookback-aware (`8` windows). The API exposes `network_state.available`, history status, candidate window IDs, and structured `model_compatibility` metadata.

This is a representation bridge, not production forecasting. PCAP candidates remain `label: UNKNOWN` unless a trusted label source is supplied. Missing or unreliable model features remain explicitly unavailable, and the compatibility gate rejects semantically incomplete states without dense zero-filling.

## Scientific model status

Phase 4 evaluation is separate from the upload path. Run `python -m ml.evaluation.scientific_forecasting` to evaluate the frozen UNSW artifact and baselines at T+1 through T+5. The current report keeps promotion at `HOLD`: the corrected evaluation has one eligible future mixed-state episode, 13 aligned five-horizon cases, persistence ahead of the existing LSTM, and validation support insufficient for calibration. No forecast is exposed by production PCAP analysis.

Phase 5 adds a separate dataset audit and direct multi-horizon logistic search. It preserves UNSW, TON-IoT, CIC, and packet-window semantics as separate domains. `artifacts/models/candidate_v2` is an evaluation artifact only; persistence remains the strongest validated baseline and no new model is production-connected.

### Capture correctness policy

The extractor preserves packet order and source timestamps for provenance. It counts equal and non-monotonic timestamps; window aggregation uses the deterministic `(timestamp, packet_index)` key and records whether a window was reordered. Duplicate candidates are retained, linked to their first packet index, and exposed through `duplicate_packets`, `duplicate_ratio`, `raw_observed_count`, and `deduplicated_count`; no duplicate is silently removed.

Declared IP lengths are used for truncation only when available. A packet is `TRUE` truncated when the declaration exceeds observed bytes, `FALSE` when sufficient bytes are proven, and `UNKNOWN` otherwise. IPv6 extension chains and fragment headers are preserved, but fragment reassembly is not implemented. VLAN stacks, ICMP/ICMPv6 type/code, and unsupported protocol/link-layer status are explicit canonical metadata.

TCP completeness is conservative: `COMPLETE` requires SYN, SYN-ACK, ACK, and FIN/RST evidence; handshake-incomplete flows are `INCOMPLETE`; flows without enough handshake evidence are `UNKNOWN`. `CaptureQuality` is `INSUFFICIENT` for empty or one-packet captures, `DEGRADED` for any malformed, unsupported, truncation, timestamp, duplicate, fragmentation, or incomplete-flow signal, and `GOOD` only for at least two parsed packets with no such signal. Unknown truncation metadata also prevents `GOOD`.

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
