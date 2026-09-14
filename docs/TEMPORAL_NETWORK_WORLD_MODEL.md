# NexSolve Temporal Network World Model & Intelligence State Engine

## Architectural Overview

The **Temporal Network World Model** is NexSolve's unified runtime foundation that models how the network state evolves across continuous observation windows. Rather than treating PCAP analysis as disjointed tables or static summaries, it maintains a persistent, queryable representation of what existed, who communicated with whom, what behavioral changes emerged, what evidence grounded each transition, and what may happen next.

---

## 1. Domain Entities & State Representation

The temporal domain is established in `nexsolve_core/temporal/world_state.py`:

- **`TemporalNetworkWindow`**: Represents an individual 60-second time slice:
  - `window_id`, `sequence_index`, `start_time`, `end_time`, `duration_seconds`
  - `packet_count`, `flow_count`, `tcp_retransmission_rate`
  - `active_entity_count`, `active_relationship_count`, `change_signals_count`
  - `dominant_attack_stage`
  - `is_capture_boundary`: Explicitly marks whether this window forms the capture edge.

- **`EntityTemporalState`**: Per-window behavioral and topological state of an entity:
  - `entity_key`: IP or host identifier.
  - `presence`: `NEWLY_EMERGED`, `ACTIVE`, `NOT_OBSERVED_IN_WINDOW`, or `LAST_OBSERVED_AT_CAPTURE_BOUNDARY`.
  - `attack_state`: `BENIGN`, `RECONNAISSANCE`, `LATERAL_MOVEMENT`, etc.
  - `fanout`, `port_diversity`, `bytes_sent`, `bytes_recv`, `packets`, `failure_ratio`
  - `active_peers`, `active_ports`, `composite_risk_score`.

- **`RelationshipTemporalState`**: Directed communication pair active within window $w$:
  - `src_entity`, `dst_entity`, `dst_port`, `protocol`
  - `status`: `NEW`, `PERSISTED`, `NOT_OBSERVED_IN_WINDOW`, `LAST_OBSERVED_AT_CAPTURE_BOUNDARY`
  - `first_seen_window`, `last_seen_window`, `packet_count`, `byte_count`, `connection_count`.

- **`WorldStateSnapshot`**: Complete snapshot of the network state at sequence index $w$.
- **`WorldStateDiff`**: Deterministic state delta between window $A$ and window $B$.
- **`TemporalNetworkWorldState`**: Capture-wide temporal container maintaining snapshots, trajectories, cross-window indexes, graph bindings, and forecast contexts.

---

## 2. Epistemic Separation & Scientific Safety

NexSolve enforces strict epistemic demarcation:
1. **Historical Ground Truth (`OBSERVED`)**:
   - Only packets and flows directly verified from the capture are admitted into `WorldStateSnapshot`.
   - Heuristics and signature alerts are tagged as `SUPPORTED_OBSERVATION` or `HEURISTIC_FINDING`.
2. **Downstream Forecast Projections (`FORECAST`)**:
   - LSTM multi-horizon rollouts remain strictly segregated in `forecast_points` and `attack_progression`.
   - Forecast points are never zero-filled or back-propagated into historical windows.
3. **Absence Semantics (`NOT_OBSERVED_IN_WINDOW`)**:
   - Absence of an entity in window $w$ does not equate to termination.
   - Termination is never declared without explicit FIN/RST or connection teardown.
4. **Capture Boundary Semantics (`LAST_OBSERVED_AT_CAPTURE_BOUNDARY`)**:
   - Entities active in the final window of a capture are designated as `LAST_OBSERVED_AT_CAPTURE_BOUNDARY`.

---

## 3. API Surface

The engine exposes dedicated endpoints in `model_service/app.py`:
- `GET /api/intelligence/world`: Top-level world state summary.
- `GET /api/intelligence/world/windows`: Window index list with entity and anomaly metrics.
- `GET /api/intelligence/world/window/{window_id}`: Full snapshot for a specific window.
- `GET /api/intelligence/world/diff?window_a={a}&window_b={b}`: Deterministic state difference.
- `GET /api/intelligence/world/entity/{entity_id}/timeline`: Entity trajectory across all windows.

---

## 4. Frontend Integration

Mounted as `<TemporalWorldView />` in `frontend/src/components/JobResult.tsx`:
- **Observation Sequence Timeline**: Interactive scrubber with window status badges.
- **Snapshot Inspector**: Active entities, communication flows, and risk indicators.
- **What Changed (Temporal Diff)**: Compares any two windows to reveal newly emerged hosts, fanout surges, and attack-state transitions.
- **Entity Trajectories**: Multi-window heatstrips showing presence longevity across the capture duration.
