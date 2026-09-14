# NexSolve Threat Hunting & Intelligence Query Engine

## Overview & Architecture

The **Threat Hunting & Intelligence Query Engine** is a core operational security intelligence subsystem within NexSolve. It transitions NexSolve from a passive incident and forecast display platform into an active, multi-modal investigation and threat-hunting workbench.

### Architectural Principles

1. **Deterministic Execution over In-Memory Intelligence Stores**
   - The engine queries structured intelligence records: `entity_profiles`, `entity_investigations`, `prioritized_threats`, `detection.findings`, `incident_story`, `campaign_clusters`, and the cross-modal `EvidenceGraph`.
   - **Zero PCAP re-parsing**: The engine operates directly on post-ingestion graph structures and entity dossiers in sub-millisecond execution times.

2. **Strict Epistemic Isolation**
   - Supported scopes:
     - `OBSERVED_ONLY`: Queries match strictly empirical, verified telemetry facts (first-party ground truth).
     - `INFERRED_AND_SUPPORTED`: Queries match observations and rule/graph-supported states (`RECONNAISSANCE`, `ANOMALY`).
     - `FORECAST_ONLY`: Queries match forward-looking Markovian and LSTM state projections.
     - `ALL`: Full epistemic fusion.
   - Guardrail: **Forecast projections never contaminate historical evidence or empirical threat queries.**

3. **Absence is Not Contradiction**
   - Unobserved entities or missing attributes return `total_matches = 0` or empty sets without fabricating default values.
   - Capture boundary conditions (`TERMINATION_NOT_OBSERVED_CAPTURE_BOUNDARY`) are explicitly carried into match uncertainties.

---

## Domain Query Model

Defined in `nexsolve_core/intelligence/query_model.py`:

- **Query Targets**:
  - `ENTITY`: Physical and logical hosts, endpoints, internal/external IPs.
  - `EVENT`: Discrete chronological network events and packet flow observations.
  - `INCIDENT`: Multi-entity reconstructed attack scenarios.
  - `CAMPAIGN`: Cross-capture or multi-incident clusters.
  - `PHASE`: Longitudinal attack progression phases (e.g. Baseline, Reconnaissance).
  - `EVIDENCE`: Heuristic findings, MITRE ATT&CK techniques, Zeek session states.
  - `GRAPH_NEIGHBOR`: Bounded N-hop traversals on the Evidence Intelligence Graph.
  - `EXPLANATION`: Attribution traces linking observations to verdicts.

- **Operators**:
  - Comparison: `=`, `!=`, `>`, `>=`, `<`, `<=`, `BETWEEN`.
  - Membership & Substring: `IN`, `NOT_IN`, `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`.
  - Existence: `EXISTS`, `NOT_EXISTS`.

- **Temporal Scopes**:
  - `DURING`, `BEFORE`, `AFTER`, `WITHIN`, `OVERLAPS`, `ANY`.
  - Supports window indices (`window_range=[0, 9]`) and floating-point timestamps.

---

## Controlled Predicate Registry

Defined in `nexsolve_core/intelligence/query_registry.py`. Provides 18 controlled field descriptors:

| Field | Target | Data Type | Description | Allowed Operators |
|---|---|---|---|---|
| `entity.ip` | ENTITY | string | Entity IPv4 address or hostname | `=`, `!=`, `IN`, `CONTAINS`, `STARTS_WITH` |
| `entity.role` | ENTITY | string | Role (SUSPECT, RECON_SOURCE, SERVER) | `=`, `!=`, `IN`, `CONTAINS` |
| `entity.attack_state` | ENTITY | string | Inferred state (BENIGN, RECONNAISSANCE) | `=`, `!=`, `IN` |
| `entity.fanout` | ENTITY | number | Count of distinct destinations contacted | `=`, `!=`, `>`, `>=`, `<`, `<=`, `BETWEEN` |
| `entity.port_diversity`| ENTITY | number | Number of distinct destination ports targeted | `=`, `!=`, `>`, `>=`, `<`, `<=`, `BETWEEN` |
| `entity.failure_ratio` | ENTITY | number | Ratio of TCP handshakes reset or unanswered | `=`, `!=`, `>`, `>=`, `<`, `<=`, `BETWEEN` |
| `entity.beaconing` | ENTITY | number | Low-jitter periodic communication score | `=`, `!=`, `>`, `>=`, `<`, `<=`, `BETWEEN` |
| `evidence.technique` | EVIDENCE | string | MITRE ATT&CK technique (e.g. T1046) | `=`, `!=`, `IN`, `CONTAINS` |
| `event.type` | EVENT | string | Chronological event type | `=`, `!=`, `IN`, `CONTAINS` |
| `phase.state` | PHASE | string | Dominant attack state in phase | `=`, `!=`, `IN` |

---

## Pre-Built Hunt Packs

Defined in `nexsolve_core/intelligence/hunt_packs.py`:

1. **High Destination-Port & Host Fan-Out** (`hunt_recon_fanout`):
   - Targets entities with `entity.port_diversity >= 5`.
2. **Confirmed Reconnaissance Entities** (`hunt_recon_state`):
   - Targets entities with `entity.attack_state = 'RECONNAISSANCE'`.
3. **Significant Behavioral Changes** (`hunt_behavior_change`):
   - Targets entities with anomalous velocity or connection shifts (`entity.behavior_change EXISTS`).
4. **Periodic Beaconing & Low-Jitter C2** (`hunt_beaconing_c2`):
   - Targets entities with `entity.beaconing >= 0.75`.
5. **Network Service Scanning (T1046)** (`hunt_t1046_evidence`):
   - Targets evidence grounded in MITRE technique T1046.
6. **High Handshake Failure Concentration** (`hunt_handshake_failures`):
   - Targets hosts with `entity.failure_ratio >= 0.6`.
7. **Reconstructed Incident Event Chronology** (`hunt_incident_chronology`):
   - Chronological event timeline extraction.
8. **Cross-Capture Campaign Clusters** (`hunt_campaign_clusters`):
   - Multi-capture cluster exploration.

---

## REST API Endpoints

Mounted in `model_service/app.py`:

- `POST /api/intelligence/query`: Accepts `IntelligenceQueryRequestModel`, runs `IntelligenceQueryEngine.execute_query()`, returns `QueryResultPayload`.
- `GET /api/intelligence/query/templates`: Returns all registered pre-built hunt packs.
- `GET /api/intelligence/query/predicates`: Returns all registered query predicate descriptors.
- `GET /api/intelligence/query/saved`: Lists saved hunts.
- `POST /api/intelligence/query/saved`: Persists custom hunting queries.

---

## Frontend Workspace

- Location: `frontend/src/components/investigation/ThreatHuntingWorkspace.tsx`
- Integrated into `JobResult.tsx` under section **2f-i**.
- Interactive features:
  - One-click **Pre-Built Hunt Packs** with tag filters.
  - Interactive **Target** and **Epistemic Scope** selectors.
  - Dynamic **Predicate Filter Builder** with add/remove rows.
  - **Matches Table** displaying semantic state, epistemic tier, match score, and port diversity.
  - **Match Inspector Drawer** displaying:
    - Grounding rationale ("WHY THIS MATCHED").
    - Supporting evidence nodes.
    - Graph evidence path (`ENTITY -> ATTACK_STATE -> MITRE_TECHNIQUE`).
    - One-click jump to **Entity Investigation** or **Analyst Decision**.
