# NexSolve Capability Forensic Verification & Reality Audit

Generated: 2026-09-14
Classification: Forensic Codebase Truth & Verification

Maturity Classification Vocabulary:
- IMPLEMENTED: Code exists and functions in unit tests.
- INTEGRATED: Wired into the main ingestion/analysis pipeline.
- REAL_PCAP_VALIDATED: Evaluated and verified on real packet captures.
- SCIENTIFICALLY_EVALUATED: Evaluated with formal benchmarks, metrics, and baselines.
- PRODUCTION_CANDIDATE: Fully integrated, validated, hardened, and defensively guarded.
- PRODUCTION: Formally deployed in continuous operational environments.
- RESEARCH_ONLY: Algorithmic prototype for experiments; not in runtime inference path.
- PLANNED: Interface or concept specified, but no functional implementation exists.
- UNVERIFIED: Cannot be confirmed with existing repository evidence.

---

## 1. Executive Summary & Verification Findings

A strict forensic audit was conducted on the entire NexSolve repository to verify claims made in previous documentation (docs/NEXSOLVE_SYSTEM_AUDIT.md, docs/PRODUCT_READINESS.md, docs/OPEN_SOURCE_CORE_EXTRACTION_AUDIT.md).

### Critical Reality Downgrades & Discoveries:
1. **System Maturity**: NexSolve is **NOT** enterprise-grade production software. It is a **Production Candidate Research Platform (Hardened Prototype)**.
2. **World Model Architecture**: Documentation claimed a 2-layer NumPy LSTM. Inspection of world_model.py (class NumpyLSTM) proves it is an **explicit single-layer NumPy LSTM with a linear projection head** (W in R^{4H x (D+H)}, Wy in R^{(D+1) x H}).
3. **Flow Counts (283 vs 374)**: The apparent discrepancy between 283 and 374 flows is resolved: on friday_10windows_slice.pcap, there are exactly **283 unique 4-tuple flow IDs** across the capture, which produce **374 window-sliced flow records** across the 10 temporal 60-second windows.
4. **Evidence Graph Structure**: NexSolve does **NOT** possess an explicit graph database or GNN network. It implements a **normalized multi-modal evidence list with semantic relationship bindings** (entities, mitre_technique_id, temporal_scope).
5. **Model Registry**: NexSolve does **NOT** have a database-backed or dynamic model registry service. It has a **file-based dual-model layout** (models/nexsolve_world_model/ and models/nexsolve_world_model_45/) governed by a deterministic schema compatibility gate in nexsolve_core/state.py.
6. **Online Learning**: Online learning does **NOT** exist. The codebase implements static weights with drift-awareness design principles.

---

## 2. Capability Forensic Table (The 19 Capabilities)

| # | Capability | Implementation Path | Production Integration | Tests | Real-PCAP Evidence | Scientific Evidence | Known Limitations | Actual Maturity | Previous Claim | Verified Verdict |
|---|---|---|---|---|---|---|---|---|---|---|
| **1** | Zeek-inspired session semantics | nexsolve_core/network/session_state.py | Integrated (pcap_upload.py) | 13 tests | 193 sessions tracked on Friday slice | RFC 793 state transitions | No layer-7 deep application protocol parsing | PRODUCTION_CANDIDATE | Production-Ready | Verified (with Zeek-inspired naming) |
| **2** | RITA-inspired periodicity | nexsolve_core/behavior/periodicity.py | Integrated (pcap_upload.py) | 5 tests | 189 communication pairs evaluated | Bowley skewness, MAD, entropy formulas | Requires >= 4 events; regularity != maliciousness | PRODUCTION_CANDIDATE | Production-Ready | Verified (Behavioral regularity only) |
| **3** | NFStream-inspired flow intelligence | nexsolve_core/flow/statistics.py | Integrated (pcap_upload.py) | 3 tests | 374 flow records profiled | Directional asymmetry in [-1.0, 1.0] | Operates on reconstructed flows; no CFFI engine | PRODUCTION_CANDIDATE | Production-Ready | Verified |
| **4** | Suricata signature ingestion | nexsolve_core/evidence/suricata.py | Integrated (pcap_upload.py) | 3 tests | Emits NO_SURICATA_EVIDENCE_AVAILABLE on passive PCAP | External EVE JSON schema normalization | No live Suricata daemon bundled | PRODUCTION_CANDIDATE | Production-Ready | Verified (Clean fallback confirmed) |
| **5** | ML / anomaly detection | ml/detection.py | Integrated (app.py, pcap_upload.py) | 4 tests | Evaluates windowed features | Statistical heuristics | Raw scores uncalibrated; not true probabilities | PRODUCTION_CANDIDATE | Production-Ready | Verified (Uncalibrated heuristic) |
| **6** | Temporal world model | world_model.py, models/nexsolve_world_model_45/ | Integrated (pcap_upload.py) | 6 tests | Rollout on 10 windows | Evaluated on UNSW/CIC temporal splits | Single-layer NumPy LSTM (not 2-layer) | PRODUCTION_CANDIDATE | Production-Ready | Downgraded architecture description |
| **7** | Forecasting engine | ml/forecasting/ | Integrated (pcap_upload.py) | 19 tests | K=1..5 rollouts on Friday slice | Persistence baselines; abstains if <8 windows | Unsupported horizons (K>5) abstain | PRODUCTION_CANDIDATE | Production-Ready | Verified |
| **8** | Attack progression forecaster | ml/forecasting/attack_progression.py | Integrated (pcap_upload.py) | 7 tests | Evaluated on Friday slice (abstains on benign) | Empirical Markov transitions from Friday episodes | Downstream Recon->DoS unsupported due to time gap | PRODUCTION_CANDIDATE | Production-Ready | Verified (Persistence vs Downstream) |
| **9** | Evidence graph / fusion | nexsolve_core/fusion.py | Integrated (pcap_upload.py) | 8 tests | Multi-modal normalization on Friday slice | Strictly isolates OBSERVED from FORECAST | Relational entity-evidence list, not graph DB/GNN | PRODUCTION_CANDIDATE | Production-Ready | Downgraded from True Graph |
| **10** | Research evaluation framework | ml/evaluation/ | Decoupled (ml/evaluation/) | 16 tests | Evaluated against baseline splits | AUROC, AUPRC, Brier, ECE, episode splits | Offline research framework; not in runtime API | RESEARCH_ONLY | Production-Ready | Downgraded to RESEARCH_ONLY |
| **11** | Model registry | models/, nexsolve_core/state.py | Integrated (pcap_upload.py) | 3 tests | Selects 45 vs 46 model via schema gate | Evaluated model metadata | Directory layout with schema gate; no dynamic registry service | PRODUCTION_CANDIDATE | Production-Ready | Downgraded from Registry Service |
| **12** | PCAP compatibility layer | ml/data/pcap_extractor.py | Integrated (app.py, jobs.py) | 12 tests | Ingests arbitrary PCAP/PCAPNG | Deterministic packet/flow extraction | High loss (>5%) blocks model readiness | PRODUCTION_CANDIDATE | Production-Ready | Verified |
| **13** | API / platform architecture | model_service/app.py, jobs.py | Live FastAPI service | 17 tests | Live HTTP upload & polling verified | Stage-aware state machine | In-memory job store (Postgres optional) | PRODUCTION_CANDIDATE | Production-Ready | Verified |
| **14** | Security architecture | nexsolve_core/config.py, app.py | Integrated across endpoints | 12 tests | Tested path traversal, bad extensions, corrupt headers | Magic byte validation, upload limits | No multi-tenant auth layer implemented | PRODUCTION_CANDIDATE | Production-Ready | Verified |
| **15** | Observability | model_service/jobs.py | Integrated in job responses | 4 tests | Records wall-clock latency on PCAPs | Decoupled from threat evidence | Basic process metrics; no Prometheus exporter | PRODUCTION_CANDIDATE | Production-Ready | Verified |
| **16** | Explainability | world_model.py (explain), fusion.py | Integrated in forecast response | 3 tests | Top-8 feature contributions on Friday slice | Feature replacement perturbation | Model attribution only; NOT causal | PRODUCTION_CANDIDATE | Production-Ready | Verified (Attribution only) |
| **17** | Dataset / evaluation pipeline | ml/data/production_packet_dataset.py | Decoupled | 8 tests | Loads CIC-IDS2017 Parquet | Parquet validation & window ordering | Static local datasets | RESEARCH_ONLY | Production-Ready | Downgraded to RESEARCH_ONLY |
| **18** | Online-learning architecture | None (Architecture spec only) | NOT WIRED | 0 tests | None | Static weights only | Online updates intentionally blocked | PLANNED / SPEC_ONLY | Production-Ready | Downgraded to PLANNED |
| **19** | Research documentation | docs/ | Comprehensive docs | N/A | Corresponds to codebase | Formal mathematical specs & audits | Requires continuous reality alignment | PRODUCTION_CANDIDATE | Production-Ready | Verified |
