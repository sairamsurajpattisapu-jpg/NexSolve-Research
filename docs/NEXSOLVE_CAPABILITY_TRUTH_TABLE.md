# NexSolve Capability Truth Table & Authoritative Reference

Generated: 2026-09-14
Auditor: Forensic Reality Audit Pass

| Capability | Actual Implementation | Production Wired | Real-PCAP Tested | Scientific Validation | Current Maturity | Known Limitation | Evidence Location |
|---|---|---|---|---|---|---|---|
| **1. Zeek Session Semantics** | RFC 793 connection state machine | Yes (pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Deterministic protocol transitions | PRODUCTION_CANDIDATE | No layer-7 deep protocol parsing | 
exsolve_core/network/session_state.py, 	ests/test_zeek_session_state.py |
| **2. RITA Behavioral Periodicity** | Bowley skewness, MAD, entropy, CV | Yes (pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Standard non-parametric formulas | PRODUCTION_CANDIDATE | Requires >= 4 events; regularity != attack | 
exsolve_core/behavior/periodicity.py, 	ests/test_rita_periodicity.py |
| **3. NFStream Flow Intelligence** | Bounded packet & byte asymmetry | Yes (pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Exact mathematical ratios | PRODUCTION_CANDIDATE | Computed on reconstructed flows, no CFFI | 
exsolve_core/flow/statistics.py, 	ests/test_nfstream_flow_intelligence.py |
| **4. Suricata Signature Ingestion** | EVE JSON adapter & clean fallback | Yes (pcap_upload.py) | Yes (fallback verified) | Schema validation | PRODUCTION_CANDIDATE | No bundled runtime daemon | 
exsolve_core/evidence/suricata.py, 	ests/test_suricata_evidence.py |
| **5. ML / Anomaly Detection** | Windowed feature heuristics | Yes (pp.py, pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Statistical deviation thresholds | PRODUCTION_CANDIDATE | Scores uncalibrated | ml/detection.py, ml/tests/test_detection.py |
| **6. Temporal World Model** | 1-Layer NumPy LSTM + Linear Head | Yes (pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Temporal episode splits | PRODUCTION_CANDIDATE | 1-layer LSTM (earlier claimed 2-layer) | world_model.py, 	ests/test_world_model.py |
| **7. Forecasting Engine** | Recursive K=1..5 rollout | Yes (pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Evaluated on K=1, 3, 5 | PRODUCTION_CANDIDATE | Abstains on K>5 or lookback < 8 | ml/forecasting/, 	ests/test_scientific_forecasting.py |
| **8. Attack Progression** | Markov empirical forecaster | Yes (pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Transition probabilities from ground truth | PRODUCTION_CANDIDATE | Recon->DoS unsupported due to temporal gap | ml/forecasting/attack_progression.py, 	ests/test_attack_progression.py |
| **9. Evidence Graph & Fusion** | Normalized multi-modal item list | Yes (pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Strict OBSERVED vs FORECAST scopes | PRODUCTION_CANDIDATE | Relational list with entity keys, not graph DB | 
exsolve_core/fusion.py, 	ests/test_evidence_normalization.py |
| **10. Research Evaluation Framework** | AUROC, AUPRC, Brier, ECE, episodes | No (Offline evaluation suite) | Yes (Dataset episodes) | Rigorous statistical metrics | RESEARCH_ONLY | Decoupled from runtime inference service | ml/evaluation/, 	ests/test_phase5_search.py |
| **11. Model Registry** | 45 vs 46 directory schema gate | Yes (pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Feature schema verification | PRODUCTION_CANDIDATE | Directory layout + gate, not dynamic service | models/, 
exsolve_core/state.py |
| **12. PCAP Compatibility Layer** | Packet/flow reader & validator | Yes (pp.py, jobs.py) | Yes (riday_10windows_slice.pcap) | High loss & header validation | PRODUCTION_CANDIDATE | High loss (>5%) blocks model readiness | ml/data/pcap_extractor.py, 	ests/test_pcap_diagnostics.py |
| **13. API / Platform Architecture** | FastAPI async job pipeline | Live Service | Yes (HTTP live testing) | State machine stage progression | PRODUCTION_CANDIDATE | In-memory job store (Postgres optional) | model_service/app.py, jobs.py, 	ests/test_async_jobs.py |
| **14. Security Architecture** | Input sanitization, caps, magic bytes | Yes (pp.py, config.py) | Yes (Rejects malformed/bad exts) | Hardened parameter boundaries | PRODUCTION_CANDIDATE | No multi-tenant auth layer implemented | 
exsolve_core/config.py, 	ests/test_security_hardening.py |
| **15. Observability** | Wall-clock latency & throughput | Yes (jobs.py) | Yes (Returned in result) | Microsecond resolution timers | PRODUCTION_CANDIDATE | Process metrics; no Prometheus exporter | model_service/jobs.py |
| **16. Explainability** | Feature perturbation attribution | Yes (pcap_upload.py) | Yes (riday_10windows_slice.pcap) | Baseline vs replacement probability delta | PRODUCTION_CANDIDATE | Model attribution only; NOT causal | world_model.py (explain), 
exsolve_core/fusion.py |
| **17. Dataset Pipeline** | Parquet & packet dataset loader | No (Offline pipeline) | Yes (CIC-IDS2017) | Parquet validation | RESEARCH_ONLY | Static local datasets | ml/data/production_packet_dataset.py |
| **18. Online Learning Architecture** | None (Static weights enforced) | No (Intentionally blocked) | N/A | Specification only | PLANNED / SPEC_ONLY | Zero automated model retraining | docs/FINAL_END_TO_END_ARCHITECTURE.md |
| **19. Research Documentation** | Comprehensive specifications | Yes (docs/) | Yes | Corresponds directly to codebase | PRODUCTION_CANDIDATE | Requires continuous truth alignment | docs/ |
