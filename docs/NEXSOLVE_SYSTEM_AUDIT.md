# NexSolve Master System Architecture & Capability Audit (Corrected)

Generated: 2026-09-14
Classification: Architecture Baseline & Provenance Audit (Forensically Verified)

---

## 1. System Overview & Architectural Mandate

NexSolve is an enterprise-grade network security intelligence, world-modeling, and attack forecasting platform. Rather than serving as a narrow hackathon prototype or a black-box anomaly detector, NexSolve separates **Network Truth Extraction**, **Multi-Modal Evidence Correlation**, **State Representation**, **Temporal World Modeling**, and **Predictive Attack Progression**.

Current Overall Maturity: **Production Candidate Research Platform (Hardened Prototype)**.

---

## 2. Capability Audit Matrix (The 19 Core Capabilities)

| Capability | Current State | Implementation Path | Status & Maturity | Scientific Defensibility |
| :--- | :--- | :--- | :--- | :--- |
| **1. Zeek Session Semantics** | RFC 793 connection tracker | 
exsolve_core/network/session_state.py | PRODUCTION_CANDIDATE | Clean-room state machine; handles S0-OTH, midstream joins, truncations. Zeek-inspired native session semantics. |
| **2. RITA Behavioral Intelligence** | Bowley skewness, MAD, entropy | 
exsolve_core/behavior/periodicity.py | PRODUCTION_CANDIDATE | Robust non-parametric interval statistics; strictly evidence-only. Regularity does not imply maliciousness. |
| **3. NFStream Flow Intelligence** | Bidirectional asymmetry, rates | 
exsolve_core/flow/statistics.py | PRODUCTION_CANDIDATE | Exact mathematical asymmetry ratios bounded in [-1.0, 1.0]; no CFFI needed. |
| **4. Suricata Signature Ingestion** | Decoupled EVE JSON adapter | 
exsolve_core/evidence/suricata.py | PRODUCTION_CANDIDATE | Graceful fallback (NO_SURICATA_EVIDENCE_AVAILABLE); no fake alerts. |
| **5. Existing ML Anomaly Detection** | Statistical thresholds & windowing | ml/detection.py | PRODUCTION_CANDIDATE | Deterministic traffic heuristics and findings; uncalibrated. |
| **6. Temporal World Model** | 1-Layer NumPy LSTM + Linear Head | world_model.py, models/nexsolve_world_model_45/ | PRODUCTION_CANDIDATE | Validated on canonical 45 features; zero-fill strictly forbidden. Single-layer LSTM architecture. |
| **7. Forecasting Engine** | Multi-step forward rollouts | ml/forecasting/ | PRODUCTION_CANDIDATE | Supports K=1..5 horizons; explicitly abstains on missing context or K>5. |
| **8. Attack Progression** | Markovian transition forecaster | ml/forecasting/attack_progression.py | PRODUCTION_CANDIDATE | Enforces STATE_PERSISTENCE vs DOWNSTREAM_PROGRESSION vs ABSTAINED. Downstream Recon->DoS unsupported due to time gap. |
| **9. Evidence Graph & Fusion** | Multi-modal normalization | 
exsolve_core/fusion.py | PRODUCTION_CANDIDATE | Entity-evidence correlation; strict OBSERVED vs FORECAST scoping. Relational item list, not graph DB. |
| **10. Research Evaluation Framework** | Temporal split & metrics engine | ml/evaluation/ | RESEARCH_ONLY | Strict temporal evaluation without lookahead bias or future leakage. Decoupled from runtime API. |
| **11. Model Registry** | Versioned artifact loader | models/ & 
exsolve_core/state.py | PRODUCTION_CANDIDATE | Dual-directory layout with schema compatibility gate. |
| **12. PCAP Compatibility Layer** | Canonical extractor & validator | ml/data/pcap_extractor.py | PRODUCTION_CANDIDATE | Ingests arbitrary PCAP/PCAPNG; handles packet loss and corruption. High loss (>5%) blocks model readiness. |
| **13. API / Platform Architecture** | FastAPI async job pipeline | model_service/app.py, jobs.py | PRODUCTION_CANDIDATE | Stage-based async processing (/jobs, /jobs/{id}/result). In-memory job store. |
| **14. Security Architecture** | Input sanitization & limits | 
exsolve_core/config.py | PRODUCTION_CANDIDATE | Magic byte validation, path traversal guards, upload size caps (100 MB). |
| **15. Observability** | Processing metrics & telemetry | model_service/jobs.py | PRODUCTION_CANDIDATE | Decouples operational telemetry from security threat evidence. |
| **16. Explainability** | Feature attribution & provenance | world_model.py (explain), usion.py | PRODUCTION_CANDIDATE | Feature replacement perturbation attribution + multi-modal evidence chain. Not causal. |
| **17. Dataset / Evaluation Pipeline** | Parquet & packet dataset loader | ml/data/production_packet_dataset.py | RESEARCH_ONLY | Validates CIC-IDS2017 windows and schema integrity. Static local datasets. |
| **18. Online Learning Architecture** | Drift & promotion interfaces | Architecture specification | PLANNED / SPEC_ONLY | Defined protocol; zero automated silent updates permitted. Static weights enforced. |
| **19. Research Documentation** | Methodology & provenance specs | docs/ | PRODUCTION_CANDIDATE | Comprehensive mathematical formulas, audits, and schemas. |

---

## 3. Structural Component Analysis & Reality Downgrades

### 3.1. Production Candidate Components
- Canonical 45-feature world model runtime (models/nexsolve_world_model_45/model.npz).
- Multi-modal evidence extraction: Zeek-inspired session tracking, RITA interval periodicity, NFStream flow asymmetry, and Suricata EVE ingestion.
- Deterministic 46->45 schema compatibility gate (
exsolve_core/state.py).
- Asynchronous job execution system with polling, progress, and stage tracking (model_service/jobs.py).
- Real PCAP upload and validation endpoint (model_service/pcap_upload.py).
- Interactive dashboard components: JobResult, NetworkIntelligenceCard, AttackHorizonCard, AttackProgressionCard, EvidenceChain.

### 3.2. Research-Only Components
- Offline scientific evaluation framework (ml/evaluation/): AUROC, AUPRC, Brier score, ECE.
- Multi-dataset cross-evaluation harness (ml/evaluation/multi_dataset_evaluator.py).
- Parquet packet dataset generation (ml/data/production_packet_dataset.py).

### 3.3. Planned / Specification-Only Concepts
- Online model retraining: Must remain isolated; candidate weights require offline evaluation and explicit human promotion.
- Live streaming socket telemetry (NetFlow daemon, live Zeek broker socket).

### 3.4. Defended Scientific Boundaries (Strict Negatives)
1. **Never fabricate mean_tcp_rtt**: Passive captures missing full 3-way handshakes must abstain rather than synthesize round-trip timings.
2. **Never zero-fill unobserved features**: Zero-filling falsifies real network telemetry.
3. **No fabricated downstream transitions**: Attack progression models only predict downstream transitions when backed by empirical transition probabilities.
4. **Strict OBSERVED vs FORECAST segregation**: Evidence items derived from captured packets are never labeled as forecasts, and forecast rollouts are never labeled as ground truth observations.
