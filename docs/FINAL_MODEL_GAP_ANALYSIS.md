# NexSolve: Final World Model Architectural Gap Analysis

**Document Version:** 1.0.0  
**Date:** September 2026  
**Status:** Approved Architectural Audit  
**Baseline Reference:** Candidate V2 (`models/candidate_v2/`, SHA-256 verified)  

---

## 1. Executive Summary

This document performs an exhaustive audit of the existing Machine Learning codebase in NexSolve and specifies the architectural roadmap for constructing the **Final NexSolve Network World Model**. 

Candidate V2 established an authoritative, zero-leakage, 45-feature temporal LSTM baseline operating on 60-second windows with an 8-window lookback. While Candidate V2 solved the chronological split leakage and achieved strong onset detection ($T+1$ Recall: 1.0000, F1: 0.7857 on Validation Episode 2; $T+1..T+5$ F1: 0.9423–1.0000 on Test Episode 3), it remains a single-view, monolithic recurrent model with flat feature concatenation, lack of host/graph multi-view representation learning, uncalibrated long-horizon uncertainty bounds, and limited risk intelligence outputs.

The Final World Model transitions from a single recurrent state to a **multi-view, multi-task Network World Model** ($Z_t$) driven by modular feature registries, causal temporal intelligence, behavioral host dynamics, dynamic graph evolution, self-supervised representation learning, calibrated multi-horizon forecasting ($T+1$ through $T+5$), evidence-based risk indicators, and a multi-level abstention engine.

---

## 2. Current Capability

The repository currently provides the following verified capabilities:

1. **Deterministic Candidate V2 Baseline:**
   - Vectorized NumPy LSTM ($D=45, H=24, K=46$).
   - 45 canonical features (17 flow, 22 packet, 6 temporal velocity).
   - Zero TCP RTT fabrication (strictly excluded).
   - Cryptographic manifest verification (`manifest.json` SHA-256 hashes).
   - Calibrated decision threshold ($\tau^* = 0.30$) and hybrid persistence blending ($\alpha = 0.25$).
   - Machine-readable abstention codes (`INSUFFICIENT_HISTORY`, `NON_CONTIGUOUS_TIMESTAMPS`, `FEATURE_SCHEMA_MISMATCH`, etc.).

2. **Leakage-Safe Temporal Partitioning:**
   - Chronological partition (`v2_chronological_split`) across UNSW-NB15 episodes:
     - Train: Episodes 0 + 1 (744 windows, 118 attacks, 626 benign, 728 sequences).
     - Validation: Episode 2 (25 windows, 15 attacks, 10 benign, 17 sequences, onset at window 14).
     - Test: Episode 3 (562 windows, 562 attacks, 554 sequences).
   - Strict scaling parameters fit only on the Train partition.
   - Non-overlapping episode sequences (zero sequences spanning episode transitions or sensor downtime).

3. **High-Speed PCAP Ingestion & Extraction:**
   - `FastPcapDecoder` and `pcap_extractor.py` for direct binary frame decoding.
   - Window aggregation into 60s windows (`TemporalWindow`, `PacketRecord`, `FlowRecord`).
   - Quality assessment scoring and payload truncation detection.

4. **Temporal Graph Foundations:**
   - `nexsolve_core/temporal_graph.py` models $G_t = (V_t, E_t)$ snapshots across 60s windows.
   - Computes degrees, fan-in/fan-out, active ports, peer IPs, activity scores, and structural change metrics.
   - Mode B graph fusion projection (`ml/forecasting/graph_fusion.py`).

5. **Formal Evidence & Abstention Primitives:**
   - `evidence_engine.py` provides 9-tier evidence hierarchies (PCAP -> PACKET -> FLOW -> WINDOW -> FEATURE -> DETECTION -> TECHNIQUE -> STAGE -> FORECAST).
   - `forecast_abstention.py` provides deterministic gating against corrupted or underspecified inputs.

---

## 3. Missing Capability

The audit reveals the following critical capabilities required for the Final World Model:

1. **Modular 18-Family Feature Registry:**
   - Current features are hardcoded in `world_model.py` as 45 flat strings.
   - Missing explicit registry declaring semantics, types, telemetry sources, availability conditions, normalization requirements, causal flags, and production safety guarantees across 18 distinct families:
     1. Packet, 2. Flow, 3. TCP, 4. UDP, 5. DNS, 6. HTTP, 7. TLS, 8. SSH, 9. ICMP, 10. ARP, 11. DHCP, 12. Temporal, 13. Behavioral, 14. Host, 15. Graph, 16. Statistical, 17. Observability, 18. Missingness.
   - Missing explicit missingness indicators to prevent accidental zero-filling of unobserved protocols.

2. **Multi-View Representation Learning & Cross-View Fusion:**
   - Current model linearly pools all 45 inputs into a single LSTM cell ($W \in \mathbb{R}^{96 \times 69}$).
   - Missing modular sub-encoders:
     - Packet Encoder (volumetric/size/flag dynamics).
     - Flow Encoder (session durations, bytes, rates).
     - Protocol Encoder (L4/L7 protocol behavior and port semantics).
     - Host Intelligence Encoder (host-level temporal activity and fan-out).
     - Temporal Velocity Encoder (acceleration, burstiness, rolling volatility).
     - Dynamic Graph Encoder (structural density, centrality, edge churn).
     - Observability / Missingness Encoder (masking unobserved telemetry).
   - Missing unified Cross-View Fusion mechanism producing the canonical Network World State ($Z_t$).

3. **Self-Supervised Learning & Pretraining Objectives:**
   - Current training optimizes only future state MSE and label BCE.
   - Missing investigated self-supervised objectives: next-state representation contrast, masked feature reconstruction, and temporal consistency.

4. **Multi-Task Prediction Heads on World State $Z_t$:**
   - Current model outputs only a single forward scalar logit + 45 predicted raw features.
   - Missing dedicated output heads for:
     - Future continuous state forecasting ($T+1$ to $T+5$).
     - Multi-horizon attack probability and trajectory risk.
     - Attack stage estimation (Recon, Lateral, C2, Exfil, Impact).
     - Attack progression trajectory.
     - Anomaly detection score (reconstruction / residual error).
     - Novelty / Out-of-Distribution (OOD) score.
     - Host risk ranking.
     - Communication / edge risk.
     - Observed network risk indicators.
     - Calibrated epistemic and aleatoric uncertainty bounds.
     - Observability and evidence sufficiency scores.

5. **Evidence-Based Risk Indicator Engine:**
   - Current system lacks a structured engine outputting observed risk indicators with: `entity`, `observation`, `severity`, `persistence`, `trend`, `evidence`, `confidence`, and `observability`.
   - Must output "OBSERVED RISK INDICATOR" rather than unsubstantiated claims of vulnerability or compromise.

6. **Calibrated Uncertainty & OOD Diagnostics:**
   - Current confidence is heuristic ($2 \cdot |p - 0.5|$).
   - Missing formal Expected Calibration Error (ECE), Brier score tracking, temperature/isotonic calibration, and Mahalanobis/reconstruction-based OOD detection.

7. **Low-Data & Degradation Regime Evaluation:**
   - No systematic evaluation across 100%, 50%, 25%, 10%, and 5% data regimes, short captures, or missing protocol families.

---

## 4. Reusable Components

The following components are scientifically sound, well-tested, and should be preserved and reused directly without unnecessary changes:

| Component | File Path | Rationale for Reuse |
| :--- | :--- | :--- |
| **Chronological Splitter** | `ml/forecasting/temporal_split.py` | Rigorously verified, zero-leakage, handles contiguous episodes and holdout sets. |
| **PCAP Binary Decoder** | `ml/data/fast_pcap_decoder.py` | Fast, robust pcap parsing without memory leaks. |
| **PCAP Frame Extractor** | `ml/data/pcap_extractor.py` | Extracts valid flows and packets into typed dataclasses. |
| **Temporal Graph Core** | `nexsolve_core/temporal_graph.py` | Models nodes, edges, snapshots, degrees, fan-in/fan-out, and graph churn. |
| **Baseline Forecasting Models** | `ml/forecasting/baselines.py` | Standardized `PersistenceBaseline` and `LogisticRegressionBaseline` for benchmarking. |
| **Evidence Data Model** | `ml/forecasting/evidence_engine.py` | Canonical `EvidenceItem`, `EvidenceGraph`, and polarity definitions. |
| **Candidate V2 Artifacts** | `models/candidate_v2/` | Immutable baseline reference against which the Final Model will be compared. |

---

## 5. Components Requiring Refactor

The following components require focused refactoring to support the Final World Model without breaking existing inference contracts:

| Component | File Path | Nature of Refactor |
| :--- | :--- | :--- |
| **Model Registry** | `ml/registry.py` | Add registration, spec resolution, manifest checksums, and loading for `final_world_model`. Maintain full backward compatibility for `candidate_v2`. |
| **World Model Representation** | `world_model.py` | Extend `NetworkState` to carry structured multi-view feature maps, host maps, and graph snapshots while preserving `encode_45()` and backward compatibility for V2. |
| **Production Inference** | `ml/forecasting/production_inference.py` | Extend to support multi-view inputs and dispatch to the Final World Model while maintaining the existing `candidate_v2` pipeline as a fully working baseline option. |
| **Dual-Mode Graph Fusion** | `ml/forecasting/graph_fusion.py` | Upgrade graph fusion from a downstream heuristic blend to a first-class feature/state embedding contributor. |

---

## 6. Components Requiring New Implementation

The following new modules and architectures will be implemented for the Final World Model:

| Module / System | Target File Path | Primary Responsibilities |
| :--- | :--- | :--- |
| **Modular Feature Registry** | `ml/features/feature_registry.py` | Complete catalog of 18 feature families, schema validation, metadata declaration (causal, source, normalization, safety), and extraction dispatch. |
| **Multi-View Feature Extractor** | `ml/features/multi_view_extractor.py` | Extracts packet, flow, host, behavioral, temporal, graph, protocol, and observability vectors from window telemetry. |
| **Final World Model Architecture** | `ml/models/final_world_model.py` | Multi-view encoders (Packet, Flow, Protocol, Host, Temporal, Behavior, Graph, Observability), Cross-View Fusion ($Z_t$), and multi-task prediction heads. |
| **Temporal & Behavioral Intelligence** | `ml/models/temporal_intelligence.py` | Causal temporal features, rolling statistics, burstiness, volatility, peer diversity, churn, and entropy calculation. |
| **Host & Graph Intelligence** | `ml/models/host_graph_intelligence.py` | Host temporal tracking, communication graph topology, centrality, and graph observability estimation. |
| **Network Risk Indicator Engine** | `ml/models/risk_indicators.py` | Evidence-based risk indicator generation (entity, observation, severity, persistence, trend, evidence, confidence, observability). |
| **Uncertainty & OOD Engine** | `ml/models/uncertainty_ood.py` | Aleatoric/epistemic uncertainty estimation, ECE calibration, Mahalanobis/reconstruction OOD scoring. |
| **Comprehensive Abstention Engine** | `ml/models/abstention_engine.py` | Five-tier abstention: FULL_FORECAST, DEGRADED_FORECAST, ANOMALY_ONLY, OBSERVABILITY_ONLY, ABSTAIN. |
| **Final Model Training & Ablation Runner** | `ml/train_final_world_model.py` | Controlled training, self-supervised pretraining ablations, multi-horizon evaluation, low-data regimes, and artifact generation. |
| **Final Model Verification & Benchmark Suite** | `scripts/verify_final_model.py` | Validates final model artifacts, hashes, reproducibility, low-data performance, PCAP corpus rollout, and benchmarks vs V2. |

---

## 7. Migration & Backward Compatibility Strategy

1. **Candidate V2 Freeze:**
   `models/candidate_v2/` will remain completely untouched. Its artifacts, hashes, and unit tests (`tests/test_candidate_v2.py`) must continue to pass seamlessly.
2. **Independent Checkpoint Directory:**
   The Final Model artifacts will reside in `models/final_world_model/` with their own `manifest.json`, `config.json`, `model.npz`, `preprocessing.npz`, `feature_schema.json`, `metadata.json`, and `metrics.json`.
3. **Canonical 45-Feature Interoperability:**
   The Final World Model will accept both the canonical 45-feature input (running in graceful single-view / degraded mode) and the full multi-view telemetry stream (running in full multi-view world model mode).
4. **Zero Frontend/CLI Disruption:**
   The production inference API will seamlessly support both models via `model_id="final_world_model"` and `model_id="candidate_v2"`.
