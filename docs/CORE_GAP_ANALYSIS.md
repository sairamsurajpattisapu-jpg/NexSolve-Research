# NexSolve Core Engine Gap Analysis

**Document Version**: 1.0
**Scope**: Detailed capability-by-capability comparison of current NexSolve against mature open-source systems.

---

## 1. Capability Comparison Matrix

| Pipeline Capability | Current NexSolve Implementation | External Reference Project | Stronger System | Architectural Decision & Action Plan |
| :--- | :--- | :--- | :---: | :--- |
| **Packet Extraction** | Pure Python Scapy `PcapNgReader` + `rdpcap` with robust magic byte validation, packet length verification, truncation checking, and error resilience. | NFStream (DPDK/C), Zeek (libpcap/C++) | **External** (throughput/speed) | **Keep Scapy as default** for universal portability (100% pure Python, zero compile dependency). Design `AcceleratedParserProvider` seam for C/Rust accelerators. |
| **Flow Reconstruction** | Endpoint pair grouping in `nexsolve_core.schemas.build_flows` tracking basic TCP flags, forward/reverse bytes/packets. | NFStream / CICFlowMeter bidirectional state machine | **External** (features & timeout management) | **Natively upgrade flow intelligence**: Add flow duration variance, IAT distribution, bidirectional ratios, active/idle time, and flag combinations. |
| **Feature Extraction** | Canonical 45-feature contract (17 flow + 22 packet + 6 temporal). Strictly enforces safety gate (no `mean_tcp_rtt` fabrication). | CICFlowMeter (84 features), NFStream (70+ features) | **Tie** (NexSolve has strict safety gates; external has richer statistical diversity) | **Define Extended Feature Registry (72 features)**. Keep 45-feature model active; populate extended flow features into state candidate metadata and investigation records. |
| **Temporal Windowing** | Continuous, non-overlapping $W=60s$ temporal windows with provenance and sequence tracking. | RITA (interval-based), Zeek (time-chunked logs) | **NexSolve** (explicit temporal state structure designed for sequence forecasting) | **Maintain NexSolve temporal architecture**. It is uniquely tailored for temporal sequence forecasting. |
| **Network State Construction** | `NetworkStateCandidate` and `NetworkState` dataclasses with strict availability tracking (`FeatureAvailability`). | None (external tools emit flat flows or event logs, not sequence states) | **NexSolve** | **Preserve & enrich**. Add behavioral and protocol evidence slots into state candidate representation. |
| **Static Detection** | `ml.detection.HeuristicDetector` for port scanning, TCP retransmissions, fragmentation, and SYN pressure. | Suricata / Zeek notice framework | **External** (Suricata has vast signature rulesets) | **Keep native heuristics**; implement `SignatureIntelligenceProvider` to ingest Suricata EVE JSON when available. |
| **Behavioral Detection** | None (basic heuristic risk score only). | RITA (beaconing score, connection regularity, DNS tunneling) | **External** (RITA is significantly stronger) | **Implement `nexsolve_core.behavior` natively**: Reimplement RITA's beaconing detection ($CV = \sigma/\mu$), connection interval analysis, and DNS entropy scoring. |
| **Temporal Forecasting** | NumPy-based LSTM multi-step rollout ($T+1 \dots T+5$) with strict lookback ($L=8$), calibration checks, and abstention gates. | None (none of the evaluated open-source tools perform predictive multi-step forecasting) | **NexSolve** (core differentiator) | **Preserve and protect forecasting engine**. Ensure behavioral/signature evidence complements but does not corrupt the state vector. |
| **Attack Horizon** | Formal `AttackHorizonResult` evaluating onset horizon, sustained attack span, lead time, and temporal consistency. | None (external tools are reactive detection engines) | **NexSolve** | **Preserve NexSolve attack horizon logic**. |
| **MITRE ATT&CK Mapping** | Contextual heuristics in `ml.forecasting.attack_stage_signals` (Reconnaissance, C2). | Zeek / Suricata tagged metadata | **External** (richer technique tagging) | **Implement formal MITRE technique mapping** linking observed findings, behavioral signals, and forecasted stages with explicit ATT&CK IDs. |
| **Explainability** | Perturbation-based feature attribution in `world_model.explain()`. | None in external network tools | **NexSolve** | **Preserve and link explanations** directly to supporting/contradictory evidence items. |
| **Evidence Handling** | `ml.forecasting.evidence_intelligence` generating `EvidenceChain`. | Arkime session tagging & investigation model | **Tie** | **Formalize unified `EvidenceItem` and `ThreatAssessment`** distinguishing OBSERVED from FORECAST evidence, inspired by Arkime's session-centric model. |

---

## 2. Summary of Strategic Actions

1. **Do not alter the 45-feature model**: The 45-feature baseline remains frozen and operational for production inference.
2. **Natively build behavioral intelligence**: Add `nexsolve_core.behavior` with beaconing, connection regularity, and DNS tunneling detection algorithms inspired by RITA.
3. **Natively extend flow metrics**: Compute extended statistical flow metrics (IAT distribution, bidirectional ratios, active/idle behaviour) without breaking the existing 45-feature model contract.
4. **Decouple external engines via providers**: Create clean, optional provider interfaces for Protocol Intelligence (Zeek) and Signature Intelligence (Suricata).
5. **Strictly separate Observed vs Forecasted intelligence**: Ensure every evidence item and UI/API field explicitly declares whether it is observed telemetry or predictive rollout.
