# Open Source Network Security Ecosystem Research

**Document Version**: 1.0
**Status**: ARCHITECTURAL RESEARCH
**Scope**: NFStream, Zeek, Suricata, RITA, Arkime, nDPI, CICFlowMeter
**Objective**: Evaluate open-source network security systems to strengthen NexSolve's core pipeline without violating safety gates, compromising commercial viability, or adopting heavy unmaintainable dependencies.

---

## 1. Executive Evaluation Matrix

| Project | Current Version | Primary Strength | Useful NexSolve Capability | Integration Type | License | Commercial Risk | Deployment Risk | Decision |
| :--- | :---: | :--- | :--- | :--- | :--- | :--- | :--- | :---: |
| **NFStream** | v6.5.4 | High-performance C-accelerated flow extraction & L7 dissection | High-value deterministic flow features (IAT, byte ratios, duration variance) | `OPTIONAL_PROVIDER` & `NATIVE_REIMPLEMENTATION` | LGPLv3 | Medium (LGPL dynamic linking required) | Medium (requires native C compilation/CFFI on Windows) | **OPTIONAL_PROVIDER** |
| **Zeek** | v7.0.x / v7.2 LTS | Deep application-layer protocol semantic extraction & stateful event logs | Structured connection, DNS, HTTP, TLS session logs (`conn.log`, `dns.log`, `ssl.log`) | `OPTIONAL_PROVIDER` | BSD-3-Clause | Low (permissive) | High (Unix-centric, heavy daemon, non-trivial on Windows) | **OPTIONAL_PROVIDER** |
| **Suricata** | v7.0.8 | Multithreaded signature detection & EVE JSON telemetry | Standardized signature evidence & MITRE-tagged rule alerts | `OPTIONAL_PROVIDER` | GPLv2 | Medium-High (GPL process boundary must remain strict via EVE JSON) | High (binary installation required, heavy ruleset maintenance) | **OPTIONAL_PROVIDER** |
| **RITA** | v5.1.0 (ActiveCM) | Statistical beaconing, connection periodicity, and DNS tunneling detection | Mathematical formulation for beacon periodicity, connection intervals, destination regularity | `NATIVE_REIMPLEMENTATION` | GPLv3 (ActiveCM) | High if linked; Zero if reimplemented | Zero for native algorithms in Python | **NATIVE_REIMPLEMENTATION** |
| **Arkime** | v5.5.0 (formerly Moloch) | Session-centric indexed PCAP navigation & investigation model | Normalized session-centric investigation data model linking flows to evidence & MITRE | `REFERENCE_ONLY` | Apache-2.0 | Low (reference only) | High (requires OpenSearch/Elasticsearch cluster) | **REFERENCE_ONLY** |
| **nDPI** | v4.12-stable (ntop) | Deep packet inspection & application/protocol classification | L7 application protocol signatures & metadata attributes | `REFERENCE_ONLY` / `REJECT` | LGPLv3 (core) / dual commercial | High (commercial restrictions, patent/IP encumbrance risks) | High (C dependency, Windows build complexity) | **REJECT (Direct)** / **REFERENCE_ONLY** |
| **CICFlowMeter** | v4.0 (Java) / cicflowmeter (Python forks) | Standard 80+ bidirectional flow feature extraction (UNSW/CIC datasets) | Deterministic flow statistics (sub-flow bytes, active/idle time, flag ratios) | `NATIVE_REIMPLEMENTATION` | Academic / Apache-2.0 (Python port) | Low for mathematical algorithms | Zero for native clean-room formulas | **NATIVE_REIMPLEMENTATION** |

---

## 2. In-Depth Project Analysis

### 2.1 NFStream
* **Current Release**: v6.5.4 (Python 3.8-3.12, C core via CFFI).
* **Maintenance Activity**: Actively maintained, periodic patch releases.
* **Architecture**: Core written in C with DPDK/libpcap backend; Python CFFI wrapper exposing Pandas/PyTorch streaming flows.
* **PCAP Capabilities**: Highly optimized packet parsing and flow assembly using idle/active timeouts.
* **Flow Capabilities**: Bidirectional flow tracking, TCP state machine, inter-arrival time (IAT) computation.
* **Strengths vs NexSolve**: 20x–50x faster packet processing; extracts rich L7 and statistical features in a single pass.
* **Limitations / Risks**: Heavy build toolchain on Windows (requires MSVC, libpcap/Npcap SDK); LGPLv3 license limits static linking in proprietary commercial binaries.
* **NexSolve Architectural Decision**:
  - **Reimplement Natively**: Incorporate NFStream's proven statistical formulations (bidirectional byte ratios, IAT skewness/variance, idle/active durations) into pure-Python `nexsolve_core.state` to run everywhere out of the box.
  - **Optional Provider**: Allow an optional `NFStreamParser` accelerator on Linux/container environments when installed.

### 2.2 Zeek (formerly Bro)
* **Current Release**: v7.0.4 / v7.2 LTS.
* **Maintenance Activity**: Extremely active, backed by Corelight and the open-source community.
* **Architecture**: Event-driven scripting engine (`Bro/Zeek script`) and stateful network protocol parsers.
* **PCAP Capabilities**: Deep offline PCAP replay generating structured, tab-separated or JSON logs (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`).
* **Strengths vs NexSolve**: Unrivaled application-layer protocol parsing (JA3/JA4 TLS fingerprints, DNS query/response structures, HTTP header extraction).
* **Limitations / Risks**: Zeek is inherently Unix-first; native Windows execution is complex (requires WSL or Docker); heavy binary footprint (>200MB).
* **NexSolve Architectural Decision**:
  - **Optional Provider (`ProtocolIntelligenceProvider`)**: Define a clean decoupled boundary. If Zeek is installed or if pre-extracted Zeek logs exist alongside the PCAP, ingest them into structured evidence. If absent, fallback gracefully to native NexSolve protocol heuristics without fabricating data.

### 2.3 Suricata
* **Current Release**: v7.0.8 (OISF).
* **Maintenance Activity**: Highly active, world standard for open-source IDS/IPS.
* **Architecture**: High-speed multithreaded engine using Hyperscan/Vectorscan for signature matching; outputs standardized `eve.json`.
* **PCAP Capabilities**: Offline PCAP inspection against Suricata/Emerging Threats (ET) rulesets.
* **Strengths vs NexSolve**: Vast community signature ecosystem detecting known exploits, CVEs, malware domains, and protocol violations.
* **Limitations / Risks**: Purely reactive/signature-based; does not forecast future attacks; GPLv2 license requires clean process separation (reading `eve.json` over subprocess/file pipe rather than linking code).
* **NexSolve Architectural Decision**:
  - **Optional Provider (`SignatureIntelligenceProvider`)**: Support reading or executing Suricata to produce `eve.json`, mapping alerts into normalized `EvidenceItem` records with severity, signature ID, and MITRE ATT&CK technique tags. The core product never requires Suricata.

### 2.4 RITA (Real Intelligence Threat Analytics)
* **Current Release**: v5.1.0 (Go rewrite by ActiveCM).
* **Maintenance Activity**: Active, specifically designed for threat hunting on Zeek logs.
* **Architecture**: Statistical analysis pipeline operating on network session intervals and DNS transactions.
* **Key Algorithmic Strengths**:
  1. **Beaconing Detection**: Calculates delta times between connections to the same destination; computes interval variance, mode, and score based on coefficient of variation ($CV = \sigma / \mu$).
  2. **Connection Periodicity**: Autocorrelation and interval regularity scoring.
  3. **DNS Tunneling**: High-entropy subdomain query detection, query length variance, and unusual TXT record frequency.
* **NexSolve Architectural Decision**:
  - **Native Reimplementation (`nexsolve_core/behavior/`)**: Directly implement lightweight, mathematically pure versions of RITA's beaconing score, connection regularity, and DNS entropy in Python. These feed the `EvidenceIntelligence` engine as non-ML behavioral evidence.

### 2.5 Arkime (formerly Moloch)
* **Current Release**: v5.5.0.
* **Maintenance Activity**: Active (backed by AWS and contributors).
* **Architecture**: C-based capture daemon (`capture`) and Node.js viewer backed by OpenSearch.
* **Strengths vs NexSolve**: Beautiful session-centric forensic model (Source IP/Port, Destination IP/Port, Protocol, Packets, Bytes, First/Last seen, Tags, Timeline scrubbing).
* **Limitations / Risks**: Massive infrastructure overhead (OpenSearch cluster, multi-gigabyte indexers). Completely unsuitable as an embedded lightweight runtime.
* **NexSolve Architectural Decision**:
  - **Reference Only**: Adopt Arkime's session data model semantics for NexSolve's `SessionInvestigationRecord` and forensic navigation UI without adopting the Arkime codebase or OpenSearch dependency.

### 2.6 nDPI
* **Current Release**: v4.12-stable.
* **Maintenance Activity**: Active (ntop).
* **Architecture**: C library for deep packet inspection and protocol/application classification.
* **Strengths vs NexSolve**: Identifies thousands of application protocols (Zoom, BitTorrent, WhatsApp, Telegram, etc.) even when encrypted.
* **Limitations / Risks**:
  - **Licensing Trap**: nDPI is LGPLv3, with parts subject to commercial licensing or restrictive clauses by ntop.
  - **Portability Barrier**: Compiling nDPI on Windows requires complex build environments (CMake, MinGW/MSVC).
* **NexSolve Architectural Decision**:
  - **Direct Integration REJECTED**.
  - **Reference Only**: Rely on standard IANA port mappings, SNI inspection, and protocol header signatures natively implemented in NexSolve.

### 2.7 CICFlowMeter
* **Current Release**: v4.0 (Java) with community Python ports (e.g. `cicflowmeter`).
* **Maintenance Activity**: Moderate / Reference implementation for Canadian Institute for Cybersecurity datasets (CIC-IDS2017, CIC-IDS2018).
* **Key Algorithmic Strengths**:
  - Definition of standard statistical flow features used across academic ML network research: Flow IAT (Mean, Std, Max, Min), Forward/Backward IAT, Active/Idle times, Sub-flow packet and byte calculations, Flag counts.
* **Limitations / Risks**: The original Java implementation has memory leaks and timestamp precision bugs; community Python ports often fail on malformed packets.
* **NexSolve Architectural Decision**:
  - **Native Clean-Room Reimplementation**: Implement the highest-value, deterministic CIC features directly in `nexsolve_core/state.py` with rigorous floating-point safety and zero division guards.

---

## 3. Summary of Decisions

1. **Native Reimplementation**:
   - RITA-style statistical beaconing and regularity algorithms.
   - CICFlowMeter/NFStream deterministic flow duration, variance, IAT distribution, and byte/packet ratios.
2. **Optional External Providers**:
   - `ProtocolIntelligenceProvider` (Zeek log ingestion seam).
   - `SignatureIntelligenceProvider` (Suricata EVE JSON parser seam).
   - `AcceleratedParserProvider` (NFStream or native C parser seam when available).
3. **Reference Only**:
   - Arkime session investigation data model.
4. **Rejected**:
   - nDPI (licensing and C build complexity).
   - Mandating Zeek, Suricata, or OpenSearch for baseline operation.
