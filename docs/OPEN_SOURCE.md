# NexSolve Open-Source Integrations & Ecosystem Architecture

NexSolve leverages specialized open-source network security, packet processing, and machine learning components through a modular **Sensor & Ingestion Adapter Architecture**.

This document outlines the purpose, licensing, integration mechanism, dependency tier, and runtime requirements for each component.

---

## 1. Component Registry

| Project | License | Dependency Tier | Primary Purpose in NexSolve | Integration Method | Runtime Requirements |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Scapy** | GPL-2.0-only | **REQUIRED** | Packet dissection, TCP flag analysis, and L3/L4 protocol distribution | Native Python Import (`scapy.layers.inet`) | Python 3.10+ |
| **Dpkt** | BSD-3-Clause | **REQUIRED** | High-throughput streaming packet parsing without full capture memory buffering | Native Python Import (`dpkt.pcap`) | Python 3.10+ |
| **PyTorch** | BSD-3-Clause | **REQUIRED** | Temporal World Model inference (LSTM latent state rollout) | Native Python Import (`torch`) | CPU or CUDA runtime |
| **FastAPI** | MIT | **REQUIRED** | REST API engine, async job lifecycle, and report streaming endpoints | Native Python Framework | Python 3.10+, Uvicorn |
| **Uvicorn** | BSD-3-Clause | **REQUIRED** | Production ASGI web server | CLI / Python Daemon | Python 3.10+ |
| **Zeek** | BSD-3-Clause | **OPTIONAL** | High-fidelity connection tracking, protocol analysis, and DNS/SSL summarization | Safe Subprocess Adapter (`zeek -r <pcap>`) | Zeek binary in PATH |
| **Suricata** | GPL-2.0-only | **OPTIONAL** | Rule-based signature detection (Emerging Threats ruleset) | Safe Subprocess Adapter (`suricata -r <pcap>`) | Suricata binary in PATH |
| **NFStream** | LGPL-3.0-only| **OPTIONAL** | Hardware-accelerated statistical flow feature extraction | Optional Python Adapter | CFFI, Python 3.10+ |

---

## 2. Architectural Boundaries & Isolation

### Zero Hard Coupling to External Daemons
NexSolve enforces strict architectural isolation:
1. **Fallback Resilience**: When external binaries (`zeek`, `suricata`, `tshark`) are absent from the host `PATH`, NexSolve automatically falls back to its deterministic internal Scapy/Dpkt packet and flow processing engine. Absence of optional sensors never halts an analysis.
2. **Subprocess Hardening**:
   - Subprocesses are executed via argument lists: `subprocess.run(["suricata", "-r", pcap_path, ...])`.
   - `shell=True` is strictly prohibited.
   - Bounded execution timeouts (default: 30s) prevent hang states on corrupted captures.
   - Working directories and outputs are quarantined within isolated `runtime/nexsolve-job-<id>/` folders.
3. **Multi-Sensor Telemetry Normalization**:
   Outputs from independent sensors are ingested through `nexsolve_core.normalized_telemetry` and mapped into canonical `EvidenceItem` records with explicit provenance (`PCAP`, `SCAPY`, `ZEEK`, `SURICATA`, `NFSTREAM`, `HEURISTIC`, `MODEL`).

---

## 3. Compliance & Licensing Notice

NexSolve is built in compliance with open-source licenses:
- All external dependencies remain in their upstream distribution packages.
- No third-party codebases are statically embedded into NexSolve proprietary source trees without attribution.
- Reciprocal licenses (GPL/LGPL) apply only to their respective standalone modules and external tools invoked over standard interfaces.
