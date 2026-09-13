# NexSolve Security & Integration Architecture

**Document Version**: 1.0
**Scope**: End-to-end security model, untrusted PCAP processing safeguards, external provider isolation, and multi-tier commercial deployment architecture.

---

## 1. Pipeline Threat Model & Security Boundaries

When processing untrusted packet captures (PCAP/PCAPNG) and raw network streams, NexSolve operates under a **zero-trust execution model**.

```
[Untrusted PCAP File]
        │
        ▼
[Security Gate 1: Magic Byte & Header Validation]
        │
        ▼
[Security Gate 2: Resource & Bounds Checking] (Max 64MB, Max 100k pkts, Max 120s)
        │
        ▼
[Isolated Ephemeral Sandbox] (Temp directory, strict unlinking)
        │
        ▼
[Deterministic Parser & Flow Reconstruction] (Scapy / Optional Accelerator)
        │
        ├──► [Native Behavioral Engine] (RITA-style algorithms in pure Python)
        ├──► [Optional Protocol Provider] (Zeek decoupled subprocess/log reader)
        └──► [Optional Signature Provider] (Suricata decoupled subprocess/EVE JSON)
        │
        ▼
[Unified Evidence Fusion & Threat Assessment] (Strict Observed vs Forecast separation)
        │
        ▼
[State Compatibility Gate] (Lookback >= 8, schema match, no RTT fabrication)
        │
        ├──► [Forecast Rollout (T+1..T+5)] (If READY)
        └──► [Safe Forecast Abstention] (If INSUFFICIENT_HISTORY or INCOMPATIBLE)
```

### 1.1 Core Protections Enforced
1. **Magic Header Inspection**: Rejects fake extensions; verifies classic PCAP (microsecond and nanosecond, big/little endian) and PCAPNG block headers.
2. **Decompression Bomb & Oversized File Protection**: Caps uploads at `NEXSOLVE_MAX_UPLOAD_BYTES` (default 64MB).
3. **Resource Exhaustion Guards**: Hard caps on packets (100,000), flows (20,000), and temporal windows (500) prevent CPU/memory starvation.
4. **Command Injection Prevention**: Optional external provider invocations (Zeek/Suricata) **never** use shell string interpolation (`shell=False` required). Arguments are passed as strictly validated, immutable parameter arrays with explicit timeouts.
5. **Path Traversal Sanitization**: All client-supplied filenames are stripped of directory components (`..`, `/`, `\`) and null bytes.
6. **No Feature Fabrication**: Never zero-fills or estimates missing features (e.g. `mean_tcp_rtt`) merely to force model execution.

---

## 2. Multi-Tier Commercial Architecture

NexSolve is architected across three clean tiers without locking the open-source community out of core forecasting capabilities:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           COMMUNITY / LOCAL                             │
│ • Pure Python Scapy PCAP/PCAPNG ingestion                               │
│ • Deterministic 45-feature state extraction                             │
│ • Heuristic detection & Rule-based finding generation                   │
│ • NumPy LSTM World Model forecasting (5 steps)                          │
│ • Basic Markdown/JSON reporting & Local Web UI                          │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                              PROFESSIONAL                               │
│ • Native Behavioral Intelligence (Beaconing, Periodicity, DNS entropy)  │
│ • Extended Flow Analytics (Duration variance, IAT distribution, ratios) │
│ • Arkime-style Session Investigation Data Model                         │
│ • Unified Evidence Chain & MITRE ATT&CK Technique Mapping               │
│ • Attack Horizon & Lead Time quantification                             │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
┌────────────────────────────────────▼────────────────────────────────────┐
│                               ENTERPRISE                                │
│ • Optional Protocol Provider (Zeek conn/dns/ssl log ingestion)          │
│ • Optional Signature Provider (Suricata EVE JSON alerts integration)    │
│ • Accelerated Parser Provider (C/Rust/NFStream high-throughput engine)  │
│ • Multi-tenant Async Job Queue & Worker Pool Throttling                 │
│ • SIEM / SOAR JSON streaming export & Enterprise Audit Trail            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Subprocess & Provider Isolation Policy

To guarantee that optional enterprise components cannot compromise system stability:
* **Fail-Open System / Fail-Closed Provider**: If an external provider binary (e.g., `zeek` or `suricata`) crashes, hangs, or is missing, the provider returns `status="UNAVAILABLE"`. NexSolve continues full operation with native heuristics.
* **Execution Sandbox**: External processes run in ephemeral subdirectories with drop-privileges, standard I/O redirection, and a strict timeout (max 30 seconds).
* **Licensing Firebreak**: All external tools run out-of-process via standard structured interfaces (`eve.json`, `conn.log`). Zero GPL/LGPL code is imported or statically linked into NexSolve proprietary source.
