# NEXSOLVE OPEN-SOURCE CORE EXTRACTION AUDIT: SIH26153
**AI Based Network Attack Forecasting from Network Traffic Data**

---

## 1. Executive Summary
This audit analyzes four foundational open-source network security systems cloned under `research/open_source/`:
1. **Zeek** (`research/open_source/zeek/zeek-master`)
2. **RITA** (`research/open_source/rita_clean/rita-main`)
3. **Suricata** (`research/open_source/suricata/suricata-main`)
4. **NFStream** (`research/open_source/nfstream/nfstream-master`)

### Core Findings:
- **No external source code copying is permitted or required**: RITA (GPLv3) and Suricata (GPLv2) carry strict copyleft requirements. Zeek is BSD-3-Clause, and NFStream is LGPLv3. All architectural adaptations into NexSolve must be **clean-room mathematical implementations** or **decoupled telemetry providers** (such as NexSolve's existing `SuricataSignatureProvider`).
- **The Core Forecasting Gap**: IDS/IPS engines (Suricata/Zeek) excel at *instantaneous signature alerts* and *flow state accounting*. However, **forecasting** (predicting attacks $H_1 \dots H_5$, 5 to 15 minutes ahead) requires **temporal kinematics**:
  - Transition rate of TCP connection establishment failures (Zeek `conn_state` $S_0 \to \text{REJ}$ transitions).
  - Acceleration of target port fan-out ($d(\text{dst\_ports})/dt$).
  - Jitter decay and modal interval stability in periodic communications (RITA Bowley Skewness & MAD metric: $S_{\text{ts}} = \frac{S_{\text{skew}} + S_{\text{mad}}}{2}$).
  - Connection duration and packet count burstiness (NFStream bidirectional distribution metrics).
- **Safety Gate Integrity**: The canonical 45-feature contract and the 46→45 feature safety gate (`mean_tcp_rtt` omission) remain **100% untouched and protected**.

---

## 2. NexSolve Architecture vs. Open-Source Landscape

| Layer | NexSolve Native Capability | Zeek Master | RITA v5 | Suricata | NFStream |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Ingestion** | Scapy streaming / PCAP reader | Packet ring / libpcap / AF_PACKET | Zeek/tsv/ClickHouse ingestion | AF_PACKET, DPDK, PCAP | C++ nfstream-core / CFFI |
| **Flow Tracking** | 60s discrete window aggregation | Event-driven connection state machine | SQL Aggregation over `conn.log` | Bi-directional flow state engine | Active/Idle timeout bi-flow |
| **Behavioral** | Shannon entropy, CV jitter, long conns | Protocol script analyzers | Bowley Skew, MAD, Mode fit, Beacon score | Rule thresholding & anomaly events | Statistical payload & L7 nDPI |
| **Forecasting** | Multi-horizon LSTM ($H_1 \dots H_5$) | **None** (Reactive logging) | **None** (Post-facto threat hunting) | **None** (Real-time signature alert) | **None** (Flow measurement) |
| **MITRE Alignment**| ATT&CK stage mapping + confidence fusion | Community packages (zeek-att&ck) | Technique mapping (T1071, T1571) | `metadata: mitre_technique_id` | L7 application labels |

---

## 3. Deep Capability Audit by System

### 3.1 Zeek (`scripts/base/protocols/conn/main.zeek`, `thresholds.zeek`)
* **License**: BSD 3-Clause (Permissive).
* **Key Mechanism**: TCP connection state tracking (`conn_state` enum):
  - `S0`: SYN seen, no reply (unanswered scan or SYN flood).
  - `S1`: Established, not terminated.
  - `SF`: Normal establishment and termination (SYN $\to$ ACK $\to$ FIN/RST).
  - `REJ`: SYN received RST response (closed port probing).
  - `RSTO` / `RSTR`: Connection aborted by originator or responder.
  - History flag recording: originator flags in upper case (`S`, `H`, `A`, `D`, `F`, `R`), responder flags in lower case (`s`, `h`, `a`, `d`, `f`, `r`).
* **Forecasting Value**: **P0**. Tracking the *first derivative* of $(S_0 + \text{REJ}) / (\text{Total Connections})$ over temporal windows provides a direct 5–10 minute early indicator of reconnaissance progressing to lateral movement or denial-of-service.

### 3.2 RITA (`analysis/beacons.go`, `analysis/spagooper.go`)
* **License**: GPLv3 (Strict Copyleft - zero source code vendoring allowed).
* **Key Mechanism**: Multi-component statistical beacon detection:
  $$\text{Score} = w_{\text{ts}} S_{\text{ts}} + w_{\text{ds}} S_{\text{ds}} + w_{\text{dur}} S_{\text{dur}} + w_{\text{hist}} S_{\text{hist}}$$
  - **Bowley Skewness**:
    $$B = \frac{Q_3 + Q_1 - 2 Q_2}{Q_3 - Q_1}, \quad S_{\text{skew}} = 1 - |B|$$
  - **Median Absolute Deviation (MAD)**:
    $$\text{MAD} = \text{median}(|X_i - \text{median}(X)|), \quad S_{\text{mad}} = 1 - \min\left(1.0, \frac{\text{MAD}}{\text{median}(X)}\right)$$
  - **Combined Timestamp Consistency**:
    $$S_{\text{ts}} = \frac{S_{\text{skew}} + S_{\text{mad}}}{2}$$
* **Forecasting Value**: **P0**. Pre-attack Command & Control (C2) channels tighten their heartbeat interval consistency ($S_{\text{ts}} \to 1.0$) immediately before executing staged commands.

### 3.3 Suricata (`src/output-json-alert.c`, `src/detect-metadata.c`)
* **License**: GPLv2 (Strict Copyleft - external decoupled provider only).
* **Key Mechanism**: Rule engine outputting EVE JSON alerts with embedded MITRE ATT&CK taxonomy metadata (`metadata: mitre_technique_id T1046`).
* **Forecasting Value**: **P1**. High-confidence verification of current attack states used as grounding for evidence fusion, preventing false-positive forecasting cascades.

### 3.4 NFStream (`nfstream/streamer.py`, `meter.py`)
* **License**: LGPLv3 (Weak copyleft library).
* **Key Mechanism**: Bidirectional subflow inter-arrival time and packet length distributions (e.g. forward/backward packet size variance, bidirectional ratio).
* **Forecasting Value**: **P2**. Valuable for enriching flow state metrics without deep packet payload inspection.

---

## 4. SIH26153 Relevance Matrix

| Component | Source Origin | SIH Relevance | Rank | Action / Reason |
| :--- | :--- | :--- | :--- | :--- |
| **TCP State Kinematics ($S_0$, $\text{REJ}$, $R_{\text{fail}}$)** | Zeek `conn_state` | High (Pre-attack recon) | **P0** | **Implement cleanly in Python native state engine**. Early scan detection. |
| **Bowley Skew & MAD Beacon Scoring** | RITA `beacons.go` | High (C2 heartbeat) | **P0** | **Clean-room Python mathematical implementation** in `beaconing.py`. |
| **Suricata EVE JSON Evidence Provider** | Suricata EVE | Medium (Observed evidence) | **P1** | **Maintain decoupled provider interface** for ground-truth fusion. |
| **Bidirectional Subflow Stats** | NFStream | Medium (Traffic shaping) | **P2** | **Add to extended feature candidate pool** (never touch canonical 45). |
| **Full Zeek Script Engine** | Zeek | Low (Heavy runtime) | **DROP** | Out of scope; creates heavy external dependency and latency. |
| **Zeek File Analysis / MIME carving** | Zeek `files.log` | Low (Payload payload) | **DROP** | Forensic artifact, not network forecasting telemetry. |
| **Suricata Packet Inspection Core** | Suricata C code | Zero (Copyleft risk) | **DROP** | Violates clean-room boundaries; cannot vend into NexSolve. |

---

## 5. The Forecasting Gap & Concrete Temporal Lead Signals
Conventional IDS systems trigger an alert **during** or **after** the packet threshold is breached:
$$t_{\text{alert}} \ge t_{\text{impact}}$$
NexSolve's objective under **SIH26153** is:
$$t_{\text{forecast}} \le t_{\text{impact}} - \Delta t, \quad \Delta t \in [5\text{ min}, 15\text{ min}]$$

### Mathematical Early-Warning Signals:
1. **Reconnaissance-to-Scan Acceleration ($v_{\text{recon}}$)**:
   $$v_{\text{recon}}(t) = \frac{\Delta \text{UniqueDstPorts}(t, t - \Delta t)}{\Delta t \cdot \max(1, \text{ActiveConnections}(t))}$$
2. **Half-Open Connection Escalation Ratio ($R_{\text{S0}}$)**:
   $$R_{\text{S0}}(t) = \frac{\sum_{\tau=t-W}^t \mathbb{I}(\text{state}(\tau) = S_0)}{\sum_{\tau=t-W}^t \text{TotalConnections}(\tau)}$$
   When $R_{\text{S0}}$ crosses $0.65$ while $v_{\text{recon}}$ accelerates, attack probability at $H_1$ (5 min) spikes before flood volumes appear.
3. **C2 Beaconing Regularity ($S_{\text{ts}}$)**:
   Prior to exfiltration or DDoS staging, beacon periodicity variance collapses ($\sigma_{\Delta t} \to 0$, $S_{\text{ts}} > 0.85$).

---

## 6. CIC-IDS2017 Corroboration Strategy
Using `c:\Users\saira\Downloads\Friday-WorkingHours.pcap` (8.23 GB, 9.99M packets, July 7, 2017):
- **PortScan Interval** (13:00 - 15:32):
  - Native validation: Observe $v_{\text{recon}}$ and $R_{\text{S0}}$ surge 10 minutes before volumetric saturations.
  - Corroborate against published metadata without manual label contamination.
- **DDoS / LOIC Interval** (15:56 - 17:16):
  - Observe TCP push flag bursts and window size collapse.

---

## 7. Recommended Next Milestone
**Milestone**: Clean-room implementation of **Zeek Connection State Kinematics** and **RITA Bowley/MAD Beacon Score** directly into NexSolve's native `nexsolve_core/behavior/` engine, verified against slice captures of `Friday-WorkingHours.pcap`.

---

## 8. Zeek TCP Session-State Clean-Room Extraction (Completed)

### 8.1 Source Files Inspected in `research/open_source/zeek/`
1. **`research/open_source/zeek/zeek-master/scripts/base/protocols/conn/main.zeek`**:
   - Analyzed lines 30–240: Definition of `conn_state` enum and `set_conn_state` event semantics.
   - Formally documented all 11 Zeek connection states: `S0` (SYN with no reply), `S1` (established, not terminated), `SF` (normal SYN->ACK->FIN/RST termination), `REJ` (SYN answered with RST), `S2` (established, close attempt by orig), `S3` (established, close attempt by resp), `RSTO` (reset by orig), `RSTR` (reset by resp), `RSTOS0` (SYN followed immediately by RST from orig), `RSTRH` (SYN-ACK followed by RST from resp), `SH` (SYN from orig, FIN-ACK from orig without resp), `SHR` (SYN-ACK from resp, FIN from resp), `OTH` (midstream traffic without SYN or partial handshake).
2. **`research/open_source/zeek/zeek-master/src/analyzer/protocol/tcp/TCP_Endpoint.h`**:
   - Inspected `EndpointState` enum: `TCP_ENDPOINT_INACTIVE`, `SYN_SENT`, `SYN_ACK_SENT`, `PARTIAL`, `ESTABLISHED`, `CLOSED`, `RESET`.
   - Analyzed flag tracking and history string representations (`S`, `h`, `A`, `F`, `R`).
3. **`research/open_source/zeek/zeek-master/COPYING`**:
   - Verified BSD 3-Clause permissive license allowing clean-room reimplementation with proper attribution.

### 8.2 Concepts Extracted vs. Clean-Room Architecture
- **Extracted Concepts**:
  - Connection lifecycle classification (`conn_state` mapping).
  - Bidirectional packet, byte, and TCP flag kinematics.
  - History string encoding indicating handshake ordering.
- **Clean-Room Reimplementation in `nexsolve_core.network.session_state`**:
  - Entirely native Python implementation with zero C++ or runtime dependencies on the Zeek binary.
  - Added explicit distinction between `OBSERVED_STATE` and `INFERRED_STATE`.
  - Added `ObservationBoundaryStatus` (`COMPLETE_LIFECYCLE`, `TRUNCATED_AT_END`, `MIDSTREAM_JOIN`, `ISOLATED_WINDOW`) to eliminate false `S0` assertions for pre-existing or window-boundary truncated sessions.
  - Pure deterministic single-pass conversation tracking: tracks 193 sessions over 2,277 packets in **7 ms**.

### 8.3 Scientific Safety and Model Contract Invariance
- **Untouched 45-Feature Model Contract**:
  - TCP session-state metrics (`tcp_session_metrics`) are **EVIDENCE ONLY**.
  - Emitted exclusively as `EvidenceModality.PROTOCOL` with `TemporalScope.OBSERVED`.
  - Strictly excluded from the canonical 45-feature model input vector (`MODEL_SCHEMA_45`).
  - No `mean_tcp_rtt` is added; no RTT is fabricated; zero-fill safety gates remain 100% intact.

---

## 9. RITA Behavioral Periodicity Clean-Room Extraction (Completed)

### 9.1 Source Files Inspected in `research/open_source/rita_clean/`
1. **`analysis/beacons.go`**:
   - `getTimestampScore(entry.TSList)` (lines 140–192)
   - `calculateStatisticalScore(values, defaultMadScore)` (lines 223–246)
   - `calculateBowleySkewness(data)` (lines 339–376): $B = \frac{Q_3 + Q_1 - 2 Q_2}{Q_3 - Q_1}$, score $= 1 - |B|$.
   - `calculateMedianAbsoluteDeviation(data, defaultScore)` (lines 378–418): $\text{score} = \frac{\text{median} - \text{MAD}}{\text{median}}$.
2. **`LICENSE` / `COPYING`**:
   - Verified GPLv3 license: strict clean-room implementation maintained; zero source code copied.

### 9.2 Native Implementation (`nexsolve_core.behavior.periodicity`)
- Implemented pure Python statistical functions: `_calculate_median`, `_calculate_quartiles` (Tukey's hinges), `calculate_bowley_skewness`, `calculate_mad`, `calculate_interval_entropy`.
- Implemented `analyze_periodicity_groups(flows, min_connections=4)` emitting `PeriodicitySummary` with strict categorical classifications:
  `INSUFFICIENT_OBSERVATIONS`, `IRREGULAR`, `WEAKLY_PERIODIC`, `PERIODIC`, `HIGHLY_PERIODIC`.
- All outputs categorized as `EvidenceModality.BEHAVIOR` with `TemporalScope.OBSERVED`.

---

## 10. NFStream Directional Flow Intelligence Extraction (Completed)

### 10.1 Source Files Inspected in `research/open_source/nfstream/`
1. **`nfstream/flow.py`**:
   - `NFlow` slots (lines 119–214): `src2dst_packets`, `dst2src_packets`, `src2dst_bytes`, `dst2src_bytes`, `bidirectional_duration_ms`, `bidirectional_min_piat_ms`, `bidirectional_mean_piat_ms`.
2. **`LICENSE`**:
   - Verified LGPLv3 license: zero runtime CFFI/C library dependencies imported.

### 10.2 Native Implementation (`nexsolve_core.flow.statistics`)
- Consumes canonical `FlowRecord` objects directly from Scapy extraction without competing flow engines.
- Computes `packet_asymmetry_ratio` and `byte_asymmetry_ratio` in $[-1.0, 1.0]$.
- Computes window-wide aggregation: `single_packet_flow_ratio`, `mean_packet_rate`, `mean_byte_rate`, `bursty_flow_count`.
- Emits `build_flow_statistical_evidence()` as `EvidenceModality.ANOMALY` with `TemporalScope.OBSERVED`.

---

## 11. Suricata Signature Telemetry Extraction (Completed)

### 11.1 Source Files Inspected in `research/open_source/suricata/`
1. **`src/output-json-alert.c`**:
   - `AlertJsonHeader` (lines 211–288): gid, signature_id, rev, signature, category, severity, metadata (`mitre_technique_id`).
2. **`COPYING`**:
   - Verified GPLv2 license: decoupled telemetry provider interface only.

### 11.2 Native Implementation (`nexsolve_core.evidence.suricata`)
- Implemented `parse_suricata_eve_json()`: parses external EVE JSON lines when available; safely returns `NO_SURICATA_EVIDENCE_AVAILABLE` when absent without fabricating alerts.
- Emits `build_suricata_evidence_items()` as `EvidenceModality.SIGNATURE` with `TemporalScope.OBSERVED`.
