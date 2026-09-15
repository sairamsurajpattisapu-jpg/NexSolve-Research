# NexSolve — SIH 2026 Live Demonstration Script
**Problem Statement ID:** 26153  
**Title:** AI-Based Network Attack Forecasting from Network Traffic Data  
**Target Duration:** Exactly 120 Seconds (2 Minutes)

---

## 120-Second Pitch & Presentation Timeline

```
[00:00 - 00:15]  PROBLEM: Reactive IDS Limitations
[00:15 - 00:30]  INGESTION: Zero-Agent Passive PCAP Upload
[00:30 - 00:50]  STATE CONSTRUCTION: 45-Feature Zero-Fabrication Contract
[00:50 - 00:75]  WORLD MODEL FORECAST: Multi-Horizon Recursive Rollout (T+1..T+5)
[00:75 - 00:95]  ATTACK PROGRESSION: Behavioral MITRE Dynamics (T1046, T1498)
[00:95 - 01:10]  EXPLAINABILITY: Physical Feature Drivers & Early Warning Score
[01:10 - 01:20]  IMPACT & CONCLUSION: True Air-Gapped Offensive Forecasting
```

---

### [00:00 – 00:15] 1. Problem: The Reactive IDS Blindspot
* **Presenter Action:** Point to the "Traditional IDS vs. NexSolve" comparison panel on the dashboard.
* **Spoken Narrative:**
  > "Respected judges, every modern intrusion detection system operates *after* damage has occurred. Snort, Suricata, and standard ML classifiers observe traffic at $T_0$, match a signature, and alert defenders when the network is already compromised. Their predictive lead time is **zero seconds**. NexSolve fundamentally shifts cybersecurity from reactive alert triage to **predictive forward simulation**."

---

### [00:15 – 00:30] 2. Ingestion: Passive Telemetry Without Endpoints
* **Presenter Action:** Click **"Launch Live Demo"** on the SIH Demo page (or upload `friday_10windows_slice.pcap` on Dashboard).
* **Spoken Narrative:**
  > "NexSolve requires no kernel hooks, no proprietary agents, and no payload decryption. We ingest passive PCAP captures. Watch as the engine parses 2,277 raw packets, reconstructs 283 bidirectional 5-tuple flows, and groups telemetry into discrete 60-second observation windows in under 4.5 seconds."

---

### [00:30 – 00:50] 3. State Construction: 45-Feature Physical Safety Contract
* **Presenter Action:** Hover over the **System Technical Specifications** drawer and highlight the 45-feature schema.
* **Spoken Narrative:**
  > "Unlike academic prototypes that cheat by zero-filling missing fields or faking metrics, NexSolve enforces a strict **Zero-Fabrication Contract**. Because passive packet capture cannot observe TCP Round Trip Time without SYN-ACK-ACK handshakes, our model strictly omits `mean_tcp_rtt` and operates on a canonical 45-feature state vector. If fewer than 8 historical windows are observed, the engine transparently **abstains** rather than hallucinating danger."

---

### [00:50 – 01:15] 4. World Model: Multi-Horizon Autoregressive Rollout
* **Presenter Action:** Point to the **Forecast Hero** metrics and interactive trajectory curve.
* **Spoken Narrative:**
  > "Here is our core scientific innovation: an autoregressive LSTM World Model. Given 8 historical windows, it recurrently simulates the future state of the network across $T+1$ through $T+5$ (up to 300 seconds into the future) without needing future ground truth. Notice the distinction: at $T+1$, single-step attack probability is 60.0%, but cumulative multi-window infiltration risk escalates monotonically to **78.6% by $T+5$**. We give SOC analysts a 5-minute lead time before volumetric disruption begins."

---

### [01:15 – 01:35] 5. Attack Progression: Behavioral MITRE Dynamics
* **Presenter Action:** Show the **Attack Progression Timeline** and **MITRE Behavior Panel**.
* **Spoken Narrative:**
  > "NexSolve does not just spit out a generic anomaly percentage. Our Markovian progression engine projects behavioral stage transitions. As destination port cardinality surges, the system flags **T1046: Network Service Discovery**, forecasting an imminent shift from reconnaissance into exploitation."

---

### [01:35 – 01:50] 6. Explainability: Direct Physical Attribution
* **Presenter Action:** Highlight the **Top Attribution Drivers** in the Explainability Panel.
* **Spoken Narrative:**
  > "Why is the future risk increasing? NexSolve computes exact mathematical feature deltas. Analysts can see that `proto_udp_count` is projected to surge while packet inter-arrival time collapses, indicating automated burst scanning. Our 0–100 Early Warning Score aggregates risk momentum into a single actionable metric."

---

### [01:50 – 02:00] 7. Impact: 100% Offline & Presentation-Ready
* **Presenter Action:** Click **"Open HTML Report"** to show the self-contained audit document.
* **Spoken Narrative:**
  > "NexSolve operates 100% offline with zero cloud API dependencies, making it suitable for air-gapped critical infrastructure, defense networks, and enterprise SOCs. We have built an end-to-end operational product that transforms network defense from reacting to the past, to forecasting the future. Thank you."

