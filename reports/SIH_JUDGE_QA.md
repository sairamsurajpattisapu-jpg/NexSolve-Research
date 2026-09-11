# NexSolve — SIH 2026 Judge Q&A Defense Guide

**Smart India Hackathon 2026 — Problem Statement 26153**  
**Document**: `reports/SIH_JUDGE_QA.md`  
**Purpose**: Comprehensive technical defense and evaluator FAQ covering algorithmic choices, dataset audits, scientific integrity, safety gates, and commercialization.

---

### 1. What problem are you solving?
Traditional network security tools (firewalls, IDS/IPS, SIEMs) operate almost entirely **reactively**: they detect an attack only after malicious packets have already entered the network, executed payloads, or triggered volumetric thresholds. By then, the enterprise is already compromised. NexSolve transforms defense from retrospective alert triaging into **forward-looking predictive intelligence**, giving defenders actionable lead time ($T+1 \dots T+5$ minutes ahead) to preemptively isolate segments, adjust firewall rules, or inspect anomalous endpoints before lateral movement or exfiltration occurs.

---

### 2. Why is forecasting better than detection?
Detection is retrospective ($T_0$ or earlier). In modern attacks (e.g., automated ransomware propagation, DDoS amplification, credential stuffing), damage occurs in tens of seconds. Forecasting projects the **state trajectory** into the future ($T+1 \dots T+5$), providing a quantifiable **Attack Horizon** and **Lead Time** (e.g., 60s to 180s). This gives automated orchestration tools and SOC analysts the opportunity to prevent damage rather than just cleaning up after it.

---

### 3. What exactly are you forecasting?
NexSolve forecasts the **multivariate temporal network state vector** across 5 discrete forward horizons ($T+1, T+2, T+3, T+4, T+5$). This includes future flow densities, packet rate surges, SYN/ACK ratio anomalies, destination port diversities, inter-arrival time distributions, and composite attack likelihood indicators, mapped to MITRE ATT&CK contextual categories.

---

### 4. How do you convert PCAP into temporal states?
Every capture passes through a deterministic 5-stage pipeline:
1. **Validation**: Magic byte sniffing (PCAP/PCAPNG), 64 MB size check, SHA-256 fingerprinting.
2. **Streaming Parse**: Scapy iterator extracts protocol headers (Ethernet, IPv4/IPv6, TCP/UDP/ICMP) with microsecond timestamps.
3. **Flow Reconstruction**: Bidirectional 5-tuple aggregation tracking forward/backward packet counts, byte volumes, and TCP handshake flags.
4. **Windowing**: Non-overlapping 60-second temporal binning.
5. **State Builder**: Group-qualified extraction of 46 canonical features (Flow, Packet, and Temporal lookback features) adhering strictly to past-only semantics.

---

### 5. Why use temporal windows?
Raw packets arrive irregularly (microsecond bursts followed by idle periods) and are high-dimensional. Individual packets lack behavioral context. Aggregating into temporal windows creates **stationary, structured time-series observations** where statistical trends, rate of change, protocol ratios, and temporal momentum become measurable and predictable without losing forensic traceability.

---

### 6. Why 60-second windows?
Through empirical evaluation of enterprise traffic and academic benchmarks, 60 seconds provides the optimal balance:
- **Signal-to-Noise**: Smooths out momentary jitter and random retransmissions.
- **Actionability**: A 60-second window length directly translates to forward forecast steps of 1 to 5 minutes ($T+1 = 60\text{s}$, $T+2 = 120\text{s}$, up to $T+5 = 300\text{s}$)—the precise time frame in which human analysts or automated SOAR playbooks can intervene.
- **Alignment with Benchmarks**: UNSW-NB15 and TON-IoT attack phases (scans, brute force, DDoS) unfold across multi-minute temporal spans.

---

### 7. How do you avoid future-data leakage?
Data leakage is the primary reason academic ML models report >99% accuracy but fail catastrophically in production. NexSolve eliminates leakage through strict architectural rules:
1. **Contiguous Episode Splits**: Data is segmented chronologically into continuous temporal episodes. Train, validation, and test episodes never overlap in time.
2. **No Random Shuffling**: Time-series sequences are never randomly shuffled.
3. **Past-Only State Builder**: At time $t_0$, the state builder is mathematically isolated from all packets with timestamp $t > t_0$.
4. **Isolated Window Aggregation**: Window statistics only use packets timestamped within that window's boundary ($t_{\text{start}} \le t < t_{\text{end}}$).

---

### 8. How do you validate the forecast?
We use contiguous multi-horizon temporal validation:
- Given an observation sequence up to $T_0$, the model predicts states for $T+1 \dots T+5$.
- Predictions are evaluated against the true future states using Mean Squared Error (MSE), Mean Absolute Error (MAE), and temporal directional consistency across each horizon individually ($h=1, 2, 3, 4, 5$).
- Baselines (Persistence, Historical Mean, Majority Class) are computed alongside every model to verify that predictions outperform trivial temporal momentum.

---

### 9. What datasets were used?
1. **UNSW-NB15**: Primary temporal benchmark domain. Used as timestamp-contiguous temporal episodes with real PCAPs and flow CSV ground truths.
2. **TON-IoT (`Network_dataset_23`)**: Retained as an independent cross-domain temporal check for IoT/OT protocol behavior.
3. **CIC-IDS2017 Audit**: Audited and rejected for temporal forecasting due to timestamp deficiencies (see Question 11). Retained strictly as an unlabeled packet-level window test artifact.

---

### 10. Why UNSW-NB15?
UNSW-NB15 contains raw packet captures recorded with authentic, continuous network packet timestamps over multi-day periods, capturing realistic normal background traffic interleaved with modern synthetic attack activities (fuzzers, analysis, backdoors, DoS, exploits, generic, reconnaissance). This preserves genuine temporal structure required for time-series forecasting.

---

### 11. Why couldn't CIC-IDS2017 be used for temporal forecasting?
Our Phase 5 scientific dataset audit revealed a fatal flaw in the widely used CIC-IDS2017 flow CSVs: **they lack per-event epoch timestamps**. The flows are recorded as aggregate durations without ordered sequence anchors, making chronologically valid time-series state reconstruction impossible without fabricating event arrival times. Rather than inventing fake timestamps (which many academic papers do), NexSolve scientifically disqualified CIC-IDS2017 flow CSVs for temporal attack forecasting and publicly documented this finding.

---

### 12. What model is currently strongest?
The **Persistence Champion Baseline** is currently the strongest, scientifically validated forecasting model in the repository. It projects future network states by extrapolating the observed multi-window temporal momentum from $T_0$.

---

### 13. Why is Persistence the current champion?
In rigorous, contiguous-episode evaluation without data leakage, network traffic displays high short-term temporal autocorrelation. On test episodes, Persistence achieved superior or equivalent Mean Squared Error compared to complex ML candidates (Ridge Regression, LightGBM), while having **zero risk of overfitting**, **deterministic explainability**, and **sub-millisecond execution time**.

---

### 14. Why haven't you promoted the ML models?
Academic teams frequently promote complex ML models that overfit to training domains. NexSolve enforces a strict **Production Promotion Gate**:
- Candidate models (`candidate_v1` Ridge, `candidate_v2` LightGBM) demonstrated domain-shift degradation when tested across heterogeneous capture episodes.
- Until an ML model consistently outperforms Persistence on out-of-distribution temporal benchmarks across all 5 horizons without hallucinating, our engineering policy keeps ML models on **`HOLD`** (research-only). This honest approach protects enterprise security operators from false confidence.

---

### 15. How do you handle uncertainty?
NexSolve separates raw model scores from statistical certainty:
- Every forecast point includes an **Uncertainty Level** (`LOW`, `MEDIUM`, `HIGH`) calculated from feature variances, observation noise, and lookback stability.
- If the model score hovers near classification boundaries or if supporting signals conflict, uncertainty is flagged as `HIGH`.
- When rigorous calibration data is unavailable, confidence is explicitly tagged as **`UNCALIBRATED`** rather than outputting a deceptive percentage.

---

### 16. What is Forecast Abstention?
Forecast Abstention is NexSolve's **Epistemic Safety Gate**. When data conditions do not meet the minimum criteria for reliable prediction, the system deliberately refuses to forecast and returns:
**`FORECAST WITHHELD`** with an explicit reason code:
- `INSUFFICIENT_HISTORY`: Fewer than 3 consecutive temporal windows (< 180s).
- `GAPPED_TELEMETRY`: Capture has chronological gaps exceeding 120 seconds.
- `DEGRADED_CAPTURE_QUALITY`: Packet loss exceeding 20% or excessive malformed frames.
- `OUT_OF_DISTRIBUTION_OVERLOAD`: Novel protocol behaviors that invalidate model assumptions.

---

### 17. What is Attack Horizon?
Attack Horizon is a high-level operational metric answering:
*"How far into the future does the threat extend, and when does it begin?"*
It outputs:
- **Horizon State**: `NO_ATTACK_FORECAST`, `EARLY_SIGNAL`, `SUSTAINED_ATTACK_FORECAST`, `UNCERTAIN_FORECAST`, or `ABSTAINED`.
- **Forecast Lead Time**: Seconds until attack onset (e.g., 60s, 120s).
- **Horizon Depth**: How many future windows the attack is projected to persist.
- **Peak Window**: The specific future window projected to experience maximum volumetric or severity impact.

---

### 18. What is Evidence Chain?
The Evidence Chain is NexSolve's explainability mechanism. Instead of opaque SHAP plots or attention heatmaps that security analysts cannot operationalize, it extracts **concrete network metric comparisons**:
- **Supporting Signals**: Features that show anomalous growth or persistence (e.g., *Destination Port Diversity surged +64.2% above moving baseline*).
- **Contradictory Signals**: Metrics that contradict the attack hypothesis (e.g., *TCP Retransmission rate remains nominal at 0.2%*).
- **Net Balance**: Overall directional weight of evidence.

---

### 19. How do you prevent hallucinated explanations?
NexSolve's Evidence Chain is computed through **deterministic server-side rule verification directly on the extracted state vectors**. Every explanation string is generated from actual numerical deltas between the current window and the lookback baseline. If a feature did not deviate, it cannot appear in the evidence chain. No Large Language Models (LLMs) are used in the core inference path, eliminating generative hallucinations.

---

### 20. What happens with unknown attacks?
NexSolve includes an **Unknown Behavior & Novelty Detection Module**. It monitors protocol header variations, payload entropy, and joint feature combinations. If traffic deviates significantly from established statistical clusters, NexSolve:
1. Elevates the **Novelty Score** (0.0 to 1.0).
2. Generates an **Out-of-Distribution (OOD) flag**.
3. Correlates the anomaly with MITRE ATT&CK techniques as an exploratory hypothesis.
4. **Crucially, never classifies unknown traffic as benign.**

---

### 21. What happens with poor PCAP quality?
The Ingestion Engine includes a **Capture Quality Evaluator**:
- Checks for truncated packets, checksum errors, malformed headers, and packet loss ratios.
- If packet loss exceeds 5%, the capture is flagged as **`DEGRADED`**.
- If loss exceeds 20%, the system triggers **Forecast Abstention**, explaining to the operator that feature fidelity is insufficient for reliable forward projection.

---

### 22. What happens if the capture has gaps?
If packet timestamps jump by more than 120 seconds between consecutive frames, NexSolve detects a **Gapped Telemetry condition**. Because temporal forecasting depends on continuous momentum, the state history is invalidated and the forecaster returns `FORECAST WITHHELD: Gapped history detected`.

---

### 23. How does the system scale?
- **Streaming Parser**: Scapy `PcapReader` processes frames as a streaming generator without buffering whole files into RAM.
- **Memory Ceiling**: Enforced at 64 MB / 100,000 packets per capture on a single node.
- **Asynchronous Execution**: FastAPI delegates analysis to background thread pools (`JobManager`) with non-blocking polling (`/jobs/{id}`) and progress tracking.
- **Horizontal Scaling**: Production deployments can front multiple ASGI worker nodes behind Nginx and leverage PostgreSQL connection pooling.

---

### 24. What are the current limitations?
1. **Single-Node Ingestion Cap**: Default deployment is bounded at 64 MB / 100,000 packets per file. Line-rate multi-gigabit streaming requires a distributed message broker (e.g., Kafka).
2. **Model Promotion**: Persistence Champion remains the validated baseline; ML candidates remain research-only pending multi-domain calibration.
3. **Encrypted Payloads**: As with all flow/packet header analysis, payload-level zero-days inside end-to-end TLS cannot be inspected without TLS decryption/offloading.

---

### 25. How is this different from IDS / Suricata / Snort / Wireshark?
- **Wireshark**: An interactive packet viewer for post-incident manual inspection. Does not automate flow aggregation or forecasting.
- **Snort / Suricata**: Rule-based signature matchers and heuristic anomaly detectors that fire alerts at $T_0$ after an attack signature is seen.
- **NexSolve**: An **evidence-backed predictive network intelligence engine**. It ingests the same packets, but answers what the network state will become at $T+1 \dots T+5$, calculates attack horizons, provides bidirectional evidence, and abstains when evidence is weak.

---

### 26. What is the real-world deployment architecture?
In an enterprise network:
1. Network TAP / SPAN port mirrors core switch traffic to a capture daemon (e.g., `tcpdump` or `netsniff-ng`).
2. Rotating 60-second PCAP slices are pushed via REST API or mounted volume to NexSolve.
3. NexSolve processes each slice, maintains a rolling state buffer, forecasts the next 5 minutes, and exposes findings to the SOC dashboard and SIEM via webhook or REST API.

---

### 27. What happens after the SIH prototype?
1. **Model Calibration**: Conduct extensive multi-class empirical calibration on live institutional enterprise network mirrors.
2. **eBPF Kernel Ingestion**: Replace user-space PCAP parsing with in-kernel eBPF probes for line-rate 10Gbps+ packet extraction without packet drops.
3. **SOAR Integration**: Build automated webhooks for Palo Alto Networks, Fortinet, and Cisco firewalls to dynamically implement suggested mitigations during the forecast lead time window.

---

### 28. What is the commercialization path?
- **Target Market**: Enterprise SOCs, MSSPs (Managed Security Service Providers), Critical National Infrastructure (utilities, banks, government networks).
- **Delivery Model**: 
  1. On-Premises Virtual Appliance (Docker / Kubernetes) for air-gapped / sovereign defense networks.
  2. Cloud-managed SOC accelerator module integrating into existing Splunk, IBM QRadar, or Microsoft Sentinel deployments.
- **Value Proposition**: Drastic reduction in mean time to respond (MTTR) by converting reactive incident response into proactive mitigation during the forecast lead-time window.
