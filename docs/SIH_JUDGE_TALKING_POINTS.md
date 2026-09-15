# NexSolve — SIH 2026 Judge Talking Points & Technical Defense
**Problem Statement ID:** 26153  
**Title:** AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Technical Novelty & Core Innovation
* **Shift from Detection to Forecasting:** Standard IDS (Snort, Zeek, Suricata) and classic ML intrusion classifiers perform point-in-time classification $P(\text{Attack} \mid X_t)$ at $T_0$. NexSolve models network dynamics as a discrete-time Markovian state space and projects future network states $S_{t+1}, \dots, S_{t+K}$ using an autoregressive World Model.
* **Autoregressive Rollout:** Rather than predicting a static binary label 5 minutes into the future, NexSolve rolls out the entire 45-dimensional physical state vector recursively:
  $$\hat{S}_{t+k} = f(\hat{S}_{t+k-1}, \dots, \hat{S}_{t+k-L})$$
  This enables visibility into *how* the network is evolving (e.g., port dispersion, buffer exhaustion) before malicious impact.

---

## 2. Why Temporal Forecasting Matters
* **Defensive Lead Time:** In automated cyber attacks (e.g., Mirai botnet scans, ransomware spreading, credential stuffing), manual remediation after alerting is too late. A 60-to-300 second advance warning enables proactive automated containment (e.g., dynamic rate-limiting, egress isolation, quarantine ACLs) *during the reconnaissance stage*.
* **Monotonic Cumulative Threat Risk:** Single-step probabilities $p_h$ can fluctuate due to traffic noise, but cumulative survival risk:
  $$\text{Risk}(H) = 1 - \prod_{h=1}^H (1 - p_h)$$
  accurately quantifies multi-window sustained exposure.

---

## 3. Passive PCAP Contract & Zero-Fabrication Integrity
* **The "Zero-Fabrication" Safety Gate:** In many academic papers, models require features (like TCP RTT) that cannot be measured from passive unilateral packet taps. To satisfy model input shapes, teams often zero-fill or average-fill these columns.
* **NexSolve's Position:** Fabricating features is scientifically indefensible. NexSolve introduces a canonical **45-Feature Passive PCAP Contract** (`schema_variant: "45_feature_pcap_compatible"`) where `mean_tcp_rtt` is strictly excluded.
* **Calibrated Abstention:** If fewer than 8 continuous 60-second windows ($L < 8$) are present in a capture, NexSolve refuses to make speculative predictions, marking status as `ABSTAINED_INSUFFICIENT_HISTORY`.

---

## 4. Why Multi-Step Simulation Beats Direct Binary Multi-Step Classification
* **Physical Interpretability:** A direct classifier predicting $P(\text{Attack at } T+5)$ is a black box. An autoregressive state simulator produces projected network feature vectors for each step. Defenders can inspect future port counts, packet deltas, and protocol balances.
* **Attribution Drivers:** By computing deltas between current state $S_0$ and projected state $\hat{S}_k$, NexSolve identifies exactly which network dimensions are driving the risk elevation.

---

## 5. Behavioral MITRE ATT&CK Mapping
* **Dynamic Technique Projection:** Rather than static signature alerts, NexSolve maps kinematic trajectories to MITRE techniques:
  * Destination port growth $> 1.5\times \implies$ **T1046: Network Service Discovery** (Reconnaissance)
  * Volumetric doubling + high TCP fraction $\implies$ **T1498: Network Denial of Service** (Impact)
  * Asymmetric destination byte ratio $\implies$ **T1071: Application Layer Protocol** (C2 / Exfiltration)
* **Scope Separation:** Observed techniques (evidence from past packets) are strictly partitioned from forecasted techniques (projected future behavior).

---

## 6. Offline & Edge Operational Advantage
* **Air-Gapped Ready:** NexSolve runs entirely locally with pure Python, NumPy, and Scapy/libpcap parsing.
* **No Cloud API Dependencies:** No reliance on OpenAI, Gemini, or external SaaS APIs. Sensitive network telemetry never leaves the on-premises SOC boundary.
* **Speed:** Full ingestion, 45-feature extraction, LSTM rollout, progression mapping, and report generation execute in **under 5 seconds** for standard PCAP slices.

---

## 7. Transparent Limitations & Scientific Disclosures
* **Uncalibrated Posterior Warning:** Unless explicit empirical Platt/Isotonic calibration is verified on the deployment subnet, raw model probabilities are disclosed as `UNCALIBRATED`.
* **Lookback Requirement:** Minimum 8 windows (480 seconds) required. Burst captures shorter than 8 minutes will abstain from forward projection.
* **Passive Visibility Boundaries:** Encrypted payload content (TLS/HTTPS application layer) is not inspected; predictions rely strictly on packet timing, transport flags, directionality, and volumetric telemetry.

