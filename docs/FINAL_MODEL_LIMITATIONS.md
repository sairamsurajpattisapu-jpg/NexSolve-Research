# NexSolve Final Network World Model — Limitations & Operational Boundaries

**Model ID:** `final_world_model`  
**Architecture:** Multi-View Causal Recurrent World Model with Multi-Task Uncertainty Decoders  
**Status:** Approved for Production Deployment  
**Evaluation Reference:** `docs/FINAL_MODEL_EVALUATION.md`  

---

## 1. Executive Summary

The NexSolve Final Network World Model operates strictly on causal, temporal network state representations derived from passive flow telemetry, packet dynamics, behavioral ratios, and host-graph interactions. While it substantially advances over the Candidate V2 baseline—achieving +11.43% validation onset F1, multi-horizon state forecasting ($T+1$ through $T+5$), and calibrated epistemic/aleatoric uncertainty quantification—it possesses well-defined boundary conditions and operational constraints.

This document formally records the system's operational boundaries, known failure modes, structural blind spots, and deployment prerequisites to ensure safe, transparent execution within enterprise SOC environments.

---

## 2. Concrete Boundary Conditions

| Dimension | Operational Range | Behavior Outside Boundary |
| :--- | :--- | :--- |
| **Observation History Length ($W$)** | Minimum 5 windows, Optimal $\ge 10$ windows (100–300s) | When $W < 5$, engine transitions to `OBSERVABILITY_ONLY` or degrades state forecasting. Initial recurrence has elevated variance until $W \ge 5$. |
| **Flow Density per Window** | 1 to $500,000$ concurrent flows | Extreme saturation (>500k flows/min) without hardware flow table offload causes window batch aggregation delays. |
| **Temporal Sampling Interval ($\Delta t$)** | Strictly nominal 10.0s ($\pm 2.0$s tolerance) | Sub-second burst jitter does not affect window aggregation; however, interval skew $>5.0$s degrades recurrence pacing, triggering temporal telemetry drift alerts. |
| **Active Host Topology Scale ($|V_t|$)** | Evaluated up to 10,000 active endpoints per enterprise enclave | Dynamic topological matrices are computed over the top-$K$ ($K=128$) dynamic host subgraph. Unseen edge degrees $>500$ are log-compressed. |
| **Input Feature Domain** | Strictly 45 normalized continuous dimensions in $[0, \infty)$ | Values $>10 \times \text{IQR}$ are clamped to 99.9th percentile bounds to prevent activation explosion. |
| **Distributional Novelty (OOD)** | Mahalanobis Distance $D_M(z) \le 12.0$ | When $D_M(z) > 12.0$, the 5-tier abstention engine demotes execution to `ANOMALY_ONLY` or `ABSTAIN`. |

---

## 3. Top 5 Failure Modes & Mitigation Strategies

### Failure Mode 1: Low-Volume Asynchronous Beaconing (< 1 packet / 60 seconds)
- **Mechanism:** Ultra-low-frequency C2 beaconing (e.g., DNS tunneling or HTTP keep-alives firing once every 120–300 seconds) generates packet counts that fall below the statistical noise floor of 10-second summary windows.
- **Consequence:** Sliding behavioral entropy and packet count bursts remain near baseline averages; onset detection recall on $T+1$ is reduced.
- **Mitigation:** Recurrent hidden state accumulator ($h_t$) retains exponential decay memory across up to 32 steps ($~320$ seconds). Combined with long-window periodicity detectors in the host graph, sustained low-frequency periodicity accumulates in the latent trajectory. When uncertain, epistemic uncertainty $\sigma^2_{\text{epistemic}}$ spikes, triggering SOC review.

### Failure Mode 2: Distributed Multi-Source Low-and-Slow Port Scans
- **Mechanism:** Port sweeps coordinated across hundreds of distinct external IP addresses where each IP probes fewer than 3 internal ports over an hour.
- **Consequence:** Ingress connection entropy increases modestly, but individual host graph degree changes remain within normal background fluctuations.
- **Mitigation:** Multi-view fusion correlates the *Global Flow Volumetric View* (entropy anomaly) with the *Host Graph View* (aggregate in-degree distribution shifts), surfacing a distributed reconnaissance signature without requiring attribution to a single IP.

### Failure Mode 3: Sudden High-Volume Legitimate Traffic Surges (Flash Crowds / Data Migration)
- **Mechanism:** Scheduled large-scale database replication, off-site backup transfers, or sudden legitimate user flash crowds cause massive surges in flow counts, byte volumes, and burst metrics.
- **Consequence:** Volumetric anomaly heads trigger high residual errors ($e_{\text{state}} > 4.0$).
- **Mitigation:** The Multi-Task Decoder decouples volumetric state prediction from attack stage classification. While state error $e_{\text{state}}$ triggers `VOLUMETRIC_SPIKE`, the MITRE taxonomy stage remains unactivated unless behavioral ratios (SYN/ACK asymmetry, DNS error ratios, NXDOMAIN rates) also shift. The output is cleanly categorized as a volumetric anomaly rather than an adversarial attack.

### Failure Mode 4: Asymmetric Routing and Unidirectional Passive Telemetry
- **Mechanism:** Passive network sensors positioned on asymmetric uplinks observe only forward traffic (client to server) without observing return traffic (server to client).
- **Consequence:** Return packet ratios, SYN/ACK handshake completion metrics, and bidirectional byte ratios are distorted or zeroed.
- **Mitigation:** The feature registry strictly treats missing reverse telemetry as unobserved rather than zero-filled. If bidirectional features are flagged as unobserved, the multi-view encoder masks out the bidirectional view and scales the epistemic uncertainty, transitioning the engine to `DEGRADED_FORECAST`.

### Failure Mode 5: Drastic Post-Maintenance Network Topology Restructuring
- **Mechanism:** Corporate subnet re-addressing or firewall routing changes instantly alter internal-to-internal graph edge patterns and host clustering.
- **Consequence:** Mahalanobis distance in the latent space $Z_t$ exceeds the 99th percentile threshold ($D_M > 12.0$), causing false OOD rejection.
- **Mitigation:** Tier 3 Abstention (`ANOMALY_ONLY`) automatically engages, suppressing high-confidence attack classification while logging an operational `OUT_OF_DISTRIBUTION` event with feature-level contribution attribution, alerting administrators to trigger background baseline recalibration.

---

## 4. Topology and Traffic Profile Dependencies

1. **Enterprise Enclave Assumption:**
   - The world model is optimized for enterprise core, distribution, and DMZ enclaves. It assumes a structured internal IP space (RFC 1918) communicating with external internet endpoints.
   - Deploying directly on transit provider peering points without internal/external distinction reduces graph localization fidelity.
2. **Encrypted Payload Independence:**
   - The model makes zero assumptions regarding payload visibility; it operates 100% on layer-3/layer-4 telemetry, packet timing, inter-arrival dynamics, and flow records. Deep packet inspection (DPI) decryption is never required.
3. **Protocol Distribution Expectations:**
   - Designed for standard corporate IP traffic mixes (TCP 60–85%, UDP 10–35%, ICMP 1–5%). Environments with exotic encapsulation (e.g., raw GRE over IP, VXLAN overlays) require outer tunnel termination before telemetry ingestion.

---

## 5. Known Blind Spots

1. **Intra-Host Process Execution:**
   - The model has no endpoint agent telemetry (EDR). Attacks that execute entirely in-memory on a single compromised host without generating network packets (e.g., local LSASS dumping) are completely invisible to network telemetry.
2. **Slow Exfiltration via Existing TLS Sessions:**
   - Data exfiltrated through established, pre-existing authorized HTTPS tunnels (e.g., authorized OneDrive or Google Drive uploads) at normal user speeds without anomalous flow creation cannot be distinguished from benign productivity traffic.
3. **Passive TCP RTT Telemetry:**
   - In accordance with the project's strict non-fabrication standard, passive TCP RTT is excluded unless direct hardware timestamping is present. RTT-based geographical distance estimation is therefore not supported.

---

## 6. Data Drift & Distributional Vulnerabilities

- **Seasonal Drift:** Weekly cycles (working hours vs. weekends, night maintenance windows) alter baseline feature distributions. The recurrent accumulator adapts to short-term changes, but seasonal baselines require weekly running-mean updates.
- **Software Upgrades:** Mass rollout of new cloud synchronization clients or VPN concentrators alters client flow fan-out ratios.
- **Drift Detection Mechanism:** The production engine continuously monitors running 500-window rolling statistics against the reference distribution in `preprocessing.npz`. When the Kolmogorov-Smirnov drift test on latent $Z_t$ outputs $p < 0.01$ over 100 consecutive windows, a `MODEL_DRIFT_ALERT` is surfaced.

---

## 7. Adversarial Evasion Limits

- **Adversarial Timing Perturbations:** Attackers who intentionally jitter packet inter-arrival times (e.g., Gaussian random delay injection) can manipulate the packet inter-arrival variance view. However, cross-view gated fusion prevents single-view evasion from suppressing host graph and volumetric indicators.
- **Volume Throttling:** Attackers limiting exfiltration to $< 10$ KB/s will bypass volumetric threshold alarms, but will remain vulnerable to cumulative graph fan-out and connection count tracking over 320-second recurrent trajectories.
- **Adversarial Latent Perturbations:** Gradient-based adversarial perturbations against the model's feature vectors are mitigated by latent clamping, Mahalanobis OOD gating, and epistemic uncertainty escalation. Any feature perturbation that pushes $z_t$ outside the training manifold forces immediate model abstention.

---

## 8. Operational Prerequisites

Before deploying the Final Network World Model into active SOC pipelines, the following operational requirements must be satisfied:

1. **Telemetry Pipeline Quality:**
   - Packet loss at the network tap/mirror port must not exceed $0.1\%$.
   - Flow export timeout must be configured to active timeout = 10s, inactive timeout = 5s to ensure synchronized window alignment.
2. **Computational Resources:**
   - Minimum 2 CPU cores dedicated to ML inference.
   - 512 MB available RAM per inference thread (model weights + state buffers require $< 15$ MB).
3. **Warm-up Period:**
   - Inference callers must allow a warm-up buffer of at least 8 consecutive windows (8 minutes) before relying on $T+1..T+5$ forecasts. During warm-up, the system operates in `OBSERVABILITY_ONLY` mode.
4. **Human Review Escalation:**
   - All high-confidence detections must feed existing SOC ticketing systems with full indicator telemetry; the model operates as a Decision Support and Early Warning World Model, not an automated firewall disruptor.

---

## 9. Hardened Technical Clarifications (Audit Resolutions)

Following the independent technical audit, the following architectural and empirical boundaries are formally established:

### 9.1 Feature Representation (45 Canonical vs 115 Registry Features)
- **45 Core Inputs:** The core mathematical model `FinalNetworkWorldModel` ingests exactly 45 canonical continuous features (`MODEL_SCHEMA_45`).
- **Feature Registry Audit:** Of the 115 features defined in `FeatureRegistry`:
  - **Category A (44 unique / 45 dimensions):** Directly enter the neural network weights.
  - **Category B (2 PCAP-extracted features):** `fwd_psh_flags` and `bwd_psh_flags` are extracted from packet headers and mapped into the transport flag sum.
  - **Category C (61 registry specs):** Theoretical/speculative feature entries in the catalog that are mathematically projected or derived via `extract_views_from_canonical_45()` into the 8 encoder views.
  - **Category D (8 host-internal features):** Structural endpoint features (`cpu_utilization`, `memory_rss`, `open_file_descriptors`, etc.) that are structurally unobservable from passive network PCAP taps without endpoint agent instrumentation. These features are cleanly flagged as unobserved with explicit missingness masks rather than fabricated.

### 9.2 Protocol Extraction & Port-Based Heuristics
- Passive packet decoders natively parse L3/L4 headers (IP, TCP, UDP, ICMP, ARP).
- When deep application payload inspection or Zeek session logs are unavailable, higher-layer protocols (DNS, HTTP, TLS, SSH, DHCP) are profiled via well-known port bindings (53, 80/8080/443, 22, 67/68) and transport flag behaviors. No unobserved payload semantics are fabricated.

### 9.3 Temporal Graph Dynamics
- The host graph module constructs directed communication topologies ($G_t = (V_t, E_t)$) between actively communicating IP endpoints within each temporal window.
- Edge churn, node churn, and degree centrality are computed dynamically over observed flows.
- When flow records lack explicit destination ports (`dst_port: None`) or contain malformed non-numeric values, the parser defaults safely to port 0 without crashing or port fabrication.

### 9.4 Single-Class Test Partition & False Positive Specificity
- UNSW-NB15 Episode 3 (Test Partition) contains exclusively attack traffic ($N=562$ windows, 100% attack). While this provides a rigorous test for multi-hour sustained attack recall and state tracking stability, it cannot mathematically yield false positive rates or specificity.
- True benign specificity is proven on Episode 1 (283 contiguous benign windows across 4.8 hours), where the hardened model achieves **97.17% Specificity (FPR = 2.83%)** at calibrated threshold $\tau = 0.30$, and **98.94% Specificity (FPR = 1.06%)** at conservative threshold $\tau = 0.50$.

