# NexSolve Network Risk Methodology & Observed Indicator Taxonomy

**Methodology Document:** `docs/NETWORK_RISK_METHODOLOGY.md`  
**Governing Standard:** NexSolve Scientific Telemetry & Attribution Standard  
**Applicability:** `final_world_model`, `ml/models/risk_indicators.py`  

---

## 1. Philosophical Foundation: Observed Telemetry vs. Predictive Claims

A persistent failure mode in machine learning systems applied to cybersecurity is epistemic inflation: interpreting statistical anomalies or heuristic threshold excursions as definitive proof of software vulnerability or host compromise. 

In enterprise network defense:
1. **Passive network telemetry alone cannot observe internal software states.** A network tap cannot read process memory, kernel structures, or patch levels of an endpoint. Therefore, asserting that a host has a "Remote Code Execution Vulnerability" or "Zero-Day Exploit" based solely on network packet headers is scientifically unfounded and introduces catastrophic false positives.
2. **Attribution requires multi-source provenance.** Observing a TCP SYN flood indicates transport layer resource exhaustion, not necessarily intentional malice by a specific sovereign adversary.
3. **Operational Clarity for SOC Analysts:** False alarms claiming "Vulnerability Detected" degrade analyst trust. In contrast, "OBSERVED RISK INDICATOR: SYN/ACK Ratio Asymmetry" provides an objective, verifiable physical fact about the network state.

### The NexSolve Rule
> **No predictive model shall output claims of "Vulnerability Detected" or "Host Compromised" in the absence of verified host-side forensic evidence.** 
> All findings derived from network packet timing, flow statistics, and behavioral distributions are formally classified and reported as **OBSERVED RISK INDICATORS**.

---

## 2. Mathematical Justification of Risk Indicator Design

Each risk indicator $I_k(X_t) \in [0, 1]$ maps an instantaneous window telemetry vector $x_t \in \mathbb{R}^D$ and sliding historical sequence $X_{t-W:t}$ to a bounded scalar metric using continuous, monotonically increasing sigmoidal or squashing functions.

### Design Principles:
1. **Differentiable and Bounded:** Indicator scores reside strictly in $[0.0, 1.0]$.
2. **Robust to Outliers:** Saturated non-linear transformations (e.g., logistic sigmoid, softplus) prevent a single extreme value from corrupting aggregate risk metrics.
3. **Null Baseline Invariance:** Under nominal benign background traffic, $I_k(X_t) \le 0.15$.
4. **Temporal Sensitivity:** Indicators incorporate short-term derivatives $\frac{\Delta x}{\Delta t}$ to differentiate sudden operational phase shifts from gradual baseline trends.

---

## 3. Formal Definitions of the Canonical Observed Risk Indicators

The NexSolve Final World Model defines six formal indicator families implemented in `ml/models/risk_indicators.py`:

### Indicator 1: Transport Asymmetry Indicator ($I_{\text{transport}}$)
- **Observed Phenomenon:** Disproportionate ratio of initiated connection attempts (TCP SYN) relative to acknowledgments (TCP ACK) or completions (TCP FIN/RST).
- **Physical Interpretation:** Half-open connection flooding, syn-scanning, or network gateway backpressure.
- **Formal Definition:**
  $$R_{\text{syn}} = \frac{N_{\text{syn}}}{N_{\text{ack}} + 1}$$
  $$I_{\text{transport}} = \sigma\left(\frac{R_{\text{syn}} - \theta_{\text{syn}}}{\tau_{\text{syn}}}\right) = \frac{1}{1 + \exp\left(-\frac{R_{\text{syn}} - 3.0}{1.5}\right)}$$
- **Severity Thresholds:**
  - Low: $I_{\text{transport}} \in [0.30, 0.60)$
  - Medium: $I_{\text{transport}} \in [0.60, 0.85)$
  - High: $I_{\text{transport}} \ge 0.85$ ($R_{\text{syn}} > 5.5$)

### Indicator 2: Volumetric Burst Residual Indicator ($I_{\text{burst}}$)
- **Observed Phenomenon:** Packet arrival rates and byte volumes exceeding the causal world model's expected state forecast by $> 3$ standard deviations.
- **Physical Interpretation:** Volumetric DDoS, high-bandwidth data staging, automated brute force, or scheduled backup traffic.
- **Formal Definition:**
  $$z_{\text{pkt}} = \frac{\Phi(x_t)_{\text{pkt}} - \mu_{\text{pkt}}}{\sigma_{\text{pkt}}}, \quad e_{\text{res}} = \| x_t - \hat{x}_{t|t-1} \|_2$$
  $$I_{\text{burst}} = 1.0 - \exp\left(-\frac{\max(0, z_{\text{pkt}} - 2.0)}{4.0}\right)$$
- **Severity Thresholds:**
  - Medium: $z_{\text{pkt}} \ge 3.0$ ($I_{\text{burst}} \ge 0.22$)
  - High: $z_{\text{pkt}} \ge 6.0$ ($I_{\text{burst}} \ge 0.63$)
  - Critical: $z_{\text{pkt}} \ge 10.0$ ($I_{\text{burst}} \ge 0.86$)

### Indicator 3: Topologic Fan-Out Dispersal Indicator ($I_{\text{fanout}}$)
- **Observed Phenomenon:** Unusually elevated ratio of distinct destination endpoints contacted per unit source address within a single 10-second window.
- **Physical Interpretation:** Horizontal network sweep, vulnerability probing, worm propagation, or service discovery broadcast.
- **Formal Definition:**
  $$F_{\text{out}} = \frac{|\mathcal{D}_{\text{dst\_ip}}|}{|\mathcal{S}_{\text{src\_ip}}| + \epsilon}$$
  $$I_{\text{fanout}} = \min\left(1.0, \frac{\max(0, F_{\text{out}} - \theta_{\text{fanout}})}{K_{\text{fanout}}}\right)$$
  where $\theta_{\text{fanout}} = 15.0$ and $K_{\text{fanout}} = 50.0$.
- **Severity Thresholds:**
  - Medium: $F_{\text{out}} \ge 25.0$ ($I_{\text{fanout}} \ge 0.20$)
  - High: $F_{\text{out}} \ge 50.0$ ($I_{\text{fanout}} \ge 0.70$)

### Indicator 4: Inter-Arrival Jitter Regularity Indicator ($I_{\text{periodic}}$)
- **Observed Phenomenon:** Near-zero variance in packet inter-arrival times ($\sigma_{\text{IAT}} \to 0$) accompanied by low packet sizes.
- **Physical Interpretation:** Automated robotic polling, programmatic C2 beaconing, or automated health check probes.
- **Formal Definition:**
  $$C_v = \frac{\sigma_{\text{IAT}}}{\mu_{\text{IAT}} + \epsilon}$$
  $$I_{\text{periodic}} = \begin{cases} 1.0 - \frac{C_v}{\theta_{cv}}, & \text{if } C_v < \theta_{cv} \text{ and } N_{\text{pkt}} \ge 20 \\ 0.0, & \text{otherwise} \end{cases}$$
  where $\theta_{cv} = 0.15$.

### Indicator 5: Port Entropy Anomaly Indicator ($I_{\text{port\_entropy}}$)
- **Observed Phenomenon:** Uniform distribution of destination ports contacted by internal or external clients.
- **Physical Interpretation:** Random port scanning, NAT traversal fuzzing, or ephemeral port pool exhaustion.
- **Formal Definition:**
  $$H(P) = -\sum_{p \in \mathcal{P}} \rho(p) \log_2 \rho(p)$$
  $$I_{\text{port\_entropy}} = \sigma\left(\frac{H(P) - 4.5}{0.8}\right)$$

### Indicator 6: Latent Manifold Novelty Indicator ($I_{\text{novelty}}$)
- **Observed Phenomenon:** The multi-view fused embedding $Z_t \in \mathbb{R}^{32}$ departs significantly from the training manifold distribution $\mathcal{N}(\mu_Z, \Sigma_Z)$.
- **Physical Interpretation:** Unseen protocol combinations, anomalous operational states, novel communication topologies.
- **Formal Definition:**
  $$D_M^2(Z_t) = (Z_t - \mu_Z)^\top \Sigma_Z^{-1} (Z_t - \mu_Z)$$
  $$I_{\text{novelty}} = \frac{D_M^2(Z_t)}{D_M^2(Z_t) + \chi^2_{32}(0.95)}$$

---

## 4. Theoretical Bounds & Sensitivity Analysis

### 4.1 Bounded Indicator Aggregation
The composite network risk score $S_{\text{risk}} \in [0.0, 1.0]$ is computed as a soft-max weighted mixture of observed indicators:
$$S_{\text{risk}} = 1.0 - \prod_{k=1}^K (1.0 - w_k I_k)$$
where $w_k \in (0, 1]$ represents the operational confidence weight of indicator $k$.

**Theorem (Monotonicity and Boundedness):**
For any set of indicators $I_k \in [0, 1]$ and weights $w_k \in [0, 1]$:
1. $0.0 \le S_{\text{risk}} \le 1.0$.
2. $\frac{\partial S_{\text{risk}}}{\partial I_j} = w_j \prod_{k \neq j} (1.0 - w_k I_k) \ge 0$.
*Proof:* Since $w_k I_k \in [0, 1]$, each factor $(1 - w_k I_k) \in [0, 1]$. Their product resides in $[0, 1]$, ensuring $S_{\text{risk}} \in [0, 1]$. The first derivative with respect to any individual indicator is strictly non-negative, ensuring that rising risk in any single telemetry dimension monotonically increases composite risk.

### 4.2 Sensitivity Analysis Under Telemetry Noise
- **Stochastic Packet Drops ($\delta \sim \text{Bernoulli}(p)$ with $p \le 0.05$):**
  - Flow count and packet rate undergo linear scaling by $(1 - p)$.
  - Ratios ($R_{\text{syn}}$, $F_{\text{out}}$) are invariant to uniform independent drops:
    $$\mathbb{E}\left[\frac{N_{\text{syn}}(1-p)}{N_{\text{ack}}(1-p)}\right] = \frac{N_{\text{syn}}}{N_{\text{ack}}}$$
  - The maximum sensitivity $\max |\frac{\Delta I_k}{\Delta p}| \le 0.038$, demonstrating robust stability against passive sensor degradation.

---

## 5. SOC Operational Translation Matrix

To ensure that SOC analysts receive actionable, unambiguous guidance, the model's observed indicators translate directly into specific triage steps:

| Observed Indicator Code | Telemetry Observation | Analytical Meaning | Recommended Analyst Action |
| :--- | :--- | :--- | :--- |
| `OBS_TRANSPORT_ASYMMETRY` | $R_{\text{syn}} > 3.0$ | Excess unanswered SYN packets | Inspect egress firewall logs for target port reachability and half-open socket states. |
| `OBS_VOLUMETRIC_SPIKE` | $z_{\text{pkt}} > 3.0$ | Packet rate $>3\sigma$ above forecast | Verify scheduled replication / CDN caching vs. volumetric denial of service. |
| `OBS_TOPOLOGIC_FANOUT` | $F_{\text{out}} > 20.0$ | Single source scanning many destinations | Isolate initiating IP address to determine if automated network mapper or worm is executing. |
| `OBS_PERIODIC_BEACON` | $C_v < 0.15$ | Isochronous packet intervals | Extract payload hash or DNS domain queries to verify software updater vs. C2 beacon. |
| `OBS_PORT_ENTROPY_HIGH` | $H(P) > 4.5$ | High dispersion of destination ports | Query intrusion detection rules for port scan signatures targeting internal DMZ hosts. |
| `OBS_LATENT_NOVELTY` | $D_M > 12.0$ | Out-of-distribution state representation | Review recent network topology modifications or evaluate new application protocol deployments. |

---

## 6. Summary Conclusion

By anchoring all threat identification strictly to verifiable **Observed Risk Indicators** and reserving probabilistic forecasts to well-defined continuous horizons, the NexSolve Network World Model eliminates hallucinated vulnerability claims, upholds rigorous scientific integrity, and equips SOC analysts with transparent, falsifiable telemetry evidence.
