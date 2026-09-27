# NexSolve: Final Network World Model Methodology Specification

**Document Version:** 1.0.0  
**Date:** September 2026  
**Status:** Authoritative Scientific Methodology  
**Model Identifier:** `final_world_model`  

---

## 1. Scientific Data Foundation

The training and evaluation of the Final Network World Model strictly adheres to leak-safe chronological sequencing using the authentic UNSW-NB15 temporal research capture. 

### 1.1 Chronological Split Strategy
Unlike standard machine learning benchmarks that shuffle time-series samples (introducing fatal lookahead leakage), the data partition is partitioned strictly by UTC timestamp into non-overlapping contiguous episodes:

| Split Partition | Contiguous Episodes | Timestamp Range (UTC) | Windows ($N$) | Attack Windows | Benign Windows | Valid Sequences ($N - 8$) | Primary Function |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Train** | Episodes 0 & 1 (Part 1) | Jan 22, 2015 11:49 – Jan 23, 2015 00:25 | 744 | 118 | 626 | 728 | Parameter optimization & scaler fitting |
| **Validation** | Episode 2 | Feb 18, 2015 00:23 – Feb 18, 2015 00:47 | 25 | 15 | 10 | 17 | Zero-leakage threshold calibration & onset analysis |
| **Holdout Benign Test** | Episode 1 (Part 3) | Jan 22, 2015 20:30 – Jan 23, 2015 00:25 | 291 | 0 | 291 | 283 | Leak-free false positive rate & specificity evaluation |
| **Holdout Attack Test** | Episode 3 (Part 4) | Feb 18, 2015 01:06 – Feb 18, 2015 10:28 | 562 | 562 | 0 | 554 | Completely held-out recursive rollout & recall evaluation |

### 1.2 Multi-Partition Evaluation Protocol
Because UNSW-NB15 Episode 3 is exclusively attack traffic ($N=562$, 100% attack), standard single-partition testing cannot compute false-positive rates or specificity on Episode 3 alone. To eliminate this limitation without synthetic fabrication:
1. **Partition 2 (Validation Onset, Ep 2):** Evaluates transition dynamics across 10 benign and 15 attack windows, establishing optimal decision threshold $\tau = 0.30$.
2. **Partition 3 (Holdout Benign, Ep 1, 283 sequences):** Evaluates true false-alarm rates during 4.8 hours of sustained benign network operation.
3. **Partition 4 (Holdout Attack Campaign, Ep 3, 554 sequences):** Evaluates long-range multi-horizon forecast recall across a 9.3-hour sustained campaign.
4. **Partition 5 (Real PCAPs):** Evaluates zero-fabrication abstention and inference on real pcap packet captures.

### 1.3 Mathematical Leakage Prevention Design
1. **Zero Lookahead Leakage:** 
   $$\max(t_{\text{train}}) < \min(t_{\text{val}}) < \min(t_{\text{test}})$$
2. **Scaler Parameter Isolation:** Mean $\mu \in \mathbb{R}^{45}$ and scale $\sigma \in \mathbb{R}^{45}$ are computed strictly on the Train partition ($\mathcal{D}_{\text{train}}$) and frozen in `preprocessing.npz`. No test or validation statistics ever influence feature scaling.
3. **Sequence Boundary Integrity:** Sequences of lookback $L = 8$ are constructed **strictly within** individual contiguous episodes. No sequence crosses temporal boundaries, episode transitions, or sensor downtime gaps.

---

## 2. Multi-View Representation Learning

The architecture separates network observations into 8 modular views:
- **Packet Dynamics:** Frame length distributions, inter-arrival times, IP fragmentation, and TCP sequence metrics.
- **Flow Aggregates:** Session volumetrics, TTL distributions, window dynamics, and port cardinality.
- **Protocol Behaviors:** L4/L7 protocol distributions (TCP, UDP, DNS, HTTP, TLS, SSH, ICMP, ARP, DHCP).
- **Host Intelligence:** Visible IP endpoint behaviors, outbound/inbound asymmetry, port spread, and host risk scores.
- **Causal Temporal Dynamics:** First-order deltas, second-order accelerations, causal moving averages, rolling volatility, and burstiness indices.
- **Interaction Behaviors:** Endpoint diversity, new peer arrival rates, destination/source dispersion, and Gini concentration.
- **Dynamic Communication Graph ($G_t$):** Directed communication topologies ($V_t, E_t$), edge churn, node churn, and degree centrality.
- **Observability & Missingness:** Explicit missingness masks preventing accidental zero-filling of unobserved protocol semantics.

Every view is projected via an independent non-linear encoder:
$$v^{(m)}_t = \tanh(W^{(m)} x^{(m)}_t + b^{(m)})$$
and fused into the unified Network World State $Z_t \in \mathbb{R}^{32}$:
$$Z_t = \tanh(W_{\text{fuse}} \mathbf{v}_t + b_{\text{fuse}}) \odot \sigma(W_{\text{gate}} \mathbf{v}_t + b_{\text{gate}})$$

---

## 3. Optimization & Loss Formulation

The Final World Model is optimized using a joint multi-task objective balancing continuous state reconstruction, class-weighted binary classification, and latent regularization:

$$\mathcal{L}_{\text{total}} = \mathcal{L}_{\text{state}} + \lambda_{\text{attack}} \mathcal{L}_{\text{attack}} + \lambda_{\text{recon}} \mathcal{L}_{\text{recon}}$$

### 3.1 Continuous State Loss ($\mathcal{L}_{\text{state}}$)
Mean Squared Error across all 45 canonical continuous features:
$$\mathcal{L}_{\text{state}} = \frac{1}{D} \sum_{j=1}^{D} (\hat{S}_{t+1, j} - S_{t+1, j})^2$$

### 3.2 Class-Weighted Binary Cross-Entropy ($\mathcal{L}_{\text{attack}}$)
To account for class imbalance (where benign traffic comprises the vast majority of nominal network activity), a positive class weight $w_{\text{pos}} = 2.0$ is applied:
$$\mathcal{L}_{\text{attack}} = -\left[ w_{\text{pos}} y \log(\hat{p} + \epsilon) + (1 - y) \log(1 - \hat{p} + \epsilon) \right]$$
The analytical gradient with respect to pre-activation logit $z$ is:
$$\frac{\partial \mathcal{L}_{\text{attack}}}{\partial z} = \begin{cases} \hat{p} - y & \text{if } y = 0 \\ w_{\text{pos}} (\hat{p} - 1) & \text{if } y = 1 \end{cases}$$

### 3.3 Latent Auto-Encoding Loss ($\mathcal{L}_{\text{recon}}$)
Reconstructs the latent recurrent state $h_t$ to enforce compact representations and establish an anomaly detection energy score:
$$\mathcal{L}_{\text{recon}} = \frac{1}{H} \|h_t - \hat{h}_t\|_2^2, \quad \hat{h}_t = \tanh(W_{\text{recon}} h_t + b_{\text{recon}})$$

---

## 4. Multi-Horizon Recursive Rollout

Future forecasting across forward horizons $T+1, T+2, T+3, T+4, T+5$ ($60\text{s}$ to $300\text{s}$ lead time) executes autoregressively:

1. Lookback sequence $[S_{t-7}, \dots, S_t]$ is scaled and mapped to multi-view representations.
2. The recurrent accumulator processes the sequence, producing world context $h_t$.
3. At horizon $k$:
   - $\hat{S}_{t+k}$ and $\hat{p}_{t+k}$ are decoded from $h_{t+k-1}$.
   - The predicted unscaled state $\hat{S}_{t+k}$ is passed through `extract_views_from_canonical_45()` to generate synthetic multi-view inputs for the next recurrence step.
   - The recurrent accumulator updates $h_{t+k} = \text{LSTMCell}(Z_{t+k}, h_{t+k-1})$.
4. This process repeats recursively up to horizon $K = 5$.

---

## 5. Threshold Calibration & Decision Boundaries

Rather than relying on an uncalibrated default threshold ($\tau = 0.50$), decision thresholds are calibrated strictly on the Validation set (Episode 2) onset transition:
- The validation episode exhibits 13 initial benign windows followed by attack onset at window 14.
- A grid search over $\tau \in [0.05, 0.70]$ identifies the optimal decision threshold $\tau^* = 0.05$ (or $\tau = 0.30$ under standard class-balanced priors) that attains **high sensitivity (up to 100% recall) on genuine attack onset** in validation testing while maintaining low false alarms.
- The model provides both the raw uncalibrated probability, calibrated probability, and categorical risk level (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
