# Scientific Methodology & World Model Architecture
**SIH 2026 Problem Statement 26153: AI based Network Attack Forecasting from Network Traffic Data**

## 1. Problem Formulation: Transition Forecasting vs. Static Classification

Standard Intrusion Detection Systems (IDS) evaluate an isolated feature vector $X_t$ and output a contemporary label $\hat{Y}_t \in \{0, 1\}$:
$$\hat{Y}_t = f(X_t) \quad \text{(Static Classification / Detection)}$$

In contrast, SIH 2026 Problem Statement 26153 demands anticipating malicious progression before infiltration completes. This requires learning the continuous transition dynamics of the computer network:
$$\hat{S}_{t+1} \sim P(S_{t+1} \mid S_{t-H:t}) \quad \text{(State Transition Dynamics)}$$
$$\text{Risk}(t, K) = P(\text{Attack occurs in } [t+1, t+K] \mid S_{t-H:t}) \quad \text{(Future Attack Forecasting)}$$

---

## 2. Mathematical Definition of Network State $S_t$

Each state $S_t$ represents the aggregated physical and behavioral properties of network traffic over a discrete non-overlapping temporal window $W_t = [t \cdot \Delta, (t+1) \cdot \Delta)$ where $\Delta = 60\text{ seconds}$.

A canonical state $S_t \in \mathbb{R}^{45}$ is defined as a concatenated vector:
$$S_t = [\mathbf{f}_t^{\text{flow}}, \mathbf{p}_t^{\text{packet}}, \mathbf{d}_t^{\text{temporal}}]$$

Where:
1. **Flow Features** $\mathbf{f}_t \in \mathbb{R}^{17}$: Active flow count, total source bytes, total destination bytes, packet volume, mean flow duration, mean flow bytes, mean flow packets, TTL metrics (forward/reverse), TCP window metrics (forward/reverse), inter-arrival time (IAT), unique port cardinalities, and protocol distribution counts (TCP, UDP, Other). *Notice: `mean_tcp_rtt` is strictly excluded under the passive capture contract.*
2. **Packet Features** $\mathbf{p}_t \in \mathbb{R}^{22}$: Packet size distribution (mean, std, min, max), IP TTL distribution, TCP control flags (SYN, ACK, FIN, RST, PSH, URG counts), TCP window distribution, IP fragmentation, TCP sequence retransmission counts, and packet inter-arrival times.
3. **Temporal Features** $\mathbf{d}_t \in \mathbb{R}^{6}$: First-order backward temporal differences:
   $$\Delta \text{flow\_count}_t = \text{flow\_count}_t - \text{flow\_count}_{t-1}$$
   $$\Delta \text{bytes}_t = \text{total\_bytes}_t - \text{total\_bytes}_{t-1}$$
   $$\Delta \text{packets}_t = \text{total\_packets}_t - \text{total\_packets}_{t-1}$$
   $$\Delta \text{ports}_t = \text{unique\_ports}_t - \text{unique\_ports}_{t-1}$$
   $$\Delta \text{iat}_t = \text{mean\_iat}_t - \text{mean\_iat}_{t-1}$$
   $$\text{rolling\_bytes}_t = \frac{1}{4} \sum_{i=0}^3 \text{total\_bytes}_{t-i}$$

---

## 3. World Model Architecture (`NumpyLSTM`)

The core sequence encoder is a dependency-free, deterministic Long Short-Term Memory (LSTM) recurrent neural network paired with dual decoding heads:

```
Input Sequence: [S_{t-7}, S_{t-6}, ..., S_t]  (8 x 45)
                      │
                      ▼
            ┌──────────────────┐
            │   LSTM Encoder   │   Hidden Dimension = 24
            │  (NumPy Gates)   │   Input Dimension  = 45
            └─────────┬────────┘
                      │ Hidden State h_t (24-dim)
                      ▼
         ┌────────────┴────────────┐
         │                         │
         ▼                         ▼
┌──────────────────┐      ┌──────────────────┐
│  State Decoder   │      │   Attack Head    │
│  W_s h_t + b_s   │      │  σ(w_a h_t + b)  │
└────────┬─────────┘      └────────┬─────────┘
         │                         │
         ▼                         ▼
Predicted State Ŝ_{t+1}   Infiltration Risk P_{t+1}
     (45-dim)                   (Scalar ∈ [0, 1])
```

### Training Objective
The model minimizes a composite loss over training sequences:
$$\mathcal{L} = \frac{1}{D} \sum_{d=1}^{45} (\hat{S}_{t+1, d} - S_{t+1, d})^2 + \lambda \cdot \text{BCE}(y_{t+1}, \hat{p}_{t+1})$$
where $\lambda = 0.5$ and BCE is standard binary cross-entropy.

---

## 4. Multi-Horizon Recursive Rollout ($K$-Step Simulation)

To forecast the network trajectory across future horizons $H \in \{T+1, T+2, \dots, T+K\}$ without accessing future observations:
1. Input historical buffer $\mathcal{H}_0 = [S_{t-7}, \dots, S_t]$.
2. For step $k = 1 \dots K$:
   - Predict $\hat{S}_{t+k}, \hat{p}_{t+k} = \text{Model}(\mathcal{H}_{k-1})$.
   - Form updated rolling buffer $\mathcal{H}_k = [\mathcal{H}_{k-1}[1:], \hat{S}_{t+k}]$.
   - Feed predicted state $\hat{S}_{t+k}$ back as input for step $k+1$.
3. Result: Bounded autoregressive trajectory simulation $\hat{S}_{t+1} \dots \hat{S}_{t+K}$.

---

## 5. Defense Against Data Leakage

Strict isolation protocols are enforced across all pipelines:
1. **Chronological Partitioning**: Datasets are partitioned strictly by timestamps:
   $$\max(T_{\text{train}}) < \min(T_{\text{val}}) < \max(T_{\text{val}}) < \min(T_{\text{test}})$$
2. **Scaler Hygiene**: Normalization parameters ($\mu, \sigma$) are computed **solely** on training windows and frozen during validation, test, and live inference.
3. **No Target Leakage**: Attack labels $y$ are never encoded in $S_t$; only observable physical traffic metrics enter the feature vector.
4. **Safety Abstention**: If the historical observation window count $N < 8$, the forecaster explicitly withholds predictions (`abstained: true`, reason: `"insufficient history"`).

---

## 6. Downstream Progression & MITRE ATT&CK Mapping

Attack stages are mapped contextually based on empirical behavioral signals rather than static rule firing:
- **Port Scan / Sweep**: $\to$ Reconnaissance (`T1046: Network Service Discovery`)
- **Beaconing / Periodic C2**: $\to$ Command & Control (`T1071: Application Layer Protocol`)
- **High Infiltration Risk & Volume Burst**: $\to$ Exploitation (`T1190: Exploit Public-Facing Application`)
- **TCP SYN Flood / Volumetric**: $\to$ Denial of Service (`T1498: Network Denial of Service`)

---

## 7. Explainability via Counterfactual Perturbation

For any forecast $\hat{p}_{t+1}$, feature attributions are computed by perturbing each feature $d \in \{1 \dots 45\}$ to its baseline mean $\mu_d$:
$$\text{Contribution}(d) = \hat{p}_{t+1}(\mathbf{X}) - \hat{p}_{t+1}(\mathbf{X}_{\cdot, d} \leftarrow \mu_d)$$
Features producing the greatest drop in predicted risk are ranked as the primary drivers of the forecast.
