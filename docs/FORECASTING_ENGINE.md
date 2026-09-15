# NexSolve Multi-Horizon World Model Forecasting Engine
**SIH 2026 Problem Statement ID**: 26153  
**System**: AI-Based Network Attack Forecasting from Network Traffic Data  

---

## 1. Architectural Overview

The **NexSolve World Model Forecasting Engine** predicts future cyber attacks by modeling continuous network telemetry dynamics rather than relying purely on static signature matching or instantaneous thresholding.

```
Passive Network PCAP / PCAPNG
              │
              ▼
   Canonical 45-Feature Extraction
   (17 Flow + 22 Packet + 6 Temporal)
   [mean_tcp_rtt strictly omitted]
              │
              ▼
    Temporal State Construction
      (Lookback Window N >= 8)
              │
              ▼
      NumpyLSTM World Model
              │
     ┌────────┴──────────────────────────┐
     ▼                                   ▼
Recursive Continuous Rollout      Attack Likelihood Scoring
(Horizons H = 1, 2, 3, 4, 5)      P(Attack at T+H)
     │                                   │
     └─────────────────┬─────────────────┘
                       ▼
          Forecasting Pipeline Core
    ┌──────────────────────────────────────────────┐
    │ 1. Cumulative Infiltration Risk              │
    │    Risk(H) = 1 - \prod_{h=1}^H (1 - p_h)     │
    │ 2. Early Warning Score (0 - 100)             │
    │    S = 35*p1 + 35*Risk(5) + 15*acc + 15*disp │
    │ 3. Behavioral Progression & MITRE Mapping    │
    │    (T1046, T1071, T1190, T1498)              │
    │ 4. Domain Feature Driver Attribution         │
    │    Top 5 drivers per horizon with deltas     │
    │ 5. Graceful Abstention Guardrails            │
    └──────────────────────────────────────────────┘
                       │
                       ▼
          REST API & Web Interface
```

---

## 2. Mathematical Formulations

### 2.1 Forward Multi-Horizon Continuous Rollout
Let $s_t \in \mathbb{R}^{45}$ denote the observable network state at epoch window $t$. Given a historical sequence of lookback length $L=8$, $[s_{t-7}, \dots, s_t]$, the world model predicts:
1. Future continuous network state: $\hat{s}_{t+1} \in \mathbb{R}^{45}$
2. Instantaneous attack probability: $p_1 = P(\text{Attack at } t+1) \in [0, 1]$

To forecast multi-step horizons $H \in \{1, 2, 3, 4, 5\}$, the model recursively feeds its own state predictions forward:
$$\hat{s}_{t+h}, p_h = \text{Model}([\hat{s}_{t+h-8}, \dots, \hat{s}_{t+h-1}])$$

### 2.2 Single-Horizon vs. Cumulative Infiltration Risk
A critical distinction implemented in NexSolve is separating single-horizon probability from multi-window cumulative risk:
- **Instantaneous Attack Probability** $p_h = P(\text{Attack at } T+h)$: The probability that an attack manifests specifically during window $T+h$.
- **Cumulative Infiltration Risk** $\text{Risk}(H)$: The cumulative probability that at least one attack occurs within the forward window from $T+1$ to $T+H$:
$$\text{Risk}(H) = 1 - \prod_{h=1}^H (1 - p_h)$$

**Properties**:
- **Monotonicity**: $\text{Risk}(H_a) \le \text{Risk}(H_b)$ for any $H_a < H_b$.
- **Survival Semantics**: Represents the probability that network defenses are breached within the time horizon.

### 2.3 Transparent Early Warning Score (0 - 100)
The early warning score aggregates multiple orthogonal threat signals into an actionable operational indicator:
$$S = \min\left(100, \max\left(0, 35 \cdot p_1 + 35 \cdot \text{Risk}(5) + 15 \cdot \Delta_{\text{accel}} + 15 \cdot \text{Dispersion}\right)\right)$$

Where:
- $p_1$: Immediate onset threat probability at $T+1$ (35% weight).
- $\text{Risk}(5)$: Cumulative 5-window infiltration risk (35% weight).
- $\Delta_{\text{accel}} = \max(0, p_3 - p_1)$: Trajectory acceleration over the first 3 minutes (15% weight).
- $\text{Dispersion} = \min(1.0, \max(0, \frac{\text{ports}_{T+3} - \text{ports}_{T}}{\max(\text{ports}_T, 1)}))$: Port cardinality and volume divergence (15% weight).

**Severity Thresholds**:
- `CRITICAL`: $S \ge 75$
- `HIGH`: $50 \le S < 75$
- `ELEVATED`: $25 \le S < 50$
- `NORMAL`: $S < 25$

---

## 3. Behavioral Progression & MITRE ATT&CK Mapping

The forecasting pipeline correlates projected state vectors across horizons to identify attack progression:

| Projected Stage | Telemetry Condition | MITRE ATT&CK Technique |
| :--- | :--- | :--- |
| **RECONNAISSANCE** | Unique destination ports $> 15$ or expanding | `T1046` (Network Service Discovery) |
| **COMMAND_AND_CONTROL** | High asymmetric outbound byte transfer ($> 4\times$ inbound) | `T1071` (Application Layer Protocol) |
| **EXPLOITATION** | Attack probability $\ge 0.70$ with flow volume expansion | `T1190` (Exploit Public-Facing Application) |
| **DENIAL_OF_SERVICE** | TCP SYN count $> 50$ or packet surge $> 2\times$ baseline | `T1498` (Network Denial of Service) |
| **STABLE_BENIGN** | Attack probability $< 0.40$ and state in equilibrium | Baseline Equilibrium |

---

## 4. Domain Feature Driver Attribution

For every forecasted horizon $H$, the engine computes the relative delta between the current state $s_t$ and projected state $\hat{s}_{t+H}$:
$$\Delta_{\text{rel}}(f) = \frac{\hat{s}_{t+H}[f] - s_t[f]}{\max(|s_t[f]|, 10^{-4})}$$

The top 5 drivers by $|\Delta_{\text{rel}}|$ are attributed with human-interpretable network security meanings:
- **Port Expansion**: Distinguishes between broad service discovery/port scanning and targeted service probing.
- **Volumetric Dynamics**: Captures throughput anomalies, packet floods, and data exfiltration pressure.
- **Inter-Arrival Times (IAT)**: Flags automated beaconing rhythms and rapid burst transmissions.
- **TCP Flags (SYN/RST/FIN)**: Signals connection exhaustion floods and half-open scans.
- **TCP Window Fluctuations**: Exposes receiver buffer exhaustion and exfiltration pacing.

---

## 5. Scientific Safety & Fallback Guardrails

1. **Passive PCAP Compatibility (45 Features)**:
   - Evaluates only passive, non-intrusive features.
   - `mean_tcp_rtt` is strictly excluded from the canonical PCAP vector.
   - Zero-filling missing features is strictly forbidden.
2. **Insufficient History Handling**:
   - If historical observations $N < 8$ (fewer than 480 seconds of capture), the pipeline explicitly withholds predictions with status `ABSTAINED_INSUFFICIENT_HISTORY`.
3. **Model Availability Fallback**:
   - If model weights or scaler parameters are missing, the pipeline gracefully outputs `MODEL_UNAVAILABLE` without crashing or returning deceptive estimates.
4. **Calibration Transparency**:
   - When using uncalibrated probability rollouts, the UI and API explicitly display `UNCALIBRATED` probability status badges.
