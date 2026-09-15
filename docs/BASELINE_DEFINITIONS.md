# Baseline Definitions & Evaluation Tasks
**SIH 2026 Problem Statement 26153: AI based Network Attack Forecasting from Network Traffic Data**

## 1. Explicit Separation of Tasks

To maintain scientific rigor and avoid misleading benchmark claims, NexSolve-Research explicitly demarcates three distinct operational tasks:

| Task ID | Task Category | Input Information | Target Predictand | Target Time Horizon | Primary Baseline |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Task A** | **Current Attack Detection** | Physical observations in $[t-60, t)$ | Attack label $Y_t \in \{0, 1\}$ | Contemporary window $t$ | Heuristic Detector / Static Classifier |
| **Task B** | **Single-Horizon Attack Forecast** | Historical trajectory $S_{t-H:t}$ | Future attack label $Y_{t+k} \in \{0, 1\}$ | Lookahead $t+k$ ($k \in \{1, 2, 3, 4, 5\}$) | Temporal Persistence ($Y_{t+k} = Y_t$) & Logistic Regression |
| **Task C** | **Continuous State Transition** | Historical trajectory $S_{t-H:t}$ | Future continuous state $S_{t+k} \in \mathbb{R}^{45}$ | Continuous rollout $t+k$ | Temporal State Persistence ($S_{t+k} = S_t$) |
| **Task D** | **Cumulative Infiltration Risk** | Historical trajectory $S_{t-H:t}$ | $\max(Y_{t+1}, \dots, Y_{t+K}) \in \{0, 1\}$ | Impending attack anywhere in $[t+1, t+K]$ | Cumulative Persistence ($P(\text{any}) = Y_t$) |

---

## 2. Mathematical Definition of Persistence Baselines

### 2.1 One-Step State Persistence
Given the observed normalized state vector $S_t \in \mathbb{R}^{45}$ at origin window $t$, the 1-step persistence forecast for window $t+1$ is defined as:
$$\hat{S}_{t+1}^{\text{pers}} = S_t$$
Transition error is measured as:
$$\text{MSE}^{\text{pers}} = \frac{1}{45} \sum_{d=1}^{45} (S_{t, d} - S_{t+1, d})^2$$

### 2.2 Multi-Step ($H$-Step) State Persistence
For an arbitrary lookahead horizon $H \in \{1, 2, 3, 4, 5\}$ from origin $t$:
$$\hat{S}_{t+H}^{\text{pers}} = S_t$$
Notice that Persistence **does not** evolve or update dynamically; it assumes static equilibrium across the entire forward horizon. In contrast, the World Model recursively updates its internal recurrent hidden state:
$$\hat{S}_{t+1}^{\text{wm}} = f(S_{t-7:t}), \quad \hat{S}_{t+2}^{\text{wm}} = f([S_{t-6:t}, \hat{S}_{t+1}^{\text{wm}}]), \quad \dots$$

### 2.3 Label Persistence
For future attack risk at horizon $t+k$:
$$\hat{Y}_{t+k}^{\text{pers}} = Y_t$$
If the network is currently experiencing an attack ($Y_t = 1$), Persistence predicts ongoing attack at $t+k$. If currently benign ($Y_t = 0$), it predicts benign at $t+k$.

---

## 3. Logistic Regression Baseline Definition
The Logistic Regression baseline operates on the identical feature space and split as the World Model, but is strictly memoryless (no recurrent state across the 8-window history):
$$P(Y_{t+1} = 1 \mid S_t) = \sigma(\mathbf{w}^T S_t + b)$$
It is trained using class-balanced weighting (`class_weight='balanced'`) on the chronological training split.
