# NexSolve Forecasting Pipeline Forensic Audit

Generated: 2026-09-14
Auditor: Forensic Scientific Claim Verification Pass
Scope: End-to-End Real Code Path Audit from PCAP to Evaluation

---

## 1. Executive Summary & Code Path Architecture

This document establishes the exact, line-by-line source code traceability of the NexSolve forecasting pipeline. It identifies exact input/output signatures, feature dimensions, windowing semantics, parameter fitting boundaries, and temporal leakage controls.

`
[ Raw PCAP / PCAPNG File ]
       │
       ▼
ml/data/pcap_extractor.py::extract_canonical_capture()
       │ Inputs: Raw bytes / Path, window_seconds=60
       │ Outputs: packets: tuple[PacketRecord], windows: tuple[TemporalWindow], quality: dict
       │ Window Semantics: Contiguous, non-overlapping 60s windows [W_start, W_start + 60)
       │ Deterministic: YES. Future Information: NONE.
       ▼
nexsolve_core/state.py::build_network_state_candidates()
       │ Inputs: windows: tuple[TemporalWindow], capture_start_timestamp: str
       │ Outputs: list[NetworkStateCandidate] (raw flow, packet, and temporal features)
       │ Temporal Semantics: Window t deltas depend strictly on t and t-1; rolling metrics average past <=4 windows.
       │ Deterministic: YES. Future Information: NONE.
       ▼
nexsolve_core/state.py::evaluate_model_compatibility()
       │ Evaluates candidates against MODEL_SCHEMA_46 vs MODEL_SCHEMA_45
       │ Safety Gate: If mean_tcp_rtt is missing, drops to MODEL_SCHEMA_45 (45 features)
       │ Prevents zero-fill or synthetic RTT fabrication.
       ▼
nexsolve_core/state.py::candidates_to_network_states()
       │ Inputs: candidates, feature_schema=MODEL_SCHEMA_45, history_status=READY
       │ Outputs: tuple[world_model.NetworkState] (45 features)
       │ Feature Dimensions: 17 Flow + 22 Packet + 6 Temporal = 45 features
       │ Deterministic: YES. Future Information: NONE.
       ▼
world_model.py::load_model()
       │ Loads models/nexsolve_world_model_45/ (model.npz, preprocessing.npz)
       │ Scaler: fixed StandardScaler parameters (mean, scale of shape (45,)) fit on UNSW-NB15 training runs.
       │ Learner: NumpyLSTM (input_size=45, hidden_size=24, output_size=46)
       ▼
world_model.py::infer() / ml/forecasting/
       │ Inputs: rolling sequence of 8 NetworkStates, K=5
       │ Preprocessing: scaled = (matrix - scaler_mean) / scaler_scale
       │ Step 1..K Autoregressive Rollout:
       │   - predicted_scaled, probability = model.predict(scaled)
       │   - vector = predicted_scaled * scaler_scale + scaler_mean
       │   - append synthesized NetworkState for step K+1 rollout
       │ Deterministic: YES. Future Information: NONE. Future Ground Truth: NEVER INJECTED.
       ▼
ml/forecasting/attack_progression.py::forecast_attack_progression()
       │ Inputs: observed_findings, behavioral_report, horizons=(1, 3, 5, 10, 15)
       │ Evaluates empirical Markov transitions P(State_{T+K} | State_T)
       │ Outputs: StageForecastPoint per horizon
       │ Constraints: Strictly separates STATE_PERSISTENCE from DOWNSTREAM_PROGRESSION.
       │   Abstains on benign baseline, K>5, or lookback < 8.
       ▼
nexsolve_core/fusion.py::fuse_threat_assessment()
       │ Synthesizes ThreatAssessment strictly segregating OBSERVED vs FORECAST evidence.
`

---

## 2. Stage-by-Stage Forensic Matrix

| Stage | Source File & Function | Input Contract | Output Contract | Dimensions | Temporal Semantics | Future Data Leakage Risk | Fitting Boundary | Deterministic? |
|---|---|---|---|:---:|---|---|---|:---:|
| **1. Ingestion** | pcap_extractor.py::extract_canonical_capture | PCAP bytes / Path | (packets, windows, quality) | N/A | Non-overlapping 60s windows | **SAFE**: Packets strictly binned by hardware epoch timestamp | No fitted parameters | YES |
| **2. State Building** | state.py::build_network_state_candidates | windows | list[NetworkStateCandidate] | 45 features | Backward-looking deltas (t vs t-1) and rolling means (t-3..t) | **SAFE**: Window 0 deltas unavailable; no lookahead | No fitted parameters | YES |
| **3. Schema Gate** | state.py::evaluate_model_compatibility | candidates, schema | ModelCompatibilityReport | 45 or 46 | Intercepts missing mean_tcp_rtt | **SAFE**: Zero-fill explicitly forbidden | No fitted parameters | YES |
| **4. State Encode** | state.py::candidates_to_network_states | candidates | 	uple[NetworkState] | 45 features | Converts candidate dictionaries to NetworkState | **SAFE**: ttack_state excluded from encoding | No fitted parameters | YES |
| **5. Model Scaling** | world_model.py::load_model | preprocessing.npz | (mean, scale) | (45,) | Fixed linear transform: (x - mean) / scale | **SAFE**: Fitted exclusively on historical training split | Frozen training parameters | YES |
| **6. LSTM Rollout** | world_model.py::infer | Sequence (8, 45) | Forecasts (K, 45) | (45,) | Autoregressive step t+k from prior predicted states | **SAFE**: True future states are never fed into rollout | Weights frozen in model.npz | YES |
| **7. Progression** | ttack_progression.py::forecast_attack_progression | Observed evidence | AttackProgressionForecast | K in {1, 3, 5} | Empirical Markov transitions from Friday baseline | **SAFE**: Predicts persistence only; abstains on downstream gap | Ground-truth empirical transition matrices | YES |
| **8. Fusion** | usion.py::fuse_threat_assessment | Observed & forecast signals | ThreatAssessment | N/A | Normalizes multi-modal items | **SAFE**: OBSERVED and FORECAST strictly isolated | Rule-based normalization | YES |

---

## 3. Scientific Discrepancy & Reality Corrections

1. **NumPy LSTM Architecture**:
   - Stated in previous audit: *2-layer NumPy LSTM*.
   - Proven reality: **Single-layer NumPy LSTM** ( \in \mathbb{R}^{96 \times 69}$,  \in \mathbb{R}^{96}$) with linear projection head ( \in \mathbb{R}^{46 \times 24}$,  \in \mathbb{R}^{46}$).
2. **Model Training Data**:
   - The production world model weights (models/nexsolve_world_model_45/model.npz) were trained on **UNSW-NB15 flow records** binned into 60-second windows.
   - Packet-level features were absent in the UNSW-NB15 flow CSVs and set to 0 with packet_features_available=False during training.
   - The model learns background temporal dynamics from UNSW-NB15, but has **NOT** been retrained on full packet-level PCAP datasets.
3. **Forecasting Accuracy vs. Persistence Baseline**:
   - As documented in eports/world_model_final_evaluation.md, on the single mixed-state held-out test episode in UNSW-NB15:
     - **LSTM**: F1 = 0.533, Balanced Accuracy = 0.682, PR-AUC = 0.849, Coverage = 0.667 (abstains on first 8 windows).
     - **Temporal Persistence Baseline**: F1 = 0.929, Balanced Accuracy = 0.914, PR-AUC = 0.904, Coverage = 1.0.
   - **Conclusion**: The temporal persistence baseline outperforms the NumPy LSTM world model on next-window attack state prediction. The LSTM world model provides future continuous state vectors, but its binary attack prediction head does not demonstrate an advantage over persistence.
