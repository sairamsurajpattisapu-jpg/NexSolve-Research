# NexSolve SIH 2-Page Architecture

## 1. System Purpose

NexSolve addresses SIH Problem Statement 26153, “AI Based Network Attack Forecasting from Network Traffic Data.” It complements reactive detection with a research World Model that forecasts likely next network states from ordered traffic history.

## 2. Architecture And Data Flow

```text
Network Traffic: CSV / PCAP
          |
Flow and Packet Feature Extraction
          |
Flow + Packet Fusion [packet branch: PENDING_PCAP]
          |
Temporal Network State S_t
          |
NumPy LSTM World Model
          |
Recursive K-step Forecast: T+1 ... T+5
          |
Contextual Attack-Stage Inference
          |
MITRE ATT&CK Context
          |
Associated-Feature Explanation
          |
Non-autonomous Defender Decision Support
```

The current executable path uses timestamped UNSW-NB15-derived flow states. CIC-IDS2017 flow CSVs are audited and usable for flow-level analysis, but their missing event timestamps prevent legitimate CIC temporal evaluation. The original PCAP is required before packet features are populated.

## 3. Feature Engineering

The protected model contract contains 46 numeric inputs: 18 flow features, 22 packet-interface features, and 6 temporal features. Flow values include counts, bytes, duration, IAT, port, TCP metadata, and protocol aggregates where available. Temporal values are derived from prior windows. Packet fields remain explicitly unavailable placeholders and are not claimed as observations.

Every active feature is represented in the provenance artifact. Labels, attack categories, IP identifiers, tuple identifiers, and future observations are excluded from the encoded state.

## 4. Temporal Representation And Model

A state is represented as $S_t = [flow_t, packet_t, temporal_t]$. The current model consumes $S_{t-7}, ..., S_t$, uses a one-layer NumPy LSTM with hidden size 24, and predicts the next state plus attack probability. The five-step rollout is recursive: each predicted state becomes input to the next horizon. Windows are 60 seconds and preprocessing is fit on training windows only.

## 5. Progression, ATT&CK, And Explanation

Traffic behavior is interpreted separately from model prediction. Supported scan-like evidence can yield a `CONTEXTUAL_HYPOTHESIS` such as reconnaissance. T1046 context is validated from the local MITRE ATT&CK STIX bundle, but no dataset label is treated as confirmed technique ground truth. Existing explanations are deterministic ablation associations, not causal explanations.

## 6. Deployment And Failure Handling

The intended product boundary is `React/Vite -> Node/Express -> ForecastEngine -> Python FastAPI research service -> NumPy World Model`. Health metadata reports availability, model version, feature count, sequence length, horizon, and packet availability. Invalid input, unavailable model, malformed model output, and insufficient evidence are explicit states; the UI never fabricates fallback probabilities.

The current CSV upload path produces traffic-analysis metadata. It does not invent a 46-feature temporal state from incompatible columns. PCAP analysis is unavailable until the dedicated packet pipeline is implemented.

## 7. Security And Privacy

Uploads are validated for type, size, schema, malformed rows, and numeric values. Raw packet payloads are not stored. Secrets are not exposed to the frontend. Uploaded content is not executed. Temporal splits, train-only preprocessing, target exclusion, and leakage reports protect evaluation integrity.

## 8. Evaluation Methodology

The current evidence uses chronological UNSW windows and one eligible mixed-state future episode. Persistence, empirical transition, and LSTM evidence are retained; CIC Logistic Regression is a static detection baseline and is not directly comparable to temporal forecasting. The LSTM macro-F1 is 0.5608 versus persistence macro-F1 0.9143 on the stored aggregate evaluation. Calibration is blocked because validation is one-class. Final model promotion remains `HOLD` until multi-horizon, calibration, leakage, and packet+flow evidence are complete.
