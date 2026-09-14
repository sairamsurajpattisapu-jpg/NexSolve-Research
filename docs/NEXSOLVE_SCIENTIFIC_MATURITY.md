# NexSolve Scientific Maturity Matrix & Claim Policy

Generated: 2026-09-14
Auditor: Forensic Scientific Claim Verification Pass
Scope: Separation of Engineering Validation vs. Scientific Validation

---

## 1. Scientific Validation Maturity Levels

- **LEVEL 0**: Code exists.
- **LEVEL 1**: Unit/integration tests pass.
- **LEVEL 2**: Real-PCAP inference demonstrated without crashes.
- **LEVEL 3**: Quantitative evaluation executed on held-out test data.
- **LEVEL 4**: Evaluation proven leakage-safe and temporally valid.
- **LEVEL 5**: Results proven statistically credible, reproducible, and superior to baselines.
- **LEVEL 6**: Generalization demonstrated across independent datasets/network topologies.

---

## 2. Capability Scientific Maturity Matrix

| Capability | Implementation Status | Real-PCAP Status | Evaluation Status | Leakage Status | Scientific Maturity | Allowed Claim |
|---|---|---|---|---|:---:|---|
| **45-Feature Extraction** | Implemented (pcap_extractor.py, state.py) | Demonstrated on Friday slice | Formally verified in unit tests | SAFE | **LEVEL 2** | "Deterministic 45-feature extraction operationally verified on real PCAP captures." |
| **45-Feature Model Compatibility** | Implemented (state.py) | Demonstrated on Friday slice | Formally verified | SAFE | **LEVEL 2** | "Deterministic schema gate verifies model readiness and prevents RTT zero-filling." |
| **World Model (NumPy LSTM)** | Implemented (world_model.py) | Demonstrated on Friday slice | Evaluated on UNSW-NB15 | SAFE (within UNSW) | **LEVEL 3** | "NumPy LSTM world model trained on UNSW-NB15 flow data; persistence baseline outperforms on binary attack prediction." |
| **Forecasting K=1 (60s)** | Implemented (world_model.py) | Demonstrated on Friday slice | Evaluated on held-out episode | SAFE | **LEVEL 3** | "Operationally validated multi-step rollout; persistence remains champion baseline on evaluated benchmark." |
| **Forecasting K=3 (180s)** | Implemented (world_model.py) | Demonstrated on Friday slice | Evaluated on held-out episode | SAFE | **LEVEL 3** | "Operationally validated multi-step rollout; persistence remains champion baseline on evaluated benchmark." |
| **Forecasting K=5 (300s)** | Implemented (world_model.py) | Demonstrated on Friday slice | Evaluated on held-out episode | SAFE | **LEVEL 3** | "Operationally validated multi-step rollout; persistence remains champion baseline on evaluated benchmark." |
| **Forecasting K>5 (K=10, 15)** | Implemented (Abstention path) | Demonstrated on Friday slice | Evaluated as unsupported | SAFE | **LEVEL 4** | "System formally abstains on horizons K > 5 due to empirical horizon decay." |
| **Attack State Persistence** | Implemented (ttack_progression.py) | Demonstrated on Friday slice | Evaluated on Friday episodes | SAFE | **LEVEL 5** | "Empirically established state persistence on CIC-IDS2017 Friday episodes (K=1: 0.975, K=3: 0.924, K=5: 0.873)." |
| **Downstream Attack Progression** | Implemented (Abstention path) | Demonstrated on Friday slice | Evaluated on Friday PCAP | SAFE | **LEVEL 4** | "Downstream Recon->DoS progression is empirically unsupported due to temporal gaps; system strictly abstains." |
| **Offline Metrics (AUROC/AUPRC)** | Implemented (ml/evaluation/) | Decoupled from runtime API | Evaluated on static datasets | SAFE | **LEVEL 1** | "Evaluation metrics implemented; uncalibrated in runtime API service." |
| **Brier Score & ECE** | Implemented (ml/evaluation/) | Decoupled from runtime API | Evaluated in evaluation suite | SAFE | **LEVEL 1** | "Calibration metrics implemented in offline research suite; runtime API uncalibrated." |
| **Dataset Pipeline** | Implemented (ml/data/) | Evaluated on CIC Parquet | Validated schema & ordering | SAFE | **LEVEL 2** | "Reproducible Parquet dataset tooling for CIC-IDS2017 packet windows." |
| **Real-PCAP Validation** | Implemented (riday_slice.pcap) | 2,277 pkts, 10 windows | Deterministic metrics match | SAFE | **LEVEL 2** | "Operationally validated on Friday-WorkingHours 10-window slice." |

---

## 3. Mandatory Final Claim Policy

### What Can Be Claimed (Engineeringally Verified):
1. NexSolve executes a deterministic, leakage-free 45-feature extraction and compatibility pipeline on arbitrary PCAP/PCAPNG captures.
2. The 46->45 safety gate strictly intercepts missing mean_tcp_rtt and prevents zero-filling or synthetic data fabrication.
3. The NumPy LSTM autoregressive forecasting engine generates 5 continuous future state vectors without injecting true future ground truth.
4. On empirical CIC-IDS2017 Friday attack episodes, active reconnaissance state persistence is demonstrated at =1$ (.975$), =3$ (.924$), and =5$ (.873$).
5. The system formally abstains from claiming downstream attack transitions when empirical temporal gaps do not support them.
6. The entire backend (272 tests) and frontend (53 tests) execute cleanly with zero test failures.

### What CANNOT Be Claimed (Scientifically Unverified):
1. **NO AI Superiority Claim**: It cannot be claimed that the LSTM world model outperforms the persistence baseline on next-window attack prediction. The persistence baseline remains the champion model ( = 0.929$ vs. LSTM .533$).
2. **NO Universal Generalization Claim**: It cannot be claimed that model accuracy or transition probabilities transfer universally across different enterprise networks or unobserved attack categories.
3. **NO Anticipatory Pre-Attack Warning Claim**: It cannot be claimed that the system anticipates attack onset from a quiescent benign baseline before $.
4. **NO Downstream Progression Claim**: It cannot be claimed that the system forecasts downstream kill-chain progression (e.g., Recon to DoS).
