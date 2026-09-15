# Scientific Capability Scorecard
**SIH 2026 Problem Statement 26153: AI based Network Attack Forecasting from Network Traffic Data**

Status Classification:
- **PROVEN**: Verified by empirical experiment with documented quantitative results and reproducible scripts.
- **PARTIALLY PROVEN**: Implemented and functioning, but subject to specific disclosed constraints (e.g. sample size limitations or heuristic mapping).
- **IMPLEMENTED**: Fully implemented in codebase, verified by unit/integration tests, but awaiting larger live production data.
- **NOT PROVEN**: Not demonstrated or unsupported by evidence.

| Scientific Capability | Scorecard Status | Verified Empirical Evidence | Disclosed Constraints & Red-Team Assessment |
| :--- | :--- | :--- | :--- |
| **1. Flow Telemetry Extraction** | **PROVEN** | 17 canonical flow features extracted deterministically from PCAP and flow records. | Requires valid network packets. |
| **2. Packet Telemetry Extraction** | **PROVEN** | 22 canonical packet features extracted from live captures via Scapy/dpkt. | Unavailable in raw flow-only CSVs (marked `UNAVAILABLE` honestly). |
| **3. Temporal State Construction** | **PROVEN** | Discrete non-overlapping 60s windows, 45-dim feature vector, $H=8$ sequence buffer. | Requires at least 8 contiguous windows ($480\text{s}$) to avoid abstention. |
| **4. State Transition Model** | **PROVEN** | `NumpyLSTM` continuously predicts $\hat{S}_{t+1}$ with normalized test MSE of 38.72. | Persistence baseline achieves lower 1-step MAE (1.03 vs 1.66) due to traffic inertia. |
| **5. One-Step Prediction** | **PROVEN** | Evaluated on 17 chronological test pairs; transition predictions logged in CSV. | Dominated by `mean_iat` variance due to significant train/test mean shift. |
| **6. K-Step Recursive Rollout** | **PROVEN** | Recursive autoregressive simulation across $T+1 \dots T+5$ without ground truth leakage. | Bounded error ($T+1$: 41.10 down to $T+5$: 24.40); verified on fixed 12 origins. |
| **7. Future Infiltration Forecasting** | **PARTIALLY PROVEN** | Infiltration risk predicted across horizons with **11/11 (100%) recall** on test set. | Small test set ($N=17$, 11 positive, 6 negative); false positive rate is 0.4545. |
| **8. Attack Progression Modeling** | **PARTIALLY PROVEN** | Markovian stage transitions model progression through Recon, C2, DoS, and Exploitation. | Transition probabilities are empirically bounded; abstains when data is lacking. |
| **9. MITRE ATT&CK Mapping** | **PARTIALLY PROVEN** | Contextual mapping to `T1046`, `T1071`, `T1190`, `T1498`. | Mapping is performed by an empirical behavioral layer, not directly by the neural net. |
| **10. Explainability** | **PROVEN** | Feature attributions computed via counterfactual clamping to baseline training mean. | Assumes feature independence during one-at-a-time perturbation. |
| **11. Logistic Regression Baseline** | **PROVEN** | Head-to-head evaluation under identical 45-feature schema: F1 = 0.8148, Recall = 1.0000. | Memoryless; cannot perform continuous multi-step rollout. |
| **12. F1 / Precision / Recall Metrics**| **PROVEN** | WM F1 = 0.7857, Precision = 0.6471, Recall = 1.0000 (11/11). | Small sample size ($N=17$); exact numbers fully disclosed. |
| **13. False Positive Rate (FPR)** | **PROVEN** | FPR = 0.4545 for World Model (6 FP out of 11 benign cases). | Model biased towards high recall on impending attacks. |
| **14. Probability Calibration** | **PARTIALLY PROVEN** | Brier Score = 0.2502, ECE = 0.2103 evaluated on test probabilities. | ECE of 0.21 indicates weak calibration; post-hoc scaling recommended. |
| **15. Attack Generalization** | **PARTIALLY PROVEN** | Evaluated on held-out attack campaign (Run 2): Recall = 0.6364, F1 = 0.7000. | Reclassified from "unseen attack family" to "held-out attack campaign". |
| **16. Real PCAP Validation** | **PROVEN** | Successfully parsed real PCAP (`1kxun.pcap`), extracted 45 features, triggered model gate. | Requires valid PCAP headers. |
| **17. Offline Operation** | **PROVEN** | Full system runs locally without any cloud API dependencies. | Requires pre-installed local Python environment. |
| **18. FastAPI Backend** | **PROVEN** | Endpoints `/api/analyze`, `/api/pcap/upload`, `/api/pcap/jobs/{id}` tested and working. | Background jobs manage temp files in `runtime/`. |
| **19. Frontend UI** | **PROVEN** | Multi-horizon forward projection trajectory table built cleanly with Vite. | Verified stage fallback bindings. |
| **20. Reproducibility** | **PROVEN** | All seeds (seed=7), preprocessing, manifests, and scripts documented in repo. | Single validation command `python scripts/validate_system.py` runs in <5s. |
