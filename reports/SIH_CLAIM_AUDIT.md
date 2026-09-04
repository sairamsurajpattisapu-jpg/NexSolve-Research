# SIH Technical Claim Audit

| Claim | Status | Evidence and boundary |
|---|---|---|
| Network traffic ingestion | SUPPORTED | Local flow CSV ingestion and validation tests. |
| Flow-level feature extraction | SUPPORTED | CIC adapter and UNSW state builder. |
| Packet-level feature extraction | NOT_YET_SUPPORTED | No PCAP exists; no packet extraction performed. |
| Temporal modeling | PARTIALLY_SUPPORTED | UNSW 60-second temporal states and chronological split; limited evaluation. |
| Attack forecasting | PARTIALLY_SUPPORTED | One eligible mixed-state UNSW episode; LSTM below persistence. |
| Multi-step forecasting | SUPPORTED | Existing recursive T+1 through T+5 implementation; performance by horizon unavailable. |
| Attack progression | PARTIALLY_SUPPORTED | Contextual hypotheses only; no stage ground truth. |
| MITRE ATT&CK mapping | PARTIALLY_SUPPORTED | T1046 validated from local STIX; contextual only, not observed technique ground truth. |
| Explainability | PARTIALLY_SUPPORTED | Existing ablation association; no causal or SHAP/attention claim. |
| Uncertainty | PARTIALLY_SUPPORTED | Margin-based confidence and abstention exist; calibration unavailable. |
| Unseen-pattern generalization | NOT_YET_SUPPORTED | No adequate independent evidence. |
| Proactive decision support | PARTIALLY_SUPPORTED | Non-autonomous recommendations exist; operational efficacy unvalidated. |

Unsupported claims must not enter the SIH presentation.
