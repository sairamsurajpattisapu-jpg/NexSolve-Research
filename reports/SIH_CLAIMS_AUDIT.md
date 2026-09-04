# SIH Claims Audit

| Claim | Status | Evidence boundary |
|---|---|---|
| AI forecasting | MEASURED | Existing UNSW next-window LSTM experiment; limited to one eligible mixed-state episode. |
| World Model | SUPPORTED | Protected NumPy LSTM implementation and 46-feature state contract. |
| T+1 through T+5 | SUPPORTED | Recursive five-step implementation; horizon-specific benchmark metrics remain unavailable. |
| MITRE ATT&CK | SUPPORTED | Local STIX metadata validation for contextual T1046; not confirmed technique ground truth. |
| Packet-level intelligence | PENDING_PCAP | No PCAP processing has occurred. |
| Flow-level intelligence | MEASURED | CIC flow audit/adapter and UNSW flow-state pipeline. |
| Explainability | SUPPORTED | Deterministic ablation association output; not causal attribution. |
| Accuracy | MEASURED | Prototype UNSW metrics only; not final CIC performance. |
| Real-time operation | NOT_SUPPORTED | No latency or production throughput evaluation. |
| Generalization | NOT_SUPPORTED | No adequate independent multi-environment evidence. |
| Unseen attack detection | BLOCKED_BY_DATA | Requires future scenario-separated test data. |
| Enterprise applicability | BLOCKED_BY_DATA | Architecture is plausible, but scale and operational efficacy are unmeasured. |
| Production readiness | NOT_SUPPORTED | Research service and integration boundary exist; final model validation is incomplete. |
| Guaranteed attack prediction | NOT_SUPPORTED | No such claim is scientifically supported. |

The final presentation must use only claims marked SUPPORTED or MEASURED with their stated boundaries. `PENDING_PCAP` and `BLOCKED_BY_DATA` items must be presented as work remaining.
