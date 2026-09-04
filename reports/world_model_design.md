# World Model Design

Run date (UTC): `2026-09-03`

## State

$S_t = [flow\ features_t, packet\ features_t, temporal\ features_t]$ for one 60-second window. Flow and packet aggregates are joined only after deterministic windowing. Temporal features use current and prior observed windows: previous observed state, rolling volume, changes in flow count, unique ports, destinations, IAT, and TCP-flag distribution. Labels, attack categories, ATT&CK stages, attack ratio, future rows, and unrestricted filename or timestamp identifiers are excluded.

## Learned Dynamics

The target transition is $P(S_{t+1} | S_t, context_t)$, where context is a fixed-length history available at prediction time. Any Logistic Regression is a chronological baseline comparison, not the world model itself. The world model must emit a distribution and uncertainty, not only a hard class.

## Forward Simulation

Use `K=5` contiguous 60-second steps, a maximum five-minute forecast horizon. Roll out the next-state distribution recursively from the last observed state. Report $P(ATTACK_{t+k} | history_{<=t})$, stage hypotheses, uncertainty, calibration, and abstention. Abstain for missing/non-contiguous history, inadequate transition support, out-of-distribution states, high uncertainty, or unverified required packet fields.

## Progression and ATT&CK

Candidate progression stages are Reconnaissance, Initial Access, Execution, Persistence, Privilege Escalation, Discovery, Lateral Movement, Command and Control, Collection, Exfiltration, and Impact. The mapping is contextual: current datasets do not provide stage ground truth. Every inferred stage must carry evidence, confidence, and an abstention option; it must never be reported as an observed stage label.

## Leakage Controls

Audit source/destination IP and tuple leakage, fixed attack-time and scenario leakage, filename leakage, label leakage, future-window leakage, future-fitted preprocessing, and train/test contamination. Use chronological episode-aware splits, training-only preprocessing, past-only deltas, and no random row splitting. Deduplicate overlapping packet/flow observations before partitioning.
