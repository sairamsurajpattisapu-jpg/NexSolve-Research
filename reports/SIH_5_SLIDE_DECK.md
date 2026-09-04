# SIH 5-Slide Deck

## SLIDE 1 — PROBLEM

- Traditional IDS is mainly reactive: it identifies suspicious activity after or during appearance.
- Attacker behavior is temporal: reconnaissance, transitions, and impact develop across windows.
- Defenders need an evidence-based early warning about likely next network states.
- SIH Problem Statement 26153: **AI Based Network Attack Forecasting from Network Traffic Data**.

## SLIDE 2 — NEXSOLVE

```text
Traffic -> Network State -> World Model -> Future States -> Attack Progression
```

Instead of asking only, “Is this traffic malicious?”, NexSolve asks, “What is the network likely to look like next?”

The system preserves the distinction between measured model prediction and contextual security interpretation.

## SLIDE 3 — TECHNICAL ARCHITECTURE

```text
PCAP/CSV
   |
Flow Extraction
   |
Packet Extraction [PENDING PCAP]
   |
Feature Fusion [PENDING PCAP]
   |
60-second Temporal Windows
   |
NumPy LSTM World Model
   |
Recursive T+1 ... T+5
   |
Local MITRE ATT&CK STIX context
   |
Ablation-based associated-feature explanation
```

Implemented technologies: Python, NumPy, scikit-learn baselines, FastAPI research service, Node/Express integration boundary, React/Vite UI, and local MITRE ATT&CK STIX data.

## SLIDE 4 — AI / WORLD MODEL

State: `S_t = [flow_features_t, packet_features_t, temporal_features_t]`

History: `S_(t-7) ... S_t`

Model: one-layer NumPy LSTM, hidden size 24, seed 7, 46 inputs.

Output: `P(attack at T+1)` through `P(attack at T+5)` using recursive rollout.

- Persistence is the required reference baseline.
- Logistic Regression is a static detection baseline, not a directly comparable temporal forecast baseline.
- Current measured UNSW result: LSTM macro-F1 `0.5608`; persistence macro-F1 `0.9143`.
- Calibration is `BLOCKED_BY_DATA` because the available validation split is one-class.
- Abstention is explicit when history or evidence is insufficient.
- Chronological splits, train-only preprocessing, and target exclusion reduce leakage risk.

## SLIDE 5 — IMPACT / DEMO

```text
Upload traffic
 -> Current State
 -> Attack Assessment
 -> Forecast
 -> Attack Progression
 -> MITRE ATT&CK
 -> Explanation
 -> Defender Decision Support
```

The current demo uses real UNSW-NB15-derived temporal states and real model output. Packet-level intelligence and final CIC evaluation remain pending the PCAP. NexSolve provides decision support, not autonomous blocking or guaranteed prediction.

**From detecting what is happening to forecasting what may happen next.**
