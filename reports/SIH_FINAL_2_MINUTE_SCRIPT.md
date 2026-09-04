# SIH Final 2-Minute Script

## 0:00–0:15 — Problem

“Most IDS tools tell us that suspicious traffic is present after it appears. That is useful, but an attacker’s behavior is a sequence, not a single event. SIH Problem Statement 26153 asks us to forecast attacks from network traffic.”

## 0:15–0:30 — Introduce NexSolve

“NexSolve represents traffic as a sequence of network states. Its research World Model uses the recent history to estimate likely future network states and gives defenders an interpretable, non-autonomous decision-support view.”

## 0:30–0:45 — Upload Traffic

“For this reproducible demo, we use the real timestamped UNSW-NB15 research input. The pipeline validates the data, preserves chronological order, and creates 60-second states. The CIC packet branch is intentionally not presented as complete because its PCAP is still pending.”

## 0:45–1:00 — Current Network State

“This section describes the observed state available at the prediction cutoff. Labels are targets for evaluation only; they are not features. If the history or required features are missing, NexSolve says insufficient evidence instead of forcing a result.”

## 1:00–1:25 — T+1 Through T+5 Forecast

“The model receives eight historical states. It produces a real T+1 prediction, then recursively consumes each predicted state to produce T+2 through T+5. These are model probabilities, not certainty, and the current prototype has not been shown to outperform persistence.”

## 1:25–1:40 — Attack Progression

“We interpret forecast behavior separately from model prediction. A supported scan-like pattern can produce a reconnaissance contextual hypothesis. It is not labeled as a confirmed attack stage.”

## 1:40–1:52 — MITRE ATT&CK Context

“When the evidence supports it, we validate ATT&CK metadata from the local STIX bundle. T1046 is shown as contextual or forecast context, never as proof that a technique occurred.”

## 1:52–2:00 — Explanation And Defender Decision Support

“The explanation panel reports features associated with the forecast, not causes. The guidance is non-autonomous, such as continuing monitoring or increasing monitoring of affected flows. Packet extraction, final CIC evaluation, and calibration remain the next validation steps.”
