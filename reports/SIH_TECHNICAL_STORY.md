# NexSolve Technical Story

## Problem

Traditional IDS primarily detects suspicious activity after it appears. That answers whether traffic looks malicious now, but attacker behavior unfolds over time and defenders also need an early warning about what the network may look like next.

## NexSolve

NexSolve is a research system for temporal network attack forecasting. It converts network traffic into time-windowed network states, uses a World Model to forecast future states, interprets supported behavior with contextual MITRE ATT&CK information, and presents evidence-based defender decision support.

```text
Network Traffic
      |
Flow + Packet Features
      |
Temporal Network State
      |
World Model
      |
K-step Forecast
      |
Attack Progression
      |
MITRE ATT&CK Context
      |
Explainability
      |
Defender Decision Support
```

## Detection And Forecasting

Detection estimates whether the current or next evaluated state is malicious. Forecasting estimates future network-state behavior from a past-only sequence. They are reported separately and are not interchangeable accuracy claims.

The current protected prototype uses UNSW-NB15-derived temporal flow states, 46 model inputs, 60-second windows, an eight-state lookback, and recursive T+1 through T+5 output. Its measured evaluation is limited to one eligible mixed-state episode, where persistence outperformed the LSTM. The CIC-IDS2017 PCAP and packet-level fusion remain pending.

## Scientific Boundary

NexSolve does not guarantee attack prediction, does not claim packet-level support before PCAP processing, and does not treat contextual ATT&CK hypotheses as confirmed techniques. When evidence is insufficient, the system abstains.
