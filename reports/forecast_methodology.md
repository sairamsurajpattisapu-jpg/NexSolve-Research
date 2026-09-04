# Forecast Methodology

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Contract

```json
[
  "Network traffic is ingested and timestamped where the source provides genuine timestamps.",
  "Features at prediction time T use only information available at or before T.",
  "Current state is represented as observed BENIGN/ATTACK; attack_cat remains descriptive metadata.",
  "The forecast target is the state of the next contiguous 60-second window.",
  "Future labels are used only after prediction for evaluation.",
  "ATT&CK context is an evidence-based optional mapping, never ground truth by label name alone.",
  "Explanations describe association or model contribution, not causality."
]
```

## Baselines

```json
{
  "current_state": "Predict the current observed state for the next window.",
  "persistence": "Predict persistence of the current state; identical to current-state for the present binary formulation.",
  "empirical_transition": "Predict the most frequent next state conditional on current state, learned from training transitions only."
}
```

## Advance Gate

```json
[
  "Sufficient future forecast cases",
  "Meaningful state variation in held-out periods",
  "Nontrivial baseline benchmark",
  "Passed leakage audit",
  "Multiple temporal episodes where possible",
  "Chronological train/validation/test comparison",
  "Interpretable improvement over trivial baselines"
]
```

## Current Gate Status

Not passed: one eligible UNSW episode with 24 pairs, tied baselines, CIC without timestamps.
