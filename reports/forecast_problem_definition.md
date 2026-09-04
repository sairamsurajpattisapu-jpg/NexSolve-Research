# Forecast Problem Definition

Run timestamp (UTC): `2026-09-03T10:49:46+00:00`

## Observation Window

One 60-second non-empty traffic window; 60 seconds is retained because it gives 1,441 windows and sufficient per-window traffic density.

## Forecast Horizon

The next contiguous 60-second window.

## Forecast Unit

One timestamp window per dataset, chronological order only.

## State Representation

Binary observed security state: BENIGN (Label=0) or ATTACK (Label=1; attack_cat retained as descriptive metadata). MITRE lifecycle stages are not directly observed.

## Target

Binary security state of the immediately following contiguous 60-second window, evaluated only from future-window labels.

## Minimum Evidence

A candidate future episode must be contiguous, strictly after training, contain both states, and contain at least 20 valid adjacent forecast pairs. The current data provides one eligible episode with 24 pairs.

## Prediction Time

End of the observed window, before reading any target-window rows.

## Probability Meaning

A probability, when produced by a future model, must mean estimated probability of the target state conditional on information available through prediction time T; current baselines emit hard labels only.

## Confidence

Not implemented by current baselines; must not be inferred from hard-label accuracy.

## Abstention

Return insufficient evidence when history, traffic, state support, or training transition support is inadequate; report coverage and abstention separately.

## Allowed Information

Rows and aggregates timestamped at or before the observation-window end.

## Forbidden Information

Future-window rows, labels, attack categories, GT events, future-fitted preprocessing, future transition probabilities, and random shuffling.

## Split

Train and validation use the first two pre-test contiguous runs (80/20 chronologically); test is the first later complete contiguous run containing both states (2015-02-18 00:23-00:48 UTC). No randomization.

## Metrics

Macro-F1, per-class precision/recall/F1, balanced accuracy, confusion matrix, coverage, and abstention rate.

## Detection Distinction

Detection asks what is happening in the current observed window; forecasting asks what state occurs in the subsequent future window. Detection accuracy is not forecasting evidence.
