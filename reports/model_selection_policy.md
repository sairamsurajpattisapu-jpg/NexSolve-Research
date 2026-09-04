# Model Selection Policy

A candidate is eligible only when it has valid metrics for all T+1 through T+5 horizons on identical chronological test targets. Rank by mean horizon macro-F1, worst-horizon macro-F1, coverage, calibration, stability, then deterministic name ordering. A single-horizon win cannot select a model that collapses at later horizons. Missing metrics remain N/A. If no candidate is complete, selection status is `HOLD`.

The current LSTM is not promoted: existing evidence contains one eligible mixed-state episode, horizon-specific metrics are not available, and persistence outperforms it on the measured aggregate evaluation.
