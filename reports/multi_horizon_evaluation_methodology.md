# Multi-Horizon Evaluation Methodology

For each source state, T+1 through T+5 are scored against their respective future target windows. Recursive models consume each preceding predicted state; persistence repeats the source state; direct plugins provide their named horizon. Horizons must be present exactly once. No T+5 score is compared with a T+1 target. Chronological split boundaries and train-only preprocessing are enforced.
