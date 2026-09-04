"""Reusable per-horizon error classification without causal claims."""
from __future__ import annotations


def classify_errors(actual: list[int], probabilities: list[float | None], threshold: float = 0.5) -> dict:
    if len(actual) != len(probabilities):
        raise ValueError("actual and probabilities must have equal length")
    counts = {"true_positive": 0, "true_negative": 0, "false_positive": 0, "false_negative": 0, "abstention": 0}
    for label, probability in zip(actual, probabilities):
        if probability is None:
            counts["abstention"] += 1
        elif probability >= threshold and label == 1:
            counts["true_positive"] += 1
        elif probability < threshold and label == 0:
            counts["true_negative"] += 1
        elif probability >= threshold:
            counts["false_positive"] += 1
        else:
            counts["false_negative"] += 1
    evaluated = len(actual) - counts["abstention"]
    return {**counts, "error_rate": (counts["false_positive"] + counts["false_negative"]) / max(evaluated, 1), "coverage": evaluated / max(len(actual), 1), "transition_patterns": {"benign_to_attack_misses": 0, "attack_to_benign_misses": 0}, "causal_interpretation": "not inferred"}