"""Calibration scores and reliability bins."""
from __future__ import annotations

from collections import defaultdict


def calibration_metrics(labels: list[int], probabilities: list[float], bins: int = 10) -> dict:
    if len(labels) != len(probabilities) or not labels:
        return {"status": "not_available", "reason": "empty or misaligned calibration input"}
    if any(not 0 <= value <= 1 for value in probabilities):
        raise ValueError("probabilities must be in [0, 1]")
    brier = sum((probability - label) ** 2 for label, probability in zip(labels, probabilities)) / len(labels)
    grouped = defaultdict(list)
    for label, probability in zip(labels, probabilities):
        grouped[min(bins - 1, int(probability * bins))].append((label, probability))
    reliability = []
    for index in sorted(grouped):
        values = grouped[index]
        reliability.append({"bin": index, "count": len(values), "mean_probability": sum(item[1] for item in values) / len(values), "observed_rate": sum(item[0] for item in values) / len(values)})
    ece = sum(item["count"] * abs(item["mean_probability"] - item["observed_rate"]) for item in reliability) / len(labels)
    return {"status": "computed", "brier_score": brier, "expected_calibration_error": ece, "reliability_bins": reliability, "fit_scope": "validation only"}