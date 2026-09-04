"""Deterministic binary metrics with explicit invalid-metric reasons."""
from __future__ import annotations

from collections import Counter
from typing import Iterable

import numpy as np
from sklearn.metrics import (average_precision_score, balanced_accuracy_score,
                             confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)


def _not_available(reason: str) -> dict[str, str]:
    return {"status": "not_available", "reason": reason}


def binary_metrics(actual: Iterable[int], probabilities: Iterable[float | None], threshold: float = 0.5) -> dict:
    labels = np.asarray(list(actual), dtype=int)
    values = list(probabilities)
    if len(labels) != len(values):
        raise ValueError("actual and probabilities must have equal length")
    if not 0 <= threshold <= 1:
        raise ValueError("threshold must be in [0, 1]")
    evaluated = [(label, float(probability)) for label, probability in zip(labels, values) if probability is not None]
    for _, probability in evaluated:
        if not np.isfinite(probability) or not 0 <= probability <= 1:
            raise ValueError("probabilities must be finite and in [0, 1]")
    if not evaluated:
        return {"status": "not_available", "reason": "no evaluated probabilities", "coverage": 0.0, "abstention_rate": 1.0, "evaluated_cases": 0, "forecast_cases": len(labels)}
    observed = np.asarray([item[0] for item in evaluated], dtype=int)
    scores = np.asarray([item[1] for item in evaluated], dtype=float)
    predicted = (scores >= threshold).astype(int)
    result = {"status": "computed", "precision": float(precision_score(observed, predicted, zero_division=0)), "recall": float(recall_score(observed, predicted, zero_division=0)), "f1": float(f1_score(observed, predicted, zero_division=0)), "macro_f1": float(f1_score(observed, predicted, average="macro", zero_division=0)), "balanced_accuracy": float(balanced_accuracy_score(observed, predicted)), "confusion_matrix": confusion_matrix(observed, predicted, labels=[0, 1]).tolist(), "coverage": len(evaluated) / max(len(labels), 1), "abstention_rate": 1 - len(evaluated) / max(len(labels), 1), "evaluated_cases": len(evaluated), "forecast_cases": len(labels), "class_distribution": dict(Counter(observed.tolist()))}
    if len(set(observed.tolist())) < 2:
        reason = "only one class present in evaluated targets"
        result["roc_auc"] = _not_available(reason)
        result["pr_auc"] = _not_available(reason)
    else:
        result["roc_auc"] = float(roc_auc_score(observed, scores))
        result["pr_auc"] = float(average_precision_score(observed, scores))
    return result