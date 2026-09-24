r"""Scientific Evaluation & Generalization Benchmarking Framework.

Strictly separates:
- DETECTION metrics (performance at T0 on observed state)
- FORECASTING metrics (multi-horizon predictive validity at T+1, T+2, T+3, T+5, T+10)

Calculates:
- Precision, Recall, F1 Score, Accuracy
- Brier Score (Probabilistic Calibration error: \frac{1}{N}\sum (p_i - y_i)^2)
- Expected Calibration Error (ECE) with reliability diagram bins
- False Positive Rate (FPR), False Negative Rate (FNR)
- Horizon Performance Decay Curves
- Unseen Attack Family Generalization (Holdout evaluation)

ZERO-FABRICATION RULE:
Missing or undefined metrics (e.g. precision when no positive predictions occur,
or recall when no positive samples exist in the ground truth) are recorded as
None with an explicit reason string, NEVER fabricated or silently filled with 0.0.
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, Sequence

import numpy as np


@dataclass(slots=True, frozen=True)
class MetricResult:
    sample_count: int
    precision: float | None
    recall: float | None
    f1_score: float | None
    accuracy: float | None
    brier_score: float | None
    false_positive_rate: float | None
    false_negative_rate: float | None
    expected_calibration_error: float | None = None
    calibration_bins: list[dict[str, Any]] = field(default_factory=list)
    undefined_reasons: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def calculate_expected_calibration_error(
    y_true: Sequence[int | bool],
    y_prob: Sequence[float],
    num_bins: int = 10,
) -> tuple[float | None, list[dict[str, Any]]]:
    r"""Compute Expected Calibration Error (ECE) and reliability bin statistics.

    ECE = \sum_{m=1}^M \frac{|B_m|}{N} | \text{acc}(B_m) - \text{conf}(B_m) |
    """
    n = len(y_true)
    if n == 0:
        return None, []

    # Construct uniform bins in [0, 1]
    bin_boundaries = np.linspace(0.0, 1.0, num_bins + 1)
    bins_data: list[dict[str, Any]] = []
    total_ece = 0.0

    for i in range(num_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]

        # Samples falling into current bin [lower, upper) or [lower, upper] for final bin
        if i == num_bins - 1:
            indices = [
                idx for idx, p in enumerate(y_prob)
                if bin_lower <= float(p) <= bin_upper
            ]
        else:
            indices = [
                idx for idx, p in enumerate(y_prob)
                if bin_lower <= float(p) < bin_upper
            ]

        bin_count = len(indices)
        if bin_count > 0:
            bin_acc = float(np.mean([1.0 if y_true[idx] else 0.0 for idx in indices]))
            bin_conf = float(np.mean([float(y_prob[idx]) for idx in indices]))
            bin_error = abs(bin_acc - bin_conf)
            weighted_error = (bin_count / n) * bin_error
            total_ece += weighted_error

            bins_data.append({
                "bin_index": i,
                "bin_lower": round(bin_lower, 2),
                "bin_upper": round(bin_upper, 2),
                "count": bin_count,
                "accuracy": round(bin_acc, 4),
                "confidence": round(bin_conf, 4),
                "calibration_error": round(bin_error, 4),
            })
        else:
            bins_data.append({
                "bin_index": i,
                "bin_lower": round(bin_lower, 2),
                "bin_upper": round(bin_upper, 2),
                "count": 0,
                "accuracy": None,
                "confidence": None,
                "calibration_error": None,
            })

    return round(total_ece, 4), bins_data


def calculate_classification_metrics(
    y_true: Sequence[int | bool],
    y_prob: Sequence[float],
    threshold: float = 0.5,
    num_calibration_bins: int = 10,
) -> MetricResult:
    """Calculate standard and probabilistic evaluation metrics with zero fabrication."""
    if len(y_true) != len(y_prob):
        raise ValueError("y_true and y_prob must have matching lengths.")

    n = len(y_true)
    if n == 0:
        return MetricResult(
            sample_count=0,
            precision=None,
            recall=None,
            f1_score=None,
            accuracy=None,
            brier_score=None,
            false_positive_rate=None,
            false_negative_rate=None,
            expected_calibration_error=None,
            calibration_bins=[],
            undefined_reasons={"all": "Empty dataset: zero samples evaluated"},
        )

    tp = fp = tn = fn = 0
    brier_sum = 0.0
    undefined_reasons: dict[str, str] = {}

    for yt, yp in zip(y_true, y_prob):
        yt_bool = bool(yt)
        pred_bool = float(yp) >= threshold

        brier_sum += (float(yp) - (1.0 if yt_bool else 0.0)) ** 2

        if pred_bool and yt_bool:
            tp += 1
        elif pred_bool and not yt_bool:
            fp += 1
        elif not pred_bool and not yt_bool:
            tn += 1
        else:
            fn += 1

    # Precision
    if (tp + fp) > 0:
        precision: float | None = round(tp / (tp + fp), 4)
    else:
        precision = None
        undefined_reasons["precision"] = "Undefined: zero positive predictions made (TP + FP == 0)"

    # Recall
    if (tp + fn) > 0:
        recall: float | None = round(tp / (tp + fn), 4)
    else:
        recall = None
        undefined_reasons["recall"] = "Undefined: zero positive ground truth samples exist (TP + FN == 0)"

    # F1 score
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1: float | None = round(2 * (precision * recall) / (precision + recall), 4)
    elif precision is not None and recall is not None and (precision + recall) == 0:
        f1 = 0.0
    else:
        f1 = None
        undefined_reasons["f1_score"] = "Undefined: precision or recall is undefined"

    # Accuracy
    acc: float = round((tp + tn) / n, 4)

    # Brier score
    brier: float = round(brier_sum / n, 4)

    # False Positive Rate: FP / (FP + TN)
    if (fp + tn) > 0:
        fpr: float | None = round(fp / (fp + tn), 4)
    else:
        fpr = None
        undefined_reasons["false_positive_rate"] = "Undefined: zero negative ground truth samples exist (FP + TN == 0)"

    # False Negative Rate: FN / (FN + TP)
    if (fn + tp) > 0:
        fnr: float | None = round(fn / (fn + tp), 4)
    else:
        fnr = None
        undefined_reasons["false_negative_rate"] = "Undefined: zero positive ground truth samples exist (FN + TP == 0)"

    # Expected Calibration Error
    ece, cal_bins = calculate_expected_calibration_error(y_true, y_prob, num_bins=num_calibration_bins)

    return MetricResult(
        sample_count=n,
        precision=precision,
        recall=recall,
        f1_score=f1,
        accuracy=acc,
        brier_score=brier,
        false_positive_rate=fpr,
        false_negative_rate=fnr,
        expected_calibration_error=ece,
        calibration_bins=cal_bins,
        undefined_reasons=undefined_reasons,
    )


class MultiHorizonEvaluator:
    """Evaluates and compares forecasting models across discrete rollout horizons."""

    def __init__(self, horizons: Sequence[int] = (1, 2, 3, 5, 10)) -> None:
        self.horizons = list(horizons)

    def evaluate_model_on_trajectories(
        self,
        model_name: str,
        predictions_by_horizon: Mapping[int, Sequence[float]],
        ground_truth_by_horizon: Mapping[int, Sequence[int | bool]],
        threshold: float = 0.5,
    ) -> dict[str, Any]:
        """Compute per-horizon metrics to plot horizon degradation curves."""
        horizon_metrics: dict[int, dict[str, Any]] = {}

        for h in self.horizons:
            probs = predictions_by_horizon.get(h, [])
            truths = ground_truth_by_horizon.get(h, [])
            if probs and truths and len(probs) == len(truths):
                metrics = calculate_classification_metrics(truths, probs, threshold=threshold)
                horizon_metrics[h] = metrics.to_dict()
            elif probs or truths:
                horizon_metrics[h] = {
                    "sample_count": 0,
                    "status": "MISMATCHED_LENGTH",
                    "prob_count": len(probs),
                    "truth_count": len(truths),
                }

        return {
            "model_name": model_name,
            "horizons": list(self.horizons),
            "horizon_metrics": horizon_metrics,
        }


def evaluate_unseen_attack_generalization(
    known_family_truths: Sequence[int | bool],
    known_family_probs: Sequence[float],
    unseen_family_truths: Sequence[int | bool],
    unseen_family_probs: Sequence[float],
    family_name: str = "C2_Beaconing",
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Measure model degradation when facing completely unseen attack classes."""
    known_metrics = calculate_classification_metrics(known_family_truths, known_family_probs, threshold=threshold)
    unseen_metrics = calculate_classification_metrics(unseen_family_truths, unseen_family_probs, threshold=threshold)

    known_f1 = known_metrics.f1_score
    unseen_f1 = unseen_metrics.f1_score

    f1_delta = round(unseen_f1 - known_f1, 4) if (unseen_f1 is not None and known_f1 is not None) else None
    recall_delta = (
        round(unseen_metrics.recall - known_metrics.recall, 4)
        if (unseen_metrics.recall is not None and known_metrics.recall is not None)
        else None
    )

    f1_retention = (
        round(unseen_f1 / max(1e-4, known_f1), 4)
        if (unseen_f1 is not None and known_f1 is not None)
        else None
    )

    verdict = (
        "ROBUST_GENERALIZATION"
        if (unseen_f1 is not None and unseen_f1 >= 0.70)
        else ("FAMILY_SPECIFIC_OVERFIT" if unseen_f1 is not None else "INSUFFICIENT_EVALUATION_DATA")
    )

    return {
        "held_out_family": family_name,
        "known_families_metrics": known_metrics.to_dict(),
        "unseen_family_metrics": unseen_metrics.to_dict(),
        "f1_retention_ratio": f1_retention,
        "f1_drop": f1_delta,
        "recall_drop": recall_delta,
        "verdict": verdict,
    }


def evaluate_attack_family_holdout(
    in_distribution_results: Mapping[str, Sequence[float]],
    in_distribution_truths: Mapping[str, Sequence[int | bool]],
    held_out_results: Mapping[str, Sequence[float]],
    held_out_truths: Mapping[str, Sequence[int | bool]],
    held_out_families: Sequence[str],
) -> dict[str, Any]:
    """Comprehensive attack-family holdout evaluation with structured fallback for unsupported datasets."""
    if not held_out_families:
        return {
            "status": "UNSUPPORTED",
            "reason": "Dataset lacks attack family taxonomy or no held-out families specified",
            "held_out_families": [],
        }

    family_evaluations: dict[str, Any] = {}
    for fam in held_out_families:
        preds = held_out_results.get(fam, [])
        truths = held_out_truths.get(fam, [])
        if not preds or not truths:
            family_evaluations[fam] = {
                "status": "NO_SAMPLES",
                "sample_count": 0,
            }
            continue

        # In-distribution aggregate
        id_preds = [p for sub in in_distribution_results.values() for p in sub]
        id_truths = [t for sub in in_distribution_truths.values() for t in sub]

        family_evaluations[fam] = evaluate_unseen_attack_generalization(
            known_family_truths=id_truths,
            known_family_probs=id_preds,
            unseen_family_truths=truths,
            unseen_family_probs=preds,
            family_name=fam,
        )

    return {
        "status": "COMPLETED",
        "held_out_families": list(held_out_families),
        "family_evaluations": family_evaluations,
    }
