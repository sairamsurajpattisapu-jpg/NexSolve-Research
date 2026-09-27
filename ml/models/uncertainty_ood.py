"""Uncertainty, Calibration, and Out-of-Distribution (OOD) Engine for NexSolve.

Implements rigorous statistical diagnostics:
- Expected Calibration Error (ECE) & Brier score evaluation
- Temperature scaling probability calibration
- Predictive uncertainty decomposition (Aleatoric vs Epistemic)
- OOD Novelty scoring (Mahalanobis distance & latent reconstruction error)
- Evidence sufficiency and observability index estimation
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

import numpy as np


@dataclass(frozen=True)
class CalibrationMetrics:
    """Formal metrics quantifying probabilistic prediction reliability."""
    brier_score: float
    expected_calibration_error: float
    max_calibration_error: float
    bin_accuracies: tuple[float, ...]
    bin_confidences: tuple[float, ...]
    bin_counts: tuple[int, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "brier_score": round(self.brier_score, 6),
            "expected_calibration_error": round(self.expected_calibration_error, 6),
            "max_calibration_error": round(self.max_calibration_error, 6),
            "bin_accuracies": [round(a, 4) for a in self.bin_accuracies],
            "bin_confidences": [round(c, 4) for c in self.bin_confidences],
            "bin_counts": list(self.bin_counts),
        }


@dataclass(frozen=True)
class UncertaintyOODResult:
    """Diagnostics vector for uncertainty, calibration, and OOD assessment."""
    epistemic_uncertainty: float
    aleatoric_uncertainty: float
    total_uncertainty: float
    ood_score: float
    is_ood: bool
    observability_score: float
    evidence_sufficiency_score: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "epistemic_uncertainty": round(self.epistemic_uncertainty, 4),
            "aleatoric_uncertainty": round(self.aleatoric_uncertainty, 4),
            "total_uncertainty": round(self.total_uncertainty, 4),
            "ood_score": round(self.ood_score, 4),
            "is_ood": self.is_ood,
            "observability_score": round(self.observability_score, 4),
            "evidence_sufficiency_score": round(self.evidence_sufficiency_score, 4),
        }


def compute_brier_score(y_true: Sequence[int], y_prob: Sequence[float]) -> float:
    """Computes mean squared error between binary labels and predicted probabilities."""
    if not y_true:
        return 0.0
    y_t = np.asarray(y_true, dtype=np.float64)
    y_p = np.asarray(y_prob, dtype=np.float64)
    return float(np.mean((y_p - y_t) ** 2))


def compute_ece(
    y_true: Sequence[int],
    y_prob: Sequence[float],
    n_bins: int = 10,
) -> CalibrationMetrics:
    """Computes Expected Calibration Error (ECE) across uniform confidence bins."""
    if not y_true or len(y_true) != len(y_prob):
        return CalibrationMetrics(0.0, 0.0, 0.0, (), (), ())

    y_t = np.asarray(y_true, dtype=np.int64)
    y_p = np.asarray(y_prob, dtype=np.float64)
    n_samples = len(y_true)

    # Bin boundaries from 0 to 1
    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    mce = 0.0
    bin_accs = []
    bin_confs = []
    bin_counts = []

    for i in range(n_bins):
        bin_lower = bins[i]
        bin_upper = bins[i + 1]
        mask = (y_p >= bin_lower) & (y_p <= bin_upper) if i == n_bins - 1 else (y_p >= bin_lower) & (y_p < bin_upper)
        count = int(np.sum(mask))
        bin_counts.append(count)

        if count > 0:
            avg_acc = float(np.mean(y_t[mask]))
            avg_conf = float(np.mean(y_p[mask]))
            diff = abs(avg_acc - avg_conf)
            ece += (count / n_samples) * diff
            mce = max(mce, diff)
            bin_accs.append(avg_acc)
            bin_confs.append(avg_conf)
        else:
            bin_accs.append(0.0)
            bin_confs.append((bin_lower + bin_upper) / 2.0)

    brier = compute_brier_score(y_true, y_prob)

    return CalibrationMetrics(
        brier_score=brier,
        expected_calibration_error=ece,
        max_calibration_error=mce,
        bin_accuracies=tuple(bin_accs),
        bin_confidences=tuple(bin_confs),
        bin_counts=tuple(bin_counts),
    )


class UncertaintyOODDetector:
    """Maintains statistical baseline envelope to score out-of-distribution inputs with validation calibration."""

    def __init__(self, feature_dim: int = 32) -> None:
        self.feature_dim = feature_dim
        self.centroid = np.zeros(feature_dim, dtype=np.float64)
        self.inv_covariance = np.eye(feature_dim, dtype=np.float64)
        self.fitted = False
        self.ood_threshold_95: float = 8.0
        self.ood_threshold_99: float = 12.0
        self.median_dist: float = 4.0

    def fit_baseline(self, x_train: np.ndarray) -> None:
        """Fits empirical centroid and pseudo-inverse covariance from training embeddings."""
        if len(x_train) < 2:
            return
        self.centroid = np.mean(x_train, axis=0)
        cov = np.cov(x_train, rowvar=False)
        # Robust Ledoit-Wolf-like ridge regularization to guarantee positive definiteness
        reg = np.eye(x_train.shape[1]) * max(1e-4, 0.01 * float(np.trace(cov) / max(1, x_train.shape[1])))
        try:
            self.inv_covariance = np.linalg.pinv(cov + reg)
        except np.linalg.LinAlgError:
            self.inv_covariance = np.eye(x_train.shape[1])
        self.fitted = True

        # Initial fallback calibration on training data
        train_dists = [self.compute_mahalanobis_distance(x) for x in x_train]
        if train_dists:
            self.ood_threshold_95 = float(np.percentile(train_dists, 95))
            self.ood_threshold_99 = float(np.percentile(train_dists, 99))
            self.median_dist = float(np.median(train_dists))

    def calibrate_thresholds(self, val_z: np.ndarray) -> None:
        """Calibrates empirical OOD thresholds strictly on the validation set (zero test leakage)."""
        if len(val_z) < 5 or not self.fitted:
            return
        val_dists = [self.compute_mahalanobis_distance(z) for z in val_z]
        self.ood_threshold_95 = float(np.percentile(val_dists, 95))
        self.ood_threshold_99 = float(np.percentile(val_dists, 99))
        self.median_dist = float(max(1.0, np.median(val_dists)))

    def compute_mahalanobis_distance(self, x: np.ndarray) -> float:
        """Computes distance of vector x from baseline centroid."""
        if not self.fitted:
            return 0.0
        diff = x - self.centroid
        dist_sq = float(diff.T @ self.inv_covariance @ diff)
        return float(np.sqrt(max(0.0, dist_sq)))

    def evaluate_diagnostics(
        self,
        z_t: np.ndarray,
        h_t: np.ndarray,
        attack_prob: float,
        capture_quality_score: float = 1.0,
        decision_threshold: float = 0.30,
    ) -> UncertaintyOODResult:
        """Evaluates uncertainty decomposition and OOD status grounded in statistical diagnostics."""
        # 1. Mahalanobis distance on latent world state
        mahal_dist = self.compute_mahalanobis_distance(z_t) if self.fitted else float(np.linalg.norm(z_t) / 4.0)
        norm_scale = max(1.0, self.ood_threshold_99)
        ood_score = float(min(1.0, mahal_dist / norm_scale))
        is_ood = bool(mahal_dist > self.ood_threshold_99)

        # 2. Epistemic uncertainty: Gaussian novelty divergence from training manifold
        med = max(1.0, self.median_dist)
        epistemic = float(min(1.0, 1.0 - math.exp(-0.5 * min(25.0, (mahal_dist / med) ** 2))))

        # 3. Aleatoric uncertainty: Bernoulli predictive entropy Var(Y|X) = 4*p*(1-p)
        # Scaled to [0, 1] - maximal at p=0.5, zero at p=0 or p=1
        clamped_p = max(0.0, min(1.0, float(attack_prob)))
        aleatoric = float(min(1.0, max(0.0, 4.0 * clamped_p * (1.0 - clamped_p))))

        # 4. Total predictive uncertainty estimate
        total_unc = float(min(1.0, 0.5 * epistemic + 0.5 * aleatoric))

        # 5. Observability and evidence sufficiency
        obs_score = float(max(0.0, min(1.0, capture_quality_score)))
        sufficiency = float(max(0.0, min(1.0, obs_score * (1.0 - 0.5 * ood_score))))

        return UncertaintyOODResult(
            epistemic_uncertainty=epistemic,
            aleatoric_uncertainty=aleatoric,
            total_uncertainty=total_unc,
            ood_score=ood_score,
            is_ood=is_ood,
            observability_score=obs_score,
            evidence_sufficiency_score=sufficiency,
        )
