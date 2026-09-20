"""Small deterministic Platt scaling implementation."""
from __future__ import annotations

import math


class PlattCalibrator:
    def __init__(self, max_iterations: int = 100, learning_rate: float = 0.05) -> None:
        self.max_iterations = max_iterations
        self.learning_rate = learning_rate
        self.slope = 1.0
        self.intercept = 0.0
        self.fitted = False

    def fit(self, probabilities: list[float], labels: list[int]) -> "PlattCalibrator":
        if len(probabilities) != len(labels) or not probabilities:
            raise ValueError("calibration probabilities and labels must be non-empty and aligned")
        if len(set(labels)) < 2:
            raise ValueError("calibration requires both classes")
        if any(not math.isfinite(value) or not 0 <= value <= 1 for value in probabilities):
            raise ValueError("calibration probabilities must be finite and in [0, 1]")
        for _ in range(self.max_iterations):
            gradients = [0.0, 0.0]
            for probability, label in zip(probabilities, labels):
                logit = math.log(max(min(probability, 1 - 1e-12), 1e-12) / max(1 - probability, 1e-12))
                estimate = 1 / (1 + math.exp(-max(min(self.slope * logit + self.intercept, 30), -30)))
                error = estimate - int(label)
                gradients[0] += error * logit
                gradients[1] += error
            self.slope -= self.learning_rate * gradients[0] / len(probabilities)
            self.intercept -= self.learning_rate * gradients[1] / len(probabilities)
        self.fitted = True
        return self

    def transform(self, probabilities: list[float]) -> list[float]:
        if not self.fitted:
            raise RuntimeError("calibrator must be fitted on validation data before transform")
        output = []
        for probability in probabilities:
            if not math.isfinite(probability) or not 0 <= probability <= 1:
                raise ValueError("probabilities must be finite and in [0, 1]")
            logit = math.log(max(min(probability, 1 - 1e-12), 1e-12) / max(1 - probability, 1e-12))
            output.append(1 / (1 + math.exp(-max(min(self.slope * logit + self.intercept, 30), -30))))
        return output


def compute_brier_score(actual: Sequence[int], probabilities: Sequence[float]) -> float:
    """Compute empirical Brier score mean((p - y)^2)."""
    if not actual or len(actual) != len(probabilities):
        return 0.0
    return float(sum((p - y) ** 2 for y, p in zip(actual, probabilities)) / len(actual))


def compute_ece(actual: Sequence[int], probabilities: Sequence[float], n_bins: int = 10) -> float:
    """Compute Expected Calibration Error (ECE) across empirical probability bins."""
    if not actual or len(actual) != len(probabilities):
        return 0.0
    bin_boundaries = [i / n_bins for i in range(n_bins + 1)]
    ece = 0.0
    n = len(actual)

    for i in range(n_bins):
        bin_lower = bin_boundaries[i]
        bin_upper = bin_boundaries[i + 1]
        in_bin = [(y, p) for y, p in zip(actual, probabilities) if bin_lower <= p < bin_upper or (i == n_bins - 1 and p == bin_upper)]
        if in_bin:
            bin_acc = sum(y for y, _ in in_bin) / len(in_bin)
            bin_conf = sum(p for _, p in in_bin) / len(in_bin)
            ece += (len(in_bin) / n) * abs(bin_acc - bin_conf)
    return float(ece)


class MahalanobisOODDetector:
    """Calibrated Out-Of-Distribution (OOD) detector evaluating distance from learned manifold."""
    def __init__(self, threshold: float = 3.5) -> None:
        self.threshold = threshold
        self.mean: list[float] | None = None
        self.var: list[float] | None = None
        self.fitted: bool = False

    def fit(self, training_vectors: Sequence[Sequence[float]]) -> "MahalanobisOODDetector":
        if not training_vectors or len(training_vectors) < 2:
            return self
        d = len(training_vectors[0])
        n = len(training_vectors)
        self.mean = [sum(v[j] for v in training_vectors) / n for j in range(d)]
        self.var = [max(1e-4, sum((v[j] - self.mean[j]) ** 2 for v in training_vectors) / (n - 1)) for j in range(d)]
        self.fitted = True
        return self

    def score(self, vector: Sequence[float]) -> float:
        """Normalized Mahalanobis-like distance along diagonal covariance."""
        if not self.fitted or not self.mean or not self.var or len(vector) != len(self.mean):
            return 0.0
        dist_sq = sum(((v - m) ** 2) / s for v, m, s in zip(vector, self.mean, self.var))
        return float(math.sqrt(dist_sq / max(len(vector), 1)))

    def is_ood(self, vector: Sequence[float]) -> tuple[bool, float]:
        dist = self.score(vector)
        return (dist > self.threshold, dist)