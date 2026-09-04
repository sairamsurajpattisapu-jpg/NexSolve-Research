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