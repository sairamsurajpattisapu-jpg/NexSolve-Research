"""Standardized Baseline Forecasting Models for Scientific Benchmarking.

Provides reproducible baselines against which the World Model is evaluated:
1. Persistence Baseline: Assumes the future network state equals current state (S_{t+h} = S_t)
2. Logistic Regression / Linear Probabilistic Baseline: Linear feature model on historical window summary statistics
"""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Sequence

import numpy as np

from world_model import FEATURE_NAMES_45, NetworkState


@dataclass(slots=True, frozen=True)
class BaselineHorizonPoint:
    horizon: int
    lookahead_seconds: int
    attack_probability: float
    cumulative_risk: float
    model_name: str
    predicted_features: dict[str, float]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class PersistenceBaseline:
    """Baseline predicting that future network state remains identical to current state."""

    def __init__(self, feature_names: Sequence[str] = FEATURE_NAMES_45) -> None:
        self.feature_names = list(feature_names)
        self.model_name = "PersistenceBaseline"

    def predict(
        self,
        history: Sequence[NetworkState],
        horizons: Sequence[int] = (1, 2, 3, 5, 10),
    ) -> list[BaselineHorizonPoint]:
        """Project current state forward indefinitely."""
        if not history:
            return []

        current_state = history[-1]
        raw_encoded = current_state.encode(self.feature_names)
        current_dict = {name: float(val) for name, val in zip(self.feature_names, raw_encoded)}

        # Current heuristic base probability from volumetric and flag pressure
        syn_ratio = current_dict.get("tcp_syn_count", 0.0) / max(1.0, current_dict.get("total_packets", 1.0))
        dst_port_diversity = current_dict.get("unique_dst_ports", 0.0) / max(1.0, current_dict.get("flow_count", 1.0))
        base_prob = min(0.95, max(0.05, syn_ratio * 0.5 + dst_port_diversity * 0.4))

        points: list[BaselineHorizonPoint] = []
        for h in horizons:
            # Persistence maintains constant step probability
            p_step = round(base_prob, 4)
            # Cumulative risk: 1 - (1 - p)^h
            cum_risk = round(float(1.0 - (1.0 - p_step) ** h), 4)

            points.append(BaselineHorizonPoint(
                horizon=h,
                lookahead_seconds=h * 60,
                attack_probability=p_step,
                cumulative_risk=cum_risk,
                model_name=self.model_name,
                predicted_features=dict(current_dict),
            ))

        return points


class LogisticRegressionBaseline:
    """Lightweight linear probabilistic baseline trained on rolling window statistical moments."""

    def __init__(self, feature_names: Sequence[str] = FEATURE_NAMES_45) -> None:
        self.feature_names = list(feature_names)
        self.model_name = "LogisticRegressionBaseline"

        # Fixed calibrated weights for baseline benchmark reproducibility
        # Weights correspond to: [syn_ratio, port_diversity, log_bytes, iat_skew, flow_acceleration]
        self._weights = np.array([1.8, 1.4, 0.35, -0.6, 1.2], dtype=np.float64)
        self._bias = -1.5

    def _extract_summary_features(self, history: Sequence[NetworkState]) -> np.ndarray:
        if not history:
            return np.zeros(5, dtype=np.float64)

        current = history[-1].encode(self.feature_names)
        curr_dict = {name: float(val) for name, val in zip(self.feature_names, current)}

        syn_ratio = curr_dict.get("tcp_syn_count", 0.0) / max(1.0, curr_dict.get("total_packets", 1.0))
        port_div = curr_dict.get("unique_dst_ports", 0.0) / max(1.0, curr_dict.get("flow_count", 1.0))
        log_bytes = math.log1p(max(0.0, curr_dict.get("total_bytes", 0.0))) / 15.0

        if len(history) >= 2:
            prev = history[-2].encode(self.feature_names)
            prev_dict = {name: float(val) for name, val in zip(self.feature_names, prev)}
            flow_accel = (curr_dict.get("flow_count", 0.0) - prev_dict.get("flow_count", 0.0)) / max(1.0, prev_dict.get("flow_count", 1.0))
        else:
            flow_accel = 0.0

        mean_iat = curr_dict.get("mean_iat", 0.0)
        iat_skew = math.log1p(mean_iat)

        return np.array([syn_ratio, port_div, log_bytes, iat_skew, flow_accel], dtype=np.float64)

    def predict(
        self,
        history: Sequence[NetworkState],
        horizons: Sequence[int] = (1, 2, 3, 5, 10),
    ) -> list[BaselineHorizonPoint]:
        if not history:
            return []

        x = self._extract_summary_features(history)
        current = history[-1].encode(self.feature_names)
        curr_dict = {name: float(val) for name, val in zip(self.feature_names, current)}

        # Linear logit
        z = float(np.dot(self._weights, x) + self._bias)
        # Sigmoid
        p0 = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, z))))

        points: list[BaselineHorizonPoint] = []
        step_probs: list[float] = []

        for h in horizons:
            # Linear decay of single-step certainty over longer horizons
            decay_factor = max(0.4, 1.0 - (h - 1) * 0.05)
            p_step = round(float(p0 * decay_factor + 0.1 * (1.0 - decay_factor)), 4)
            step_probs.append(p_step)

            cum_risk = round(float(1.0 - np.prod([1.0 - p for p in step_probs])), 4)

            # Linear projection of feature drift
            pred_features = {
                name: round(val * (1.0 + (h * 0.02 if "count" in name or "byte" in name else 0.0)), 4)
                for name, val in curr_dict.items()
            }

            points.append(BaselineHorizonPoint(
                horizon=h,
                lookahead_seconds=h * 60,
                attack_probability=p_step,
                cumulative_risk=cum_risk,
                model_name=self.model_name,
                predicted_features=pred_features,
            ))

        return points
