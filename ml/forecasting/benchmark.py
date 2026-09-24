"""Standardized Baseline Benchmarking Engine for Scientific Comparison.

Provides rigorous, input-parity benchmarking across:
1. Persistence Baseline (S_{t+h} = S_t)
2. Logistic Regression Baseline (calibrated rolling window linear model)
3. NexSolve World Model (LSTM continuous state dynamic rollout)

SCIATIVIC INTEGRITY PRINCIPLES:
- Identical input sequence definitions across all models.
- Identical temporal partitions and zero forward leakage.
- Strict multi-horizon validation (T+1, T+2, T+3, T+5, optional T+10).
- Pure metric reporting with zero subjective ranking or hype language.
- Missing values and undefined metrics returned as None with explicit reasons.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np

from ml.forecasting.baselines import LogisticRegressionBaseline, PersistenceBaseline
from ml.forecasting.evaluation import (
    MetricResult,
    calculate_classification_metrics,
    evaluate_unseen_attack_generalization,
)
from world_model import (
    FEATURE_NAMES_45,
    LOOKBACK,
    NetworkState,
    infer,
    load_model,
)

ROOT = Path(__file__).resolve().parents[2]


@dataclass(slots=True, frozen=True)
class ModelHorizonPerformance:
    model_name: str
    horizon: int
    lookahead_seconds: int
    metrics: MetricResult

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "horizon": self.horizon,
            "lookahead_seconds": self.lookahead_seconds,
            "metrics": self.metrics.to_dict(),
        }


@dataclass(slots=True)
class BenchmarkRunResult:
    dataset_name: str
    horizons: list[int]
    models_evaluated: list[str]
    sample_count: int
    evaluated_trajectories: int
    horizon_metrics: dict[str, dict[int, MetricResult]] = field(default_factory=dict)
    comparative_deltas: dict[str, Any] = field(default_factory=dict)
    holdout_results: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        h_dict: dict[str, dict[str, Any]] = {}
        for m_name, h_map in self.horizon_metrics.items():
            h_dict[m_name] = {str(h): m.to_dict() for h, m in h_map.items()}

        return {
            "dataset_name": self.dataset_name,
            "horizons": self.horizons,
            "models_evaluated": self.models_evaluated,
            "sample_count": self.sample_count,
            "evaluated_trajectories": self.evaluated_trajectories,
            "horizon_metrics": h_dict,
            "comparative_deltas": self.comparative_deltas,
            "holdout_results": self.holdout_results,
            "metadata": self.metadata,
        }


class StandardizedBenchmarkHarness:
    """Executes input-parity benchmarking across World Model and baselines."""

    def __init__(
        self,
        horizons: Sequence[int] = (1, 2, 3, 5, 10),
        world_model_dir: Path | None = None,
        lookback: int = LOOKBACK,
    ) -> None:
        self.horizons = sorted(list(horizons))
        self.lookback = lookback
        self.world_model_dir = world_model_dir or (ROOT / "models" / "nexsolve_world_model_45")

        # Initialize standard baseline models
        self.persistence = PersistenceBaseline()
        self.logistic_regression = LogisticRegressionBaseline()

        # Load World Model weights and scaler
        self._world_model_loaded = False
        self._world_model = None
        self._scaler_mean = None
        self._scaler_scale = None
        self._load_world_model()

    def _load_world_model(self) -> None:
        try:
            model_dir = self.world_model_dir
            if not model_dir.exists():
                alt_dir = ROOT / "models" / "nexsolve_world_model"
                if alt_dir.exists():
                    model_dir = alt_dir

            if model_dir.exists():
                self._world_model, self._scaler_mean, self._scaler_scale = load_model(model_dir)
                self._world_model_loaded = True
        except Exception:
            self._world_model_loaded = False

    def run_benchmark(
        self,
        test_states: Sequence[NetworkState],
        dataset_name: str = "EvaluationDataset",
        held_out_states: Sequence[NetworkState] | None = None,
        held_out_family: str | None = None,
        threshold: float = 0.5,
    ) -> BenchmarkRunResult:
        """Run all models on identical contiguous test trajectories.

        Evaluation method:
        At every time index t >= lookback where future states exist for the largest horizon:
        1. Input: history = test_states[t - lookback : t]
        2. Forecast: evaluate each model for h in horizons
        3. Target: ground truth attack_state at test_states[t + h]
        4. Metrics computed per horizon across all rollout points.
        """
        n_states = len(test_states)
        max_h = max(self.horizons) if self.horizons else 1

        models = ["PersistenceBaseline", "LogisticRegressionBaseline"]
        if self._world_model_loaded:
            models.append("NexSolveWorldModel")

        # Storage for predictions and ground truth per model per horizon
        preds: dict[str, dict[int, list[float]]] = {m: {h: [] for h in self.horizons} for m in models}
        truths: dict[int, list[int]] = {h: [] for h in self.horizons}

        evaluated_trajectories = 0

        # Roll through all eligible evaluation points
        for t in range(self.lookback, n_states):
            history = list(test_states[t - self.lookback : t])

            # Check which horizons have valid ground truth
            step_truths: dict[int, int] = {}
            valid_point = False
            for h in self.horizons:
                target_idx = t + h - 1  # 0-indexed: h=1 corresponds to index t
                if target_idx < n_states and test_states[target_idx].attack_state is not None:
                    step_truths[h] = int(test_states[target_idx].attack_state)
                    valid_point = True

            if not valid_point:
                continue

            evaluated_trajectories += 1

            # 1. Persistence Baseline
            p_points = self.persistence.predict(history, horizons=self.horizons)
            for pt in p_points:
                if pt.horizon in step_truths:
                    preds["PersistenceBaseline"][pt.horizon].append(pt.attack_probability)

            # 2. Logistic Regression Baseline
            lr_points = self.logistic_regression.predict(history, horizons=self.horizons)
            for pt in lr_points:
                if pt.horizon in step_truths:
                    preds["LogisticRegressionBaseline"][pt.horizon].append(pt.attack_probability)

            # 3. NexSolve World Model
            if self._world_model_loaded and self._world_model is not None:
                feat_names = (
                    FEATURE_NAMES_45 if len(self._scaler_mean) == len(FEATURE_NAMES_45)
                    else None
                )
                try:
                    wm_out = infer(
                        history,
                        self._world_model,
                        self._scaler_mean,
                        self._scaler_scale,
                        k=max_h,
                        feature_names=feat_names,
                    )
                    forecast_list = wm_out.get("forecasts", [])
                    for fc in forecast_list:
                        h_val = fc.get("horizon")
                        p_val = fc.get("attack_probability")
                        if h_val in step_truths and p_val is not None:
                            preds["NexSolveWorldModel"][h_val].append(float(p_val))
                except Exception:
                    pass

            for h, val in step_truths.items():
                truths[h].append(val)

        # Compute metric results per model per horizon
        horizon_metrics: dict[str, dict[int, MetricResult]] = {m: {} for m in models}
        for m in models:
            for h in self.horizons:
                m_probs = preds[m][h]
                h_truths = truths[h]
                if m_probs and h_truths and len(m_probs) == len(h_truths):
                    m_result = calculate_classification_metrics(h_truths, m_probs, threshold=threshold)
                    horizon_metrics[m][h] = m_result

        # Calculate comparative deltas (World Model vs Persistence)
        deltas: dict[str, Any] = {}
        if "NexSolveWorldModel" in horizon_metrics and "PersistenceBaseline" in horizon_metrics:
            for h in self.horizons:
                wm_m = horizon_metrics["NexSolveWorldModel"].get(h)
                p_m = horizon_metrics["PersistenceBaseline"].get(h)
                if wm_m and p_m:
                    brier_delta = (
                        round(wm_m.brier_score - p_m.brier_score, 4)
                        if wm_m.brier_score is not None and p_m.brier_score is not None
                        else None
                    )
                    f1_delta = (
                        round(wm_m.f1_score - p_m.f1_score, 4)
                        if wm_m.f1_score is not None and p_m.f1_score is not None
                        else None
                    )
                    ece_delta = (
                        round(wm_m.expected_calibration_error - p_m.expected_calibration_error, 4)
                        if (wm_m.expected_calibration_error is not None and p_m.expected_calibration_error is not None)
                        else None
                    )
                    deltas[f"T+{h}"] = {
                        "brier_delta": brier_delta,
                        "f1_delta": f1_delta,
                        "ece_delta": ece_delta,
                        "interpretation": (
                            "World Model exhibits lower Brier error" if (brier_delta is not None and brier_delta < 0)
                            else "Persistence exhibits lower Brier error"
                        ),
                    }

        # Attack-family holdout evaluation if requested
        holdout_results: dict[str, Any] = {}
        if held_out_states and held_out_family:
            holdout_results = self._evaluate_holdout(
                held_out_states=held_out_states,
                held_out_family=held_out_family,
                in_distribution_truths=truths.get(1, []),
                in_distribution_preds=preds.get("NexSolveWorldModel", {}).get(1, []),
            )
        elif held_out_family and not held_out_states:
            holdout_results = {
                "status": "UNSUPPORTED",
                "reason": f"No held-out states found for family: {held_out_family}",
            }

        return BenchmarkRunResult(
            dataset_name=dataset_name,
            horizons=self.horizons,
            models_evaluated=models,
            sample_count=n_states,
            evaluated_trajectories=evaluated_trajectories,
            horizon_metrics=horizon_metrics,
            comparative_deltas=deltas,
            holdout_results=holdout_results,
            metadata={
                "world_model_loaded": self._world_model_loaded,
                "world_model_dir": str(self.world_model_dir),
                "lookback": self.lookback,
                "threshold": threshold,
            },
        )

    def _evaluate_holdout(
        self,
        held_out_states: Sequence[NetworkState],
        held_out_family: str,
        in_distribution_truths: Sequence[int],
        in_distribution_preds: Sequence[float],
    ) -> dict[str, Any]:
        """Evaluate out-of-distribution holdout performance."""
        if not held_out_states or len(held_out_states) < self.lookback + 1:
            return {
                "status": "INSUFFICIENT_DATA",
                "sample_count": len(held_out_states),
                "family": held_out_family,
            }

        holdout_probs: list[float] = []
        holdout_truths: list[int] = []

        for t in range(self.lookback, len(held_out_states)):
            hist = list(held_out_states[t - self.lookback : t])
            target_state = held_out_states[t]
            if target_state.attack_state is None:
                continue

            if self._world_model_loaded and self._world_model is not None:
                feat_names = (
                    FEATURE_NAMES_45 if len(self._scaler_mean) == len(FEATURE_NAMES_45)
                    else None
                )
                try:
                    wm_out = infer(
                        hist,
                        self._world_model,
                        self._scaler_mean,
                        self._scaler_scale,
                        k=1,
                        feature_names=feat_names,
                    )
                    fc = wm_out.get("forecasts", [{}])[0]
                    p_val = fc.get("attack_probability")
                    if p_val is not None:
                        holdout_probs.append(float(p_val))
                        holdout_truths.append(int(target_state.attack_state))
                except Exception:
                    pass

        if not holdout_probs or not in_distribution_preds:
            return {
                "status": "EMPTY_PREDICTIONS",
                "family": held_out_family,
            }

        gen_res = evaluate_unseen_attack_generalization(
            known_family_truths=in_distribution_truths,
            known_family_probs=in_distribution_preds,
            unseen_family_truths=holdout_truths,
            unseen_family_probs=holdout_probs,
            family_name=held_out_family,
        )
        return {
            "status": "COMPLETED",
            **gen_res,
        }
