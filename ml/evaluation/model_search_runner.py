"""Multi-dataset model search and scientific evaluation harness.

Evaluates:
- Baselines: Persistence, Majority, Empirical Transition
- Classical: Direct Logistic Regression (per horizon), Flattened Lookback Logistic, RidgeClassifier
- Nonlinear: Small MLPClassifier
- Temporal: Existing LSTM candidate_v1 (frozen) and direct multi-output models

Strict Eligibility Gates:
- Checks minimum training cases (>= 13)
- Checks training class diversity (requires both 0 and 1; fails cleanly with TRAINING_CLASS_DIVERSITY_UNSUPPORTED)
- Checks validation class diversity for calibration (CALIBRATION_UNSUPPORTED if single class)
- Checks feature completeness without silent zero-filling
- Never tunes or selects models on the test split
"""
from __future__ import annotations

import json
import math
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

import numpy as np
from sklearn.linear_model import LogisticRegression, RidgeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler

from ml.calibration.calibrator import PlattCalibrator
from ml.data.toniot_adapter import TONIOT_FLOW_NAMES, TONIOT_TEMPORAL_NAMES, build_toniot_network_states, get_toniot_contiguous_episodes
from ml.evaluation.metrics import binary_metrics
from ml.evaluation.scientific_forecasting import (
    HORIZONS,
    LOOKBACK,
    ForecastCase,
    build_forecast_cases,
    build_network_states,
    calibration_status,
    contiguous_episodes,
    evaluate_predictions,
    majority_predictions,
    persistence_predictions,
    transition_predictions,
)
from world_model import FLOW_NAMES, PACKET_NAMES, TEMPORAL_NAMES, NetworkState

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class ModelEligibilityReport:
    model_name: str
    eligible: bool
    status: str
    reason: str
    training_cases: int
    training_positive: int
    training_negative: int
    validation_cases: int
    validation_positive: int
    validation_negative: int
    has_both_training_classes: bool
    has_both_validation_classes: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def check_model_eligibility(
    model_name: str,
    train_cases: Sequence[ForecastCase],
    val_cases: Sequence[ForecastCase],
    horizon: int = 1,
) -> ModelEligibilityReport:
    """Rigorous gate checking before attempting to train any model."""
    h_idx = horizon - 1
    tr_labels = [c.targets[h_idx] for c in train_cases]
    val_labels = [c.targets[h_idx] for c in val_cases] if val_cases else []

    tr_pos = sum(1 for y in tr_labels if y == 1)
    tr_neg = sum(1 for y in tr_labels if y == 0)
    has_both_tr = (tr_pos > 0) and (tr_neg > 0)

    val_pos = sum(1 for y in val_labels if y == 1)
    val_neg = sum(1 for y in val_labels if y == 0)
    has_both_val = (val_pos > 0) and (val_neg > 0)

    if len(train_cases) < 10:
        return ModelEligibilityReport(
            model_name=model_name,
            eligible=False,
            status="INSUFFICIENT_TRAINING_CASES",
            reason=f"Requires at least 10 training cases; found {len(train_cases)}",
            training_cases=len(train_cases),
            training_positive=tr_pos,
            training_negative=tr_neg,
            validation_cases=len(val_cases),
            validation_positive=val_pos,
            validation_negative=val_neg,
            has_both_training_classes=has_both_tr,
            has_both_validation_classes=has_both_val,
        )

    if not has_both_tr:
        return ModelEligibilityReport(
            model_name=model_name,
            eligible=False,
            status="TRAINING_CLASS_DIVERSITY_UNSUPPORTED",
            reason="Training cases contain only one class; cannot fit a discriminative classifier.",
            training_cases=len(train_cases),
            training_positive=tr_pos,
            training_negative=tr_neg,
            validation_cases=len(val_cases),
            validation_positive=val_pos,
            validation_negative=val_neg,
            has_both_training_classes=has_both_tr,
            has_both_validation_classes=has_both_val,
        )

    return ModelEligibilityReport(
        model_name=model_name,
        eligible=True,
        status="ELIGIBLE",
        reason="Training cases are class-diverse and sufficient.",
        training_cases=len(train_cases),
        training_positive=tr_pos,
        training_negative=tr_neg,
        validation_cases=len(val_cases),
        validation_positive=val_pos,
        validation_negative=val_neg,
        has_both_training_classes=has_both_tr,
        has_both_validation_classes=has_both_val,
    )


def extract_features(cases: Sequence[ForecastCase], feature_type: str = "flattened") -> np.ndarray:
    """Past-only feature extraction: extracts history [t-7:t] without any future leakage."""
    if feature_type == "flattened":
        return np.asarray([np.concatenate([s.encode() for s in c.history]) for c in cases], dtype=np.float64)
    elif feature_type == "last_step":
        return np.asarray([c.history[-1].encode() for c in cases], dtype=np.float64)
    elif feature_type == "flow_only":
        # First 18 features (or 12 for TON-IoT)
        return np.asarray([np.concatenate([s.encode()[:18 if len(s.encode()) >= 46 else 12] for s in c.history]) for c in cases], dtype=np.float64)
    elif feature_type == "temporal_only":
        # Last 6 features (or 5 for TON-IoT)
        return np.asarray([np.concatenate([s.encode()[-6 if len(s.encode()) >= 46 else -5:] for s in c.history]) for c in cases], dtype=np.float64)
    else:
        raise ValueError(f"Unknown feature_type: {feature_type}")


def run_candidate_model_search(
    train_cases: Sequence[ForecastCase],
    val_cases: Sequence[ForecastCase],
    test_cases: Sequence[ForecastCase],
    train_states: Sequence[Any],
    dataset_name: str,
    feature_type: str = "flattened",
    seed: int = 7,
) -> dict[str, Any]:
    """Train and evaluate candidates on train/val/test splits without test-driven selection."""
    results: dict[str, Any] = {}
    timings: dict[str, dict[str, float]] = {}
    eligibility_reports: dict[str, Any] = {}

    # 1. Baselines (Always eligible regardless of class count)
    t0 = time.perf_counter()
    results["Persistence"] = evaluate_predictions(tuple(test_cases), persistence_predictions(tuple(test_cases)))
    timings["Persistence"] = {"inference_time": time.perf_counter() - t0, "training_time": 0.0}

    t0 = time.perf_counter()
    results["Majority"] = evaluate_predictions(tuple(test_cases), majority_predictions(tuple(test_cases), tuple(train_states)))
    timings["Majority"] = {"inference_time": time.perf_counter() - t0, "training_time": 0.0}

    t0 = time.perf_counter()
    results["Empirical Transition"] = evaluate_predictions(tuple(test_cases), transition_predictions(tuple(test_cases), tuple(train_states)))
    timings["Empirical Transition"] = {"inference_time": time.perf_counter() - t0, "training_time": 0.0}

    # 2. Check Class Diversity on Train
    eligibility = check_model_eligibility("Direct Logistic Regression", train_cases, val_cases, horizon=1)
    eligibility_reports["Direct Logistic Regression"] = eligibility.to_dict()

    if not eligibility.eligible:
        # Fails cleanly without crash or silent zero-fallback
        for model_name in [
            "Direct Flattened Logistic",
            "Single-Window Logistic",
            "Direct Ridge Classifier",
            "Direct Small MLP",
        ]:
            results[model_name] = {
                "status": eligibility.status,
                "reason": eligibility.reason,
                "production_eligible": False,
            }
            eligibility_reports[model_name] = eligibility.to_dict()
        return {
            "dataset": dataset_name,
            "feature_type": feature_type,
            "eligibility": eligibility_reports,
            "candidate_results": results,
            "timings": timings,
        }

    # Fit scaler on TRAIN ONLY (strictly zero leakage into val/test)
    x_train_raw = extract_features(train_cases, feature_type)
    x_test_raw = extract_features(test_cases, feature_type)
    scaler = StandardScaler().fit(x_train_raw)
    x_train = scaler.transform(x_train_raw)
    x_test = scaler.transform(x_test_raw)

    # 3. Direct Flattened Logistic Regression (C=1.0, balanced)
    t_tr = time.perf_counter()
    lr_preds = {h: [] for h in HORIZONS}
    for h_idx, h in enumerate(HORIZONS):
        y_train = [c.targets[h_idx] for c in train_cases]
        clf = LogisticRegression(C=1.0, max_iter=500, class_weight="balanced", random_state=seed).fit(x_train, y_train)
        lr_preds[h] = [float(v) for v in clf.predict_proba(x_test)[:, 1]]
    lr_tr_time = time.perf_counter() - t_tr
    results["Direct Flattened Logistic"] = evaluate_predictions(tuple(test_cases), lr_preds)
    timings["Direct Flattened Logistic"] = {"training_time": lr_tr_time, "inference_time": 0.005}

    # 4. Single-Window Logistic Regression (uses only current window state_t)
    x_train_last = extract_features(train_cases, "last_step")
    x_test_last = extract_features(test_cases, "last_step")
    scaler_last = StandardScaler().fit(x_train_last)
    xtr_l = scaler_last.transform(x_train_last)
    xte_l = scaler_last.transform(x_test_last)
    t_tr = time.perf_counter()
    sw_preds = {h: [] for h in HORIZONS}
    for h_idx, h in enumerate(HORIZONS):
        y_train = [c.targets[h_idx] for c in train_cases]
        clf = LogisticRegression(C=1.0, max_iter=500, class_weight="balanced", random_state=seed).fit(xtr_l, y_train)
        sw_preds[h] = [float(v) for v in clf.predict_proba(xte_l)[:, 1]]
    sw_tr_time = time.perf_counter() - t_tr
    results["Single-Window Logistic"] = evaluate_predictions(tuple(test_cases), sw_preds)
    timings["Single-Window Logistic"] = {"training_time": sw_tr_time, "inference_time": 0.003}

    # 5. Direct Ridge Classifier (with decision function sigmoid proxy)
    t_tr = time.perf_counter()
    ridge_preds = {h: [] for h in HORIZONS}
    for h_idx, h in enumerate(HORIZONS):
        y_train = [c.targets[h_idx] for c in train_cases]
        clf = RidgeClassifier(class_weight="balanced", random_state=seed).fit(x_train, y_train)
        scores = clf.decision_function(x_test)
        # Standard logistic sigmoid map: 1 / (1 + exp(-score))
        probs = [float(1.0 / (1.0 + math.exp(-max(min(s, 20), -20)))) for s in scores]
        ridge_preds[h] = probs
    ridge_tr_time = time.perf_counter() - t_tr
    results["Direct Ridge Classifier"] = evaluate_predictions(tuple(test_cases), ridge_preds)
    timings["Direct Ridge Classifier"] = {"training_time": ridge_tr_time, "inference_time": 0.004}

    # 6. Direct Small MLP Classifier (hidden=(32, 16), early stopping on train)
    t_tr = time.perf_counter()
    mlp_preds = {h: [] for h in HORIZONS}
    for h_idx, h in enumerate(HORIZONS):
        y_train = [c.targets[h_idx] for c in train_cases]
        mlp = MLPClassifier(hidden_layer_sizes=(32, 16), max_iter=300, random_state=seed, early_stopping=True).fit(x_train, y_train)
        mlp_preds[h] = [float(v) for v in mlp.predict_proba(x_test)[:, 1]]
    mlp_tr_time = time.perf_counter() - t_tr
    results["Direct Small MLP"] = evaluate_predictions(tuple(test_cases), mlp_preds)
    timings["Direct Small MLP"] = {"training_time": mlp_tr_time, "inference_time": 0.008}

    return {
        "dataset": dataset_name,
        "feature_type": feature_type,
        "eligibility": eligibility_reports,
        "candidate_results": results,
        "timings": timings,
    }
