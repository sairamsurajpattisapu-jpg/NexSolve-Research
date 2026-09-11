"""Leakage-safe scientific evaluation for the UNSW temporal forecast contract.

This module evaluates the existing artifact and simple baselines. It does not
connect forecasts to production and does not retrain or overwrite the model.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from world_model import K, LOOKBACK, NetworkState, build_network_states, infer, load_model
from ml.calibration.calibrator import PlattCalibrator
from ml.evaluation.leakage_auditor import audit_features

ROOT = Path(__file__).resolve().parents[2]
HORIZONS = tuple(range(1, K + 1))
WINDOW_SECONDS = 60


@dataclass(frozen=True)
class ForecastCase:
    episode_id: str
    source_index: int
    input_timestamps: tuple[int, ...]
    target_timestamps: tuple[int, ...]
    history: tuple[NetworkState, ...]
    targets: tuple[int, ...]

    @property
    def source_timestamp(self) -> int:
        return self.input_timestamps[-1]


def contiguous_episodes(states: Iterable[NetworkState], window_seconds: int = WINDOW_SECONDS) -> tuple[tuple[NetworkState, ...], ...]:
    ordered = sorted(states, key=lambda state: state.timestamp)
    episodes: list[list[NetworkState]] = []
    for state in ordered:
        if not episodes or state.timestamp != episodes[-1][-1].timestamp + window_seconds:
            episodes.append([])
        episodes[-1].append(state)
    return tuple(tuple(episode) for episode in episodes if episode)


def build_forecast_cases(episode: Iterable[NetworkState], lookback: int = LOOKBACK, horizons: tuple[int, ...] = HORIZONS, episode_id: str = "episode") -> tuple[ForecastCase, ...]:
    states = tuple(episode)
    if not horizons or min(horizons) < 1:
        raise ValueError("horizons must be positive")
    cases: list[ForecastCase] = []
    max_source = len(states) - max(horizons) - 1
    for source_index in range(lookback - 1, max_source + 1):
        history = states[source_index - lookback + 1:source_index + 1]
        targets = tuple(states[source_index + horizon].attack_state for horizon in horizons)
        if any(target is None for target in targets) or any(state.attack_state is None for state in history):
            continue
        input_timestamps = tuple(state.timestamp for state in history)
        target_timestamps = tuple(states[source_index + horizon].timestamp for horizon in horizons)
        if any(target_timestamp <= input_timestamps[-1] for target_timestamp in target_timestamps):
            raise AssertionError("forecast target is not strictly after input end")
        if tuple(sorted(target_timestamps)) != target_timestamps:
            raise AssertionError("forecast targets are not horizon ordered")
        cases.append(ForecastCase(episode_id, source_index, input_timestamps, target_timestamps, history, tuple(int(target) for target in targets)))
    return tuple(cases)


def chronological_episode_split(episodes: tuple[tuple[NetworkState, ...], ...]) -> dict[str, tuple[tuple[NetworkState, ...], ...]]:
    if len(episodes) < 3:
        raise ValueError("at least three chronological episodes are required for train/validation/test")
    return {"train": (episodes[0],), "validation": (episodes[1],), "test": (episodes[2],)}


def _score(actual: list[int], probabilities: list[float | None], threshold: float = 0.5) -> dict:
    evaluated = [(int(label), float(probability)) for label, probability in zip(actual, probabilities) if probability is not None]
    if not evaluated:
        return {"status": "not_available", "reason": "no evaluated probabilities", "forecast_cases": len(actual), "evaluated_cases": 0, "coverage": 0.0, "abstention_rate": 1.0}
    labels = np.asarray([item[0] for item in evaluated], dtype=int)
    scores = np.asarray([item[1] for item in evaluated], dtype=float)
    predicted = (scores >= threshold).astype(int)
    from ml.evaluation.metrics import binary_metrics
    result = binary_metrics(labels.tolist(), scores.tolist(), threshold)
    result["brier_score"] = float(np.mean((scores - labels) ** 2))
    result["confidence_intervals"] = {"status": "not_available", "reason": "fewer than 30 evaluated cases"} if len(evaluated) < 30 else {"status": "not_computed", "reason": "bootstrap confidence intervals are not enabled"}
    result["evaluated_cases"] = len(evaluated)
    return result


def evaluate_predictions(cases: tuple[ForecastCase, ...], predictions: dict[int, list[float | None]]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for horizon_index, horizon in enumerate(HORIZONS):
        actual = [case.targets[horizon_index] for case in cases]
        result[f"T+{horizon}"] = _score(actual, predictions.get(horizon, [None] * len(cases)))
    return result


def persistence_predictions(cases: tuple[ForecastCase, ...]) -> dict[int, list[float]]:
    return {horizon: [float(case.history[-1].attack_state) if case.history[-1].attack_state is not None else None for case in cases] for horizon in HORIZONS}


def majority_predictions(cases: tuple[ForecastCase, ...], training_states: tuple[NetworkState, ...]) -> dict[int, list[float]]:
    attack_rate = sum(int(state.attack_state or 0) for state in training_states) / max(len(training_states), 1)
    return {horizon: [attack_rate] * len(cases) for horizon in HORIZONS}


def transition_predictions(cases: tuple[ForecastCase, ...], training_states: tuple[NetworkState, ...]) -> dict[int, list[float]]:
    counts = np.ones((2, 2), dtype=float)
    for previous, current in zip(training_states, training_states[1:]):
        if previous.attack_state in (0, 1) and current.attack_state in (0, 1):
            counts[int(previous.attack_state), int(current.attack_state)] += 1
    transition = counts / counts.sum(axis=1, keepdims=True)
    predictions: dict[int, list[float]] = {horizon: [] for horizon in HORIZONS}
    for case in cases:
        state = int(case.history[-1].attack_state)
        distribution = np.eye(2)[state]
        for horizon in HORIZONS:
            distribution = distribution @ transition
            predictions[horizon].append(float(distribution[1]))
    return predictions


def logistic_predictions(cases: tuple[ForecastCase, ...], training_states: tuple[NetworkState, ...]) -> dict[int, list[float]]:
    train_cases = build_forecast_cases(training_states, episode_id="train")
    if not train_cases:
        return {horizon: [None] * len(cases) for horizon in HORIZONS}
    scaler = StandardScaler().fit(np.asarray([case.history[-1].encode() for case in train_cases]))
    predictions: dict[int, list[float]] = {horizon: [] for horizon in HORIZONS}
    for horizon_index, horizon in enumerate(HORIZONS):
        labels = [case.targets[horizon_index] for case in train_cases]
        if len(set(labels)) < 2:
            for _case in cases:
                predictions[horizon].append(None)
            continue
        classifier = LogisticRegression(max_iter=500, class_weight="balanced", random_state=7).fit(
            scaler.transform(np.asarray([case.history[-1].encode() for case in train_cases])), labels
        )
        probabilities = classifier.predict_proba(scaler.transform(np.asarray([case.history[-1].encode() for case in cases])))[:, 1]
        predictions[horizon].extend(float(value) for value in probabilities)
    return predictions


def lstm_predictions(cases: tuple[ForecastCase, ...], artifact_dir: Path) -> dict[int, list[float | None]]:
    model, mean, scale = load_model(artifact_dir)
    predictions: dict[int, list[float | None]] = {horizon: [] for horizon in HORIZONS}
    for case in cases:
        forecast = infer(list(case.history), model, mean, scale, K)["forecasts"]
        for point in forecast:
            predictions[int(point["horizon"])].append(point["attack_probability"])
    return predictions


def calibration_status(validation_cases: tuple[ForecastCase, ...], validation_predictions: dict[int, list[float | None]]) -> dict:
    statuses = {}
    for horizon_index, horizon in enumerate(HORIZONS):
        labels = [case.targets[horizon_index] for case in validation_cases]
        probabilities = [value for value in validation_predictions.get(horizon, []) if value is not None]
        if len(set(labels)) < 2 or len(probabilities) < 20:
            statuses[f"T+{horizon}"] = {"status": "CALIBRATION_UNSUPPORTED", "reason": "validation data lacks two classes or sufficient support"}
            continue
        calibrator = PlattCalibrator().fit(probabilities, labels)
        statuses[f"T+{horizon}"] = {"status": "CALIBRATED_ON_VALIDATION_ONLY", "slope": calibrator.slope, "intercept": calibrator.intercept}
    return statuses


def promotion_report(results: dict[str, dict], eligible_episode_count: int, calibration: dict[str, dict]) -> dict:
    reasons = []
    persistence = results.get("Persistence", {})
    lstm = results.get("Existing LSTM", {})
    persistence_f1 = [persistence.get(f"T+{horizon}", {}).get("f1") for horizon in HORIZONS]
    lstm_f1 = [lstm.get(f"T+{horizon}", {}).get("f1") for horizon in HORIZONS]
    if eligible_episode_count < 2:
        reasons.append("fewer than two eligible future evaluation episodes")
    if any(isinstance(left, (int, float)) and isinstance(right, (int, float)) and left <= right for left, right in zip(lstm_f1, persistence_f1)):
        reasons.append("existing LSTM does not consistently beat persistence")
    if any(value.get("status") == "CALIBRATION_UNSUPPORTED" for value in calibration.values()):
        reasons.append("calibration unsupported by validation support")
    return {"production_eligible": False, "status": "HOLD", "reasons": reasons or ["promotion criteria not met"]}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evaluate(artifact_dir: Path | None = None) -> dict:
    started = time.perf_counter()
    artifact_dir = artifact_dir or ROOT / "models" / "nexsolve_world_model"
    states, _labels = build_network_states()
    episodes = contiguous_episodes(states)
    splits = chronological_episode_split(episodes)
    train_states = tuple(splits["train"][0])
    validation_cases = build_forecast_cases(splits["validation"][0], episode_id="validation")
    test_cases = build_forecast_cases(splits["test"][0], episode_id="test")
    lstm_started = time.perf_counter()
    lstm_prediction_values = lstm_predictions(test_cases, artifact_dir)
    lstm_seconds = time.perf_counter() - lstm_started
    candidate_predictions = {
        "Persistence": persistence_predictions(test_cases),
        "Majority": majority_predictions(test_cases, train_states),
        "Empirical Transition": transition_predictions(test_cases, train_states),
        "Logistic Regression": logistic_predictions(test_cases, train_states),
        "Existing LSTM": lstm_prediction_values,
    }
    results = {name: evaluate_predictions(test_cases, predictions) for name, predictions in candidate_predictions.items()}
    validation_lstm = lstm_predictions(validation_cases, artifact_dir)
    calibration = calibration_status(validation_cases, validation_lstm)
    schema = json.loads((artifact_dir / "feature_schema.json").read_text(encoding="utf-8"))
    feature_names = [name for group in ("flow_features", "packet_features", "temporal_features") for name in schema.get(group, [])]
    feature_audit = audit_features(feature_names)
    report = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "task": {"state": "X_t", "target": "Y_(t+h) attack_state", "horizons": list(HORIZONS), "window_seconds": WINDOW_SECONDS, "lookback": LOOKBACK, "attack_state": "UNSW Label != 0 within the target window", "benign_state": "UNSW Label == 0 within the target window", "unknown_state": "missing/untrusted target or feature evidence", "unknown_semantics": "unknown is not benign or attack; it abstains"},
        "dataset": "UNSW-NB15",
        "episode_construction": {"episode_count": len(episodes), "episode_rule": "timestamp-contiguous 60-second runs; no capture or dataset boundary crossing", "train_episodes": [0], "validation_episodes": [1], "test_episodes": [2], "eligible_test_episode_count": 1},
        "split": {name: {"episodes": len(value), "windows": sum(len(episode) for episode in value), "start_timestamp": value[0][0].timestamp, "end_timestamp": value[-1][-1].timestamp} for name, value in splits.items()},
        "target_alignment": {"input_end_strictly_before_targets": True, "horizon_order_enforced": True, "future_targets_in_inputs": False, "test_cases": len(test_cases)},
        "leakage_audit": {"feature_schema": feature_audit, "scaler_fit_scope": "Logistic Regression scaler fit on train source states only; LSTM uses frozen artifact preprocessing", "test_threshold_selection": False, "episode_boundaries_enforced": True},
        "candidate_results": results,
        "calibration": calibration,
        "abstention": {"status": "EXPLICIT_GATE", "reasons": ["insufficient history", "missing future-compatible feature semantics", "calibration unsupported", "unknown labels"], "probability_is_not_confidence": True},
        "promotion": promotion_report(results, 1, calibration),
        "training": {"status": "NOT_RUN", "reason": "Phase 4 evaluated the frozen existing artifact; no retraining or overwrite was performed.", "training_duration": "not recorded in the existing artifact metadata"},
        "inference": {"model": "Existing LSTM", "total_seconds": round(lstm_seconds, 6), "sequences": len(test_cases), "seconds_per_sequence": round(lstm_seconds / max(len(test_cases), 1), 6), "model_size_bytes": (artifact_dir / "model.npz").stat().st_size},
        "reproducibility": {"seed": 7, "artifact": str(artifact_dir.relative_to(ROOT)), "artifact_files": {path.name: {"sha256": _sha256(path), "size_bytes": path.stat().st_size} for path in artifact_dir.iterdir() if path.is_file()}, "evaluation_seconds": round(time.perf_counter() - started, 6)},
        "artifact_version": "candidate_v1_existing_lstm_evaluation_only",
        "production_forecast_connected": False,
    }
    return report


def write_report(report: dict, output_dir: Path | None = None) -> None:
    output_dir = output_dir or ROOT / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "phase4_scientific_evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (output_dir / "phase4_scientific_evaluation.md").write_text("# Phase 4 Scientific Forecasting Evaluation\n\n```json\n" + json.dumps(report, indent=2) + "\n```\n", encoding="utf-8")
    artifact_dir = ROOT / "artifacts" / "models" / "candidate_v1"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    for name in ("model.npz", "preprocessing.npz", "feature_schema.json", "config.json", "metadata.json"):
        shutil.copy2(ROOT / "models" / "nexsolve_world_model" / name, artifact_dir / name)
    (artifact_dir / "evaluation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (artifact_dir / "promotion.json").write_text(json.dumps(report["promotion"], indent=2), encoding="utf-8")


if __name__ == "__main__":
    result = evaluate()
    write_report(result)
    print(json.dumps(result["promotion"], indent=2))
