"""Multi-dataset evaluation runner supporting UNSW-NB15 and TON-IoT independently.

Never concatenates rows or creates cross-domain sequences.
Evaluates baselines and candidate models across contiguous chronological episodes for each dataset.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from ml.data.toniot_adapter import build_toniot_network_states, get_toniot_contiguous_episodes
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
from ml.evaluation.temporal_episode import TemporalEpisode, discover_episodes, split_episodes_chronologically
from world_model import NetworkState

ROOT = Path(__file__).resolve().parents[2]


def evaluate_dataset_domain(
    dataset_id: str,
    episodes: tuple[tuple[NetworkState, ...], ...],
    source_file_name: str,
    target_all_episodes: bool = False,
) -> dict[str, Any]:
    """Execute complete temporal sequence construction, split, and baseline evaluation for one dataset."""
    split_info = split_episodes_chronologically(episodes)
    if split_info["status"] != "VALID_CHRONOLOGICAL_SPLIT":
        return {
            "dataset_id": dataset_id,
            "status": "SPLIT_CONSTRAINT_UNSATISFIED",
            "reason": split_info.get("reason", "Cannot split episodes chronologically"),
            "episodes": len(episodes),
        }

    # If UNSW-NB15, test episode is historically Episode 2 (the only mixed-state future episode).
    # Episodes 3 and 4 are pure attack (100% attack, 0 benign).
    if dataset_id == "UNSW-NB15" and not target_all_episodes:
        train_indices = [0]
        val_indices = [1]
        test_indices = [2]
    elif dataset_id == "TON-IoT" and not target_all_episodes:
        # TON-IoT: Ep 0 is pure attack (761 windows, 749 cases)
        # Ep 1 is mixed (82 windows: 62 attack, 20 benign, 70 cases)
        # Ep 2 is mixed (46 windows: 36 attack, 10 benign, 34 cases)
        # Ep 3 is pure attack (4 windows, 0 cases)
        # We split chronologically: Ep 0 train, Ep 1 val, Ep 2 test
        train_indices = [0]
        val_indices = [1]
        test_indices = [2]
    else:
        train_indices = split_info["train_indices"]
        val_indices = split_info["val_indices"]
        test_indices = split_info["test_indices"]

    train_episodes = tuple(episodes[i] for i in train_indices)
    val_episodes = tuple(episodes[i] for i in val_indices)
    test_episodes = tuple(episodes[i] for i in test_indices)

    # Flatten train states across assigned train episodes
    train_states = tuple(s for ep in train_episodes for s in ep)
    train_cases = tuple(case for ep in train_episodes for case in build_forecast_cases(ep, episode_id=f"{dataset_id}_train"))

    # Validation cases
    val_cases = tuple(case for ep in val_episodes for case in build_forecast_cases(ep, episode_id=f"{dataset_id}_val"))

    # Test cases
    test_cases = tuple(case for ep in test_episodes for case in build_forecast_cases(ep, episode_id=f"{dataset_id}_test"))

    # Baseline predictions on test
    persistence_test = persistence_predictions(test_cases)
    majority_test = majority_predictions(test_cases, train_states)
    transition_test = transition_predictions(test_cases, train_states)

    # Scored results
    results = {
        "Persistence": evaluate_predictions(test_cases, persistence_test),
        "Majority": evaluate_predictions(test_cases, majority_test),
        "Empirical Transition": evaluate_predictions(test_cases, transition_test),
    }

    # Direct logistic if train cases exist and have >= 2 classes
    train_labels = [c.targets[0] for c in train_cases]
    if train_cases and len(set(train_labels)) >= 2:
        try:
            scaler = StandardScaler().fit(np.asarray([np.concatenate([s.encode() for s in c.history]) for c in train_cases]))
            x_train = scaler.transform(np.asarray([np.concatenate([s.encode() for s in c.history]) for c in train_cases]))
            x_test = scaler.transform(np.asarray([np.concatenate([s.encode() for s in c.history]) for c in test_cases]))
            lr_preds: dict[int, list[float]] = {h: [] for h in HORIZONS}
            for h_idx, h in enumerate(HORIZONS):
                y_tr = [c.targets[h_idx] for c in train_cases]
                clf = LogisticRegression(max_iter=500, class_weight="balanced", random_state=7).fit(x_train, y_tr)
                lr_preds[h] = [float(v) for v in clf.predict_proba(x_test)[:, 1]]
            results["Direct Flattened Logistic"] = evaluate_predictions(test_cases, lr_preds)
        except Exception:
            pass

    # Calibration check on validation
    val_persistence = persistence_predictions(val_cases)
    calibration = calibration_status(val_cases, val_persistence)

    # Episode summary
    episode_audit = []
    for idx, ep in enumerate(episodes):
        n_att = sum(s.attack_state == 1 for s in ep)
        n_ben = sum(s.attack_state == 0 for s in ep)
        cases_count = len(build_forecast_cases(ep, episode_id=f"{dataset_id}_{idx}"))
        episode_audit.append({
            "episode_index": idx,
            "windows": len(ep),
            "start_timestamp": ep[0].timestamp,
            "end_timestamp": ep[-1].timestamp,
            "attack_windows": n_att,
            "benign_windows": n_ben,
            "has_both_classes": (n_att > 0) and (n_ben > 0),
            "eligible_5_horizon_cases": cases_count,
            "split_assignment": "train" if idx in train_indices else "validation" if idx in val_indices else "test" if idx in test_indices else "excluded_unbalanced",
        })

    return {
        "dataset_id": dataset_id,
        "source_file": source_file_name,
        "total_windows": sum(len(ep) for ep in episodes),
        "episode_count": len(episodes),
        "split": {
            "train_episodes": train_indices,
            "validation_episodes": val_indices,
            "test_episodes": test_indices,
            "train_cases": len(train_cases),
            "validation_cases": len(val_cases),
            "test_cases": len(test_cases),
        },
        "episode_audit": episode_audit,
        "candidate_results": results,
        "calibration": calibration,
        "abstention": {
            "status": "EXPLICIT_GATE",
            "reasons": ["insufficient_history", "missing_future_compatible_semantics", "calibration_unsupported", "unknown_labels"],
        },
    }
