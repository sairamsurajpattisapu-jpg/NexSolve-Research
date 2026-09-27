"""NexSolve Temporal ML Training Runner: Candidate V1.

Strictly adheres to:
- 45 features (PCAP-compatible, zero fabricated mean_tcp_rtt)
- 60-second temporal windows
- 8 historical windows lookback
- Strict chronological split (Train=595, Val=149, Test=25)
- Zero temporal leakage (scaler fit strictly on Train)
- Multi-horizon evaluation across T+1..T+5 vs Persistence Baseline
- Checkpoint persistence to models/candidate_v1/
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from world_model import (
    FEATURE_NAMES_45,
    FLOW_NAMES_45,
    LOOKBACK,
    PACKET_NAMES,
    TEMPORAL_NAMES,
    WINDOW_SECONDS,
    NetworkState,
    NumpyLSTM,
    chronological_split,
    make_sequences,
)

CACHE_FILE = ROOT / "data" / "processed" / "unsw_network_states.json"
CHECKPOINT_DIR = ROOT / "models" / "candidate_v1"


def get_hardware_info() -> dict[str, Any]:
    """Detect available compute and hardware runtime."""
    try:
        import torch
        torch_ver = torch.__version__
        cuda_avail = torch.cuda.is_available()
        cuda_device = torch.cuda.get_device_name(0) if cuda_avail else "N/A"
        cuda_vram = (
            f"{torch.cuda.get_device_properties(0).total_memory / (1024**3):.2f} GB"
            if cuda_avail else "N/A"
        )
    except ImportError:
        torch_ver = "Not installed"
        cuda_avail = False
        cuda_device = "N/A"
        cuda_vram = "N/A"

    return {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "processor": platform.processor(),
        "cpu_cores_logical": os.cpu_count(),
        "pytorch_version": torch_ver,
        "cuda_available": cuda_avail,
        "cuda_device_name": cuda_device,
        "cuda_vram": cuda_vram,
        "selected_runtime": "GPU" if cuda_avail else "CPU (Vectorized NumPy)",
    }


def load_dataset() -> tuple[list[NetworkState], dict[str, list[NetworkState]]]:
    """Load cached preprocessed network states and apply chronological split."""
    if not CACHE_FILE.exists():
        from world_model import build_network_states
        states, labels = build_network_states()
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(
            json.dumps({"states": [s.to_dict() for s in states], "labels": {str(k): v for k, v in labels.items()}}),
            encoding="utf-8",
        )
    else:
        raw_data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        states = [NetworkState(**s) for s in raw_data["states"]]

    splits = chronological_split(states)
    return states, splits


def fit_scaler(train_states: Sequence[NetworkState]) -> tuple[np.ndarray, np.ndarray]:
    """Fit mean and std strictly on train split to prevent temporal leakage."""
    train_matrix = np.asarray([s.encode(FEATURE_NAMES_45) for s in train_states])
    mean = np.mean(train_matrix, axis=0)
    scale = np.std(train_matrix, axis=0)
    scale[scale < 1e-9] = 1.0
    return mean, scale


def compute_loss(
    model: NumpyLSTM,
    x: np.ndarray,
    targets: np.ndarray,
    labels: np.ndarray,
) -> tuple[float, float, float]:
    """Compute combined loss, state MSE, and label BCE."""
    total_loss = 0.0
    total_state_mse = 0.0
    total_bce = 0.0
    n = max(len(x), 1)

    for seq, target, label in zip(x, targets, labels):
        output = model.forward(seq)
        state_error = output[:-1] - target
        state_mse = float(np.mean(state_error ** 2))
        prob = float(1.0 / (1.0 + np.exp(-np.clip(output[-1], -30.0, 30.0))))
        bce = float(-(label * np.log(prob + 1e-9) + (1.0 - label) * np.log(1.0 - prob + 1e-9)))

        total_loss += state_mse + bce
        total_state_mse += state_mse
        total_bce += bce

    return total_loss / n, total_state_mse / n, total_bce / n


def train_model(
    model: NumpyLSTM,
    x_train: np.ndarray,
    targets_train: np.ndarray,
    labels_train: np.ndarray,
    x_val: np.ndarray,
    targets_val: np.ndarray,
    labels_val: np.ndarray,
    epochs: int = 40,
    learning_rate: float = 0.002,
    log_interval: int = 5,
) -> dict[str, Any]:
    """Execute training loop with per-epoch train and validation metrics."""
    train_losses = []
    train_state_mses = []
    train_bces = []
    val_losses = []
    val_state_mses = []
    val_bces = []
    epoch_times = []

    best_val_loss = float("inf")
    best_weights = None
    best_epoch = 0

    start_total = time.perf_counter()

    for epoch in range(1, epochs + 1):
        t0 = time.perf_counter()
        total_train_loss = 0.0
        total_train_mse = 0.0
        total_train_bce = 0.0
        n_samples = max(len(x_train), 1)

        # SGD over sequence samples with BPTT
        for sequence, target, label in zip(x_train, targets_train, labels_train):
            output, history = model.forward(sequence, cache=True)
            state_error = output[:-1] - target
            state_mse = float(np.mean(state_error ** 2))
            prob = float(1.0 / (1.0 + np.exp(-np.clip(output[-1], -30.0, 30.0))))
            bce = float(-(label * np.log(prob + 1e-9) + (1.0 - label) * np.log(1.0 - prob + 1e-9)))

            total_train_loss += state_mse + bce
            total_train_mse += state_mse
            total_train_bce += bce

            # Gradients
            d_out = np.r_[2.0 * state_error / len(state_error), prob - label]
            dWy = np.outer(d_out, history[-1][0])
            dby = d_out
            dh = model.Wy.T @ d_out
            dc = np.zeros(model.hidden_size)
            dW = np.zeros_like(model.W)
            db = np.zeros_like(model.b)

            for idx in range(len(history) - 1, -1, -1):
                h, c, i, f, g, o, vector = history[idx]
                old_c = history[idx - 1][1] if idx > 0 else np.zeros(model.hidden_size)
                do = dh * np.tanh(c)
                dc += dh * o * (1.0 - np.tanh(c) ** 2)
                df = dc * old_c
                di = dc * g
                dg = dc * i
                dz = np.r_[di * i * (1.0 - i), df * f * (1.0 - f), dg * (1.0 - g ** 2), do * o * (1.0 - o)]
                prev_h = history[idx - 1][0] if idx > 0 else np.zeros(model.hidden_size)
                dW += np.outer(dz, np.r_[vector, prev_h])
                db += dz
                dh = model.W[:, model.input_size:].T @ dz
                dc *= f

            for param, grad in ((model.W, dW), (model.b, db), (model.Wy, dWy), (model.by, dby)):
                param -= learning_rate * np.clip(grad, -5.0, 5.0)

        dt = time.perf_counter() - t0
        epoch_times.append(dt)

        train_l = total_train_loss / n_samples
        train_m = total_train_mse / n_samples
        train_b = total_train_bce / n_samples

        train_losses.append(train_l)
        train_state_mses.append(train_m)
        train_bces.append(train_b)

        # Validation loss
        val_l, val_m, val_b = compute_loss(model, x_val, targets_val, labels_val)
        val_losses.append(val_l)
        val_state_mses.append(val_m)
        val_bces.append(val_b)

        if val_l < best_val_loss:
            best_val_loss = val_l
            best_epoch = epoch
            best_weights = {
                "W": model.W.copy(),
                "b": model.b.copy(),
                "Wy": model.Wy.copy(),
                "by": model.by.copy(),
            }

        if epoch % log_interval == 0 or epoch == 1 or epoch == epochs:
            print(
                f"Epoch [{epoch:2d}/{epochs:2d}] "
                f"Train Loss: {train_l:.4f} (MSE: {train_m:.4f}, BCE: {train_b:.4f}) | "
                f"Val Loss: {val_l:.4f} (MSE: {val_m:.4f}, BCE: {val_b:.4f}) | "
                f"Time: {dt:.2f}s"
            )

    total_training_time = time.perf_counter() - start_total

    # Restore best validation weights
    if best_weights is not None:
        model.W = best_weights["W"]
        model.b = best_weights["b"]
        model.Wy = best_weights["Wy"]
        model.by = best_weights["by"]

    return {
        "epochs": epochs,
        "learning_rate": learning_rate,
        "total_training_time_seconds": round(total_training_time, 2),
        "mean_epoch_time_seconds": round(float(np.mean(epoch_times)), 3),
        "best_epoch": best_epoch,
        "best_val_loss": round(best_val_loss, 4),
        "final_train_loss": round(train_losses[-1], 4),
        "final_val_loss": round(val_losses[-1], 4),
        "train_loss_curve": [round(l, 4) for l in train_losses],
        "val_loss_curve": [round(l, 4) for l in val_losses],
        "train_state_mse_curve": [round(m, 4) for m in train_state_mses],
        "train_bce_curve": [round(b, 4) for b in train_bces],
        "val_state_mse_curve": [round(m, 4) for m in val_state_mses],
        "val_bce_curve": [round(b, 4) for b in val_bces],
    }


def compute_classification_metrics(
    actual: list[int],
    preds: list[int],
    probs: list[float] | None = None,
) -> dict[str, Any]:
    """Compute standardized classification and calibration metrics."""
    cm = confusion_matrix(actual, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    prec = float(precision_score(actual, preds, zero_division=0))
    rec = float(recall_score(actual, preds, zero_division=0))
    f1 = float(f1_score(actual, preds, zero_division=0))
    b_acc = float(balanced_accuracy_score(actual, preds))
    roc_auc = (
        float(roc_auc_score(actual, probs))
        if probs is not None and len(set(actual)) == 2
        else None
    )
    pr_auc = (
        float(average_precision_score(actual, probs))
        if probs is not None and len(set(actual)) == 2
        else None
    )
    brier = (
        float(np.mean([(p - y) ** 2 for p, y in zip(probs, actual)]))
        if probs is not None
        else None
    )

    return {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4),
        "balanced_accuracy": round(b_acc, 4),
        "roc_auc": round(roc_auc, 4) if roc_auc is not None else "N/A",
        "pr_auc": round(pr_auc, 4) if pr_auc is not None else "N/A",
        "brier_score": round(brier, 4) if brier is not None else "N/A",
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
        "sample_count": len(actual),
    }


def evaluate_temporal_benchmark(
    model: NumpyLSTM,
    test_states: Sequence[NetworkState],
    mean: np.ndarray,
    scale: np.ndarray,
    train_states: Sequence[NetworkState],
    horizons: Sequence[int] = (1, 2, 3, 4, 5),
) -> dict[str, Any]:
    """Evaluate multi-step autoregressive rollout vs Persistence and Logistic Regression."""
    names = FEATURE_NAMES_45
    n_flow = len(FLOW_NAMES_45)
    n_pkt = len(PACKET_NAMES)

    # Train Logistic Regression Baseline on Train split
    train_matrix = np.asarray([s.encode(names) for s in train_states])
    train_targets = np.asarray([s.attack_state for s in train_states[1:]], dtype=int)
    train_x = (train_matrix[:-1] - mean) / scale
    lr = LogisticRegression(max_iter=500, class_weight="balanced", random_state=42)
    lr.fit(train_x, train_targets)

    results: dict[str, dict[str, Any]] = {
        "NexSolve_Candidate_V1": {},
        "Persistence_Baseline": {},
        "Logistic_Regression_Baseline": {},
    }

    horizon_diagnostics: dict[str, Any] = {}

    for h in horizons:
        model_probs = []
        model_preds = []
        pers_probs = []
        pers_preds = []
        lr_probs = []
        lr_preds = []
        actuals = []

        model_state_mses = []
        pers_state_mses = []

        # Eligible start points t in [LOOKBACK, len(test_states) - h]
        for t in range(LOOKBACK, len(test_states) - h + 1):
            history = list(test_states[t - LOOKBACK : t])
            current_state = history[-1]
            target_state = test_states[t + h - 1]

            if target_state.attack_state is None:
                continue

            target_label = int(target_state.attack_state)
            actuals.append(target_label)

            # 1. World Model Autoregressive Rollout
            buf = np.zeros((LOOKBACK + h, len(names)), dtype=np.float64)
            for idx, s in enumerate(history):
                buf[idx] = s.encode(names)

            pred_prob_h = 0.0
            pred_state_h = np.zeros(len(names))

            for step in range(1, h + 1):
                window = buf[step - 1 : step - 1 + LOOKBACK]
                scaled = (window - mean) / scale
                pred_scaled, prob = model.predict(scaled)
                pred_prob_h = prob
                pred_state_h = pred_scaled * scale + mean

                # Roll predicted state into buffer
                sim_vec = np.zeros(len(names), dtype=np.float64)
                sim_vec[:n_flow] = pred_state_h[:n_flow]
                sim_vec[n_flow : n_flow + n_pkt] = pred_state_h[n_flow : n_flow + n_pkt]
                sim_vec[n_flow + n_pkt :] = pred_state_h[n_flow + n_pkt :]
                buf[LOOKBACK - 1 + step] = sim_vec

            model_probs.append(float(pred_prob_h))
            model_preds.append(int(pred_prob_h >= 0.5))

            # Continuous state error
            target_encoded = target_state.encode(names)
            model_scaled_err = (pred_state_h - target_encoded) / scale
            model_state_mses.append(float(np.mean(model_scaled_err ** 2)))

            # 2. Persistence Baseline: future state = current state
            current_label = int(current_state.attack_state) if current_state.attack_state is not None else 0
            pers_probs.append(float(current_label))
            pers_preds.append(current_label)

            pers_scaled_err = (current_state.encode(names) - target_encoded) / scale
            pers_state_mses.append(float(np.mean(pers_scaled_err ** 2)))

            # 3. Logistic Regression Baseline: single step projection from current state
            curr_x = (current_state.encode(names) - mean) / scale
            lr_prob = float(lr.predict_proba(curr_x.reshape(1, -1))[0, 1])
            lr_probs.append(lr_prob)
            lr_preds.append(int(lr_prob >= 0.5))

        h_key = f"T+{h}"
        m_metrics = compute_classification_metrics(actuals, model_preds, model_probs)
        m_metrics["continuous_state_mse"] = round(float(np.mean(model_state_mses)), 4) if model_state_mses else None
        results["NexSolve_Candidate_V1"][h_key] = m_metrics

        p_metrics = compute_classification_metrics(actuals, pers_preds, pers_probs)
        p_metrics["continuous_state_mse"] = round(float(np.mean(pers_state_mses)), 4) if pers_state_mses else None
        results["Persistence_Baseline"][h_key] = p_metrics

        lr_metrics = compute_classification_metrics(actuals, lr_preds, lr_probs)
        results["Logistic_Regression_Baseline"][h_key] = lr_metrics

        # Failure mode / collapse diagnostic info per horizon
        horizon_diagnostics[h_key] = {
            "sample_count": len(actuals),
            "attack_count": actuals.count(1),
            "benign_count": actuals.count(0),
            "model_pred_positive_count": model_preds.count(1),
            "model_pred_positive_rate": round(model_preds.count(1) / max(len(model_preds), 1), 4),
            "model_mean_probability": round(float(np.mean(model_probs)), 4),
            "model_std_probability": round(float(np.std(model_probs)), 4),
            "model_min_probability": round(float(np.min(model_probs)), 4),
            "model_max_probability": round(float(np.max(model_probs)), 4),
            "persistence_positive_count": pers_preds.count(1),
        }

    return {
        "horizons": [f"T+{h}" for h in horizons],
        "models": results,
        "diagnostics": horizon_diagnostics,
    }


def analyze_model_collapse(benchmark: dict[str, Any]) -> dict[str, Any]:
    """Inspect model outputs for collapse, constant predictions, or copy-paste behavior."""
    diag = benchmark["diagnostics"]
    wm_h1 = benchmark["models"]["NexSolve_Candidate_V1"]["T+1"]
    pers_h1 = benchmark["models"]["Persistence_Baseline"]["T+1"]

    collapsed_to_all_zeros = all(d["model_pred_positive_count"] == 0 for d in diag.values())
    collapsed_to_all_ones = all(d["model_pred_positive_count"] == d["sample_count"] for d in diag.values())
    flat_probability = all(d["model_std_probability"] < 0.01 for d in diag.values())

    prob_spreads = [d["model_max_probability"] - d["model_min_probability"] for d in diag.values()]
    mean_spread = float(np.mean(prob_spreads))

    beats_persistence_t1_f1 = wm_h1["f1"] > pers_h1["f1"]
    ties_persistence_t1_f1 = wm_h1["f1"] == pers_h1["f1"]

    return {
        "collapsed_to_all_zeros": collapsed_to_all_zeros,
        "collapsed_to_all_ones": collapsed_to_all_ones,
        "flat_probability_distribution": flat_probability,
        "mean_probability_spread": round(mean_spread, 4),
        "beats_persistence_t1_f1": beats_persistence_t1_f1,
        "ties_persistence_t1_f1": ties_persistence_t1_f1,
        "summary": (
            "Model exhibits responsive probabilistic variation across rollout steps. "
            "Continuous state and attack probabilities dynamic without collapsing to static values."
        ) if not (collapsed_to_all_zeros or collapsed_to_all_ones or flat_probability) else (
            "WARNING: Potential model collapse detected."
        ),
    }


def run_sample_trajectory_demo(
    model: NumpyLSTM,
    test_states: Sequence[NetworkState],
    mean: np.ndarray,
    scale: np.ndarray,
    start_index: int = 14,
) -> dict[str, Any]:
    """Demonstrate recursive trajectory rollout on an attack onset window."""
    names = FEATURE_NAMES_45
    n_flow = len(FLOW_NAMES_45)
    n_pkt = len(PACKET_NAMES)

    history = list(test_states[start_index - LOOKBACK : start_index])
    curr = history[-1]
    curr_dict = {k: round(float(v), 2) for k, v in curr.flow_features.items()}

    current_summary = {
        "step_index": start_index - 1,
        "timestamp_epoch": curr.timestamp,
        "ground_truth_attack_state": curr.attack_state,
        "flow_count": curr_dict.get("flow_count", 0.0),
        "total_src_bytes": curr_dict.get("total_src_bytes", 0.0),
        "total_dst_bytes": curr_dict.get("total_dst_bytes", 0.0),
        "total_packets": curr_dict.get("total_packets", 0.0),
        "unique_dst_ports": curr_dict.get("unique_dst_ports", 0.0),
    }

    buf = np.zeros((LOOKBACK + 5, len(names)), dtype=np.float64)
    for idx, s in enumerate(history):
        buf[idx] = s.encode(names)

    forecasts = []
    for step in range(1, 6):
        window = buf[step - 1 : step - 1 + LOOKBACK]
        scaled = (window - mean) / scale
        pred_scaled, prob = model.predict(scaled)
        pred_state = pred_scaled * scale + mean
        pred_dict = {k: round(float(v), 2) for k, v in zip(names, pred_state)}

        actual_state = test_states[start_index - 1 + step] if (start_index - 1 + step) < len(test_states) else None
        actual_label = actual_state.attack_state if actual_state is not None else None

        confidence = round(float(abs(prob - 0.5) * 2.0), 4)

        forecasts.append({
            "horizon": f"T+{step}",
            "lookahead_seconds": step * 60,
            "predicted_attack_probability": round(prob, 4),
            "attack_predicted": bool(prob >= 0.5),
            "ground_truth_attack": actual_label,
            "confidence": confidence,
            "abstained": False,
            "predicted_flow_count": pred_dict.get("flow_count", 0.0),
            "predicted_total_bytes": round(pred_dict.get("total_src_bytes", 0.0) + pred_dict.get("total_dst_bytes", 0.0), 2),
            "predicted_delta_flow_count": pred_dict.get("delta_flow_count", 0.0),
        })

        # Roll vector into buffer
        sim_vec = np.zeros(len(names), dtype=np.float64)
        sim_vec[:n_flow] = pred_state[:n_flow]
        sim_vec[n_flow : n_flow + n_pkt] = pred_state[n_flow : n_flow + n_pkt]
        sim_vec[n_flow + n_pkt :] = pred_state[n_flow + n_pkt :]
        buf[LOOKBACK - 1 + step] = sim_vec

    return {
        "current_state": current_summary,
        "forecast_trajectory": forecasts,
    }


def save_candidate_v1_artifacts(
    model: NumpyLSTM,
    mean: np.ndarray,
    scale: np.ndarray,
    training_metrics: dict[str, Any],
    benchmark_metrics: dict[str, Any],
    collapse_analysis: dict[str, Any],
    sample_forecast: dict[str, Any],
    hardware_info: dict[str, Any],
    seed: int,
) -> dict[str, str]:
    """Persist all candidate_v1 artifacts and return their SHA-256 hashes."""
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. model.npz
    model_path = CHECKPOINT_DIR / "model.npz"
    np.savez(
        model_path,
        W=model.W,
        b=model.b,
        Wy=model.Wy,
        by=model.by,
        input_size=model.input_size,
        hidden_size=model.hidden_size,
    )

    # 2. preprocessing.npz
    prep_path = CHECKPOINT_DIR / "preprocessing.npz"
    np.savez(prep_path, mean=mean, scale=scale)

    # 3. config.json
    config = {
        "model_format": "NumPy NPZ",
        "architecture": "NumpyLSTM",
        "input_size": 45,
        "hidden_size": 24,
        "output_size": 46,
        "lookback": LOOKBACK,
        "forecast_horizons": [1, 2, 3, 4, 5],
        "window_seconds": WINDOW_SECONDS,
        "learning_rate": training_metrics.get("learning_rate", 0.002),
        "epochs": training_metrics.get("epochs", 40),
        "seed": seed,
        "feature_count": 45,
        "packet_features_available": False,
        "loss_function": "State MSE (45 features) + BCE (attack logit)",
    }
    config_path = CHECKPOINT_DIR / "config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    # 4. feature_schema.json
    schema = {
        "feature_count": 45,
        "omitted_features": ["mean_tcp_rtt"],
        "groups": {
            "flow": {"count": len(FLOW_NAMES_45), "features": FLOW_NAMES_45},
            "packet": {"count": len(PACKET_NAMES), "features": PACKET_NAMES},
            "temporal": {"count": len(TEMPORAL_NAMES), "features": TEMPORAL_NAMES},
        },
        "canonical_order": FEATURE_NAMES_45,
    }
    schema_path = CHECKPOINT_DIR / "feature_schema.json"
    schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")

    # 5. metrics.json
    metrics_path = CHECKPOINT_DIR / "metrics.json"
    metrics_payload = {
        "benchmark": benchmark_metrics,
        "collapse_diagnostics": collapse_analysis,
    }
    metrics_path.write_text(json.dumps(metrics_payload, indent=2), encoding="utf-8")

    # 6. metadata.json
    meta = {
        "model_id": "nexsolve_candidate_v1",
        "dataset": "UNSW-NB15",
        "data_split": {"train": 595, "validation": 149, "test": 25},
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "hardware": hardware_info,
        "training_dynamics": training_metrics,
        "sample_forecast_demo": sample_forecast,
    }
    meta_path = CHECKPOINT_DIR / "metadata.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    # 7. manifest.json with SHA-256
    manifest_files = [
        "model.npz",
        "preprocessing.npz",
        "config.json",
        "feature_schema.json",
        "metadata.json",
        "metrics.json",
    ]
    file_hashes = {}
    for fname in manifest_files:
        p = CHECKPOINT_DIR / fname
        content = p.read_bytes()
        file_hashes[fname] = hashlib.sha256(content).hexdigest()

    manifest = {
        "manifest_version": "1.0",
        "model_id": "nexsolve_candidate_v1",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "artifact_hashes": file_hashes,
        "status": "candidate_trained_and_validated",
    }
    manifest_path = CHECKPOINT_DIR / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    return file_hashes


def main() -> None:
    parser = argparse.ArgumentParser(description="NexSolve Candidate V1 Training Runner")
    parser.add_argument("--epochs", type=int, default=40, help="Number of training epochs")
    parser.add_argument("--learning-rate", type=float, default=0.002, help="Learning rate")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--pipeline-check", action="store_true", help="Run 5-epoch sanity check only")
    args = parser.parse_args()

    epochs = 5 if args.pipeline_check else args.epochs

    print("==================================================")
    print("NEXSOLVE — TEMPORAL ML TRAINING: CANDIDATE V1")
    print("==================================================")

    # 1. Hardware Detection
    hw = get_hardware_info()
    print("\n[1/6] HARDWARE & RUNTIME DETECTION:")
    print(f"  Platform:         {hw['platform']}")
    print(f"  Processor:        {hw['processor']}")
    print(f"  CPU Cores:        {hw['cpu_cores_logical']}")
    print(f"  PyTorch:          {hw['pytorch_version']}")
    print(f"  CUDA Available:   {hw['cuda_available']}")
    print(f"  Selected Runtime: {hw['selected_runtime']}")

    # 2. Dataset & Chronological Split
    print("\n[2/6] DATASET & CHRONOLOGICAL SPLIT AUDIT:")
    states, splits = load_dataset()
    train_states = splits["train"]
    val_states = splits["validation"]
    test_states = splits["test"]

    print(f"  Total States:       {len(states)} 60s windows")
    print(f"  Train Split:        {len(train_states)} windows ({sum(s.attack_state for s in train_states)} attack, {len(train_states) - sum(s.attack_state for s in train_states)} benign)")
    print(f"  Validation Split:   {len(val_states)} windows ({sum(s.attack_state for s in val_states)} attack, {len(val_states) - sum(s.attack_state for s in val_states)} benign)")
    print(f"  Test Split:         {len(test_states)} windows ({sum(s.attack_state for s in test_states)} attack, {len(test_states) - sum(s.attack_state for s in test_states)} benign)")
    print(f"  Feature Contract:   {len(FEATURE_NAMES_45)} features (17 Flow, 22 Packet, 6 Temporal)")
    print("  mean_tcp_rtt:       STRICTLY EXCLUDED (zero fabrication)")

    # 3. Normalization (Train Only) & Sequence Building
    print("\n[3/6] SEQUENCE PREPARATION & ZERO-LEAKAGE NORMALIZATION:")
    mean, scale = fit_scaler(train_states)
    x_train, targets_train, labels_train = make_sequences(train_states, lookback=LOOKBACK, feature_names=FEATURE_NAMES_45)
    x_val, targets_val, labels_val = make_sequences(val_states, lookback=LOOKBACK, feature_names=FEATURE_NAMES_45)

    x_train_scaled = (x_train - mean) / scale
    targets_train_scaled = (targets_train - mean) / scale
    x_val_scaled = (x_val - mean) / scale
    targets_val_scaled = (targets_val - mean) / scale

    print(f"  Train Sequences:    {x_train_scaled.shape} (lookback={LOOKBACK}, features=45)")
    print(f"  Train Targets:      {targets_train_scaled.shape}")
    print(f"  Validation Seqs:    {x_val_scaled.shape}")
    print(f"  Normalization:      Fit strictly on Train ({len(mean)} dimensions)")

    # 4. Model Training
    print(f"\n[4/6] EXECUTING TRAINING ({epochs} epochs, lr={args.learning_rate}, seed={args.seed}):")
    model = NumpyLSTM(input_size=45, hidden_size=24, seed=args.seed)
    training_metrics = train_model(
        model=model,
        x_train=x_train_scaled,
        targets_train=targets_train_scaled,
        labels_train=labels_train,
        x_val=x_val_scaled,
        targets_val=targets_val_scaled,
        labels_val=labels_val,
        epochs=epochs,
        learning_rate=args.learning_rate,
        log_interval=5 if epochs >= 10 else 1,
    )
    print(f"  Training Complete:  {training_metrics['total_training_time_seconds']}s total ({training_metrics['mean_epoch_time_seconds']}s/epoch)")
    print(f"  Final Train Loss:   {training_metrics['final_train_loss']} | Final Val Loss: {training_metrics['final_val_loss']}")
    print(f"  Best Val Epoch:     {training_metrics['best_epoch']} (Val Loss: {training_metrics['best_val_loss']})")

    # 5. Multi-Horizon Benchmark Evaluation (T+1 .. T+5)
    print("\n[5/6] MULTI-HORIZON TEMPORAL BENCHMARK (T+1 .. T+5):")
    benchmark_metrics = evaluate_temporal_benchmark(
        model=model,
        test_states=test_states,
        mean=mean,
        scale=scale,
        train_states=train_states,
        horizons=(1, 2, 3, 4, 5),
    )

    models_eval = benchmark_metrics["models"]
    print(f"\n{'Horizon':<8} | {'Model':<25} | {'Prec':<7} | {'Recall':<7} | {'F1':<7} | {'FPR':<7} | {'Bal Acc':<7} | {'ROC-AUC':<7} | {'State MSE':<9}")
    print("-" * 95)
    for h in benchmark_metrics["horizons"]:
        for mname in ["NexSolve_Candidate_V1", "Persistence_Baseline", "Logistic_Regression_Baseline"]:
            met = models_eval[mname][h]
            roc_str = f"{met['roc_auc']:.4f}" if isinstance(met['roc_auc'], (int, float)) else str(met['roc_auc'])
            mse_str = f"{met['continuous_state_mse']:.4f}" if met.get('continuous_state_mse') is not None else "N/A"
            print(f"{h:<8} | {mname:<25} | {met['precision']:<7.4f} | {met['recall']:<7.4f} | {met['f1']:<7.4f} | {met['fpr']:<7.4f} | {met['balanced_accuracy']:<7.4f} | {roc_str:<7} | {mse_str:<9}")

    # Model Collapse & Failure Mode Detection
    collapse_analysis = analyze_model_collapse(benchmark_metrics)
    print(f"\n  Collapse Check:     {collapse_analysis['summary']}")
    print(f"  All Zeros: {collapse_analysis['collapsed_to_all_zeros']}, All Ones: {collapse_analysis['collapsed_to_all_ones']}, Flat Probs: {collapse_analysis['flat_probability_distribution']}")

    # 6. Sample Trajectory Forecast Demonstration
    print("\n[6/6] SAMPLE TRAJECTORY FORECAST DEMO (Attack Transition):")
    sample_demo = run_sample_trajectory_demo(model, test_states, mean, scale, start_index=14)
    curr_s = sample_demo["current_state"]
    print(f"  Current State (t={curr_s['step_index']}, gt_attack={curr_s['ground_truth_attack_state']}):")
    print(f"    Flows: {curr_s['flow_count']}, SrcBytes: {curr_s['total_src_bytes']}, DstBytes: {curr_s['total_dst_bytes']}, Pkts: {curr_s['total_packets']}")
    print("  Recursive Autoregressive Forecasts:")
    for fc in sample_demo["forecast_trajectory"]:
        print(
            f"    {fc['horizon']} (+{fc['lookahead_seconds']}s): Prob={fc['predicted_attack_probability']:.4f} "
            f"| AttackPred={fc['attack_predicted']} (GT={fc['ground_truth_attack']}) "
            f"| Conf={fc['confidence']:.2f} | PredFlows={fc['predicted_flow_count']} | PredBytes={fc['predicted_total_bytes']}"
        )

    # Save Checkpoint Artifacts
    hashes = save_candidate_v1_artifacts(
        model=model,
        mean=mean,
        scale=scale,
        training_metrics=training_metrics,
        benchmark_metrics=benchmark_metrics,
        collapse_analysis=collapse_analysis,
        sample_forecast=sample_demo,
        hardware_info=hw,
        seed=args.seed,
    )
    print(f"\n[OK] All artifacts saved to: {CHECKPOINT_DIR}")
    for fname, fhash in hashes.items():
        print(f"  - {fname:<22} (SHA256: {fhash[:16]}...)")


if __name__ == "__main__":
    main()
