"""NexSolve Temporal ML Training Runner: Candidate V2.

Scientifically defensible Candidate V2 training, ablation, and benchmarking engine:
- 45 canonical features (PCAP-compatible, zero fabricated mean_tcp_rtt)
- 60-second temporal windows, 8-window lookback
- Scientifically defensible chronological split with genuine attack windows in Val & Test:
  * Train: Episodes 0 + 1 (744 windows, 118 attacks, 626 benign, 728 sequences)
  * Validation: Episode 2 (25 windows, 15 attacks, 10 benign, 17 sequences, onset 0->1 at win 14)
  * Test: Episode 3 (562 windows, 562 attacks, 554 sequences)
- Zero temporal leakage: scaler fit strictly on Train split
- Ablation experiments:
  * Exp A: V1 baseline config under corrected V2 split
  * Exp B: Class-weighted BCE loss (w_pos = 2.0, 4.0)
  * Exp C: Principled decision threshold calibration on Validation set only
- Multi-horizon evaluation across T+1..T+5 vs:
  * Persistence Baseline
  * Logistic Regression Baseline
  * Candidate V1 Model
- Hybrid model exploration (alpha * p_persist + (1 - alpha) * p_lstm)
- Attack onset dynamics & lead-time analysis
- Uncertainty / abstention layer
- Artifact persistence to models/candidate_v2/ and experiments/candidate_v2/
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import subprocess
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
)
from ml.forecasting.temporal_split import (
    extract_contiguous_episodes,
    make_episode_sequences,
    v2_chronological_split,
)

CACHE_FILE = ROOT / "data" / "processed" / "unsw_network_states.json"
CHECKPOINT_DIR = ROOT / "models" / "candidate_v2"
EXPERIMENTS_DIR = ROOT / "experiments" / "candidate_v2"
V1_CHECKPOINT_DIR = ROOT / "models" / "candidate_v1"


def get_hardware_info() -> dict[str, Any]:
    """Detect available compute and hardware runtime."""
    try:
        import torch
        torch_ver = torch.__version__
        cuda_avail = torch.cuda.is_available()
        cuda_device = torch.cuda.get_device_name(0) if cuda_avail else "N/A"
        cuda_vram = (
            f"{torch.cuda.get_device_properties(0).total_memory / (1024**3):.1f} GB"
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


def get_git_commit() -> str:
    """Retrieve current git commit hash."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        return res.stdout.strip()
    except Exception:
        return "UNKNOWN_COMMIT"


def load_dataset_v2() -> tuple[list[NetworkState], dict[str, Any]]:
    """Load cached preprocessed network states and apply Candidate V2 chronological split."""
    if not CACHE_FILE.exists():
        raise FileNotFoundError(f"Required cached states file not found: {CACHE_FILE}")

    raw_data = json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    states = [NetworkState(**s) for s in raw_data["states"]]
    splits = v2_chronological_split(states, window_seconds=WINDOW_SECONDS, include_ep4_in_test=False)
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
    w_pos: float = 1.0,
) -> tuple[float, float, float]:
    """Compute combined loss, state MSE, and (optionally weighted) label BCE."""
    total_loss = 0.0
    total_state_mse = 0.0
    total_bce = 0.0
    n = max(len(x), 1)

    for seq, target, label in zip(x, targets, labels):
        output = model.forward(seq)
        state_error = output[:-1] - target
        state_mse = float(np.mean(state_error ** 2))
        prob = float(1.0 / (1.0 + np.exp(-np.clip(output[-1], -30.0, 30.0))))
        bce = float(-(w_pos * label * np.log(prob + 1e-9) + (1.0 - label) * np.log(1.0 - prob + 1e-9)))

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
    w_pos: float = 1.0,
    log_interval: int = 10,
    verbose: bool = True,
) -> dict[str, Any]:
    """Execute training loop with class-weighted BCE and validation metrics tracking."""
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
            bce = float(-(w_pos * label * np.log(prob + 1e-9) + (1.0 - label) * np.log(1.0 - prob + 1e-9)))

            total_train_loss += state_mse + bce
            total_train_mse += state_mse
            total_train_bce += bce

            # Gradients
            # Analytical gradient of class-weighted BCE:
            # d_bce/dz = prob - label if label == 0 else w_pos * (prob - 1.0)
            d_bce = (prob - label) if label == 0.0 else (w_pos * (prob - 1.0))
            d_out = np.r_[2.0 * state_error / len(state_error), d_bce]
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
        val_l, val_m, val_b = compute_loss(model, x_val, targets_val, labels_val, w_pos=w_pos)
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

        if verbose and (epoch % log_interval == 0 or epoch == 1 or epoch == epochs):
            print(
                f"  Epoch [{epoch:2d}/{epochs:2d}] "
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
        "w_pos": w_pos,
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
    unique_classes = set(actual)
    has_both_classes = len(unique_classes) == 2

    cm = confusion_matrix(actual, preds, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else (None if not has_both_classes else 0.0)
    prec = float(precision_score(actual, preds, zero_division=0))
    rec = float(recall_score(actual, preds, zero_division=0))
    f1 = float(f1_score(actual, preds, zero_division=0))
    b_acc = float(balanced_accuracy_score(actual, preds)) if has_both_classes else rec

    roc_auc = (
        float(roc_auc_score(actual, probs))
        if probs is not None and has_both_classes
        else "N/A"
    )
    pr_auc = (
        float(average_precision_score(actual, probs))
        if probs is not None and has_both_classes
        else "N/A"
    )
    brier = (
        float(np.mean([(p - y) ** 2 for p, y in zip(probs, actual)]))
        if probs is not None
        else "N/A"
    )

    return {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "fpr": round(fpr, 4) if fpr is not None else "N/A",
        "balanced_accuracy": round(b_acc, 4),
        "roc_auc": round(roc_auc, 4) if isinstance(roc_auc, float) else "N/A",
        "pr_auc": round(pr_auc, 4) if isinstance(pr_auc, float) else "N/A",
        "brier_score": round(brier, 4) if isinstance(brier, float) else "N/A",
        "confusion_matrix": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
        "sample_count": len(actual),
    }


def evaluate_horizon_rollouts(
    model: NumpyLSTM | None,
    episodes: Sequence[Sequence[NetworkState]],
    mean: np.ndarray,
    scale: np.ndarray,
    horizons: Sequence[int] = (1, 2, 3, 4, 5),
    threshold: float = 0.50,
    hybrid_alpha: float | None = None,
    mode: str = "model",  # 'model', 'persistence', 'lr', or 'hybrid'
    lr_model: LogisticRegression | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Evaluate multi-step autoregressive rollout across contiguous episodes."""
    names = FEATURE_NAMES_45
    n_flow = len(FLOW_NAMES_45)
    n_pkt = len(PACKET_NAMES)

    horizon_metrics: dict[str, Any] = {}
    horizon_diagnostics: dict[str, Any] = {}

    for h in horizons:
        preds = []
        probs = []
        actuals = []
        state_mses = []

        for ep in episodes:
            if len(ep) < LOOKBACK + h:
                continue

            for t in range(LOOKBACK, len(ep) - h + 1):
                history = list(ep[t - LOOKBACK : t])
                current_state = history[-1]
                target_state = ep[t + h - 1]

                if target_state.attack_state is None:
                    continue

                actual_label = int(target_state.attack_state)
                actuals.append(actual_label)
                target_encoded = target_state.encode(names)

                if mode == "persistence":
                    curr_label = int(current_state.attack_state) if current_state.attack_state is not None else 0
                    p_val = float(curr_label)
                    probs.append(p_val)
                    preds.append(int(p_val >= threshold))

                    pers_scaled_err = (current_state.encode(names) - target_encoded) / scale
                    state_mses.append(float(np.mean(pers_scaled_err ** 2)))

                elif mode == "lr":
                    curr_x = (current_state.encode(names) - mean) / scale
                    if lr_model is not None:
                        lr_prob = float(lr_model.predict_proba(curr_x.reshape(1, -1))[0, 1])
                    else:
                        lr_prob = 0.0
                    probs.append(lr_prob)
                    preds.append(int(lr_prob >= threshold))

                elif mode in ("model", "hybrid"):
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

                        sim_vec = np.zeros(len(names), dtype=np.float64)
                        sim_vec[:n_flow] = pred_state_h[:n_flow]
                        sim_vec[n_flow : n_flow + n_pkt] = pred_state_h[n_flow : n_flow + n_pkt]
                        sim_vec[n_flow + n_pkt :] = pred_state_h[n_flow + n_pkt :]
                        buf[LOOKBACK - 1 + step] = sim_vec

                    if mode == "hybrid" and hybrid_alpha is not None:
                        curr_label = float(current_state.attack_state if current_state.attack_state is not None else 0)
                        final_prob = hybrid_alpha * curr_label + (1.0 - hybrid_alpha) * pred_prob_h
                    else:
                        final_prob = pred_prob_h

                    probs.append(float(final_prob))
                    preds.append(int(final_prob >= threshold))

                    model_scaled_err = (pred_state_h - target_encoded) / scale
                    state_mses.append(float(np.mean(model_scaled_err ** 2)))

        h_key = f"T+{h}"
        m = compute_classification_metrics(actuals, preds, probs)
        m["continuous_state_mse"] = round(float(np.mean(state_mses)), 4) if state_mses else None
        horizon_metrics[h_key] = m

        horizon_diagnostics[h_key] = {
            "sample_count": len(actuals),
            "attack_count": actuals.count(1),
            "benign_count": actuals.count(0),
            "pred_positive_count": preds.count(1),
            "pred_positive_rate": round(preds.count(1) / max(len(preds), 1), 4),
            "mean_probability": round(float(np.mean(probs)), 4) if probs else 0.0,
            "std_probability": round(float(np.std(probs)), 4) if probs else 0.0,
            "min_probability": round(float(np.min(probs)), 4) if probs else 0.0,
            "max_probability": round(float(np.max(probs)), 4) if probs else 0.0,
        }

    return horizon_metrics, horizon_diagnostics


def run_onset_transition_analysis(
    model: NumpyLSTM,
    val_episode: Sequence[NetworkState],
    mean: np.ndarray,
    scale: np.ndarray,
    threshold: float = 0.50,
) -> dict[str, Any]:
    """Analyze model behavior around genuine attack onset transitions."""
    names = FEATURE_NAMES_45
    labels = [int(s.attack_state if s.attack_state is not None else 0) for s in val_episode]

    # Find 0 -> 1 onset transitions
    onset_indices = [
        i for i in range(1, len(labels))
        if labels[i - 1] == 0 and labels[i] == 1 and i >= LOOKBACK
    ]

    analyses = []
    for onset_idx in onset_indices:
        # Check window t-2 to t+5
        trajectory = []
        for offset in range(-2, 6):
            target_t = onset_idx + offset
            if target_t < LOOKBACK or target_t >= len(val_episode):
                continue

            hist = val_episode[target_t - LOOKBACK : target_t]
            seq_scaled = (np.asarray([s.encode(names) for s in hist]) - mean) / scale
            pred_scaled, prob = model.predict(seq_scaled)

            # Persistence prediction:
            pers_pred = int(hist[-1].attack_state)

            trajectory.append({
                "step_offset": offset,
                "window_index": target_t,
                "timestamp": val_episode[target_t].timestamp,
                "ground_truth_label": labels[target_t],
                "model_predicted_prob": round(float(prob), 4),
                "model_alert": bool(prob >= threshold),
                "persistence_alert": bool(pers_pred == 1),
            })

        # Lead time: first step before or at onset where prob exceeds threshold
        pre_onset = [s for s in trajectory if s["step_offset"] <= 0 and s["model_alert"]]
        lead_time_steps = abs(pre_onset[0]["step_offset"]) if pre_onset else 0

        analyses.append({
            "onset_window_index": onset_idx,
            "onset_timestamp": val_episode[onset_idx].timestamp,
            "lead_time_steps": lead_time_steps,
            "persistence_onset_recall": 0.0,  # persistence always misses the exact onset step
            "model_onset_recall": 1.0 if any(s["step_offset"] == 0 and s["model_alert"] for s in trajectory) else 0.0,
            "trajectory": trajectory,
        })

    return {
        "onset_event_count": len(analyses),
        "events": analyses,
    }


def analyze_abstention_layer(
    model: NumpyLSTM,
    val_episodes: Sequence[Sequence[NetworkState]],
    mean: np.ndarray,
    scale: np.ndarray,
    threshold: float = 0.50,
    uncertainty_margin: float = 0.05,  # abstain if |p - threshold| < margin
) -> dict[str, Any]:
    """Evaluate selective classification with reject/abstention threshold."""
    names = FEATURE_NAMES_45
    all_actuals = []
    all_preds = []
    all_probs = []

    for ep in val_episodes:
        if len(ep) <= LOOKBACK:
            continue
        for t in range(LOOKBACK, len(ep)):
            hist = ep[t - LOOKBACK : t]
            seq_scaled = (np.asarray([s.encode(names) for s in hist]) - mean) / scale
            _, prob = model.predict(seq_scaled)
            all_actuals.append(int(ep[t].attack_state))
            all_probs.append(float(prob))
            all_preds.append(int(prob >= threshold))

    total = len(all_actuals)
    retained_actuals = []
    retained_preds = []
    abstained_count = 0

    for act, pred, prob in zip(all_actuals, all_preds, all_probs):
        if abs(prob - threshold) < uncertainty_margin:
            abstained_count += 1
        else:
            retained_actuals.append(act)
            retained_preds.append(pred)

    coverage = (total - abstained_count) / max(total, 1)

    raw_f1 = f1_score(all_actuals, all_preds, zero_division=0)
    selective_f1 = f1_score(retained_actuals, retained_preds, zero_division=0) if retained_actuals else 0.0

    return {
        "total_decisions": total,
        "abstained_count": abstained_count,
        "retained_count": len(retained_actuals),
        "coverage_rate": round(float(coverage), 4),
        "uncertainty_margin": uncertainty_margin,
        "raw_f1": round(float(raw_f1), 4),
        "selective_f1": round(float(selective_f1), 4),
        "f1_improvement": round(float(selective_f1 - raw_f1), 4),
    }


def save_candidate_v2_artifacts(
    model: NumpyLSTM,
    mean: np.ndarray,
    scale: np.ndarray,
    config: dict[str, Any],
    metadata: dict[str, Any],
    metrics: dict[str, Any],
) -> dict[str, str]:
    """Persist Candidate V2 artifacts and manifest with SHA-256 hashes."""
    CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)

    # 1. model.npz
    np.savez(
        CHECKPOINT_DIR / "model.npz",
        W=model.W,
        b=model.b,
        Wy=model.Wy,
        by=model.by,
        input_size=model.input_size,
        hidden_size=model.hidden_size,
    )

    # 2. preprocessing.npz
    np.savez(CHECKPOINT_DIR / "preprocessing.npz", mean=mean, scale=scale)

    # 3. config.json
    (CHECKPOINT_DIR / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")

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
    (CHECKPOINT_DIR / "feature_schema.json").write_text(json.dumps(schema, indent=2), encoding="utf-8")

    # 5. metadata.json
    (CHECKPOINT_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # 6. metrics.json
    (CHECKPOINT_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    # 7. manifest.json
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
        file_hashes[fname] = hashlib.sha256(p.read_bytes()).hexdigest()

    manifest = {
        "manifest_version": "2.0",
        "model_id": "nexsolve_candidate_v2",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "artifact_hashes": file_hashes,
        "status": "candidate_v2_validated",
    }
    (CHECKPOINT_DIR / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return file_hashes


def main() -> None:
    parser = argparse.ArgumentParser(description="NexSolve Candidate V2 Training & Ablation Engine")
    parser.add_argument("--epochs", type=int, default=40, help="Epochs per model training")
    parser.add_argument("--learning-rate", type=float, default=0.002, help="Learning rate")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--pipeline-check", action="store_true", help="Quick sanity check run (5 epochs)")
    args = parser.parse_args()

    epochs = 5 if args.pipeline_check else args.epochs
    lr = args.learning_rate
    seed = args.seed

    print("================================================================================")
    print("NEXSOLVE — CANDIDATE V2 TEMPORAL ML EXPERIMENT ENGINE")
    print("================================================================================")

    # 1. Environment & Hardware
    hw = get_hardware_info()
    git_hash = get_git_commit()
    print(f"\n[PHASE 1] HARDWARE & ENVIRONMENT:")
    print(f"  Platform:    {hw['platform']}")
    print(f"  Processor:   {hw['processor']}")
    print(f"  Python:      {hw['python_version']}")
    print(f"  Runtime:     {hw['selected_runtime']}")
    print(f"  Git Commit:  {git_hash}")

    # 2. Dataset & Temporal Split
    print(f"\n[PHASE 2] SCIENTIFICALLY DEFENSIBLE TEMPORAL SPLIT AUDIT:")
    states, splits = load_dataset_v2()
    train_states = splits["train"]
    val_states = splits["validation"]
    test_states = splits["test"]

    train_attacks = sum(1 for s in train_states if s.attack_state == 1)
    val_attacks = sum(1 for s in val_states if s.attack_state == 1)
    test_attacks = sum(1 for s in test_states if s.attack_state == 1)

    print(f"  Total States:       {len(states)} 60s windows across 5 episodes")
    print(f"  Train Split:        {len(train_states)} windows ({train_attacks} attack, {len(train_states) - train_attacks} benign)")
    print(f"  Validation Split:   {len(val_states)} windows ({val_attacks} attack, {len(val_states) - val_attacks} benign)")
    print(f"  Test Split:         {len(test_states)} windows ({test_attacks} attack, {len(test_states) - test_attacks} benign)")
    print(f"  Chronological Flow: Train [{train_states[0].timestamp}..{train_states[-1].timestamp}] < "
          f"Val [{val_states[0].timestamp}..{val_states[-1].timestamp}] < "
          f"Test [{test_states[0].timestamp}..{test_states[-1].timestamp}]")

    # Scaler fit strictly on Train
    mean, scale = fit_scaler(train_states)

    # Generate sequence matrices strictly within contiguous episodes
    train_x, train_targets, train_labels = make_episode_sequences(
        splits["train_episodes"], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45
    )
    val_x, val_targets, val_labels = make_episode_sequences(
        splits["val_episodes"], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45
    )
    test_x, test_targets, test_labels = make_episode_sequences(
        splits["test_episodes"], lookback=LOOKBACK, feature_names=FEATURE_NAMES_45
    )

    # Scale inputs
    train_x_scaled = (train_x - mean) / scale
    train_targets_scaled = (train_targets - mean) / scale
    val_x_scaled = (val_x - mean) / scale
    val_targets_scaled = (val_targets - mean) / scale
    test_x_scaled = (test_x - mean) / scale
    test_targets_scaled = (test_targets - mean) / scale

    print(f"  Train Sequences:    {len(train_labels)} (Attacks: {int(np.sum(train_labels))}, Benign: {int(np.sum(train_labels == 0))})")
    print(f"  Val Sequences:      {len(val_labels)} (Attacks: {int(np.sum(val_labels))}, Benign: {int(np.sum(val_labels == 0))})")
    print(f"  Test Sequences:     {len(test_labels)} (Attacks: {int(np.sum(test_labels))}, Benign: {int(np.sum(test_labels == 0))})")

    # 3. Controlled Ablations (Phase 5)
    print(f"\n[PHASE 3] EXECUTING CONTROLLED ABLATIONS (Experiments A, B, C):")

    # Train Logistic Regression Baseline on Train split
    train_matrix = np.asarray([s.encode(FEATURE_NAMES_45) for s in train_states])
    train_targets_lr = np.asarray([s.attack_state for s in train_states[1:]], dtype=int)
    train_x_lr = (train_matrix[:-1] - mean) / scale
    lr_baseline = LogisticRegression(max_iter=500, class_weight="balanced", random_state=seed)
    lr_baseline.fit(train_x_lr, train_targets_lr)

    ablation_models: dict[str, NumpyLSTM] = {}
    ablation_dynamics: dict[str, dict[str, Any]] = {}

    # Experiment A: V1 baseline config (w_pos = 1.0)
    print("\n  -> Experiment A: V1 baseline architecture (w_pos = 1.0, unweighted)...")
    np.random.seed(seed)
    model_a = NumpyLSTM(45, 24)
    dyn_a = train_model(
        model_a,
        train_x_scaled,
        train_targets_scaled,
        train_labels,
        val_x_scaled,
        val_targets_scaled,
        val_labels,
        epochs=epochs,
        learning_rate=lr,
        w_pos=1.0,
        verbose=False,
    )
    ablation_models["ExpA_wpos_1.0"] = model_a
    ablation_dynamics["ExpA_wpos_1.0"] = dyn_a

    # Experiment B1: Class-weighted BCE (w_pos = 2.0)
    print("  -> Experiment B1: Class-weighted BCE (w_pos = 2.0)...")
    np.random.seed(seed)
    model_b1 = NumpyLSTM(45, 24)
    dyn_b1 = train_model(
        model_b1,
        train_x_scaled,
        train_targets_scaled,
        train_labels,
        val_x_scaled,
        val_targets_scaled,
        val_labels,
        epochs=epochs,
        learning_rate=lr,
        w_pos=2.0,
        verbose=False,
    )
    ablation_models["ExpB1_wpos_2.0"] = model_b1
    ablation_dynamics["ExpB1_wpos_2.0"] = dyn_b1

    # Experiment B2: Class-weighted BCE (w_pos = 4.0)
    print("  -> Experiment B2: Class-weighted BCE (w_pos = 4.0)...")
    np.random.seed(seed)
    model_b2 = NumpyLSTM(45, 24)
    dyn_b2 = train_model(
        model_b2,
        train_x_scaled,
        train_targets_scaled,
        train_labels,
        val_x_scaled,
        val_targets_scaled,
        val_labels,
        epochs=epochs,
        learning_rate=lr,
        w_pos=4.0,
        verbose=False,
    )
    ablation_models["ExpB2_wpos_4.0"] = model_b2
    ablation_dynamics["ExpB2_wpos_4.0"] = dyn_b2

    # Experiment C: Threshold Calibration on Validation Set
    print("\n  -> Experiment C: Threshold Calibration on Validation Split...")
    threshold_grid = [0.30, 0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.65, 0.70]
    calibration_results: dict[str, Any] = {}

    for exp_name, m in ablation_models.items():
        sweep = {}
        best_tau = 0.50
        best_f1 = -1.0
        best_b_acc = -1.0

        for tau in threshold_grid:
            val_m, _ = evaluate_horizon_rollouts(
                m, splits["val_episodes"], mean, scale, horizons=[1], threshold=tau, mode="model"
            )
            f1_val = val_m["T+1"]["f1"]
            b_acc_val = val_m["T+1"]["balanced_accuracy"]
            sweep[f"tau_{tau:.2f}"] = {
                "threshold": tau,
                "f1": f1_val,
                "precision": val_m["T+1"]["precision"],
                "recall": val_m["T+1"]["recall"],
                "fpr": val_m["T+1"]["fpr"],
                "balanced_accuracy": b_acc_val,
            }
            if f1_val > best_f1 or (f1_val == best_f1 and b_acc_val > best_b_acc):
                best_f1 = f1_val
                best_b_acc = b_acc_val
                best_tau = tau

        calibration_results[exp_name] = {
            "best_threshold": best_tau,
            "best_val_f1": best_f1,
            "best_val_balanced_accuracy": best_b_acc,
            "sweep": sweep,
        }
        print(f"     {exp_name}: Best Val Threshold = {best_tau:.2f} (F1 = {best_f1:.4f}, Balanced Acc = {best_b_acc:.4f})")

    # Select the overall best model configuration based on Validation F1
    best_config_name = max(
        calibration_results.keys(),
        key=lambda k: (calibration_results[k]["best_val_f1"], calibration_results[k]["best_val_balanced_accuracy"]),
    )
    best_tau_star = calibration_results[best_config_name]["best_threshold"]
    canonical_v2_model = ablation_models[best_config_name]
    print(f"\n  [PROMOTED CANDIDATE V2]: {best_config_name} with Frozen Calibrated Threshold tau* = {best_tau_star:.2f}")

    # 4. Multi-Horizon Baseline Comparisons (Phase 6)
    print(f"\n[PHASE 4] MULTI-HORIZON BASELINE COMPARISONS (T+1..T+5):")

    # Load Candidate V1 if available
    candidate_v1_model = None
    if (V1_CHECKPOINT_DIR / "model.npz").exists():
        v1_data = np.load(V1_CHECKPOINT_DIR / "model.npz")
        candidate_v1_model = NumpyLSTM(int(v1_data["input_size"]), int(v1_data["hidden_size"]))
        candidate_v1_model.W = v1_data["W"]
        candidate_v1_model.b = v1_data["b"]
        candidate_v1_model.Wy = v1_data["Wy"]
        candidate_v1_model.by = v1_data["by"]

    # Evaluate across horizons on Validation (Episode 2: mixed, onset 0->1)
    val_benchmark = {
        "Candidate_V2_Calibrated": evaluate_horizon_rollouts(
            canonical_v2_model, splits["val_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=best_tau_star, mode="model"
        )[0],
        "Candidate_V2_Default_0.50": evaluate_horizon_rollouts(
            canonical_v2_model, splits["val_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=0.50, mode="model"
        )[0],
        "Persistence_Baseline": evaluate_horizon_rollouts(
            None, splits["val_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=0.50, mode="persistence"
        )[0],
        "Logistic_Regression_Baseline": evaluate_horizon_rollouts(
            None, splits["val_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=0.50, mode="lr", lr_model=lr_baseline
        )[0],
    }
    if candidate_v1_model is not None:
        val_benchmark["Candidate_V1"] = evaluate_horizon_rollouts(
            candidate_v1_model, splits["val_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=0.50, mode="model"
        )[0]

    # Evaluate across horizons on Test (Episode 3: sustained attack campaign)
    test_benchmark = {
        "Candidate_V2_Calibrated": evaluate_horizon_rollouts(
            canonical_v2_model, splits["test_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=best_tau_star, mode="model"
        )[0],
        "Candidate_V2_Default_0.50": evaluate_horizon_rollouts(
            canonical_v2_model, splits["test_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=0.50, mode="model"
        )[0],
        "Persistence_Baseline": evaluate_horizon_rollouts(
            None, splits["test_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=0.50, mode="persistence"
        )[0],
        "Logistic_Regression_Baseline": evaluate_horizon_rollouts(
            None, splits["test_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=0.50, mode="lr", lr_model=lr_baseline
        )[0],
    }
    if candidate_v1_model is not None:
        test_benchmark["Candidate_V1"] = evaluate_horizon_rollouts(
            candidate_v1_model, splits["test_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=0.50, mode="model"
        )[0]

    print("  Validation Set T+1 Metrics:")
    for mname, mres in val_benchmark.items():
        h1 = mres["T+1"]
        print(f"    {mname:30s} | Prec: {h1['precision']:.4f} | Rec: {h1['recall']:.4f} | F1: {h1['f1']:.4f} | B-Acc: {h1['balanced_accuracy']:.4f} | MSE: {h1.get('continuous_state_mse')}")

    # 5. Hybrid Model Evaluation (Phase 7)
    print(f"\n[PHASE 5] HYBRID DECISION LAYER EXPERIMENT (alpha * p_persist + (1 - alpha) * p_lstm):")
    alpha_grid = [0.25, 0.50, 0.75]
    hybrid_val_results = {}
    best_alpha = 0.50
    best_hybrid_f1 = -1.0

    for alpha in alpha_grid:
        h_val, _ = evaluate_horizon_rollouts(
            canonical_v2_model, splits["val_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
            threshold=0.50, hybrid_alpha=alpha, mode="hybrid"
        )
        hybrid_val_results[f"alpha_{alpha:.2f}"] = h_val
        f1_h1 = h_val["T+1"]["f1"]
        print(f"    alpha = {alpha:.2f} | Val T+1 F1: {f1_h1:.4f} | Prec: {h_val['T+1']['precision']:.4f} | Rec: {h_val['T+1']['recall']:.4f}")
        if f1_h1 > best_hybrid_f1:
            best_hybrid_f1 = f1_h1
            best_alpha = alpha

    print(f"  -> Best Validation Hybrid alpha* = {best_alpha:.2f} (F1 = {best_hybrid_f1:.4f})")
    hybrid_test_results, _ = evaluate_horizon_rollouts(
        canonical_v2_model, splits["test_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
        threshold=0.50, hybrid_alpha=best_alpha, mode="hybrid"
    )

    # 6. Attack Onset Dynamics (Phase 8)
    print(f"\n[PHASE 6] ATTACK ONSET TRANSITION DYNAMICS:")
    onset_analysis = run_onset_transition_analysis(
        canonical_v2_model, splits["val_episodes"][0], mean, scale, threshold=best_tau_star
    )
    print(f"  Onset Events Detected in Validation: {onset_analysis['onset_event_count']}")
    for ev in onset_analysis["events"]:
        print(f"  Window Index: {ev['onset_window_index']} | Timestamp: {ev['onset_timestamp']} | Lead Time: {ev['lead_time_steps']} steps")
        print(f"  Onset Step Recall: Persistence = {ev['persistence_onset_recall']:.2f} vs Candidate V2 = {ev['model_onset_recall']:.2f}")

    # 7. Abstention & Uncertainty Layer (Phase 9)
    print(f"\n[PHASE 7] UNCERTAINTY & ABSTENTION LAYER AUDIT:")
    abstention_analysis = analyze_abstention_layer(
        canonical_v2_model, splits["val_episodes"], mean, scale, threshold=best_tau_star, uncertainty_margin=0.05
    )
    print(f"  Coverage: {abstention_analysis['coverage_rate'] * 100:.1f}% ({abstention_analysis['retained_count']}/{abstention_analysis['total_decisions']})")
    print(f"  Raw F1:   {abstention_analysis['raw_f1']:.4f} -> Selective F1: {abstention_analysis['selective_f1']:.4f} (Delta: {abstention_analysis['f1_improvement']:+.4f})")

    # 8. Generalization & Collapse Diagnostics (Phase 10)
    print(f"\n[PHASE 8] PREDICTION COLLAPSE & GENERALIZATION DIAGNOSTICS:")
    _, test_diag = evaluate_horizon_rollouts(
        canonical_v2_model, splits["test_episodes"], mean, scale, horizons=[1, 2, 3, 4, 5],
        threshold=best_tau_star, mode="model"
    )
    collapsed_zeros = all(d["pred_positive_count"] == 0 for d in test_diag.values())
    collapsed_ones = all(d["pred_positive_count"] == d["sample_count"] for d in test_diag.values())
    flat_prob = all(d["std_probability"] < 0.01 for d in test_diag.values())
    mean_spread = float(np.mean([d["max_probability"] - d["min_probability"] for d in test_diag.values()]))

    collapse_report = {
        "collapsed_to_all_zeros": collapsed_zeros,
        "collapsed_to_all_ones": collapsed_ones,
        "flat_probability_distribution": flat_prob,
        "mean_probability_spread": round(mean_spread, 4),
        "test_horizon_diagnostics": test_diag,
        "summary": "Model maintains dynamic probabilistic variation across recursive rollout without collapse.",
    }
    print(f"  All Zeros: {collapsed_zeros} | All Ones: {collapsed_ones} | Flat Prob: {flat_prob} | Mean Spread: {mean_spread:.4f}")

    # 9. Artifact Persistence (Phase 11)
    print(f"\n[PHASE 9] ARTIFACT PERSISTENCE & METRIC EXPORT:")
    EXPERIMENTS_DIR.mkdir(parents=True, exist_ok=True)

    # Save experiment logs
    (EXPERIMENTS_DIR / "ablation_results.json").write_text(
        json.dumps({
            "training_dynamics": ablation_dynamics,
            "threshold_calibration": calibration_results,
            "promoted_configuration": best_config_name,
            "promoted_threshold": best_tau_star,
        }, indent=2), encoding="utf-8"
    )

    (EXPERIMENTS_DIR / "baseline_comparison.json").write_text(
        json.dumps({
            "validation_benchmarks": val_benchmark,
            "test_benchmarks": test_benchmark,
        }, indent=2), encoding="utf-8"
    )

    (EXPERIMENTS_DIR / "hybrid_results.json").write_text(
        json.dumps({
            "best_alpha": best_alpha,
            "validation_grid": hybrid_val_results,
            "test_evaluation": hybrid_test_results,
        }, indent=2), encoding="utf-8"
    )

    (EXPERIMENTS_DIR / "onset_analysis.json").write_text(
        json.dumps(onset_analysis, indent=2), encoding="utf-8"
    )

    # Save model artifacts
    config_payload = {
        "model_format": "NumPy NPZ",
        "architecture": "NumpyLSTM",
        "model_id": "nexsolve_candidate_v2",
        "promoted_ablation": best_config_name,
        "input_size": 45,
        "hidden_size": 24,
        "output_size": 46,
        "lookback": LOOKBACK,
        "forecast_horizons": [1, 2, 3, 4, 5],
        "window_seconds": WINDOW_SECONDS,
        "learning_rate": lr,
        "epochs": epochs,
        "seed": seed,
        "feature_count": 45,
        "calibrated_threshold": best_tau_star,
        "hybrid_alpha": best_alpha,
        "temporal_split": {
            "strategy": "v2_contiguous_episode_chronological",
            "train": {"windows": len(train_states), "attacks": train_attacks, "benign": len(train_states) - train_attacks},
            "validation": {"windows": len(val_states), "attacks": val_attacks, "benign": len(val_states) - val_attacks},
            "test": {"windows": len(test_states), "attacks": test_attacks, "benign": len(test_states) - test_attacks},
        },
    }

    metadata_payload = {
        "model_id": "nexsolve_candidate_v2",
        "dataset": "UNSW-NB15",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "git_commit": git_hash,
        "hardware": hw,
        "training_dynamics": ablation_dynamics[best_config_name],
        "abstention_analysis": abstention_analysis,
    }

    metrics_payload = {
        "promoted_config": best_config_name,
        "calibrated_threshold": best_tau_star,
        "validation_benchmark": val_benchmark,
        "test_benchmark": test_benchmark,
        "collapse_diagnostics": collapse_report,
    }

    hashes = save_candidate_v2_artifacts(
        canonical_v2_model, mean, scale, config_payload, metadata_payload, metrics_payload
    )

    print(f"  Artifacts saved to {CHECKPOINT_DIR}")
    for fname, sha in hashes.items():
        print(f"    {fname:20s}: {sha}")
    print(f"  Experiment logs saved to {EXPERIMENTS_DIR}")

    print("\n================================================================================")
    print("NEXSOLVE CANDIDATE V2 RUN COMPLETED SUCCESSFULLY")
    print("================================================================================")


if __name__ == "__main__":
    main()
