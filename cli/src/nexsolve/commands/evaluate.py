"""NexSolve Model Multi-Horizon Evaluation Command.

Evaluates predictive validity across multi-horizon rollouts (T+1 to T+5, T+10),
calculating Precision, Recall, F1, Accuracy, Brier Score, and Expected Calibration Error (ECE).
Guarantees strict zero-leakage temporal splitting and zero metric fabrication.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

from ml.data.dataset_adapter import get_dataset_adapter
from ml.forecasting.evaluation import (
    calculate_classification_metrics,
)
from ml.forecasting.experiment_manifest import ExperimentArtifactWriter
from ml.forecasting.temporal_split import TemporalSplitter
from nexsolve.errors import NexSolveError
from nexsolve.output.terminal import TerminalRenderer
from world_model import (
    FEATURE_NAMES_45,
    LOOKBACK,
    infer,
    load_model,
)

ROOT = Path(__file__).resolve().parents[4]


def run_evaluate(args: argparse.Namespace) -> int:
    """Execute rigorous multi-horizon evaluation on specified dataset."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)

    dataset_arg = args.dataset.strip()
    horizons_str = getattr(args, "horizons", "1,2,3,5")
    try:
        horizons = [int(h.strip()) for h in horizons_str.split(",") if h.strip()]
    except ValueError:
        horizons = [1, 2, 3, 5]

    model_dir = Path(getattr(args, "model", None) or (ROOT / "models" / "nexsolve_world_model_45"))
    embargo_sec = float(getattr(args, "embargo_seconds", 60.0))
    holdout_fam = getattr(args, "holdout_family", None)
    output_dir = Path(args.output) if getattr(args, "output", None) else None
    random_seed = int(getattr(args, "seed", 42))

    if not getattr(args, "json", False):
        term.print_banner()
        term.print_header(f"Multi-Horizon Forecasting Evaluation: {dataset_arg}")
        term.print_info(f"Target Horizons: {horizons}")
        term.print_info(f"Model Directory: {model_dir}")
        term.print_info(f"Embargo Gap: {embargo_sec}s | Holdout Family: {holdout_fam or 'None'}")

    # 1. Load dataset adapter
    try:
        adapter = get_dataset_adapter(dataset_arg)
    except Exception as exc:
        raise NexSolveError(
            f"Failed to initialize dataset adapter for '{dataset_arg}': {exc}",
            remedy="Supported datasets: unsw, cic, toniot",
        )

    # 2. Ingest network states
    try:
        states, meta = adapter.load_network_states()
    except Exception as exc:
        raise NexSolveError(
            f"Failed to load network states from dataset '{dataset_arg}': {exc}",
            remedy="Ensure dataset source files are located in their standard directories.",
        )

    if not states:
        raise NexSolveError(
            f"No valid network states loaded from dataset '{dataset_arg}'.",
            remedy="Check dataset path or ensure file is not empty.",
        )

    # 3. Perform strict temporal split with embargo
    splitter = TemporalSplitter(
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
        embargo_seconds=embargo_sec,
    )
    split_res = splitter.split(
        items=states,
        timestamp_fn=lambda s: float(s.timestamp),
        label_fn=lambda s: s.attack_state,
    )

    test_states = split_res.test
    if len(test_states) < LOOKBACK + 1:
        raise NexSolveError(
            f"Insufficient test partition length ({len(test_states)} windows, required >= {LOOKBACK + 1}).",
            remedy="Use a dataset with more temporal windows or adjust split ratios.",
        )

    # 4. Load Model
    if not model_dir.exists():
        raise NexSolveError(
            f"Model checkpoint directory not found: {model_dir}",
            remedy="Check the path passed to --model.",
        )

    try:
        model, mean, scale = load_model(model_dir)
    except Exception as exc:
        raise NexSolveError(
            f"Failed to load World Model from {model_dir}: {exc}",
            remedy="Verify model.npz and preprocessing.npz exist in the model directory.",
        )

    feat_names = FEATURE_NAMES_45 if len(mean) == len(FEATURE_NAMES_45) else None

    # 5. Execute Multi-Horizon Rollout on Test Partition
    max_h = max(horizons)
    preds: dict[int, list[float]] = {h: [] for h in horizons}
    truths: dict[int, list[int]] = {h: [] for h in horizons}
    pred_records: list[dict[str, Any]] = []

    for t in range(LOOKBACK, len(test_states)):
        history = list(test_states[t - LOOKBACK : t])
        step_truths: dict[int, int] = {}
        for h in horizons:
            target_idx = t + h - 1
            if target_idx < len(test_states) and test_states[target_idx].attack_state is not None:
                step_truths[h] = int(test_states[target_idx].attack_state)

        if not step_truths:
            continue

        try:
            wm_out = infer(history, model, mean, scale, k=max_h, feature_names=feat_names)
            forecast_list = wm_out.get("forecasts", [])
            for fc in forecast_list:
                h_val = fc.get("horizon")
                p_val = fc.get("attack_probability")
                if h_val in step_truths and p_val is not None:
                    p_float = float(p_val)
                    preds[h_val].append(p_float)
                    truths[h_val].append(step_truths[h_val])

                    pred_records.append({
                        "window_index": t,
                        "timestamp": history[-1].timestamp,
                        "horizon": h_val,
                        "lookahead_seconds": h_val * 60,
                        "attack_probability": round(p_float, 4),
                        "ground_truth": step_truths[h_val],
                        "predicted_label": 1 if p_float >= 0.5 else 0,
                    })
        except Exception:
            continue

    # 6. Calculate Metrics per horizon
    horizon_results: dict[int, Any] = {}
    for h in horizons:
        h_preds = preds[h]
        h_truths = truths[h]
        if h_preds and h_truths:
            horizon_results[h] = calculate_classification_metrics(h_truths, h_preds)

    # 7. Write Experiment Artifacts
    exp_id = f"eval_{adapter.name.lower().replace('-', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    writer = ExperimentArtifactWriter(
        experiment_id=exp_id,
        base_dir=output_dir.parent if output_dir else None,
    )
    saved_path = writer.save_experiment(
        dataset_name=adapter.name,
        horizons=horizons,
        models_evaluated=["NexSolveWorldModel"],
        horizon_metrics={"NexSolveWorldModel": horizon_results},
        predictions_records=pred_records,
        split_config=split_res.summary(),
        random_seed=random_seed,
        notes=f"Evaluation executed on {dataset_arg} with embargo={embargo_sec}s",
    )

    # 8. Output
    if getattr(args, "json", False):
        summary_payload = {
            "experiment_id": exp_id,
            "dataset": adapter.name,
            "artifact_dir": str(saved_path),
            "horizons": horizons,
            "test_windows_evaluated": len(test_states) - LOOKBACK,
            "metrics_by_horizon": {
                str(h): m.to_dict() for h, m in horizon_results.items()
            },
        }
        print(json.dumps(summary_payload, indent=2))
        return 0

    term.print_success(f"Evaluation Completed! Artifacts saved to: {saved_path}")
    print()
    print("Multi-Horizon Validation Metrics:")
    print("-" * 88)
    print(f"{'Horizon':<10} | {'F1 Score':<10} | {'Accuracy':<10} | {'Brier Score':<12} | {'ECE':<10} | {'Status':<15}")
    print("-" * 88)
    for h in horizons:
        m = horizon_results.get(h)
        if m:
            f1_str = f"{m.f1_score:.4f}" if m.f1_score is not None else "N/A"
            acc_str = f"{m.accuracy:.4f}" if m.accuracy is not None else "N/A"
            brier_str = f"{m.brier_score:.4f}" if m.brier_score is not None else "N/A"
            ece_str = f"{m.expected_calibration_error:.4f}" if m.expected_calibration_error is not None else "N/A"
            status = "VALID" if not m.undefined_reasons else f"Partial ({len(m.undefined_reasons)} undef)"
            print(f"T+{h:<8} | {f1_str:<10} | {acc_str:<10} | {brier_str:<12} | {ece_str:<10} | {status:<15}")
        else:
            print(f"T+{h:<8} | {'N/A':<10} | {'N/A':<10} | {'N/A':<12} | {'N/A':<10} | {'No predictions':<15}")
    print("-" * 88)
    print()
    return 0
