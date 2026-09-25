"""NexSolve Standardized Forecasting Baseline Benchmark Command.

Executes input-parity benchmarking across:
1. Persistence Baseline
2. Logistic Regression Baseline
3. NexSolve World Model (LSTM)

Adheres strictly to zero-leakage temporal splitting, multi-horizon validity,
and zero metric fabrication.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from typing import Any

from nexsolve.errors import NexSolveError
from nexsolve.output.terminal import TerminalRenderer

ROOT = Path(__file__).resolve().parents[4]


def run_benchmark(args: argparse.Namespace) -> int:
    """Execute standardized baseline benchmark across models."""
    use_color = not getattr(args, "no_color", False)
    term = TerminalRenderer(use_color=use_color)

    try:
        from ml.data.dataset_adapter import get_dataset_adapter
        from ml.forecasting.benchmark import StandardizedBenchmarkHarness
        from ml.forecasting.experiment_manifest import ExperimentArtifactWriter
        from ml.forecasting.temporal_split import TemporalSplitter
    except ModuleNotFoundError as exc:
        raise NexSolveError(
            f"The 'benchmark' command requires the NexSolve research environment (missing: {exc.name}).",
            remedy="Run from within the NexSolve research repository or install the research/ML dependencies.",
        )

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
        term.print_header(f"Standardized Baseline Benchmarking: {dataset_arg}")
        term.print_info(f"Target Horizons: {horizons}")
        term.print_info(f"Models: PersistenceBaseline, LogisticRegressionBaseline, NexSolveWorldModel")
        term.print_info(f"Temporal Embargo: {embargo_sec}s | Holdout Family: {holdout_fam or 'None'}")

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
            remedy="Ensure dataset source files exist in their expected directories.",
        )

    if not states:
        raise NexSolveError(
            f"No valid network states loaded from dataset '{dataset_arg}'.",
            remedy="Check dataset path or ensure file is not empty.",
        )

    # 3. Perform temporal split
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

    if len(test_states) < 10:
        raise NexSolveError(
            f"Insufficient test partition length ({len(test_states)} windows).",
            remedy="Use a dataset with more temporal windows or adjust split ratios.",
        )

    # 4. Run Benchmark Harness
    harness = StandardizedBenchmarkHarness(
        horizons=horizons,
        world_model_dir=model_dir,
    )

    benchmark_res = harness.run_benchmark(
        test_states=test_states,
        dataset_name=adapter.name,
        held_out_states=split_res.holdout_test if holdout_fam else None,
        held_out_family=holdout_fam,
    )

    # 5. Save Experiment Artifacts
    exp_id = f"bm_{adapter.name.lower().replace('-', '_')}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    writer = ExperimentArtifactWriter(
        experiment_id=exp_id,
        base_dir=output_dir.parent if output_dir else None,
    )

    saved_path = writer.save_experiment(
        dataset_name=adapter.name,
        horizons=horizons,
        models_evaluated=benchmark_res.models_evaluated,
        horizon_metrics=benchmark_res.horizon_metrics,
        predictions_records=[],
        split_config=split_res.summary(),
        comparative_deltas=benchmark_res.comparative_deltas,
        holdout_results=benchmark_res.holdout_results,
        random_seed=random_seed,
        notes=f"Standardized baseline benchmark on {dataset_arg} with embargo={embargo_sec}s",
    )

    # 6. Render Output
    if getattr(args, "json", False):
        print(json.dumps(benchmark_res.to_dict(), indent=2))
        return 0

    term.print_success(f"Benchmark Completed! Artifacts saved to: {saved_path}")
    print()
    print("Forecasting Model Comparison Across Horizons:")
    print("=" * 95)
    print(f"{'Model':<28} | {'Horizon':<8} | {'F1 Score':<10} | {'Accuracy':<10} | {'Brier Score':<12} | {'ECE':<10}")
    print("-" * 95)

    for m_name in benchmark_res.models_evaluated:
        m_dict = benchmark_res.horizon_metrics.get(m_name, {})
        for h in horizons:
            m = m_dict.get(h)
            if m:
                f1_s = f"{m.f1_score:.4f}" if m.f1_score is not None else "N/A"
                acc_s = f"{m.accuracy:.4f}" if m.accuracy is not None else "N/A"
                brier_s = f"{m.brier_score:.4f}" if m.brier_score is not None else "N/A"
                ece_s = f"{m.expected_calibration_error:.4f}" if m.expected_calibration_error is not None else "N/A"
                print(f"{m_name:<28} | T+{h:<6} | {f1_s:<10} | {acc_s:<10} | {brier_s:<12} | {ece_s:<10}")
        print("-" * 95)

    if benchmark_res.comparative_deltas:
        print()
        print("Comparative Deltas (World Model vs Persistence Baseline):")
        print("-" * 75)
        print(f"{'Horizon':<10} | {'Delta Brier':<14} | {'Delta F1':<12} | {'Delta ECE':<12}")
        print("-" * 75)
        for h_str, d in benchmark_res.comparative_deltas.items():
            b_d = d.get("brier_delta")
            b_s = f"{b_d:+.4f}" if b_d is not None else "N/A"
            f_d = d.get("f1_delta")
            f_s = f"{f_d:+.4f}" if f_d is not None else "N/A"
            e_d = d.get("ece_delta")
            e_s = f"{e_d:+.4f}" if e_d is not None else "N/A"
            print(f"{h_str:<10} | {b_s:<14} | {f_s:<12} | {e_s:<12}")
        print("-" * 75)

    print()
    return 0
