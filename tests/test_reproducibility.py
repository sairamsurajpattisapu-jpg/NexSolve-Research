"""Tests for Experiment Manifest, Artifact Persistence, and Reproducibility."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import pytest

from ml.forecasting.evaluation import MetricResult
from ml.forecasting.experiment_manifest import ExperimentArtifactWriter


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_experiment_artifact_generation(tmp_path: Path) -> None:
    writer = ExperimentArtifactWriter(
        experiment_id="test_exp_001",
        base_dir=tmp_path,
    )

    mock_metrics = {
        "WorldModel": {
            1: MetricResult(10, 0.9, 0.8, 0.85, 0.88, 0.05, 0.1, 0.2, 0.04, [], {}),
            2: MetricResult(10, 0.85, 0.75, 0.80, 0.82, 0.08, 0.15, 0.25, 0.06, [], {}),
        }
    }

    mock_preds = [
        {"sample_id": "s1", "horizon": 1, "y_true": 1, "y_prob": 0.88},
        {"sample_id": "s2", "horizon": 1, "y_true": 0, "y_prob": 0.12},
    ]

    exp_dir = writer.save_experiment(
        dataset_name="TestDataset",
        horizons=[1, 2],
        models_evaluated=["WorldModel"],
        horizon_metrics=mock_metrics,
        predictions_records=mock_preds,
        split_config={"train": 70, "test": 30},
        comparative_deltas={"T+1": {"brier_delta": -0.02}},
        holdout_results={"status": "UNSUPPORTED", "reason": "No taxonomy"},
        random_seed=42,
        notes="Reproducibility test run",
    )

    assert exp_dir.exists()
    assert (exp_dir / "manifest.json").exists()
    assert (exp_dir / "metrics.json").exists()
    assert (exp_dir / "horizon_metrics.json").exists()
    assert (exp_dir / "predictions.jsonl").exists()
    assert (exp_dir / "provenance.json").exists()
    assert (exp_dir / "README.md").exists()

    # Verify manifest integrity
    manifest = json.loads((exp_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["experiment_id"] == "test_exp_001"
    assert manifest["dataset"] == "TestDataset"
    assert manifest["random_seed"] == 42
    assert manifest["total_predictions"] == 2

    # Verify cryptographic checksums recorded in manifest
    checksums = manifest["checksums"]
    for fname, recorded_hash in checksums.items():
        actual_hash = _sha256(exp_dir / fname)
        assert recorded_hash == actual_hash, f"Checksum mismatch for {fname}!"

    # Verify README contains sections
    readme = (exp_dir / "README.md").read_text(encoding="utf-8")
    assert "# NexSolve Forecasting Experiment: test_exp_001" in readme
    assert "Multi-Horizon Metric Degradation" in readme
    assert "Zero-Fabrication" in readme
