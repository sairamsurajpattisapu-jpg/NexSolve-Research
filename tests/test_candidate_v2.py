"""Tests for Candidate V2 Model Artifacts, Inference, and Manifest Integrity."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import numpy as np
import pytest

from world_model import FEATURE_NAMES_45, LOOKBACK, NumpyLSTM

MODEL_DIR = Path("models/candidate_v2")


def test_candidate_v2_artifacts_exist() -> None:
    assert MODEL_DIR.exists(), "models/candidate_v2 directory must exist"
    required_files = [
        "model.npz",
        "preprocessing.npz",
        "config.json",
        "feature_schema.json",
        "metadata.json",
        "metrics.json",
        "manifest.json",
    ]
    for fname in required_files:
        p = MODEL_DIR / fname
        assert p.exists(), f"Missing required Candidate V2 artifact: {fname}"


def test_candidate_v2_manifest_checksums() -> None:
    manifest_path = MODEL_DIR / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest.get("status") == "candidate_v2_validated"

    hashes = manifest["artifact_hashes"]
    for fname, expected_hash in hashes.items():
        file_path = MODEL_DIR / fname
        assert file_path.exists(), f"Manifest lists {fname} which does not exist"
        actual_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
        assert actual_hash == expected_hash, f"SHA-256 mismatch for {fname}"


def test_candidate_v2_model_loading_and_inference() -> None:
    model_data = np.load(MODEL_DIR / "model.npz")
    prep_data = np.load(MODEL_DIR / "preprocessing.npz")

    assert int(model_data["input_size"]) == 45
    assert int(model_data["hidden_size"]) == 24

    mean = prep_data["mean"]
    scale = prep_data["scale"]
    assert len(mean) == 45
    assert len(scale) == 45

    model = NumpyLSTM(int(model_data["input_size"]), int(model_data["hidden_size"]))
    model.W = model_data["W"]
    model.b = model_data["b"]
    model.Wy = model_data["Wy"]
    model.by = model_data["by"]

    # Test forward pass with 8 lookback steps
    dummy_input = np.zeros((LOOKBACK, 45), dtype=np.float64)
    scaled_input = (dummy_input - mean) / scale
    pred_state, prob = model.predict(scaled_input)

    assert pred_state.shape == (45,)
    assert 0.0 <= prob <= 1.0
    assert not np.isnan(prob)
    assert not np.isnan(pred_state).any()


def test_candidate_v2_feature_schema() -> None:
    schema_path = MODEL_DIR / "feature_schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    assert schema["feature_count"] == 45
    assert "mean_tcp_rtt" in schema["omitted_features"]
    assert schema["canonical_order"] == FEATURE_NAMES_45
