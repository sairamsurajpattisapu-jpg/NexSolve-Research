"""NexSolve Centralized Model Registry and Checkpoint Configuration Engine.

Manages authoritative model artifacts, canonical feature schemas, normalization
parameters, decision thresholds, and cryptographic manifest verification.
Eliminates scattered hardcoded paths and ensures zero-leakage runtime loading.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np

ROOT = Path(__file__).resolve().parents[1]

from world_model import FEATURE_NAMES_45, LOOKBACK, NumpyLSTM


class ModelRegistryError(Exception):
    """Base exception for model registry errors."""
    pass


class ModelArtifactNotFoundError(ModelRegistryError):
    """Raised when a required model artifact or directory is missing."""
    pass


class ModelArtifactCorruptedError(ModelRegistryError):
    """Raised when SHA-256 checksum does not match authoritative manifest."""
    pass


@dataclass(frozen=True)
class ModelSpec:
    """Immutable specification and metadata for a registered model checkpoint."""
    model_name: str
    model_id: str
    version: str
    feature_schema_version: str
    feature_count: int
    feature_names: tuple[str, ...]
    lookback: int
    horizons: tuple[int, ...]
    window_seconds: int
    checkpoint_dir: Path
    model_path: Path
    preprocessing_path: Path
    config_path: Path
    feature_schema_path: Path
    metadata_path: Path
    metrics_path: Path
    manifest_path: Path
    calibrated_threshold: float
    default_threshold: float
    hybrid_alpha: float
    training_dataset: str
    training_split: dict[str, Any]
    artifact_hashes: dict[str, str]
    created_at_utc: str
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "model_name": self.model_name,
            "model_id": self.model_id,
            "version": self.version,
            "feature_schema_version": self.feature_schema_version,
            "feature_count": self.feature_count,
            "feature_names": list(self.feature_names),
            "lookback": self.lookback,
            "horizons": list(self.horizons),
            "window_seconds": self.window_seconds,
            "checkpoint_dir": str(self.checkpoint_dir),
            "calibrated_threshold": self.calibrated_threshold,
            "default_threshold": self.default_threshold,
            "hybrid_alpha": self.hybrid_alpha,
            "training_dataset": self.training_dataset,
            "training_split": self.training_split,
            "artifact_hashes": self.artifact_hashes,
            "created_at_utc": self.created_at_utc,
            "status": self.status,
        }


class ModelRegistry:
    """Authoritative registry for NexSolve predictive models."""

    DEFAULT_MODEL_ID = "candidate_v2"

    _REGISTRY_PATHS: dict[str, Path] = {
        "final_world_model": ROOT / "models" / "final_world_model",
        "candidate_v2": ROOT / "models" / "candidate_v2",
        "candidate_v1": ROOT / "models" / "candidate_v1",
        "nexsolve_world_model_45": ROOT / "models" / "nexsolve_world_model_45",
    }

    _CACHE: dict[str, tuple[NumpyLSTM, np.ndarray, np.ndarray, ModelSpec]] = {}

    @classmethod
    def list_available_models(cls) -> list[str]:
        """List registered model identifiers available on disk."""
        available = []
        for model_id, p in cls._REGISTRY_PATHS.items():
            if p.exists() and (p / "model.npz").exists():
                available.append(model_id)
        return available

    @classmethod
    def get_model_spec(cls, model_id: str | None = None) -> ModelSpec:
        """Resolve and return authoritative ModelSpec for the requested model."""
        target_id = model_id or cls.DEFAULT_MODEL_ID
        if target_id not in cls._REGISTRY_PATHS:
            raise ModelArtifactNotFoundError(
                f"Unknown model_id '{target_id}'. Known models: {list(cls._REGISTRY_PATHS.keys())}"
            )

        cdir = cls._REGISTRY_PATHS[target_id]
        if not cdir.exists():
            raise ModelArtifactNotFoundError(f"Checkpoint directory does not exist: {cdir}")

        # Check required files
        req_files = [
            "model.npz",
            "preprocessing.npz",
            "config.json",
            "feature_schema.json",
            "metadata.json",
            "metrics.json",
            "manifest.json",
        ]
        for fname in req_files:
            if not (cdir / fname).exists():
                raise ModelArtifactNotFoundError(f"Required artifact '{fname}' missing from {cdir}")

        config = json.loads((cdir / "config.json").read_text(encoding="utf-8"))
        schema = json.loads((cdir / "feature_schema.json").read_text(encoding="utf-8"))
        meta = json.loads((cdir / "metadata.json").read_text(encoding="utf-8"))
        manifest = json.loads((cdir / "manifest.json").read_text(encoding="utf-8"))

        return ModelSpec(
            model_name=meta.get("model_name", "NexSolve Temporal World Model"),
            model_id=target_id,
            version=manifest.get("manifest_version", "2.0"),
            feature_schema_version=schema.get("schema_version", "45_canonical_v1"),
            feature_count=int(config.get("state_dim", schema.get("feature_count", 45))),
            feature_names=tuple(schema.get("canonical_order", FEATURE_NAMES_45)),
            lookback=int(config.get("lookback", LOOKBACK)),
            horizons=tuple(config.get("forecast_horizons", [1, 2, 3, 4, 5])),
            window_seconds=int(config.get("window_seconds", 60)),
            checkpoint_dir=cdir,
            model_path=cdir / "model.npz",
            preprocessing_path=cdir / "preprocessing.npz",
            config_path=cdir / "config.json",
            feature_schema_path=cdir / "feature_schema.json",
            metadata_path=cdir / "metadata.json",
            metrics_path=cdir / "metrics.json",
            manifest_path=cdir / "manifest.json",
            calibrated_threshold=float(config.get("calibrated_threshold", 0.30)),
            default_threshold=0.50,
            hybrid_alpha=float(config.get("hybrid_alpha", 0.25)),
            training_dataset=meta.get("dataset", "UNSW-NB15"),
            training_split=config.get("temporal_split", {}),
            artifact_hashes=manifest.get("artifact_hashes", {}),
            created_at_utc=meta.get("created_at_utc", ""),
            status=manifest.get("status", "unknown"),
        )

    @classmethod
    def verify_integrity(cls, model_id: str | None = None) -> tuple[bool, dict[str, str]]:
        """Verify SHA-256 checksums of all model artifacts against manifest.json.

        Raises:
            ModelArtifactCorruptedError: If any checksum fails to match.
        """
        spec = cls.get_model_spec(model_id)
        verified_hashes: dict[str, str] = {}

        for fname, expected_hash in spec.artifact_hashes.items():
            fpath = spec.checkpoint_dir / fname
            if not fpath.exists():
                raise ModelArtifactNotFoundError(f"Artifact {fname} specified in manifest not found at {fpath}")
            actual_hash = hashlib.sha256(fpath.read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise ModelArtifactCorruptedError(
                    f"Integrity check failed for {fname}: expected {expected_hash}, got {actual_hash}"
                )
            verified_hashes[fname] = actual_hash

        return True, verified_hashes

    @classmethod
    def load_model(
        cls,
        model_id: str | None = None,
        verify_checksums: bool = True,
        use_cache: bool = True,
    ) -> tuple[Any, np.ndarray, np.ndarray, ModelSpec]:
        """Load and cache the requested model, preprocessing parameters, and specification.

        Args:
            model_id: Model identifier (default: 'candidate_v2').
            verify_checksums: If True, validates SHA-256 checksums before loading.
            use_cache: If True, caches loaded model instance in memory.

        Returns:
            (model, mean, scale, model_spec)
        """
        target_id = model_id or cls.DEFAULT_MODEL_ID

        if use_cache and target_id in cls._CACHE:
            return cls._CACHE[target_id]

        if verify_checksums:
            cls.verify_integrity(target_id)

        spec = cls.get_model_spec(target_id)

        if target_id == "final_world_model":
            from ml.models.final_world_model import FinalNetworkWorldModel
            model = FinalNetworkWorldModel.load(spec.checkpoint_dir)
            mean = model.scaler_mean
            scale = model.scaler_scale
            loaded = (model, mean, scale, spec)
            if use_cache:
                cls._CACHE[target_id] = loaded
            return loaded

        # Load weights for NumPyLSTM models
        weights_data = np.load(spec.model_path)
        input_size = int(weights_data["input_size"])
        hidden_size = int(weights_data["hidden_size"])

        model = NumpyLSTM(input_size, hidden_size)
        model.W = weights_data["W"]
        model.b = weights_data["b"]
        model.Wy = weights_data["Wy"]
        model.by = weights_data["by"]

        # Load scaler
        prep_data = np.load(spec.preprocessing_path)
        mean = prep_data["mean"]
        scale = prep_data["scale"]

        if len(mean) != spec.feature_count or len(scale) != spec.feature_count:
            raise ModelArtifactCorruptedError(
                f"Scaler dimension mismatch: expected {spec.feature_count}, "
                f"got mean={len(mean)}, scale={len(scale)}"
            )

        loaded = (model, mean, scale, spec)
        if use_cache:
            cls._CACHE[target_id] = loaded

        return loaded
