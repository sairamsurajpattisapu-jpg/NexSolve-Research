"""Reusable chronological multi-horizon evaluation harness."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

from .metrics import binary_metrics


def validate_temporal_splits(train: Sequence[Any], validation: Sequence[Any], test: Sequence[Any], timestamp_getter: Callable[[Any], int] = lambda item: item.timestamp) -> None:
    """Reject unsorted, overlapping, or cross-boundary temporal splits."""
    for name, values in (("train", train), ("validation", validation), ("test", test)):
        timestamps = [timestamp_getter(item) for item in values]
        if timestamps != sorted(timestamps):
            raise ValueError(f"{name} is not chronological")
        if len(timestamps) != len(set(timestamps)):
            raise ValueError(f"{name} contains duplicate windows")
    if train and validation and timestamp_getter(train[-1]) >= timestamp_getter(validation[0]):
        raise ValueError("train and validation windows overlap")
    if validation and test and timestamp_getter(validation[-1]) >= timestamp_getter(test[0]):
        raise ValueError("validation and test windows overlap")


def evaluate_horizons(targets: Sequence[int], predictions_by_horizon: dict[int, Sequence[float | None]], threshold: float = 0.5) -> dict[str, Any]:
    """Score each horizon against its own future target sequence."""
    expected = set(range(1, 6))
    if set(predictions_by_horizon) != expected:
        raise ValueError("predictions_by_horizon must contain horizons 1 through 5")
    return {f"T+{horizon}": binary_metrics(targets, predictions_by_horizon[horizon], threshold) for horizon in range(1, 6)}


def evaluate_model_plugin(targets_by_horizon: dict[int, Sequence[int]], predictor: Callable[[int], Sequence[float | None]], threshold: float = 0.5) -> dict[str, Any]:
    """Evaluate a future model plugin without prescribing its architecture."""
    predictions = {horizon: predictor(horizon) for horizon in range(1, 6)}
    return {f"T+{horizon}": binary_metrics(targets_by_horizon[horizon], predictions[horizon], threshold) for horizon in range(1, 6)}