"""Tests for Window Leakage Detection and Temporal Validation."""
from __future__ import annotations

import pytest

from ml.forecasting.temporal_split import (
    TemporalLeakageError,
    validate_temporal_windows,
)


def test_validate_temporal_windows_valid() -> None:
    history = [100.0, 160.0, 220.0, 280.0]
    forecast = [340.0, 400.0, 460.0]

    # Should pass cleanly without error
    validate_temporal_windows(history, forecast, expected_step_seconds=60.0)


def test_validate_temporal_windows_future_leakage() -> None:
    # History extends into forecast horizon
    history = [100.0, 160.0, 220.0, 340.0]
    forecast = [280.0, 340.0, 400.0]

    with pytest.raises(TemporalLeakageError, match="Forward leakage detected"):
        validate_temporal_windows(history, forecast)


def test_validate_temporal_windows_equal_timestamp_leakage() -> None:
    # History boundary equals forecast boundary (not strictly preceding)
    history = [100.0, 160.0, 220.0]
    forecast = [220.0, 280.0, 340.0]

    with pytest.raises(TemporalLeakageError, match="Forward leakage detected"):
        validate_temporal_windows(history, forecast)


def test_validate_temporal_windows_non_monotonic_history() -> None:
    # History contains time reversal
    history = [100.0, 180.0, 160.0, 220.0]
    forecast = [280.0, 340.0]

    with pytest.raises(TemporalLeakageError, match="History timestamps not strictly monotonic"):
        validate_temporal_windows(history, forecast)


def test_validate_temporal_windows_non_monotonic_forecast() -> None:
    # Forecast contains time reversal
    history = [100.0, 160.0, 220.0]
    forecast = [280.0, 270.0, 340.0]

    with pytest.raises(TemporalLeakageError, match="Forecast timestamps not strictly monotonic"):
        validate_temporal_windows(history, forecast)


def test_validate_temporal_windows_spacing_mismatch() -> None:
    history = [100.0, 160.0, 220.0]
    forecast = [300.0, 360.0]  # First step is 80s, expected 60s

    with pytest.raises(TemporalLeakageError, match="Forecast target spacing mismatch"):
        validate_temporal_windows(history, forecast, expected_step_seconds=60.0)


def test_validate_temporal_windows_empty() -> None:
    with pytest.raises(TemporalLeakageError, match="Empty history and forecast"):
        validate_temporal_windows([], [])

    # When allow_empty=True, empty sequences do not raise
    validate_temporal_windows([], [], allow_empty=True)
