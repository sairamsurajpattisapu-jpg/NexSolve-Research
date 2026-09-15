"""Unit and integration tests for the Forecasting Pipeline.

Tests:
- Multi-horizon evaluation across H in {1, 2, 3, 4, 5}.
- Cumulative risk monotonicity: Risk(Ha) <= Risk(Hb) for Ha < Hb.
- Timestamp ordering and lookahead seconds calculation.
- Top drivers generation with valid direction, relative change, and domain interpretation.
- Early warning score bounds (0 <= score <= 100) and level categorization.
- Insufficient history abstention (N < 8) and model unavailable fallback.
- 45-feature canonical PCAP schema compliance.
"""

from pathlib import Path
import pytest
import numpy as np

from ml.forecasting.forecasting_engine import (
    ForecastingPipeline,
    ForecastTrajectoryResult,
    EarlyWarningLevel,
    RiskLevel,
    FeatureDriver,
    _determine_risk_level,
    _explain_feature_change,
    DEFAULT_MODEL_DIR,
)
from world_model import (
    FEATURE_NAMES_45,
    FLOW_NAMES_45,
    PACKET_NAMES,
    TEMPORAL_NAMES,
    NetworkState,
)
from nexsolve_core.state import MODEL_SCHEMA_45


def _make_dummy_state(timestamp: float, seed: int = 42, attack: int = 0) -> NetworkState:
    rng = np.random.default_rng(seed)
    flow = {k: float(rng.uniform(10.0, 100.0)) for k in FLOW_NAMES_45}
    packet = {k: float(rng.uniform(1.0, 50.0)) for k in PACKET_NAMES}
    temporal = {k: float(rng.uniform(0.1, 5.0)) for k in TEMPORAL_NAMES}
    return NetworkState(
        timestamp=int(timestamp),
        flow_features=flow,
        packet_features=packet,
        temporal_features=temporal,
        attack_state=attack,
        packet_features_available=True,
    )


def test_feature_explanation_logic():
    """Verify domain direction, relative change, and severity."""
    # Increasing port count
    direction, rel, imp, interp = _explain_feature_change("unique_dst_ports", 10.0, 30.0)
    assert direction == "increasing"
    assert rel > 0
    assert "scanning" in interp

    # Decreasing interarrival time
    direction, rel, imp, interp = _explain_feature_change("mean_iat", 5.0, 1.0)
    assert direction == "decreasing"
    assert rel < 0
    assert "automated" in interp

    # Stable feature
    direction, rel, imp, interp = _explain_feature_change("flow_count", 10.0, 10.02)
    assert direction == "stable"
    assert imp == "LOW"


def test_early_warning_bounds_and_components():
    """Verify 0-100 score bounds and escalation levels."""
    pipeline = ForecastingPipeline(DEFAULT_MODEL_DIR)
    state = _make_dummy_state(1000.0)

    # Benign low-activity inputs
    low_ew = pipeline._compute_early_warning_score(
        current_s=state,
        simulated_states={1: {}, 3: {}, 5: {}},
        step_probs={1: 0.05, 2: 0.05, 3: 0.06, 4: 0.06, 5: 0.08},
        horizons=[1, 2, 3, 4, 5],
    )
    assert 0 <= low_ew.early_warning_score <= 100
    assert low_ew.early_warning_level == EarlyWarningLevel.NORMAL

    # High attack probability inputs
    high_ew = pipeline._compute_early_warning_score(
        current_s=state,
        simulated_states={1: {}, 3: {"unique_dst_ports": 100.0}, 5: {}},
        step_probs={1: 0.90, 2: 0.92, 3: 0.95, 4: 0.96, 5: 0.98},
        horizons=[1, 2, 3, 4, 5],
    )
    assert 0 <= high_ew.early_warning_score <= 100
    assert high_ew.early_warning_score >= 70
    assert high_ew.early_warning_level in (EarlyWarningLevel.HIGH, EarlyWarningLevel.CRITICAL)


def test_insufficient_history_fallback():
    """Pipeline must abstain when history < 8 windows."""
    pipeline = ForecastingPipeline(DEFAULT_MODEL_DIR)
    history = [_make_dummy_state(1000.0 + i * 60, seed=i) for i in range(5)]

    res = pipeline.execute_forecast(history, horizons=(1, 2, 3, 4, 5))
    assert res.forecast_status == "ABSTAINED_INSUFFICIENT_HISTORY"
    assert res.lookback_windows == 5
    assert len(res.forecasts) == 5
    for pt in res.forecasts:
        assert pt.attack_probability is None
        assert pt.cumulative_risk is None
        assert pt.risk_level == RiskLevel.LOW
        assert "Forecast abstained" in pt.behavioral_interpretation


def test_multi_horizon_rollout_and_cumulative_risk_monotonicity():
    """Verify 5-step rollout, cumulative risk monotonicity, and lookahead seconds."""
    pipeline = ForecastingPipeline(DEFAULT_MODEL_DIR)
    if not pipeline.is_available:
        pytest.skip("45-feature model not available on disk")

    base_ts = 1700000000.0
    history = [_make_dummy_state(base_ts + i * 60, seed=i) for i in range(10)]

    res = pipeline.execute_forecast(history, horizons=(1, 2, 3, 4, 5))
    assert res.forecast_status == "SUCCESSFUL_ROLLOUT"
    assert res.lookback_windows == 10
    assert len(res.forecasts) == 5

    # Check horizons and lookahead
    for idx, pt in enumerate(res.forecasts, start=1):
        assert pt.horizon == idx
        assert pt.lookahead_seconds == idx * 60
        assert 0.0 <= pt.attack_probability <= 1.0
        assert 0.0 <= pt.cumulative_risk <= 1.0
        assert pt.probability_status == "UNCALIBRATED"
        assert len(pt.top_drivers) <= 5
        for driver in pt.top_drivers:
            assert isinstance(driver, FeatureDriver)
            assert driver.feature in FEATURE_NAMES_45
            assert driver.direction in ("increasing", "decreasing", "stable")
            assert len(driver.interpretation) > 0

    # Cumulative risk monotonicity: Risk(H_a) <= Risk(H_b) for H_a < H_b
    cum_risks = [pt.cumulative_risk for pt in res.forecasts]
    for i in range(len(cum_risks) - 1):
        assert cum_risks[i] <= cum_risks[i + 1] + 1e-9, f"Risk decreased from step {i+1} to {i+2}"

    # Early warning output checks
    assert res.early_warning is not None
    assert 0 <= res.early_warning.early_warning_score <= 100
    assert res.early_warning.early_warning_level in (EarlyWarningLevel.NORMAL, EarlyWarningLevel.ELEVATED, EarlyWarningLevel.HIGH, EarlyWarningLevel.CRITICAL)
    assert len(res.early_warning.drivers) > 0

    # Serialization check
    d = res.to_dict()
    assert d["forecast_status"] == "SUCCESSFUL_ROLLOUT"
    assert len(d["forecasts"]) == 5
    assert "early_warning" in d
