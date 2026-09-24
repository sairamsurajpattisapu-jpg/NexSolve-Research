"""Tests for Temporal Splitter, Chronological Partitioning, and Embargo Logic."""
from __future__ import annotations

from dataclasses import dataclass
import pytest

from ml.forecasting.temporal_split import (
    SplitMetadata,
    TemporalLeakageError,
    TemporalSplitResult,
    TemporalSplitter,
)


@dataclass
class DummyItem:
    item_id: str
    timestamp: float
    label: int
    attack_family: str | None = None


def test_temporal_split_ratios_and_order() -> None:
    items = [
        DummyItem(item_id=f"item_{i}", timestamp=1000.0 + i * 60.0, label=i % 2)
        for i in range(100)
    ]

    splitter = TemporalSplitter(train_ratio=0.70, val_ratio=0.15, test_ratio=0.15)
    res = splitter.split(items, timestamp_fn=lambda x: x.timestamp, label_fn=lambda x: x.label)

    assert len(res.train) == 70
    assert len(res.val) == 15
    assert len(res.test) == 15
    assert res.embargo_purged_count == 0

    # Verify strictly monotonic separation
    assert max(x.timestamp for x in res.train) < min(x.timestamp for x in res.val)
    assert max(x.timestamp for x in res.val) < min(x.timestamp for x in res.test)

    # Check metadata
    assert res.train_meta is not None
    assert res.train_meta.sample_count == 70
    assert res.val_meta is not None
    assert res.val_meta.sample_count == 15
    assert res.test_meta is not None
    assert res.test_meta.sample_count == 15


def test_temporal_split_time_embargo() -> None:
    # 60s step between items
    items = [
        DummyItem(item_id=f"item_{i}", timestamp=1000.0 + i * 60.0, label=0)
        for i in range(100)
    ]

    # Embargo of 120s purges items within 120s of the previous split boundary
    splitter = TemporalSplitter(
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
        embargo_seconds=120.0,
    )
    res = splitter.split(items, timestamp_fn=lambda x: x.timestamp)

    assert len(res.train) == 70
    # Boundary between train and val: train[-1].timestamp = 1000 + 69*60 = 5140.
    # Val items with timestamp <= 5140 + 120 = 5260 must be purged (at least 2 items)
    assert res.embargo_purged_count > 0
    assert min(x.timestamp for x in res.val) - max(x.timestamp for x in res.train) > 120.0
    assert min(x.timestamp for x in res.test) - max(x.timestamp for x in res.val) > 120.0


def test_temporal_split_step_embargo() -> None:
    items = [
        DummyItem(item_id=f"item_{i}", timestamp=float(i), label=0)
        for i in range(100)
    ]

    splitter = TemporalSplitter(
        train_ratio=0.70,
        val_ratio=0.15,
        test_ratio=0.15,
        embargo_steps=3,
    )
    res = splitter.split(items, timestamp_fn=lambda x: x.timestamp)

    assert len(res.train) == 70
    assert len(res.val) == 12  # 15 - 3
    assert len(res.test) == 12  # 15 - 3
    assert res.embargo_purged_count == 6


def test_temporal_split_holdout_family() -> None:
    items = [
        DummyItem(item_id="b1", timestamp=1.0, label=0, attack_family="BENIGN"),
        DummyItem(item_id="b2", timestamp=2.0, label=0, attack_family="BENIGN"),
        DummyItem(item_id="a1", timestamp=3.0, label=1, attack_family="DDoS"),
        DummyItem(item_id="h1", timestamp=4.0, label=1, attack_family="HeldoutExfil"),
        DummyItem(item_id="b3", timestamp=5.0, label=0, attack_family="BENIGN"),
        DummyItem(item_id="h2", timestamp=6.0, label=1, attack_family="HeldoutExfil"),
        DummyItem(item_id="a2", timestamp=7.0, label=1, attack_family="DDoS"),
        DummyItem(item_id="b4", timestamp=8.0, label=0, attack_family="BENIGN"),
        DummyItem(item_id="b5", timestamp=9.0, label=0, attack_family="BENIGN"),
        DummyItem(item_id="b6", timestamp=10.0, label=0, attack_family="BENIGN"),
    ]

    splitter = TemporalSplitter(
        train_ratio=0.60,
        val_ratio=0.20,
        test_ratio=0.20,
        holdout_families=["HeldoutExfil"],
    )
    res = splitter.split(
        items,
        timestamp_fn=lambda x: x.timestamp,
        label_fn=lambda x: x.label,
        family_fn=lambda x: x.attack_family,
    )

    # Held-out items should be isolated into holdout_test
    assert len(res.holdout_test) == 2
    assert all(x.attack_family == "HeldoutExfil" for x in res.holdout_test)

    # Train, val, test must NEVER contain HeldoutExfil
    assert not any(x.attack_family == "HeldoutExfil" for x in res.train)
    assert not any(x.attack_family == "HeldoutExfil" for x in res.val)
    assert not any(x.attack_family == "HeldoutExfil" for x in res.test)


def test_invalid_split_ratios() -> None:
    with pytest.raises(ValueError, match="Split ratios must sum to 1.0"):
        TemporalSplitter(train_ratio=0.8, val_ratio=0.2, test_ratio=0.2)

    with pytest.raises(ValueError, match="strictly positive"):
        TemporalSplitter(train_ratio=-0.1, val_ratio=0.5, test_ratio=0.6)
