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


def test_v2_chronological_split_synthetic() -> None:
    from ml.forecasting.temporal_split import (
        extract_contiguous_episodes,
        make_episode_sequences,
        v2_chronological_split,
    )

    # Construct 5 episodes with distinct timestamps and gaps
    # Episode 0: 20 states, mixed (10 benign, 10 attack)
    ep0 = [DummyItem(item_id=f"e0_{i}", timestamp=1000.0 + i * 60.0, label=1 if i >= 10 else 0) for i in range(20)]
    # Episode 1: 15 states, pure benign, gap of 300s
    t_start_ep1 = ep0[-1].timestamp + 300.0
    ep1 = [DummyItem(item_id=f"e1_{i}", timestamp=t_start_ep1 + i * 60.0, label=0) for i in range(15)]
    # Episode 2: 12 states, mixed with onset 0->1, gap of 500s
    t_start_ep2 = ep1[-1].timestamp + 500.0
    ep2 = [DummyItem(item_id=f"e2_{i}", timestamp=t_start_ep2 + i * 60.0, label=1 if i >= 6 else 0) for i in range(12)]
    # Episode 3: 25 states, attacks, gap of 400s
    t_start_ep3 = ep2[-1].timestamp + 400.0
    ep3 = [DummyItem(item_id=f"e3_{i}", timestamp=t_start_ep3 + i * 60.0, label=1) for i in range(25)]
    # Episode 4: 10 states, attacks, gap of 200s
    t_start_ep4 = ep3[-1].timestamp + 200.0
    ep4 = [DummyItem(item_id=f"e4_{i}", timestamp=t_start_ep4 + i * 60.0, label=1) for i in range(10)]

    all_items = ep0 + ep1 + ep2 + ep3 + ep4

    split = v2_chronological_split(all_items, window_seconds=60, timestamp_fn=lambda x: x.timestamp)

    # 1. Monotonicity: max(train) < min(val) < min(test)
    max_train_t = max(x.timestamp for x in split["train"])
    min_val_t = min(x.timestamp for x in split["validation"])
    max_val_t = max(x.timestamp for x in split["validation"])
    min_test_t = min(x.timestamp for x in split["test"])

    assert max_train_t < min_val_t
    assert max_val_t < min_test_t

    # 2. No leakage / zero overlap
    train_ids = {x.item_id for x in split["train"]}
    val_ids = {x.item_id for x in split["validation"]}
    test_ids = {x.item_id for x in split["test"]}
    assert train_ids.isdisjoint(val_ids)
    assert val_ids.isdisjoint(test_ids)
    assert train_ids.isdisjoint(test_ids)

    # 3. Attack presence across all three splits
    assert any(x.label == 1 for x in split["train"])
    assert any(x.label == 1 for x in split["validation"])
    assert any(x.label == 1 for x in split["test"])

    # 4. Validation contains onset transition (0 -> 1)
    val_labels = [x.label for x in split["validation"]]
    transitions = sum(1 for a, b in zip(val_labels[:-1], val_labels[1:]) if a == 0 and b == 1)
    assert transitions >= 1


def test_v2_make_episode_sequences_no_cross_boundary() -> None:
    from ml.forecasting.temporal_split import make_episode_sequences

    # Episode A: 10 items (t=0..9)
    # Episode B: 10 items (t=100..109, large gap)
    class StateStub:
        def __init__(self, t: float, val: float, atk: int):
            self.timestamp = t
            self.val = val
            self.attack_state = atk

        def encode(self, names=None):
            return np.array([self.val], dtype=np.float64)

    import numpy as np

    ep_a = [StateStub(float(i), float(i), 0) for i in range(10)]
    ep_b = [StateStub(100.0 + float(i), 100.0 + float(i), 1) for i in range(10)]

    x, targets, labels = make_episode_sequences([ep_a, ep_b], lookback=8)

    # Lookback=8: each 10-item episode produces 10-8 = 2 sequences
    # Total sequences: 4
    assert len(x) == 4
    assert len(targets) == 4
    assert len(labels) == 4

    # Sequences from ep_a have targets from ep_a (val < 10, label = 0)
    assert targets[0][0] == 8.0
    assert labels[0] == 0.0
    assert targets[1][0] == 9.0
    assert labels[1] == 0.0

    # Sequences from ep_b have targets from ep_b (val >= 108, label = 1)
    # The history MUST NOT contain items from ep_a!
    assert x[2][0][0] == 100.0  # first item of lookback in ep_b
    assert targets[2][0] == 108.0
    assert labels[2] == 1.0


def test_v2_chronological_split_real_dataset() -> None:
    import json
    from pathlib import Path
    from ml.forecasting.temporal_split import v2_chronological_split, make_episode_sequences

    cache_file = Path("data/processed/unsw_network_states.json")
    if not cache_file.exists():
        pytest.skip("Processed dataset not found on disk")

    raw_data = json.loads(cache_file.read_text(encoding="utf-8"))
    states = raw_data["states"]

    split = v2_chronological_split(states, window_seconds=60)

    # Train: 744 states (118 attacks, 626 benign)
    assert len(split["train"]) == 744
    train_attacks = sum(1 for s in split["train"] if s.get("attack_state") == 1)
    assert train_attacks == 118

    # Validation: 25 states (15 attacks, 10 benign)
    assert len(split["validation"]) == 25
    val_attacks = sum(1 for s in split["validation"] if s.get("attack_state") == 1)
    assert val_attacks == 15

    # Test: at least 562 states, all attacks
    assert len(split["test"]) >= 562
    test_attacks = sum(1 for s in split["test"] if s.get("attack_state") == 1)
    assert test_attacks == len(split["test"])

    # Strict chronological ordering
    max_train_t = max(s["timestamp"] for s in split["train"])
    min_val_t = min(s["timestamp"] for s in split["validation"])
    max_val_t = max(s["timestamp"] for s in split["validation"])
    min_test_t = min(s["timestamp"] for s in split["test"])

    assert max_train_t < min_val_t
    assert max_val_t < min_test_t

    # Validation onset transition exists
    val_labels = [s.get("attack_state", 0) for s in split["validation"]]
    onsets = sum(1 for a, b in zip(val_labels[:-1], val_labels[1:]) if a == 0 and b == 1)
    assert onsets >= 1

