"""Tests for Dataset Adapters and EvaluationSample Normalization."""
from __future__ import annotations

import hashlib
from pathlib import Path
import pytest

from ml.data.dataset_adapter import (
    CicIds2017DatasetAdapter,
    EvaluationSample,
    TonIotDatasetAdapter,
    UnswDatasetAdapter,
    get_dataset_adapter,
)

ROOT = Path(__file__).resolve().parents[1]


def test_get_dataset_adapter_factory() -> None:
    unsw = get_dataset_adapter("unsw")
    assert isinstance(unsw, UnswDatasetAdapter)
    assert unsw.name == "UNSW-NB15"

    cic = get_dataset_adapter("cic-ids2017")
    assert isinstance(cic, CicIds2017DatasetAdapter)
    assert cic.name == "CIC-IDS2017"

    ton = get_dataset_adapter("toniot")
    assert isinstance(ton, TonIotDatasetAdapter)
    assert ton.name == "TON-IoT"

    with pytest.raises(ValueError, match="Unknown dataset"):
        get_dataset_adapter("non_existent_dataset")


def test_unsw_adapter_load_and_validation() -> None:
    adapter = UnswDatasetAdapter()
    samples = adapter.load(max_samples=25)

    assert len(samples) == 25
    first = samples[0]
    assert isinstance(first, EvaluationSample)
    assert first.source_dataset == "UNSW-NB15"
    assert first.timestamp > 0
    assert first.label in (0, 1)
    assert isinstance(first.features, dict)
    assert "src_bytes" in first.features

    val = adapter.validate(samples)
    assert val["valid"] is True
    assert val["sample_count"] == 25
    assert val["is_chronologically_monotonic"] is True

    rep = adapter.quality_report(samples)
    assert rep["adapter"] == "UNSW-NB15"
    assert "feature_completeness" in rep


def test_cic_adapter_load_and_validation() -> None:
    adapter = CicIds2017DatasetAdapter()
    samples = adapter.load(max_samples=25)

    assert len(samples) == 25
    first = samples[0]
    assert isinstance(first, EvaluationSample)
    assert first.source_dataset == "CIC-IDS2017"
    assert first.label in (0, 1)
    assert first.attack_family is not None

    val = adapter.validate(samples)
    assert val["valid"] is True
    assert val["sample_count"] == 25


def test_toniot_adapter_load_and_validation() -> None:
    adapter = TonIotDatasetAdapter()
    samples = adapter.load(max_samples=25)

    assert len(samples) == 25
    first = samples[0]
    assert isinstance(first, EvaluationSample)
    assert first.source_dataset == "TON-IoT"
    assert first.label in (0, 1)

    val = adapter.validate(samples)
    assert val["valid"] is True


def test_dataset_adapters_non_mutating() -> None:
    """Guarantee that loading datasets does NOT alter the source files."""
    unsw_file = ROOT / "UNSW-NB15" / "raw" / "UNSW-NB15_1.csv"
    if unsw_file.exists():
        initial_hash = hashlib.sha256(unsw_file.read_bytes()[:10000]).hexdigest()

        adapter = UnswDatasetAdapter(default_path=unsw_file)
        _ = adapter.load(max_samples=10)

        after_hash = hashlib.sha256(unsw_file.read_bytes()[:10000]).hexdigest()
        assert initial_hash == after_hash, "Dataset source file was mutated by adapter!"
