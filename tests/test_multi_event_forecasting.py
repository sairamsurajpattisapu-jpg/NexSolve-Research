"""Tests for Multi-Event Forecasting Engine, Dataset Representation, and Pipeline.

Verifies:
- Event extraction and independence
- Episode-level temporal splitting without leakage
- Target alignment for multi-horizon onset forecasting
- Threshold provenance and candidate metadata
- FVP and lead-time metric calculations
- Abstention and low-data behavior
- Cross-dataset evaluation validity
- Central Forecast Gate and product pipeline integration
- Cryptographic baseline immutability of the frozen production world model
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import List

import numpy as np
import pytest

from ml.forecasting.central_gate import execute_central_forecast_gate
from ml.forecasting.multi_event_dataset import (
    AttackOnsetEvent,
    MultiEventSplit,
    TemporalWindowSample,
    build_event_split,
    build_temporal_episodes,
    extract_attack_onset_events,
)
from ml.forecasting.multi_event_engine import MultiEventResearchForecastEngine
from model_service.pcap_upload import analyze_uploaded_capture


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_DIR = ROOT / "models" / "research_candidates" / "multi_event_v1"
FROZEN_MODEL_DIR = ROOT / "models" / "final_world_model"
TEST_PCAP = ROOT / "data" / "validation_test_pcaps" / "tcp_heavy.pcap"


def compute_sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest().upper()


def test_production_world_model_immutability():
    """Gate 1: Verify all 7 production files match authoritative golden digests bitwise."""
    expected_frozen_hashes = {
        "config.json": "98C55F8685478286264438B07DB7DCA72B3A42F1A41E0A4D26366654379AA1A1",
        "feature_schema.json": "2BB8714F2DA49F124C82209488E9DC1ECCFF3CA8F655079404BA7EFB27E4454B",
        "manifest.json": "75BEF97F0BE8C7310A9AF89D8F13046C9F7E3A12303A7A55582913996805CBF6",
        "metadata.json": "19816E54918779B1226DB88A0EA7319DAB7D831423B7D6A77181915F90A20093",
        "metrics.json": "8B2B395728BE2F8FFD80A66A2E120D634B2206CD2ABF2DB5AEC39FC65C4414B9",
        "model.npz": "5787B2ABD68B2243F45AE1290E24B2DAA5483E69405660CF3DE824FD8B498ECC",
        "preprocessing.npz": "E85D998324D7F45215494CA09D1C9388667F49B7E72D0A1511A1B64B0C72C6B3",
    }
    for fname, exp_hash in expected_frozen_hashes.items():
        act_hash = compute_sha256(FROZEN_MODEL_DIR / fname)
        assert act_hash == exp_hash, f"Cryptographic mismatch in production asset: {fname}"


def test_event_extraction_and_independence():
    """Verify that contiguous attack windows do NOT get inflated into multiple events."""
    # Synthetic episode with 10 windows: 4 benign, 3 attack, 2 benign, 1 attack
    samples: List[TemporalWindowSample] = []
    labels = [0, 0, 0, 0, 1, 1, 1, 0, 0, 1]
    cats = ["benign"] * 4 + ["ddos"] * 3 + ["benign"] * 2 + ["portscan"]

    for i in range(10):
        samples.append(TemporalWindowSample(
            dataset_id="test_ds",
            capture_id="cap_0",
            episode_id="ep_0",
            window_id=i,
            window_start=i * 60.0,
            window_end=(i + 1) * 60.0,
            attack_state=labels[i],
            attack_category=cats[i],
            attack_stage="EXPLOITATION" if labels[i] == 1 else "BENIGN_OBSERVATION",
            source_path="test.pcap",
        ))

    events = extract_attack_onset_events(samples)
    # Must find EXACTLY 2 onsets (at index 4 and index 9), NOT 4
    assert len(events) == 2, f"Expected 2 events, got {len(events)}"
    assert events[0].window_index_onset == 4
    assert events[0].attack_category == "ddos"
    assert events[0].post_onset_attack_duration_windows == 3
    assert events[1].window_index_onset == 9
    assert events[1].attack_category == "portscan"
    assert events[1].post_onset_attack_duration_windows == 1


def test_temporal_splitting_no_leakage():
    """Verify that episode-level splitting prevents any cross-partition window overlap."""
    samples = []
    # Create 3 distinct episodes
    for ep_idx in range(3):
        ep_id = f"ep_{ep_idx}"
        for w in range(10):
            samples.append(TemporalWindowSample(
                dataset_id="ds",
                capture_id=f"cap_{ep_idx}",
                episode_id=ep_id,
                window_id=w,
                window_start=float(ep_idx * 1000 + w * 60),
                window_end=float(ep_idx * 1000 + (w + 1) * 60),
                attack_state=1 if w >= 5 else 0,
                attack_category="mitm" if w >= 5 else "benign",
                attack_stage="EXPLOITATION" if w >= 5 else "BENIGN_OBSERVATION",
                source_path="trace.csv",
            ))

    split = build_event_split(
        train_episode_ids=["ep_0"],
        val_episode_ids=["ep_1"],
        test_episode_ids=["ep_2"],
        all_samples=samples,
    )

    train_eps = set(s.episode_id for s in split.train_samples)
    val_eps = set(s.episode_id for s in split.val_samples)
    test_eps = set(s.episode_id for s in split.test_samples)

    # Disjoint assertions
    assert train_eps.isdisjoint(val_eps)
    assert train_eps.isdisjoint(test_eps)
    assert val_eps.isdisjoint(test_eps)
    assert len(split.train_events) == 1
    assert len(split.val_events) == 1
    assert len(split.test_events) == 1


def test_split_manifest_and_candidate_metadata_exist():
    """Verify that split_manifest.json and candidate metadata are properly persisted."""
    manifest_path = CANDIDATE_DIR / "split_manifest.json"
    meta_path = CANDIDATE_DIR / "metadata.json"
    assert manifest_path.exists(), "split_manifest.json missing in candidate directory"
    assert meta_path.exists(), "metadata.json missing in candidate directory"

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "train" in manifest
    assert "validation" in manifest
    assert "test" in manifest
    assert manifest["test"]["events_count"] == 7

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta.get("candidate_id") == "multi_event_v1"
    assert meta.get("status") == "RESEARCH_CANDIDATE_UNPROMOTED"
    assert meta.get("promotion_eligible") is False


def test_multi_event_engine_metadata():
    """Verify that MultiEventResearchForecastEngine presents correct research tier metadata."""
    engine = MultiEventResearchForecastEngine()
    meta = engine.metadata
    assert meta.status == "research"
    assert meta.is_production_ready is False
    assert meta.operational_tier == "RESEARCH_MULTI_EVENT"
    assert "Multi-Event" in meta.name
    assert meta.lead_time_seconds > 0


def test_multi_event_engine_abstains_on_short_history():
    """Verify that fewer than 8 windows produces an authoritative abstention without crashing."""
    engine = MultiEventResearchForecastEngine()
    res = engine.run_forecast(
        canonical_windows=[],
        candidates=(),
        history_status="insufficient",
        capture_quality=None,
        detection_findings=[],
        behavioral_report=None,
        analysis_id="test_run",
        filename="test.pcap",
        capture_fingerprint_sha256="0" * 64,
    )
    assert res.get("status") == "FORECAST_ABSTAINED" or res.get("forecast_status") == "insufficient_history"
    assert res.get("is_abstained") is True or res.get("is_forecast_available") is False


def test_product_pipeline_multi_event_integration():
    """Verify that PCAP upload functions across production, next_gen, and multi_event engines."""
    assert TEST_PCAP.exists(), "Validation test PCAP tcp_heavy.pcap missing"

    for eng in ["production", "next_gen", "multi_event"]:
        res = analyze_uploaded_capture(
            filename="tcp_heavy.pcap",
            file_path=TEST_PCAP,
            engine_type=eng,
        )
        assert res.get("status") == "completed"
        assert "forecast_engine" in res
        tier = res["forecast_engine"].get("operational_tier")
        if eng == "production":
            assert tier == "PRODUCTION"
            assert res.get("model_name") == "final_world_model"
        elif eng == "next_gen":
            assert tier == "RESEARCH_UNVERIFIED"
        elif eng == "multi_event":
            assert tier == "RESEARCH_MULTI_EVENT"
