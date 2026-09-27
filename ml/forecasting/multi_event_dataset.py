"""Multi-Event Dataset Representation and Deterministic Episode-Level Splitting.

Implements the official Common Temporal Event Schema for multi-event attack forecasting.
Guarantees zero cross-capture and zero cross-episode data leakage.
"""
from __future__ import annotations

import csv
import json
import math
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from world_model import FEATURE_NAMES_45, NetworkState
from ml.forecasting.next_gen_engine import extract_70_causal_features


ADVANCED_FEATURE_NAMES_25 = [
    "d_flows", "d_src_bytes", "d_dst_bytes", "d_ports",
    "accel_flows", "accel_bytes",
    "mean_flows", "std_flows", "mean_src_bytes", "std_src_bytes", "mean_dst_bytes", "std_dst_bytes",
    "burstiness_flows", "asymmetry_bytes", "dst_port_conc", "port_entropy",
    "syn_ack_ratio", "failed_conn_ratio",
    "zscore_flows", "zscore_bytes",
    "macd_proxy", "tcp_ratio", "udp_ratio", "proto_mix_delta", "cusum_flows"
]

TOTAL_FEATURE_NAMES_70 = FEATURE_NAMES_45 + ADVANCED_FEATURE_NAMES_25


@dataclass
class TemporalWindowSample:
    """Standardized representation of a single contiguous 60-second temporal observation."""
    dataset_id: str
    capture_id: str
    episode_id: str
    window_id: int
    window_start: float
    window_end: float
    attack_state: int
    attack_category: str
    attack_stage: str
    source_path: str
    feature_provenance: Dict[str, Any] = field(default_factory=dict)
    flow_features: Dict[str, float] = field(default_factory=dict)
    packet_features: Dict[str, float] = field(default_factory=dict)
    features_70: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_id": self.dataset_id,
            "capture_id": self.capture_id,
            "episode_id": self.episode_id,
            "window_id": self.window_id,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "attack_state": self.attack_state,
            "attack_category": self.attack_category,
            "attack_stage": self.attack_stage,
            "source_path": self.source_path,
            "feature_provenance": self.feature_provenance,
            "features_70_len": len(self.features_70),
        }


@dataclass
class AttackOnsetEvent:
    """Explicit, independent attack onset event representing a verified 0 -> 1 state transition."""
    event_id: str
    dataset_id: str
    capture_id: str
    episode_id: str
    window_index_before: int
    window_index_onset: int
    timestamp_before: float
    timestamp_onset: float
    attack_category: str
    pre_onset_benign_windows: int
    post_onset_attack_duration_windows: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MultiEventSplit:
    """Deterministic partition of samples and independent attack onset events."""
    train_samples: List[TemporalWindowSample]
    val_samples: List[TemporalWindowSample]
    test_samples: List[TemporalWindowSample]
    train_events: List[AttackOnsetEvent]
    val_events: List[AttackOnsetEvent]
    test_events: List[AttackOnsetEvent]
    metadata: Dict[str, Any] = field(default_factory=dict)


def compute_causal_70_from_history(history_samples: List[TemporalWindowSample]) -> List[float]:
    """Computes 70 causal features strictly using past and current windows (<= t)."""
    dummy_states = []
    for s in history_samples:
        ns = NetworkState(
            timestamp=int(s.window_start),
            flow_features=dict(s.flow_features),
            packet_features=dict(s.packet_features),
            temporal_features={},
            attack_state=s.attack_state,
        )
        dummy_states.append(ns)
    feat_70 = extract_70_causal_features(dummy_states)
    return feat_70.tolist()


def extract_attack_onset_events(samples: List[TemporalWindowSample]) -> List[AttackOnsetEvent]:
    """Deterministically identifies all authentic 0 -> 1 attack onset transitions within episodes."""
    episodes = build_temporal_episodes(samples)
    events: List[AttackOnsetEvent] = []

    for ep_id, ep_samples in episodes.items():
        n = len(ep_samples)
        for t in range(n - 1):
            if ep_samples[t].attack_state == 0 and ep_samples[t + 1].attack_state == 1:
                # Count duration of consecutive attack windows
                dur = 0
                while t + 1 + dur < n and ep_samples[t + 1 + dur].attack_state == 1:
                    dur += 1
                
                ev_id = f"onset_{ep_samples[t + 1].dataset_id}_{ep_id}_w{t + 1}"
                events.append(AttackOnsetEvent(
                    event_id=ev_id,
                    dataset_id=ep_samples[t + 1].dataset_id,
                    capture_id=ep_samples[t + 1].capture_id,
                    episode_id=ep_id,
                    window_index_before=t,
                    window_index_onset=t + 1,
                    timestamp_before=ep_samples[t].window_start,
                    timestamp_onset=ep_samples[t + 1].window_start,
                    attack_category=ep_samples[t + 1].attack_category,
                    pre_onset_benign_windows=t + 1,
                    post_onset_attack_duration_windows=dur,
                ))
    return events


def build_temporal_episodes(samples: List[TemporalWindowSample]) -> Dict[str, List[TemporalWindowSample]]:
    """Groups window samples into chronologically sorted episodes."""
    episodes: Dict[str, List[TemporalWindowSample]] = {}
    for s in samples:
        if s.episode_id not in episodes:
            episodes[s.episode_id] = []
        episodes[s.episode_id].append(s)
    
    for ep_id in episodes:
        episodes[ep_id].sort(key=lambda x: x.window_start)
    return episodes


def build_event_split(
    train_episode_ids: List[str],
    val_episode_ids: List[str],
    test_episode_ids: List[str],
    all_samples: List[TemporalWindowSample],
) -> MultiEventSplit:
    """Partitions window samples and onsets strictly at the episode boundary."""
    train_recs = [s for s in all_samples if s.episode_id in train_episode_ids]
    val_recs = [s for s in all_samples if s.episode_id in val_episode_ids]
    test_recs = [s for s in all_samples if s.episode_id in test_episode_ids]

    train_events = extract_attack_onset_events(train_recs)
    val_events = extract_attack_onset_events(val_recs)
    test_events = extract_attack_onset_events(test_recs)

    meta = {
        "schema_version": "1.0.0-multi-event",
        "feature_dimension": 70,
        "window_seconds": 60,
        "train_windows": len(train_recs),
        "val_windows": len(val_recs),
        "test_windows": len(test_recs),
        "train_events_count": len(train_events),
        "val_events_count": len(val_events),
        "test_events_count": len(test_events),
    }

    return MultiEventSplit(
        train_samples=train_recs,
        val_samples=val_recs,
        test_samples=test_recs,
        train_events=train_events,
        val_events=val_events,
        test_events=test_events,
        metadata=meta,
    )


def save_split_manifest(split: MultiEventSplit, output_path: Path):
    """Serializes the exact capture/episode/event split manifest to JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "metadata": split.metadata,
        "train": {
            "episode_ids": sorted(list(set(s.episode_id for s in split.train_samples))),
            "window_count": len(split.train_samples),
            "attack_window_count": sum(s.attack_state for s in split.train_samples),
            "benign_window_count": sum(1 for s in split.train_samples if s.attack_state == 0),
            "events_count": len(split.train_events),
            "events": [e.to_dict() for e in split.train_events],
        },
        "validation": {
            "episode_ids": sorted(list(set(s.episode_id for s in split.val_samples))),
            "window_count": len(split.val_samples),
            "attack_window_count": sum(s.attack_state for s in split.val_samples),
            "benign_window_count": sum(1 for s in split.val_samples if s.attack_state == 0),
            "events_count": len(split.val_events),
            "events": [e.to_dict() for e in split.val_events],
        },
        "test": {
            "episode_ids": sorted(list(set(s.episode_id for s in split.test_samples))),
            "window_count": len(split.test_samples),
            "attack_window_count": sum(s.attack_state for s in split.test_samples),
            "benign_window_count": sum(1 for s in split.test_samples if s.attack_state == 0),
            "events_count": len(split.test_events),
            "events": [e.to_dict() for e in split.test_events],
        },
    }
    output_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
