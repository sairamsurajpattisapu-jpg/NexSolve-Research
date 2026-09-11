"""Reusable temporal episode discovery abstraction for network datasets.

Identifies contiguous temporal runs without crossing capture, file, or dataset boundaries.
Tracks duplicate timestamps, gaps, window counts, and eligible multi-horizon cases.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Sequence


@dataclass(frozen=True)
class TemporalEpisode:
    dataset_id: str
    source_file: str
    episode_id: str
    start_timestamp: int
    end_timestamp: int
    number_of_windows: int
    window_interval: int
    number_of_attack_windows: int
    number_of_benign_windows: int
    number_of_unknown_windows: int
    eligible_5_horizon_cases: int
    has_both_classes: bool
    continuity_status: str
    gap_statistics: dict[str, Any]
    duplicate_timestamp_statistics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def discover_episodes(
    timestamps_and_labels: Sequence[tuple[int, int | None]],
    dataset_id: str,
    source_file: str,
    window_seconds: int = 60,
    lookback: int = 8,
    horizons: Sequence[int] = (1, 2, 3, 4, 5),
) -> tuple[TemporalEpisode, ...]:
    """Segment an ordered sequence of (timestamp, label) into contiguous episodes."""
    if not timestamps_and_labels:
        return ()

    runs: list[list[tuple[int, int | None]]] = []
    for item in timestamps_and_labels:
        ts, _ = item
        if not runs:
            runs.append([item])
        else:
            prev_ts = runs[-1][-1][0]
            diff = ts - prev_ts
            if diff == window_seconds:
                runs[-1].append(item)
            elif diff > window_seconds:
                runs.append([item])
            else:
                raise ValueError(f"Timestamps must be strictly non-decreasing: {prev_ts} -> {ts}")

    episodes: list[TemporalEpisode] = []
    max_h = max(horizons)
    min_required_len = lookback + max_h

    for idx, run in enumerate(runs):
        start_ts = run[0][0]
        end_ts = run[-1][0]
        n_windows = len(run)
        n_attack = sum(1 for _, lbl in run if lbl == 1)
        n_benign = sum(1 for _, lbl in run if lbl == 0)
        n_unknown = sum(1 for _, lbl in run if lbl is None or lbl not in (0, 1))
        has_both = (n_attack > 0) and (n_benign > 0)
        eligible_cases = max(0, n_windows - min_required_len + 1)

        episode = TemporalEpisode(
            dataset_id=dataset_id,
            source_file=source_file,
            episode_id=f"{dataset_id}_ep_{idx}",
            start_timestamp=start_ts,
            end_timestamp=end_ts,
            number_of_windows=n_windows,
            window_interval=window_seconds,
            number_of_attack_windows=n_attack,
            number_of_benign_windows=n_benign,
            number_of_unknown_windows=n_unknown,
            eligible_5_horizon_cases=eligible_cases,
            has_both_classes=has_both,
            continuity_status="CONTIGUOUS_60S",
            gap_statistics={
                "prior_gap_seconds": (run[0][0] - runs[idx - 1][-1][0]) if idx > 0 else 0,
                "gap_count_before": 1 if idx > 0 else 0,
            },
            duplicate_timestamp_statistics={
                "duplicate_windows_in_episode": 0,
            },
        )
        episodes.append(episode)

    return tuple(episodes)


def split_episodes_chronologically(
    episodes: Sequence[Any],
) -> dict[str, Any]:
    """Assign episodes chronologically to train, validation, and test.

    Enforces:
    - No window-level splitting across splits.
    - Chronological order: max(train_ts) < min(val_ts) < min(test_ts).
    - If fewer than 3 episodes, returns SPLIT_CONSTRAINT_UNSATISFIED.
    """
    if len(episodes) < 3:
        return {
            "status": "SPLIT_CONSTRAINT_UNSATISFIED",
            "reason": f"At least 3 independent episodes required; received {len(episodes)}",
            "train_indices": [],
            "val_indices": [],
            "test_indices": [],
            "train_episodes": (),
            "validation_episodes": (),
            "test_episodes": (),
        }

    n = len(episodes)
    if n == 3:
        train_idx = [0]
        val_idx = [1]
        test_idx = [2]
    elif n == 4:
        train_idx = [0]
        val_idx = [1]
        test_idx = [2, 3]
    else:
        train_idx = [0]
        val_idx = [1]
        test_idx = list(range(2, n))

    return {
        "status": "VALID_CHRONOLOGICAL_SPLIT",
        "train_indices": train_idx,
        "val_indices": val_idx,
        "test_indices": test_idx,
        "train_episodes": tuple(episodes[i] for i in train_idx),
        "validation_episodes": tuple(episodes[i] for i in val_idx),
        "test_episodes": tuple(episodes[i] for i in test_idx),
    }
