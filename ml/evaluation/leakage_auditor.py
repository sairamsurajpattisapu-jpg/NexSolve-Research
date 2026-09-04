"""Automated checks for feature, temporal, and split leakage."""
from __future__ import annotations

from collections.abc import Iterable


def audit_features(feature_names: Iterable[str], target_names: Iterable[str] = ("attack_state", "label", "attack_cat")) -> dict:
    names = {name.lower() for name in feature_names}
    targets = {name.lower() for name in target_names}
    leaked = sorted(names & targets)
    future = sorted(name for name in names if any(token in name for token in ("future", "next", "target", "y_")))
    return {"passed": not leaked and not future, "target_features": leaked, "future_named_features": future}


def audit_windows(splits: dict[str, list[int]]) -> dict:
    sets = {name: set(values) for name, values in splits.items()}
    overlaps = {f"{left}_{right}": sorted(sets[left] & sets[right]) for left in sets for right in sets if left < right}
    return {"passed": not any(overlaps.values()), "overlaps": overlaps}