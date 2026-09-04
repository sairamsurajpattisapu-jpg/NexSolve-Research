"""Timestamp-tolerant flow/packet alignment interface with past-only safety checks."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class AlignmentConfig:
    window_seconds: int = 60
    timestamp_tolerance_seconds: float = 1.0


def _window_key(item: dict[str, Any], window_seconds: int) -> int:
    if "window_start" in item:
        return int(item["window_start"]) // window_seconds
    if "timestamp" in item:
        return int(item["timestamp"]) // window_seconds
    raise ValueError("observation missing required timestamp/window_start field")


def validate_observation(observation: dict[str, Any], required: tuple[str, ...] = ("timestamp",)) -> None:
    missing = [name for name in required if name not in observation]
    if missing:
        raise ValueError(f"observation missing required fields: {', '.join(missing)}")
    timestamp = observation.get("timestamp")
    if not isinstance(timestamp, (int, float)):
        raise ValueError("observation timestamp must be numeric epoch seconds")


def validate_past_only(states: Iterable[dict[str, Any]]) -> None:
    ordered = list(states)
    previous = None
    for state in ordered:
        timestamp = state.get("timestamp", state.get("window_start"))
        if timestamp is None:
            raise ValueError("state missing timestamp/window_start for past-only validation")
        if previous is not None and timestamp < previous:
            raise ValueError("future observations detected in a past-only state sequence")
        previous = timestamp


def align_observations(flow_observations: list[dict[str, Any]], packet_observations: list[dict[str, Any]], config: AlignmentConfig = AlignmentConfig()) -> dict[str, Any]:
    """Align observations by 60-second windows while preserving causality constraints."""
    if config.window_seconds <= 0 or config.timestamp_tolerance_seconds < 0:
        raise ValueError("alignment configuration must be positive")
    for observation in flow_observations + packet_observations:
        validate_observation(observation)

    flow_windows = {_window_key(item, config.window_seconds) for item in flow_observations}
    packet_windows = {_window_key(item, config.window_seconds) for item in packet_observations}
    matched = flow_windows & packet_windows
    total = max(len(flow_windows | packet_windows), 1)
    coverage = len(matched) / total if total else 0.0
    return {
        "config": {"window_seconds": config.window_seconds, "timestamp_tolerance_seconds": config.timestamp_tolerance_seconds},
        "flow_records": len(flow_observations),
        "packet_records": len(packet_observations),
        "total_flow_windows": len(flow_windows),
        "total_packet_windows": len(packet_windows),
        "matched_windows": len(matched),
        "unmatched_flow_windows": len(flow_windows - matched),
        "unmatched_packet_windows": len(packet_windows - matched),
        "alignment_coverage": coverage,
        "match_rate_by_window": len(matched) / max(len(flow_windows), 1),
        "tuple_identity_used": any(all(key in item for key in ("src_ip", "dst_ip", "src_port", "dst_port", "protocol")) for item in flow_observations + packet_observations),
        "feature_fabrication": False,
    }


def determine_label_alignment_status(label_state: dict[str, Any]) -> str:
    if not label_state:
        return "BLOCKED"
    status = str(label_state.get("status", "")).upper()
    if status in {"VALIDATED", "PARTIALLY_VALIDATED"}:
        return status
    if status == "BLOCKED":
        return "BLOCKED"
    return "PARTIALLY_VALIDATED"