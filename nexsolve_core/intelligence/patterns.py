"""Multi-Entity Attack Pattern Detection Engine.

Detects higher-order coordinated patterns across multiple entities:
- HORIZONTAL_SCAN: One source → many hosts → similar ports
- VERTICAL_SCAN: One source → one host → many ports
- DISTRIBUTED_SCAN: Many sources → same target/ports
- FANOUT_BURST: One entity → rapid expansion across peers
- FANIN_BURST: Many entities → same target
- BEACONING_CLUSTER: Multiple entities exhibiting similar periodic communication
- VOLUME_AMPLIFICATION: Asymmetric traffic explosion targeting a service
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import deterministic_id


class AttackPatternType(str, Enum):
    HORIZONTAL_SCAN = "HORIZONTAL_SCAN"
    VERTICAL_SCAN = "VERTICAL_SCAN"
    DISTRIBUTED_SCAN = "DISTRIBUTED_SCAN"
    FANOUT_BURST = "FANOUT_BURST"
    FANIN_BURST = "FANIN_BURST"
    BEACONING_CLUSTER = "BEACONING_CLUSTER"
    VOLUME_AMPLIFICATION = "VOLUME_AMPLIFICATION"


@dataclass(frozen=True)
class AttackPattern:
    """Coordinated higher-order attack pattern involving one or more entities."""
    pattern_id: str
    pattern_type: AttackPatternType
    primary_entities: tuple[str, ...]
    target_entities: tuple[str, ...]
    targeted_ports: tuple[int, ...]
    time_window_range: tuple[int, int]
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    supporting_events: tuple[str, ...]
    supporting_features: dict[str, Any]
    observed_or_forecast: str
    explanation: str
    provenance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "pattern_type": self.pattern_type.value,
            "primary_entities": list(self.primary_entities),
            "target_entities": list(self.target_entities),
            "targeted_ports": list(self.targeted_ports),
            "time_window_range": list(self.time_window_range),
            "severity": self.severity,
            "supporting_events": list(self.supporting_events),
            "supporting_features": self.supporting_features,
            "observed_or_forecast": self.observed_or_forecast,
            "explanation": self.explanation,
            "provenance": self.provenance,
        }


def detect_attack_patterns(
    tcp_sessions: Sequence[Any] | None = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    beaconing_signals: Sequence[Any] | None = None,
    change_signals: Sequence[Any] | None = None,
) -> tuple[AttackPattern, ...]:
    """Detect deterministic multi-entity attack patterns."""
    patterns: list[AttackPattern] = []
    sessions = tcp_sessions or []
    findings = observed_findings or []
    beacons = beaconing_signals or []
    changes = change_signals or []

    # Map sessions by source and by destination
    src_targets: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
    dst_sources: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
    src_windows: dict[str, set[int]] = defaultdict(set)
    dst_windows: dict[str, set[int]] = defaultdict(set)

    for s in sessions:
        src = getattr(s, "src_ip", None)
        dst = getattr(s, "dst_ip", None)
        port = getattr(s, "dst_port", None)
        w = getattr(s, "window_index", 0) or 0

        if src and dst:
            if port:
                src_targets[src][dst].add(port)
                dst_sources[dst][src].add(port)
            src_windows[src].add(w)
            dst_windows[dst].add(w)

    # 1. HORIZONTAL_SCAN (One source -> many hosts -> small number of ports per host)
    for src, targets in src_targets.items():
        if len(targets) >= 5:
            # Check port concentration
            all_ports = set().union(*targets.values())
            # Average ports per target <= 3 indicates horizontal sweep
            avg_ports = sum(len(p) for p in targets.values()) / max(1, len(targets))
            if avg_ports <= 4.0:
                w_sorted = sorted(src_windows[src])
                w_range = (w_sorted[0], w_sorted[-1]) if w_sorted else (0, 0)
                pid = deterministic_id("pat", src, "HORIZ_SCAN", w_range[0])
                patterns.append(AttackPattern(
                    pattern_id=pid,
                    pattern_type=AttackPatternType.HORIZONTAL_SCAN,
                    primary_entities=(src,),
                    target_entities=tuple(sorted(targets.keys())[:20]),
                    targeted_ports=tuple(sorted(all_ports)[:10]),
                    time_window_range=w_range,
                    severity="HIGH",
                    supporting_events=(f"Scanned {len(targets)} distinct hosts across ports {sorted(all_ports)[:5]}",),
                    supporting_features={"target_count": len(targets), "avg_ports_per_target": avg_ports},
                    observed_or_forecast="OBSERVED",
                    explanation=f"Source {src} executed horizontal port sweep targeting {len(targets)} hosts.",
                    provenance={"rule": "horizontal_sweep_rule"},
                ))

    # 2. VERTICAL_SCAN (One source -> one host -> many ports >= 10)
    for src, targets in src_targets.items():
        for dst, ports in targets.items():
            if len(ports) >= 10:
                w_sorted = sorted(src_windows[src])
                w_range = (w_sorted[0], w_sorted[-1]) if w_sorted else (0, 0)
                pid = deterministic_id("pat", src, dst, "VERT_SCAN", w_range[0])
                patterns.append(AttackPattern(
                    pattern_id=pid,
                    pattern_type=AttackPatternType.VERTICAL_SCAN,
                    primary_entities=(src,),
                    target_entities=(dst,),
                    targeted_ports=tuple(sorted(ports)[:25]),
                    time_window_range=w_range,
                    severity="HIGH",
                    supporting_events=(f"Scanned {len(ports)} distinct ports on single target {dst}",),
                    supporting_features={"port_count": len(ports)},
                    observed_or_forecast="OBSERVED",
                    explanation=f"Source {src} executed intense vertical port scan against {dst} ({len(ports)} ports probed).",
                    provenance={"rule": "vertical_scan_rule"},
                ))

    # 3. DISTRIBUTED_SCAN / FANIN_BURST (Many sources >= 5 -> same target)
    for dst, sources in dst_sources.items():
        if len(sources) >= 5:
            all_ports = set().union(*sources.values())
            w_sorted = sorted(dst_windows[dst])
            w_range = (w_sorted[0], w_sorted[-1]) if w_sorted else (0, 0)
            pid = deterministic_id("pat", dst, "DIST_SCAN", w_range[0])
            patterns.append(AttackPattern(
                pattern_id=pid,
                pattern_type=AttackPatternType.DISTRIBUTED_SCAN,
                primary_entities=tuple(sorted(sources.keys())[:20]),
                target_entities=(dst,),
                targeted_ports=tuple(sorted(all_ports)[:10]),
                time_window_range=w_range,
                severity="HIGH",
                supporting_events=(f"{len(sources)} sources converged on target {dst}",),
                supporting_features={"convergent_source_count": len(sources)},
                observed_or_forecast="OBSERVED",
                explanation=f"Distributed scanning convergence detected: {len(sources)} sources targeted host {dst}.",
                provenance={"rule": "distributed_convergence_rule"},
            ))

    # 4. BEACONING_CLUSTER (Multiple entities exhibiting similar periodic beaconing)
    beacon_sources = [b.src_ip for b in beacons if getattr(b, "is_beaconing", False)]
    if len(set(beacon_sources)) >= 2:
        pid = deterministic_id("pat", "c2_cluster", len(beacon_sources))
        patterns.append(AttackPattern(
            pattern_id=pid,
            pattern_type=AttackPatternType.BEACONING_CLUSTER,
            primary_entities=tuple(sorted(set(beacon_sources))),
            target_entities=tuple(sorted({b.dst_ip for b in beacons if getattr(b, "is_beaconing", False)})),
            targeted_ports=tuple(sorted({b.dst_port for b in beacons if getattr(b, "dst_port", None) is not None})),
            time_window_range=(0, 0),
            severity="CRITICAL",
            supporting_events=(f"Identified {len(set(beacon_sources))} distinct periodic beaconing endpoints",),
            supporting_features={"beacon_count": len(beacon_sources)},
            observed_or_forecast="OBSERVED",
            explanation=f"Command-and-control cluster detected: {len(set(beacon_sources))} endpoints actively beaconing.",
            provenance={"rule": "beacon_cluster_rule"},
        ))

    # 5. VOLUME_AMPLIFICATION / DoS Surge
    for f in findings:
        cat = str(f.get("attack_category", "")).lower()
        if "dos" in cat or "flood" in cat:
            src = str(f.get("source_ip") or "unknown")
            dst = str(f.get("destination_ip") or "unknown")
            w = int(f.get("window_index") or 0)
            pid = deterministic_id("pat", src, dst, "VOL_AMP", w)
            patterns.append(AttackPattern(
                pattern_id=pid,
                pattern_type=AttackPatternType.VOLUME_AMPLIFICATION,
                primary_entities=(src,),
                target_entities=(dst,),
                targeted_ports=(),
                time_window_range=(w, w),
                severity="CRITICAL",
                supporting_events=(f"High-rate volume asymmetry targeting {dst}",),
                supporting_features={"attack_category": cat},
                observed_or_forecast="OBSERVED",
                explanation=f"Denial-of-Service / volume amplification flow anomaly observed from {src} to {dst}.",
                provenance={"rule": "dos_volume_rule"},
            ))

    return tuple(patterns)
