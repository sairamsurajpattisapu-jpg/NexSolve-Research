"""Evidence-bounded detection and risk scoring for packet-window aggregates."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

DETECTION_METHOD = "traffic_heuristics"


def _severity(score: float) -> str:
    if score >= 60:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


class DetectionEngine:
    """Stable detector interface for current heuristics and a future validated ML engine."""

    detection_method = DETECTION_METHOD

    def analyze(self, windows: list[dict[str, Any]]) -> dict[str, Any]:
        raise NotImplementedError


class MLDetector(DetectionEngine):
    """Future seam for a validated model with the production window contract."""

    detection_method = "validated_ml"

    def analyze(self, windows: list[dict[str, Any]]) -> dict[str, Any]:
        raise NotImplementedError("validated ML is unavailable until compatible labeled packet windows exist")


class HeuristicDetector(DetectionEngine):
    def _window_risk(self, window: dict[str, Any]) -> tuple[float, list[dict[str, Any]]]:
        packet_count = max(int(window.get("packet_count", 0)), 1)
        port_scan = min(max(float(window.get("port_scan_score") or 0.0), 0.0), 1.0)
        retransmission = min(max(float(window.get("tcp_retransmission_rate") or 0.0) / 0.10, 0.0), 1.0)
        fragmentation = min(max(float(window.get("fragment_ratio") or 0.0) / 0.05, 0.0), 1.0)
        syn_pressure = min(max(float(window.get("syn_count") or 0) / (packet_count * 0.50), 0.0), 1.0)
        risk = 100.0 * (0.55 * port_scan + 0.20 * retransmission + 0.10 * fragmentation + 0.15 * syn_pressure)
        evidence: list[dict[str, Any]] = []
        if port_scan >= 0.50:
            evidence.append({"rule_id": "PORT_SCAN_SCORE_HIGH", "type": "port_scan_indicator", "value": port_scan, "metric": "port_scan_score", "threshold": 0.50, "message": "Traffic-derived port-scan score is at least 0.50."})
        if retransmission >= 0.50:
            evidence.append({"rule_id": "TCP_RETRANSMISSION_RATE_HIGH", "type": "retransmission_indicator", "value": float(window.get("tcp_retransmission_rate") or 0.0), "metric": "tcp_retransmission_rate", "threshold": 0.05, "message": "TCP retransmission rate is at least 5 percent."})
        if fragmentation >= 0.50:
            evidence.append({"rule_id": "FRAGMENTATION_RATIO_HIGH", "type": "fragmentation_indicator", "value": float(window.get("fragment_ratio") or 0.0), "metric": "fragment_ratio", "threshold": 0.025, "message": "Fragmentation ratio is at least 2.5 percent."})
        if syn_pressure >= 0.50:
            evidence.append({"rule_id": "SYN_PRESSURE_HIGH", "type": "syn_pressure_indicator", "value": float(window.get("syn_count") or 0), "metric": "syn_count", "threshold": packet_count * 0.50, "message": "SYN attempts are at least half of observed packets."})
        return round(risk, 2), evidence

    def analyze(self, windows: list[dict[str, Any]]) -> dict[str, Any]:
        return _analyze_with_detector(windows, self)


def _window_risk(window: dict[str, Any]) -> tuple[float, list[dict[str, Any]]]:
    """Backward-compatible helper for existing callers and tests."""
    return HeuristicDetector()._window_risk(window)


def _analyze_with_detector(windows: list[dict[str, Any]], detector: DetectionEngine) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    risk_scores: list[float] = []
    for index, window in enumerate(windows):
        risk_score, evidence = detector._window_risk(window)
        risk_scores.append(risk_score)
        if not evidence:
            continue
        timestamp = datetime.fromtimestamp(int(window["window_start"]), timezone.utc).isoformat()
        findings.append({
            "finding_id": f"window-{index + 1}",
            "window_id": index,
            "timestamp": timestamp,
            "prediction": "suspicious_traffic",
            "attack_category": "network_reconnaissance" if any(item["type"] == "port_scan_indicator" for item in evidence) else "traffic_anomaly",
            "detection_method": detector.detection_method,
            "severity": _severity(risk_score),
            "confidence": None,
            "risk_score": risk_score,
            "evidence": evidence,
            "explanation": [item["message"] for item in evidence],
            "recommendation": "Review the source and destination context for this window before taking containment action.",
        })
    average_risk = round(sum(risk_scores) / len(risk_scores), 2) if risk_scores else 0.0
    maximum_risk = round(max(risk_scores), 2) if risk_scores else 0.0
    return {
        "status": "completed",
        "detection_mode": detector.detection_method,
        "detection_method": detector.detection_method,
        "model_prediction_available": False,
        "windows_analyzed": len(windows),
        "detected_events": len(findings),
        "risk_score": maximum_risk,
        "average_window_risk": average_risk,
        "threat_level": _severity(maximum_risk),
        "findings": findings,
        "risk_method": "100 * (0.55*port_scan_score + 0.20*min(retransmission_rate/0.10,1) + 0.10*min(fragment_ratio/0.05,1) + 0.15*min(syn_count/(packet_count*0.50),1)); no labels or model probabilities are used.",
    }


def analyze_packet_windows(windows: list[dict[str, Any]]) -> dict[str, Any]:
    return HeuristicDetector().analyze(windows)


def traffic_summary(windows: list[dict[str, Any]]) -> dict[str, Any]:
    protocols: Counter[str] = Counter()
    for window in windows:
        protocols.update({str(name): int(value or 0) for name, value in (window.get("protocol_counts") or {}).items()})
    return {
        "status": "completed" if windows else "empty",
        "windows": len(windows),
        "packets": sum(int(window.get("packet_count", 0)) for window in windows),
        "tcp": sum(int(window.get("tcp_count", 0)) for window in windows),
        "udp": sum(int(window.get("udp_count", 0)) for window in windows),
        "icmp": sum(int(window.get("icmp_count", 0)) for window in windows),
        "retransmissions": sum(int(window.get("tcp_retransmission_count", 0)) for window in windows),
        "fragmented_packets": sum(int(window.get("fragment_count", 0)) for window in windows),
        "protocol_counts": dict(sorted(protocols.items())),
        "windows_data": windows,
    }