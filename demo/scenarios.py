"""Deterministic SIH Demo Scenarios for NexSolve.

Provides 7 validated, realistic demo scenarios matching actual production API contracts:
1. NORMAL_TRAFFIC
2. EARLY_ATTACK_SIGNAL
3. SUSTAINED_ATTACK_FORECAST
4. CONTRADICTORY_EVIDENCE
5. UNKNOWN_BEHAVIOR
6. FORECAST_ABSTAINED
7. POOR_CAPTURE_QUALITY

Each scenario includes complete, realistic structured data for traffic, quality,
detection, network_state, forecast horizons, attack horizon, evidence chain,
confidence, unknown behavior, and abstention.
"""
from __future__ import annotations

from typing import Any
from reporting.report_engine import assemble_report, generate_html_report, generate_json_report

# Metadata descriptors for SIH Judge selection
DEMO_SCENARIO_METADATA = [
    {
        "id": "NORMAL_TRAFFIC",
        "name": "Normal Traffic Baseline",
        "badge": "Benign Baseline",
        "tone": "success",
        "description": "Standard business hours traffic with normal packet rates, low connection concurrency, and zero threat indicators.",
        "expected_behavior": "Attack Horizon reports NO_ATTACK_FORECAST. Forecast scores remain low (<0.05). Evidence shows stable baseline with zero contradictory signals. Confidence is uncalibrated but consistent.",
    },
    {
        "id": "EARLY_ATTACK_SIGNAL",
        "name": "Early Attack Signal",
        "badge": "Early Warning",
        "tone": "warning",
        "description": "Traffic activity begins shifting toward an anomalous state with port scanning and elevated connection diversity.",
        "expected_behavior": "Attack Horizon identifies EARLY_SIGNAL with onset at window T+1 (lead time 60s). Evidence highlights 64% surge in destination port diversity. Uncalibrated forecast score rises to 0.58.",
    },
    {
        "id": "SUSTAINED_ATTACK_FORECAST",
        "name": "Sustained Attack Forecast",
        "badge": "Critical Progression",
        "tone": "danger",
        "description": "Multi-stage attack progression with heavy flow surges, synchronized connection flooding, and persistent anomalous patterns.",
        "expected_behavior": "Attack Horizon confirms SUSTAINED_ATTACK_FORECAST spanning 3 windows (180s continuous) through T+3. Strong supporting evidence (+62.8% flow volume). Raw forecast score 0.82.",
    },
    {
        "id": "CONTRADICTORY_EVIDENCE",
        "name": "Contradictory Evidence",
        "badge": "Signal Conflict",
        "tone": "neutral",
        "description": "A heuristic detector triggers on high packet burst, but baseline flow durations and destination ports remain completely normal.",
        "expected_behavior": "Attack Horizon reports UNCERTAIN_FORECAST. Evidence Intelligence explicitly isolates contradictory signals. Uncertainty level is HIGH, preventing false-positive escalation.",
    },
    {
        "id": "UNKNOWN_BEHAVIOR",
        "name": "Unknown / Out-of-Distribution Behavior",
        "badge": "OOD Anomaly",
        "tone": "warning",
        "description": "Unusual protocol header variations and payload entropy not matching known benign profiles or cataloged attack signatures.",
        "expected_behavior": "Classification identifies UNKNOWN_BEHAVIOR (coverage 38%). NexSolve treats this as Out-of-Distribution, NOT an automatic attack. Abstention is recommended to prevent blind extrapolation.",
    },
    {
        "id": "FORECAST_ABSTAINED",
        "name": "Forecast Abstained (Safety Gate)",
        "badge": "Safety Withheld",
        "tone": "warning",
        "description": "Traffic capture contains an irregular lookback gap, falling short of the 8 continuous temporal windows required for forecasting.",
        "expected_behavior": "Forecast status is FORECAST WITHHELD. Attack Horizon is ABSTAINED. UI communicates a deliberate safety decision rather than a system crash, listing missing requirements.",
    },
    {
        "id": "POOR_CAPTURE_QUALITY",
        "name": "Poor Capture Quality",
        "badge": "Degraded Capture",
        "tone": "danger",
        "description": "Network capture exhibits 22.4% packet loss, packet truncation, and out-of-order sequence headers.",
        "expected_behavior": "Capture Integrity is flagged DEGRADED. Evidence Chain documents packet loss as a primary capture limitation. Forecast is safely withheld due to untrustworthy input data.",
    },
]


def _build_scenario_payload(scenario_id: str) -> dict[str, Any]:
    timestamp = "2026-09-10T08:00:00Z"
    meta = next((m for m in DEMO_SCENARIO_METADATA if m["id"] == scenario_id), DEMO_SCENARIO_METADATA[0])

    if scenario_id == "NORMAL_TRAFFIC":
        traffic = {
            "packets": 14250,
            "flows": 3120,
            "windows": 10,
            "retransmissions": 18,
            "protocol_counts": {"TCP": 11200, "UDP": 2850, "ICMP": 200},
            "windows_data": [
                {"window_start": i * 60, "window_end": (i + 1) * 60, "packets": 1400 + (i * 5), "flows": 310, "bytes": 850000}
                for i in range(10)
            ],
        }
        quality = {
            "status": "GOOD",
            "packet_loss_ratio": 0.001,
            "reordered_packets": 2,
            "truncated_packets": 0,
            "malformed_packets": 0,
            "capture_duration_seconds": 600,
        }
        detection = {
            "threat_level": "low",
            "risk_score": 1.2,
            "detected_events": 0,
            "findings": [],
            "detection_method": "Heuristic Rule Engine (Transparent)",
        }
        forecasts = [
            {"horizon": 1, "attackProbability": 0.02, "predictedStage": "Baseline", "confidence": None, "uncertainty": 0.05, "explanation": ["Flow rate within normal baseline (-2.1%)"]},
            {"horizon": 2, "attackProbability": 0.03, "predictedStage": "Baseline", "confidence": None, "uncertainty": 0.06, "explanation": ["Connection concurrency nominal"]},
            {"horizon": 3, "attackProbability": 0.03, "predictedStage": "Baseline", "confidence": None, "uncertainty": 0.07, "explanation": ["Port diversity stable"]},
            {"horizon": 4, "attackProbability": 0.04, "predictedStage": "Baseline", "confidence": None, "uncertainty": 0.08, "explanation": []},
            {"horizon": 5, "attackProbability": 0.03, "predictedStage": "Baseline", "confidence": None, "uncertainty": 0.08, "explanation": []},
        ]
        attack_horizon = {
            "state": "NO_ATTACK_FORECAST",
            "onset_horizon": None,
            "onset_timestamp": None,
            "lead_time_seconds": None,
            "horizon_windows": 0,
            "horizon_seconds": 0,
            "end_horizon": None,
            "end_timestamp": None,
            "decision_threshold": 0.5,
            "temporal_consistency": 1.0,
            "decay_observed": False,
            "confidence_summary": {"mean_confidence": None, "min_confidence": None, "max_confidence": None, "calibration_status": "UNSUPPORTED"},
            "evidence_chain": [
                {"horizon": i, "horizon_seconds": i * 60, "predicted_timestamp": f"2026-09-10T08:0{i}:00Z", "attack_probability": 0.02 + (i * 0.003), "confidence": None, "predicted_stage": "Baseline", "above_threshold": False, "abstained": False}
                for i in range(1, 6)
            ],
            "abstention_reason": None,
            "summary": "No attack forecasted across next 5 temporal windows (300s). All projected indicators remain within normal baseline parameters.",
        }
        evidence_chain = {
            "current_window_id": "w-demo-norm-10",
            "current_timestamp": timestamp,
            "forecast_horizon": 0,
            "supporting": [
                {"evidence_id": "EV-NORM-01", "timestamp": timestamp, "window_id": "w-demo-norm-10", "evidence_type": "FLOW_ACTIVITY", "feature_name": "flow_count", "observed_value": 312, "baseline_value": 310, "delta": 2, "relative_change": 0.006, "direction": "STABLE", "severity": "LOW", "reliability": 1.0, "source": "state.flow_features", "provenance": {"capture_id": "demo-normal"}, "explanation": "Flow concurrency is completely nominal (312 vs 310 baseline).", "is_supporting": True},
            ],
            "contradictory": [],
            "evidence_strength": 0.15,
            "evidence_quality": "HIGH",
            "supporting_feature_count": 1,
            "contradictory_feature_count": 0,
            "provenance_complete": True,
            "explanation": "Traffic metrics demonstrate normal baseline behavior across all monitored protocols.",
            "limitations": [],
        }
        confidence = {
            "forecast_score": 0.03,
            "confidence_value": None,
            "confidence_state": "UNCALIBRATED",
            "evidence_strength": 0.15,
            "calibration_status": "UNSUPPORTED",
            "uncertainty_level": "LOW",
            "explanation": "Raw forecast score is 0.03. Model calibration is UNSUPPORTED; score reflects raw persistence baseline margin.",
        }
        unknown_behavior = {
            "classification": "KNOWN_PATTERN",
            "reason": "Observed traffic matches verified enterprise benign baseline distribution.",
            "supporting_evidence": ["Standard HTTP/HTTPS and DNS request-response distributions."],
            "contradictory_evidence": [],
            "coverage": 0.98,
            "abstain_recommended": False,
        }
        abstention = {
            "abstained": False,
            "reason": None,
            "severity": "LOW",
            "status": "FORECAST_AVAILABLE_BUT_UNCALIBRATED",
            "missing_requirements": [],
            "explanation": "Prerequisites satisfied: 10 contiguous windows available. Forecast is active under uncalibrated baseline.",
        }

    elif scenario_id == "EARLY_ATTACK_SIGNAL":
        traffic = {
            "packets": 28400,
            "flows": 7450,
            "windows": 10,
            "retransmissions": 142,
            "protocol_counts": {"TCP": 24100, "UDP": 4100, "ICMP": 200},
            "windows_data": [
                {"window_start": i * 60, "window_end": (i + 1) * 60, "packets": 2200 + (i * 120), "flows": 500 + (i * 50), "bytes": 1200000}
                for i in range(10)
            ],
        }
        quality = {
            "status": "GOOD",
            "packet_loss_ratio": 0.004,
            "reordered_packets": 6,
            "truncated_packets": 0,
            "malformed_packets": 0,
            "capture_duration_seconds": 600,
        }
        detection = {
            "threat_level": "medium",
            "risk_score": 5.4,
            "detected_events": 2,
            "findings": [
                {
                    "finding_id": "FIND-DEMO-01",
                    "attack_category": "PORT_SCAN",
                    "severity": "medium",
                    "timestamp": timestamp,
                    "risk_score": 5.4,
                    "prediction": "Reconnaissance",
                    "recommendation": "Monitor perimeter firewall for horizontal sweep on ports 445, 3389.",
                    "evidence": [{"type": "PORT_SWEEP", "message": "Rapid destination port probe observed across 64 discrete ports.", "metric": "dst_ports", "threshold": 30}],
                }
            ],
            "detection_method": "Heuristic Rule Engine (Transparent)",
        }
        forecasts = [
            {"horizon": 1, "attackProbability": 0.58, "predictedStage": "Reconnaissance", "confidence": None, "uncertainty": 0.42, "explanation": ["Port diversity increased 64% over baseline"]},
            {"horizon": 2, "attackProbability": 0.65, "predictedStage": "Reconnaissance", "confidence": None, "uncertainty": 0.35, "explanation": ["SYN-to-ACK ratio elevated (3.4x)"]},
            {"horizon": 3, "attackProbability": 0.48, "predictedStage": None, "confidence": None, "uncertainty": 0.52, "explanation": []},
            {"horizon": 4, "attackProbability": 0.28, "predictedStage": None, "confidence": None, "uncertainty": 0.72, "explanation": []},
            {"horizon": 5, "attackProbability": 0.15, "predictedStage": None, "confidence": None, "uncertainty": 0.85, "explanation": []},
        ]
        attack_horizon = {
            "state": "EARLY_SIGNAL",
            "onset_horizon": 1,
            "onset_timestamp": "2026-09-10T08:01:00Z",
            "lead_time_seconds": 60,
            "horizon_windows": 2,
            "horizon_seconds": 120,
            "end_horizon": 2,
            "end_timestamp": "2026-09-10T08:02:00Z",
            "decision_threshold": 0.5,
            "temporal_consistency": 0.85,
            "decay_observed": True,
            "confidence_summary": {"mean_confidence": None, "min_confidence": None, "max_confidence": None, "calibration_status": "UNSUPPORTED"},
            "evidence_chain": [
                {"horizon": 1, "horizon_seconds": 60, "predicted_timestamp": "2026-09-10T08:01:00Z", "attack_probability": 0.58, "confidence": None, "predicted_stage": "Reconnaissance", "above_threshold": True, "abstained": False},
                {"horizon": 2, "horizon_seconds": 120, "predicted_timestamp": "2026-09-10T08:02:00Z", "attack_probability": 0.65, "confidence": None, "predicted_stage": "Reconnaissance", "above_threshold": True, "abstained": False},
                {"horizon": 3, "horizon_seconds": 180, "predicted_timestamp": "2026-09-10T08:03:00Z", "attack_probability": 0.48, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False},
                {"horizon": 4, "horizon_seconds": 240, "predicted_timestamp": "2026-09-10T08:04:00Z", "attack_probability": 0.28, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False},
                {"horizon": 5, "horizon_seconds": 300, "predicted_timestamp": "2026-09-10T08:05:00Z", "attack_probability": 0.15, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False},
            ],
            "abstention_reason": None,
            "summary": "Early attack signal detected with onset at window T+1 (lead time 60s), continuing through T+2 before decaying below decision threshold.",
        }
        evidence_chain = {
            "current_window_id": "w-demo-early-10",
            "current_timestamp": timestamp,
            "forecast_horizon": 2,
            "supporting": [
                {"evidence_id": "EV-EARLY-01", "timestamp": timestamp, "window_id": "w-demo-early-10", "evidence_type": "PORT_DIVERSITY", "feature_name": "unique_dst_ports", "observed_value": 72, "baseline_value": 44, "delta": 28, "relative_change": 0.636, "direction": "INCREASE", "severity": "MEDIUM", "reliability": 1.0, "source": "state.flow_features", "provenance": {"capture_id": "demo-early"}, "explanation": "Target port fanout surged 63.6% over baseline (72 vs 44 ports).", "is_supporting": True},
                {"evidence_id": "EV-EARLY-02", "timestamp": timestamp, "window_id": "w-demo-early-10", "evidence_type": "TCP_SYN_RATIO", "feature_name": "syn_ack_ratio", "observed_value": 3.4, "baseline_value": 1.05, "delta": 2.35, "relative_change": 2.238, "direction": "INCREASE", "severity": "MEDIUM", "reliability": 1.0, "source": "state.packet_features", "provenance": {"capture_id": "demo-early"}, "explanation": "SYN to ACK packet ratio is elevated 2.2x above baseline expectation.", "is_supporting": True},
            ],
            "contradictory": [],
            "evidence_strength": 0.68,
            "evidence_quality": "HIGH",
            "supporting_feature_count": 2,
            "contradictory_feature_count": 0,
            "provenance_complete": True,
            "explanation": "Evidence supports early stage reconnaissance with directional indicators pointing toward active port discovery.",
            "limitations": [],
        }
        confidence = {
            "forecast_score": 0.58,
            "confidence_value": None,
            "confidence_state": "UNCALIBRATED",
            "evidence_strength": 0.68,
            "calibration_status": "UNSUPPORTED",
            "uncertainty_level": "LOW",
            "explanation": "Raw forecast score is 0.58 at T+1. Score represents raw model margin; calibration is UNSUPPORTED.",
        }
        unknown_behavior = {
            "classification": "KNOWN_PATTERN",
            "reason": "Observed activity conforms to recognized port sweep and discovery signatures.",
            "supporting_evidence": ["Horizontal destination port dispersion across TCP endpoints."],
            "contradictory_evidence": [],
            "coverage": 0.91,
            "abstain_recommended": False,
        }
        abstention = {
            "abstained": False,
            "reason": None,
            "severity": "LOW",
            "status": "FORECAST_AVAILABLE_BUT_UNCALIBRATED",
            "missing_requirements": [],
            "explanation": "Lookback prerequisites satisfied; early warning forecast generated under uncalibrated baseline.",
        }

    elif scenario_id == "SUSTAINED_ATTACK_FORECAST":
        traffic = {
            "packets": 94800,
            "flows": 24100,
            "windows": 10,
            "retransmissions": 890,
            "protocol_counts": {"TCP": 84200, "UDP": 9800, "ICMP": 800},
            "windows_data": [
                {"window_start": i * 60, "window_end": (i + 1) * 60, "packets": 5000 + (i * 1200), "flows": 1200 + (i * 300), "bytes": 6800000}
                for i in range(10)
            ],
        }
        quality = {
            "status": "GOOD",
            "packet_loss_ratio": 0.012,
            "reordered_packets": 24,
            "truncated_packets": 0,
            "malformed_packets": 0,
            "capture_duration_seconds": 600,
        }
        detection = {
            "threat_level": "high",
            "risk_score": 8.7,
            "detected_events": 5,
            "findings": [
                {
                    "finding_id": "FIND-DEMO-SUST-01",
                    "attack_category": "DENIAL_OF_SERVICE",
                    "severity": "high",
                    "timestamp": timestamp,
                    "risk_score": 8.7,
                    "prediction": "Volumetric Progression",
                    "recommendation": "Activate upstream DDoS scrubbing and rate-limit ingress TCP SYN floods.",
                    "evidence": [{"type": "FLOW_SURGE", "message": "Flow count increased 62.8% above baseline.", "metric": "flow_count", "threshold": 15000}],
                }
            ],
            "detection_method": "Heuristic Rule Engine (Transparent)",
        }
        forecasts = [
            {"horizon": 1, "attackProbability": 0.82, "predictedStage": "Reconnaissance", "confidence": None, "uncertainty": 0.36, "explanation": ["flow_count contributed +0.14"]},
            {"horizon": 2, "attackProbability": 0.88, "predictedStage": "Lateral Movement", "confidence": None, "uncertainty": 0.24, "explanation": ["unique_dst_ports contributed +0.22"]},
            {"horizon": 3, "attackProbability": 0.80, "predictedStage": "Command and Control", "confidence": None, "uncertainty": 0.40, "explanation": ["total_src_bytes contributed +0.18"]},
            {"horizon": 4, "attackProbability": 0.35, "predictedStage": None, "confidence": None, "uncertainty": 0.70, "explanation": []},
            {"horizon": 5, "attackProbability": 0.15, "predictedStage": None, "confidence": None, "uncertainty": 0.85, "explanation": []},
        ]
        attack_horizon = {
            "state": "SUSTAINED_ATTACK_FORECAST",
            "onset_horizon": 1,
            "onset_timestamp": "2026-09-10T08:01:00Z",
            "lead_time_seconds": 60,
            "horizon_windows": 3,
            "horizon_seconds": 180,
            "end_horizon": 3,
            "end_timestamp": "2026-09-10T08:03:00Z",
            "decision_threshold": 0.5,
            "temporal_consistency": 1.0,
            "decay_observed": False,
            "confidence_summary": {"mean_confidence": None, "min_confidence": None, "max_confidence": None, "calibration_status": "UNSUPPORTED"},
            "evidence_chain": [
                {"horizon": 1, "horizon_seconds": 60, "predicted_timestamp": "2026-09-10T08:01:00Z", "attack_probability": 0.82, "confidence": None, "predicted_stage": "Reconnaissance", "above_threshold": True, "abstained": False},
                {"horizon": 2, "horizon_seconds": 120, "predicted_timestamp": "2026-09-10T08:02:00Z", "attack_probability": 0.88, "confidence": None, "predicted_stage": "Lateral Movement", "above_threshold": True, "abstained": False},
                {"horizon": 3, "horizon_seconds": 180, "predicted_timestamp": "2026-09-10T08:03:00Z", "attack_probability": 0.80, "confidence": None, "predicted_stage": "Command and Control", "above_threshold": True, "abstained": False},
                {"horizon": 4, "horizon_seconds": 240, "predicted_timestamp": "2026-09-10T08:04:00Z", "attack_probability": 0.35, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False},
                {"horizon": 5, "horizon_seconds": 300, "predicted_timestamp": "2026-09-10T08:05:00Z", "attack_probability": 0.15, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False},
            ],
            "abstention_reason": None,
            "summary": "Sustained attack forecast spanning 3 continuous windows (180s) starting at horizon T+1 (lead time 60s) through T+3.",
        }
        evidence_chain = {
            "current_window_id": "w-demo-sust-10",
            "current_timestamp": timestamp,
            "forecast_horizon": 3,
            "supporting": [
                {"evidence_id": "EV-SUST-01", "timestamp": timestamp, "window_id": "w-demo-sust-10", "evidence_type": "FLOW_ACTIVITY", "feature_name": "flow_count", "observed_value": 280, "baseline_value": 172, "delta": 108, "relative_change": 0.628, "direction": "INCREASE", "severity": "HIGH", "reliability": 1.0, "source": "state.flow_features", "provenance": {"capture_id": "demo-sustained"}, "explanation": "Active concurrent flow volume increased 62.8% over baseline (280.0 vs 172.0).", "is_supporting": True},
                {"evidence_id": "EV-SUST-02", "timestamp": timestamp, "window_id": "w-demo-sust-10", "evidence_type": "PORT_DIVERSITY", "feature_name": "unique_dst_ports", "observed_value": 45, "baseline_value": 31, "delta": 14, "relative_change": 0.452, "direction": "INCREASE", "severity": "MEDIUM", "reliability": 1.0, "source": "state.flow_features", "provenance": {"capture_id": "demo-sustained"}, "explanation": "Destination port diversity increased 45.2% over baseline (45.0 vs 31.0).", "is_supporting": True},
                {"evidence_id": "EV-SUST-03", "timestamp": timestamp, "window_id": "w-demo-sust-10", "evidence_type": "FORECAST_SUPPORT", "feature_name": "attack_horizon", "observed_value": 3, "baseline_value": 0, "delta": 3, "relative_change": 1.0, "direction": "INCREASE", "severity": "HIGH", "reliability": 1.0, "source": "ml.forecasting.attack_horizon", "provenance": {"capture_id": "demo-sustained"}, "explanation": "Forecast rollout indicates sustained attack across 3 windows (180s).", "is_supporting": True},
            ],
            "contradictory": [],
            "evidence_strength": 0.82,
            "evidence_quality": "HIGH",
            "supporting_feature_count": 3,
            "contradictory_feature_count": 0,
            "provenance_complete": True,
            "explanation": "Observation supported by 3 consistent traffic indicators with high evidence quality.",
            "limitations": [],
        }
        confidence = {
            "forecast_score": 0.82,
            "confidence_value": None,
            "confidence_state": "UNCALIBRATED",
            "evidence_strength": 0.82,
            "calibration_status": "UNSUPPORTED",
            "uncertainty_level": "LOW",
            "explanation": "Raw forecast score is 0.82. Model calibration is UNSUPPORTED; score reflects raw model margin, NOT calibrated posterior confidence.",
        }
        unknown_behavior = {
            "classification": "KNOWN_PATTERN",
            "reason": "Observed traffic conforms cleanly to supported multi-step attack progression patterns.",
            "supporting_evidence": ["Active concurrent flow volume increased 62.8%", "Destination port diversity increased 45.2%"],
            "contradictory_evidence": [],
            "coverage": 0.92,
            "abstain_recommended": False,
        }
        abstention = {
            "abstained": False,
            "reason": None,
            "severity": "LOW",
            "status": "FORECAST_AVAILABLE_BUT_UNCALIBRATED",
            "missing_requirements": [],
            "explanation": "Forecast is available and supported by lookback history, but model calibration is UNSUPPORTED.",
        }

    elif scenario_id == "CONTRADICTORY_EVIDENCE":
        traffic = {
            "packets": 32100,
            "flows": 4200,
            "windows": 10,
            "retransmissions": 45,
            "protocol_counts": {"TCP": 21000, "UDP": 9800, "ICMP": 1300},
            "windows_data": [
                {"window_start": i * 60, "window_end": (i + 1) * 60, "packets": 3200, "flows": 420, "bytes": 1400000}
                for i in range(10)
            ],
        }
        quality = {
            "status": "GOOD",
            "packet_loss_ratio": 0.002,
            "reordered_packets": 3,
            "truncated_packets": 0,
            "malformed_packets": 0,
            "capture_duration_seconds": 600,
        }
        detection = {
            "threat_level": "medium",
            "risk_score": 5.1,
            "detected_events": 1,
            "findings": [
                {
                    "finding_id": "FIND-DEMO-CONTRA-01",
                    "attack_category": "ICMP_PRESSURE",
                    "severity": "medium",
                    "timestamp": timestamp,
                    "risk_score": 5.1,
                    "prediction": "Potential Flood",
                    "recommendation": "Verify ICMP echo traffic from management subnet.",
                    "evidence": [{"type": "PACKET_BURST", "message": "Sudden ICMP echo packet spike observed.", "metric": "icmp_packets", "threshold": 500}],
                }
            ],
            "detection_method": "Heuristic Rule Engine (Transparent)",
        }
        forecasts = [
            {"horizon": 1, "attackProbability": 0.54, "predictedStage": "Suspicious", "confidence": None, "uncertainty": 0.72, "explanation": ["ICMP burst elevated score (+0.31)", "Flow durations and TCP metrics stable (-0.27)"]},
            {"horizon": 2, "attackProbability": 0.49, "predictedStage": None, "confidence": None, "uncertainty": 0.76, "explanation": []},
            {"horizon": 3, "attackProbability": 0.42, "predictedStage": None, "confidence": None, "uncertainty": 0.81, "explanation": []},
            {"horizon": 4, "attackProbability": 0.30, "predictedStage": None, "confidence": None, "uncertainty": 0.85, "explanation": []},
            {"horizon": 5, "attackProbability": 0.20, "predictedStage": None, "confidence": None, "uncertainty": 0.89, "explanation": []},
        ]
        attack_horizon = {
            "state": "UNCERTAIN_FORECAST",
            "onset_horizon": 1,
            "onset_timestamp": "2026-09-10T08:01:00Z",
            "lead_time_seconds": 60,
            "horizon_windows": 1,
            "horizon_seconds": 60,
            "end_horizon": 1,
            "end_timestamp": "2026-09-10T08:01:00Z",
            "decision_threshold": 0.5,
            "temporal_consistency": 0.45,
            "decay_observed": True,
            "confidence_summary": {"mean_confidence": None, "min_confidence": None, "max_confidence": None, "calibration_status": "UNSUPPORTED"},
            "evidence_chain": [
                {"horizon": 1, "horizon_seconds": 60, "predicted_timestamp": "2026-09-10T08:01:00Z", "attack_probability": 0.54, "confidence": None, "predicted_stage": "Suspicious", "above_threshold": True, "abstained": False},
                {"horizon": 2, "horizon_seconds": 120, "predicted_timestamp": "2026-09-10T08:02:00Z", "attack_probability": 0.49, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False},
                {"horizon": 3, "horizon_seconds": 180, "predicted_timestamp": "2026-09-10T08:03:00Z", "attack_probability": 0.42, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False},
                {"horizon": 4, "horizon_seconds": 240, "predicted_timestamp": "2026-09-10T08:04:00Z", "attack_probability": 0.30, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False},
                {"horizon": 5, "horizon_seconds": 300, "predicted_timestamp": "2026-09-10T08:05:00Z", "attack_probability": 0.20, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False},
            ],
            "abstention_reason": "CONTRADICTORY_SIGNALS",
            "summary": "Forecast uncertain: Elevated packet burst is directly contradicted by normal flow duration and nominal port distribution.",
        }
        evidence_chain = {
            "current_window_id": "w-demo-contra-10",
            "current_timestamp": timestamp,
            "forecast_horizon": 1,
            "supporting": [
                {"evidence_id": "EV-CONTRA-01", "timestamp": timestamp, "window_id": "w-demo-contra-10", "evidence_type": "PACKET_RATE", "feature_name": "icmp_packet_count", "observed_value": 1300, "baseline_value": 200, "delta": 1100, "relative_change": 5.5, "direction": "INCREASE", "severity": "MEDIUM", "reliability": 0.8, "source": "state.packet_features", "provenance": {"capture_id": "demo-contradictory"}, "explanation": "ICMP packet volume spiked 5.5x above baseline.", "is_supporting": True},
            ],
            "contradictory": [
                {"evidence_id": "EV-CONTRA-02", "timestamp": timestamp, "window_id": "w-demo-contra-10", "evidence_type": "FLOW_STABILITY", "feature_name": "flow_duration_mean", "observed_value": 4.2, "baseline_value": 4.1, "delta": 0.1, "relative_change": 0.024, "direction": "STABLE", "severity": "LOW", "reliability": 1.0, "source": "state.flow_features", "provenance": {"capture_id": "demo-contradictory"}, "explanation": "Flow durations remain completely normal, contradicting automated flood hypothesis.", "is_supporting": False},
                {"evidence_id": "EV-CONTRA-03", "timestamp": timestamp, "window_id": "w-demo-contra-10", "evidence_type": "PORT_DIVERSITY", "feature_name": "unique_dst_ports", "observed_value": 28, "baseline_value": 27, "delta": 1, "relative_change": 0.037, "direction": "STABLE", "severity": "LOW", "reliability": 1.0, "source": "state.flow_features", "provenance": {"capture_id": "demo-contradictory"}, "explanation": "Destination port diversity is unchanged, ruling out multi-target scanning.", "is_supporting": False},
            ],
            "evidence_strength": 0.38,
            "evidence_quality": "MEDIUM",
            "supporting_feature_count": 1,
            "contradictory_feature_count": 2,
            "provenance_complete": True,
            "explanation": "High uncertainty due to conflicting indicators: single metric burst contradicted by 2 primary flow stability metrics.",
            "limitations": [],
        }
        confidence = {
            "forecast_score": 0.54,
            "confidence_value": None,
            "confidence_state": "UNCALIBRATED",
            "evidence_strength": 0.38,
            "calibration_status": "UNSUPPORTED",
            "uncertainty_level": "HIGH",
            "explanation": "High statistical uncertainty. Forecast score margin (0.54) is contradicted by 2 core stability features.",
        }
        unknown_behavior = {
            "classification": "KNOWN_PATTERN",
            "reason": "Traffic patterns are known but contain internal contradiction.",
            "supporting_evidence": ["ICMP ping bursts from diagnostic tool."],
            "contradictory_evidence": ["TCP/UDP flow stability remains baseline."],
            "coverage": 0.88,
            "abstain_recommended": False,
        }
        abstention = {
            "abstained": False,
            "reason": "HIGH_UNCERTAINTY",
            "severity": "MEDIUM",
            "status": "FORECAST_AVAILABLE_BUT_UNCALIBRATED",
            "missing_requirements": [],
            "explanation": "Forecast generated with high uncertainty advisory; analysts should cross-check contradictory metrics.",
        }

    elif scenario_id == "UNKNOWN_BEHAVIOR":
        traffic = {
            "packets": 19400,
            "flows": 2900,
            "windows": 10,
            "retransmissions": 82,
            "protocol_counts": {"TCP": 12000, "UDP": 4400, "UNKNOWN_0x99": 3000},
            "windows_data": [
                {"window_start": i * 60, "window_end": (i + 1) * 60, "packets": 1900, "flows": 290, "bytes": 950000}
                for i in range(10)
            ],
        }
        quality = {
            "status": "GOOD",
            "packet_loss_ratio": 0.003,
            "reordered_packets": 4,
            "truncated_packets": 0,
            "malformed_packets": 0,
            "capture_duration_seconds": 600,
        }
        detection = {
            "threat_level": "low",
            "risk_score": 2.4,
            "detected_events": 0,
            "findings": [],
            "detection_method": "Heuristic Rule Engine (Transparent)",
        }
        forecasts = [
            {"horizon": 1, "attackProbability": 0.44, "predictedStage": None, "confidence": None, "uncertainty": 0.88, "explanation": ["OOD traffic distance exceeds known cluster boundaries"]},
            {"horizon": 2, "attackProbability": 0.42, "predictedStage": None, "confidence": None, "uncertainty": 0.90, "explanation": []},
            {"horizon": 3, "attackProbability": 0.41, "predictedStage": None, "confidence": None, "uncertainty": 0.92, "explanation": []},
            {"horizon": 4, "attackProbability": 0.38, "predictedStage": None, "confidence": None, "uncertainty": 0.94, "explanation": []},
            {"horizon": 5, "attackProbability": 0.35, "predictedStage": None, "confidence": None, "uncertainty": 0.95, "explanation": []},
        ]
        attack_horizon = {
            "state": "UNCERTAIN_FORECAST",
            "onset_horizon": None,
            "onset_timestamp": None,
            "lead_time_seconds": None,
            "horizon_windows": 0,
            "horizon_seconds": 0,
            "end_horizon": None,
            "end_timestamp": None,
            "decision_threshold": 0.5,
            "temporal_consistency": 0.20,
            "decay_observed": False,
            "confidence_summary": {"mean_confidence": None, "min_confidence": None, "max_confidence": None, "calibration_status": "UNSUPPORTED"},
            "evidence_chain": [
                {"horizon": i, "horizon_seconds": i * 60, "predicted_timestamp": f"2026-09-10T08:0{i}:00Z", "attack_probability": 0.44 - (i * 0.02), "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": False}
                for i in range(1, 6)
            ],
            "abstention_reason": "OUT_OF_DISTRIBUTION_BEHAVIOR",
            "summary": "Out-of-distribution traffic detected. Behavior falls outside supported feature manifold. Automatic attack classification withheld.",
        }
        evidence_chain = {
            "current_window_id": "w-demo-ood-10",
            "current_timestamp": timestamp,
            "forecast_horizon": 0,
            "supporting": [],
            "contradictory": [],
            "evidence_strength": 0.25,
            "evidence_quality": "INSUFFICIENT",
            "supporting_feature_count": 0,
            "contradictory_feature_count": 0,
            "provenance_complete": True,
            "explanation": "Observed traffic falls outside supported feature distribution (Mahalanobis distance = 14.8).",
            "limitations": [
                {"type": "OUT_OF_DISTRIBUTION", "description": "Protocol IP 0x99 is not in the canonical feature space.", "impact": "Feature extraction incomplete"}
            ],
        }
        confidence = {
            "forecast_score": 0.44,
            "confidence_value": None,
            "confidence_state": "UNCALIBRATED",
            "evidence_strength": 0.25,
            "calibration_status": "UNSUPPORTED",
            "uncertainty_level": "HIGH",
            "explanation": "Out-of-distribution traffic. Model confidence is withheld due to high epistemic distance.",
        }
        unknown_behavior = {
            "classification": "UNKNOWN_BEHAVIOR",
            "reason": "Traffic profile exhibits high Mahalanobis distance from training distributions and non-standard IP protocol framing.",
            "supporting_evidence": ["Protocol number 0x99 observed in 3,000 packets.", "Feature correlation matrix diverges from normal traffic."],
            "contradictory_evidence": [],
            "coverage": 0.38,
            "abstain_recommended": True,
        }
        abstention = {
            "abstained": False,
            "reason": "OUT_OF_DISTRIBUTION",
            "severity": "MEDIUM",
            "status": "FORECAST_AVAILABLE_BUT_UNCALIBRATED",
            "missing_requirements": ["Known protocol manifold mapping"],
            "explanation": "Traffic is classified as UNKNOWN_BEHAVIOR (out-of-distribution). Not labeled an attack.",
        }

    elif scenario_id == "FORECAST_ABSTAINED":
        traffic = {
            "packets": 5100,
            "flows": 820,
            "windows": 3,
            "retransmissions": 12,
            "protocol_counts": {"TCP": 4100, "UDP": 900, "ICMP": 100},
            "windows_data": [
                {"window_start": 0, "window_end": 60, "packets": 1700, "flows": 280, "bytes": 450000},
                {"window_start": 60, "window_end": 120, "packets": 1800, "flows": 290, "bytes": 480000},
                {"window_start": 360, "window_end": 420, "packets": 1600, "flows": 250, "bytes": 420000},
            ],
        }
        quality = {
            "status": "DEGRADED",
            "packet_loss_ratio": 0.005,
            "reordered_packets": 1,
            "truncated_packets": 0,
            "malformed_packets": 0,
            "capture_duration_seconds": 420,
        }
        detection = {
            "threat_level": "low",
            "risk_score": 1.5,
            "detected_events": 0,
            "findings": [],
            "detection_method": "Heuristic Rule Engine (Transparent)",
        }
        forecasts = [
            {"horizon": i, "attackProbability": None, "predictedStage": None, "confidence": None, "uncertainty": None, "explanation": ["Forecast withheld: Lookback history contains a 240s timestamp gap and only 3 windows."]}
            for i in range(1, 6)
        ]
        attack_horizon = {
            "state": "ABSTAINED",
            "onset_horizon": None,
            "onset_timestamp": None,
            "lead_time_seconds": None,
            "horizon_windows": 0,
            "horizon_seconds": 0,
            "end_horizon": None,
            "end_timestamp": None,
            "decision_threshold": 0.5,
            "temporal_consistency": 0.0,
            "decay_observed": False,
            "confidence_summary": {"mean_confidence": None, "min_confidence": None, "max_confidence": None, "calibration_status": "UNSUPPORTED"},
            "evidence_chain": [
                {"horizon": i, "horizon_seconds": i * 60, "predicted_timestamp": None, "attack_probability": None, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": True}
                for i in range(1, 6)
            ],
            "abstention_reason": "INSUFFICIENT_LOOKBACK_HISTORY",
            "summary": "Forecast deliberately withheld: Capture contains insufficient temporal lookback history (3 windows observed; minimum 8 required) with a 240s gap.",
        }
        evidence_chain = {
            "current_window_id": "w-demo-abst-03",
            "current_timestamp": timestamp,
            "forecast_horizon": 0,
            "supporting": [],
            "contradictory": [],
            "evidence_strength": 0.0,
            "evidence_quality": "INSUFFICIENT",
            "supporting_feature_count": 0,
            "contradictory_feature_count": 0,
            "provenance_complete": True,
            "explanation": "Evidence extraction withheld due to discontinuous temporal observation history.",
            "limitations": [
                {"type": "LOOKBACK_GAP", "description": "Contiguous timestamp sequence broken between window 2 and 3 (gap 240s).", "impact": "Lookback state invalid"}
            ],
        }
        confidence = {
            "forecast_score": None,
            "confidence_value": None,
            "confidence_state": "WITHHELD",
            "evidence_strength": 0.0,
            "calibration_status": "UNSUPPORTED",
            "uncertainty_level": "HIGH",
            "explanation": "Confidence score cannot be calculated because forecasting was withheld by the epistemic safety gate.",
        }
        unknown_behavior = {
            "classification": "KNOWN_PATTERN",
            "reason": "Traffic framing is recognized, but temporal depth is insufficient.",
            "supporting_evidence": [],
            "contradictory_evidence": [],
            "coverage": 0.90,
            "abstain_recommended": True,
        }
        abstention = {
            "abstained": True,
            "reason": "INSUFFICIENT_LOOKBACK_HISTORY",
            "severity": "HIGH",
            "status": "FORECAST_UNAVAILABLE",
            "missing_requirements": [
                "Contiguous lookback sequence >= 8 windows (observed: 3 windows)",
                "Zero inter-window timestamp gaps > 60s (observed: 240s gap)",
            ],
            "explanation": "NexSolve does not have enough reliable evidence to forecast the next network state. Deliberate safety abstention triggered.",
        }

    elif scenario_id == "POOR_CAPTURE_QUALITY":
        traffic = {
            "packets": 12800,
            "flows": 2100,
            "windows": 10,
            "retransmissions": 1820,
            "protocol_counts": {"TCP": 10200, "UDP": 2400, "ICMP": 200},
            "windows_data": [
                {"window_start": i * 60, "window_end": (i + 1) * 60, "packets": 1280, "flows": 210, "bytes": 520000}
                for i in range(10)
            ],
        }
        quality = {
            "status": "DEGRADED",
            "packet_loss_ratio": 0.224,
            "reordered_packets": 312,
            "truncated_packets": 482,
            "malformed_packets": 94,
            "capture_duration_seconds": 600,
        }
        detection = {
            "threat_level": "medium",
            "risk_score": 4.8,
            "detected_events": 1,
            "findings": [
                {
                    "finding_id": "FIND-DEMO-QUAL-01",
                    "attack_category": "TCP_RETRANSMISSION_SURGE",
                    "severity": "medium",
                    "timestamp": timestamp,
                    "risk_score": 4.8,
                    "prediction": "Loss Artifact or Interference",
                    "recommendation": "Inspect SPAN port configuration and NIC drop counters.",
                    "evidence": [{"type": "RETRANSMISSION_RATE", "message": "High TCP retransmission rate (14.2%).", "metric": "retransmission_ratio", "threshold": 0.05}],
                }
            ],
            "detection_method": "Heuristic Rule Engine (Transparent)",
        }
        forecasts = [
            {"horizon": i, "attackProbability": None, "predictedStage": None, "confidence": None, "uncertainty": None, "explanation": ["Forecast withheld: Capture quality degraded (22.4% packet loss, 482 truncated frames)."]}
            for i in range(1, 6)
        ]
        attack_horizon = {
            "state": "ABSTAINED",
            "onset_horizon": None,
            "onset_timestamp": None,
            "lead_time_seconds": None,
            "horizon_windows": 0,
            "horizon_seconds": 0,
            "end_horizon": None,
            "end_timestamp": None,
            "decision_threshold": 0.5,
            "temporal_consistency": 0.0,
            "decay_observed": False,
            "confidence_summary": {"mean_confidence": None, "min_confidence": None, "max_confidence": None, "calibration_status": "UNSUPPORTED"},
            "evidence_chain": [
                {"horizon": i, "horizon_seconds": i * 60, "predicted_timestamp": None, "attack_probability": None, "confidence": None, "predicted_stage": None, "above_threshold": False, "abstained": True}
                for i in range(1, 6)
            ],
            "abstention_reason": "CAPTURE_QUALITY_DEGRADED",
            "summary": "Forecast deliberately withheld: Capture exhibits severe packet loss (22.4%) and packet truncation. Ground-truth state reconstruction cannot be validated.",
        }
        evidence_chain = {
            "current_window_id": "w-demo-qual-10",
            "current_timestamp": timestamp,
            "forecast_horizon": 0,
            "supporting": [],
            "contradictory": [],
            "evidence_strength": 0.0,
            "evidence_quality": "INSUFFICIENT",
            "supporting_feature_count": 0,
            "contradictory_feature_count": 0,
            "provenance_complete": False,
            "explanation": "Evidence cannot be reliably verified due to severe capture degradation.",
            "limitations": [
                {"type": "PACKET_LOSS", "description": "Packet loss ratio 22.4% exceeds maximum tolerance of 5.0%.", "impact": "Flow reconstruction incomplete"},
                {"type": "TRUNCATED_FRAMES", "description": "482 frames truncated before IP payload header.", "impact": "Layer-4 feature distortion"},
                {"type": "OUT_OF_ORDER", "description": "312 TCP sequence anomalies observed.", "impact": "State timing skewed"},
            ],
        }
        confidence = {
            "forecast_score": None,
            "confidence_value": None,
            "confidence_state": "WITHHELD",
            "evidence_strength": 0.0,
            "calibration_status": "UNSUPPORTED",
            "uncertainty_level": "HIGH",
            "explanation": "Confidence withheld. Ingested capture fails capture integrity standards.",
        }
        unknown_behavior = {
            "classification": "WEAK_PATTERN",
            "reason": "High loss rates obscure genuine protocol behaviors.",
            "supporting_evidence": [],
            "contradictory_evidence": [],
            "coverage": 0.62,
            "abstain_recommended": True,
        }
        abstention = {
            "abstained": True,
            "reason": "CAPTURE_QUALITY_DEGRADED",
            "severity": "HIGH",
            "status": "FORECAST_UNAVAILABLE",
            "missing_requirements": [
                "Packet loss ratio < 5.0% (observed: 22.4%)",
                "Truncated packet count = 0 (observed: 482)",
            ],
            "explanation": "NexSolve withheld prediction because capture quality is compromised. Operating on damaged data produces unreliable hallucinations.",
        }

    else:
        raise ValueError(f"Unknown demo scenario: {scenario_id}")

    analysis_id = f"demo-{scenario_id.lower()}"
    clean_name = f"demo_{scenario_id.lower()}.pcap"

    return {
        "analysis_id": analysis_id,
        "status": "completed",
        "is_demo": True,
        "demo_scenario_id": scenario_id,
        "demo_scenario_name": meta["name"],
        "demo_scenario_description": meta["description"],
        "demo_expected_behavior": meta["expected_behavior"],
        "source": {
            "name": f"[DEMO MODE] {meta['name']}",
            "kind": "demo_scenario",
            "filename": clean_name,
            "size_bytes": traffic["packets"] * 128,
        },
        "upload": {
            "filename": clean_name,
            "size_bytes": traffic["packets"] * 128,
            "format": "pcap",
        },
        "validation": {
            "status": "VALID",
            "rows": traffic["windows"],
            "columns": ["window_start", "window_end", "packets", "flows", "bytes"],
            "dtypes": {"packets": "int64", "flows": "int64", "bytes": "int64"},
            "null_counts": {},
            "null_ratios": {},
            "protocol_counts": traffic["protocol_counts"],
            "window": {"unit": "UTC epoch seconds", "seconds": 60, "ordered": True},
            "model_compatibility": {
                "flow_features_available": True,
                "packet_features_available": True,
                "labels_available": False,
                "forecast_model_ready": not abstention["abstained"],
                "reason": abstention["reason"] if abstention["abstained"] else "Temporal sequence criteria satisfied.",
            },
        },
        "traffic": traffic,
        "detection": detection,
        "quality": quality,
        "packet_count": traffic["packets"],
        "window_count": traffic["windows"],
        "duration_seconds": traffic["windows"] * 60,
        "protocol_summary": traffic["protocol_counts"],
        "findings": detection["findings"],
        "summary": {
            "packet_count": traffic["packets"],
            "window_count": traffic["windows"],
            "finding_count": detection["detected_events"],
            "threat_level": detection["threat_level"],
        },
        # Forecast and Trust Layer
        "forecasts": forecasts,
        "attack_horizon": attack_horizon,
        "attackHorizon": attack_horizon,
        "evidence_chain": evidence_chain,
        "evidenceChain": evidence_chain,
        "confidence": confidence,
        "unknown_behavior": unknown_behavior,
        "unknownBehavior": unknown_behavior,
        "abstention": abstention,
        "processing_metrics": {
            "upload_validation_ms": 0.42,
            "pcap_parsing_ms": 12.18,
            "flow_reconstruction_ms": 18.35,
            "window_generation_ms": 6.12,
            "network_state_extraction_ms": 9.45,
            "forecasting_ms": 14.80,
            "evidence_generation_ms": 8.22,
            "report_generation_ms": 11.54,
            "total_processing_ms": 81.08,
        },
    }


def get_demo_scenarios_metadata() -> list[dict[str, Any]]:
    """Return list of scenario metadata cards for UI selection."""
    return DEMO_SCENARIO_METADATA


def get_demo_scenario(scenario_id: str) -> dict[str, Any]:
    """Return full production-compatible analysis payload for a scenario."""
    clean_id = scenario_id.upper().strip()
    return _build_scenario_payload(clean_id)


def get_demo_report_json(scenario_id: str) -> str:
    """Generate 13-section JSON report for a demo scenario."""
    payload = get_demo_scenario(scenario_id)
    report_obj = assemble_report(
        analysis_result=payload,
        job_id=payload["analysis_id"],
        capture_hash=f"sha256-demo-{scenario_id.lower()}-synthetic",
        model_version="nexsolve-v1.0-persistence-champion",
        processing_seconds=0.081,
    )
    return generate_json_report(report_obj)


def get_demo_report_html(scenario_id: str) -> str:
    """Generate printable, standalone HTML forensic report for a demo scenario."""
    payload = get_demo_scenario(scenario_id)
    report_obj = assemble_report(
        analysis_result=payload,
        job_id=payload["analysis_id"],
        capture_hash=f"sha256-demo-{scenario_id.lower()}-synthetic",
        model_version="nexsolve-v1.0-persistence-champion",
        processing_seconds=0.081,
    )
    return generate_html_report(report_obj)
