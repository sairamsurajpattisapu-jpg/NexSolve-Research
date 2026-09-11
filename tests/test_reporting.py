"""Unit tests for NexSolve Report Generation Engine (JSON and HTML)."""
from __future__ import annotations

import json
import pytest

from reporting.report_engine import assemble_report, generate_html_report, generate_json_report


@pytest.fixture
def sample_analysis_result() -> dict:
    return {
        "analysis_id": "analysis-test-123",
        "status": "completed",
        "source": {
            "name": "sample_traffic.pcap",
            "filename": "sample_traffic.pcap",
            "size_bytes": 10240,
        },
        "validation": {
            "rows": 8,
            "window": {
                "unit": "UTC epoch seconds",
                "seconds": 60,
                "start_min": 1773302400,
                "start_max": 1773302820,
                "ordered": True,
            },
        },
        "traffic": {
            "packets": 1500,
            "flows": 120,
            "bytes": 204800,
            "duration_seconds": 480.0,
            "protocol_counts": {"TCP": 1200, "UDP": 300},
            "tcp_flag_counts": {"SYN": 450, "ACK": 1200},
            "unique_src_ips": 5,
            "unique_dst_ips": 12,
            "unique_dst_ports": 8,
            "rate_trend": "INCREASING",
            "churn_trend": "ELEVATED",
        },
        "detection": {
            "status": "completed",
            "threat_level": "HIGH",
            "detected_events": 2,
            "findings": [
                {
                    "rule_id": "SYN_FLOOD_ANOMALY",
                    "explanation": "Observed SYN/ACK ratio skewed > 3.5:1",
                    "severity": "HIGH",
                }
            ],
        },
        "quality": {
            "capture_id": "pcap-001",
            "parsed_packets": 1500,
            "total_packets_observed": 1520,
            "malformed_packets": 2,
            "truncated_packets": 0,
            "reordered_packets": 4,
            "packet_loss_ratio": 0.013,
        },
        "forecasts": [
            {
                "horizon": 1,
                "attackProbability": 0.85,
                "predictedStage": "Reconnaissance",
                "confidence": None,
                "uncertainty": 0.30,
                "explanation": ["flow_count surge +45%"],
            },
            {
                "horizon": 2,
                "attackProbability": 0.90,
                "predictedStage": "Lateral Movement",
                "confidence": None,
                "uncertainty": 0.20,
                "explanation": ["port_entropy +0.32"],
            },
        ],
        "attack_horizon": {
            "state": "SUSTAINED_ATTACK_FORECAST",
            "onset_horizon": 1,
            "onset_timestamp": "2026-09-10T06:01:00Z",
            "lead_time_seconds": 60,
            "horizon_windows": 2,
            "horizon_seconds": 120,
            "end_horizon": 2,
            "end_timestamp": "2026-09-10T06:02:00Z",
            "temporal_consistency": 1.0,
            "decay_observed": False,
            "summary": "Sustained multi-window forecast spanning 120s.",
        },
        "evidence_chain": {
            "evidence_strength": 0.88,
            "evidence_quality": "HIGH",
            "supporting": [
                {
                    "evidence_id": "EV-1",
                    "evidence_type": "FLOW_CHURN",
                    "feature_name": "flow_count",
                    "observed_value": 450.0,
                    "baseline_value": 200.0,
                    "relative_change": 1.25,
                    "direction": "INCREASE",
                    "severity": "HIGH",
                    "explanation": "Flow count surged +125% over baseline.",
                }
            ],
            "contradictory": [
                {
                    "evidence_id": "EV-2",
                    "evidence_type": "TRAFFIC_VOLUME",
                    "feature_name": "total_bytes",
                    "observed_value": 5000.0,
                    "baseline_value": 12000.0,
                    "relative_change": -0.58,
                    "direction": "DECREASE",
                    "severity": "MEDIUM",
                    "explanation": "Byte throughput dropped 58%.",
                }
            ],
            "explanation": "Strong flow churn indicates active reconnaissance despite throughput drop.",
            "limitations": ["Packet reordering observed in capture pipeline."],
        },
        "confidence": {
            "forecast_score": 0.85,
            "confidence_value": None,
            "confidence_state": "UNCALIBRATED",
            "calibration_status": "UNSUPPORTED",
            "uncertainty_level": "LOW",
        },
        "unknown_behavior": {
            "classification": "KNOWN_PATTERN",
            "reason": "Observed traffic conforms to supported reconnaissance patterns.",
            "supporting_evidence": ["Flow churn elevated"],
            "contradictory_evidence": [],
            "coverage": 0.95,
            "abstain_recommended": False,
        },
        "abstention": {
            "abstained": False,
            "reason": None,
            "severity": "LOW",
            "status": "FORECAST_AVAILABLE_BUT_UNCALIBRATED",
            "missing_requirements": [],
            "explanation": "Sequence meets all historical length and contiguity preconditions.",
        },
    }


def test_assemble_report_populates_all_13_sections(sample_analysis_result):
    report = assemble_report(sample_analysis_result, job_id="job-sample-123", capture_hash="abc123hash", processing_seconds=1.45)
    
    assert report.report_id == "rep-job-sample-123"
    assert report.system_tagline == "Evidence-backed predictive network intelligence"
    
    # Check sections
    d = report.to_dict()
    secs = d["sections"]
    expected_sections = [
        "executive_summary",
        "capture_quality",
        "network_activity",
        "temporal_behavior",
        "forecast",
        "attack_horizon",
        "evidence_chain",
        "confidence",
        "unknown_behavior",
        "abstention",
        "limitations",
        "provenance",
        "processing_metadata",
    ]
    for sec_name in expected_sections:
        assert sec_name in secs, f"Missing section: {sec_name}"


def test_epistemic_categories_distinguished(sample_analysis_result):
    report = assemble_report(sample_analysis_result)
    secs = report.to_dict()["sections"]
    
    assert secs["capture_quality"]["category"] == "OBSERVED"
    assert secs["network_activity"]["category"] == "OBSERVED"
    assert secs["temporal_behavior"]["category"] == "OBSERVED"
    assert secs["forecast"]["category"] == "FORECAST"
    assert secs["attack_horizon"]["category"] == "FORECAST"
    assert secs["evidence_chain"]["category"] == "INFERRED"
    assert secs["confidence"]["category"] == "INFERRED"
    assert secs["unknown_behavior"]["category"] == "UNKNOWN"
    assert secs["abstention"]["category"] == "ABSTAINED"


def test_confidence_disclaimer_and_uncalibrated_policy(sample_analysis_result):
    report = assemble_report(sample_analysis_result)
    conf = report.confidence
    assert conf.confidence_value is None
    assert conf.calibration_status == "UNSUPPORTED"
    assert "uncalibrated" in conf.disclaimer.lower()


def test_supporting_and_contradictory_evidence_included(sample_analysis_result):
    report = assemble_report(sample_analysis_result)
    ev = report.evidence_chain
    assert len(ev.supporting_evidence) == 1
    assert len(ev.contradictory_evidence) == 1
    assert ev.supporting_evidence[0].feature_name == "flow_count"
    assert ev.contradictory_evidence[0].feature_name == "total_bytes"


def test_json_report_serialization(sample_analysis_result):
    report = assemble_report(sample_analysis_result)
    json_text = generate_json_report(report)
    parsed = json.loads(json_text)
    assert parsed["report_id"] == report.report_id
    assert parsed["sections"]["executive_summary"]["overall_threat_level"] == "HIGH"


def test_html_report_printable_and_no_external_cdns(sample_analysis_result):
    report = assemble_report(sample_analysis_result)
    html_text = generate_html_report(report)
    
    assert "<!DOCTYPE html>" in html_text
    assert "@media print" in html_text
    assert "http://" not in html_text
    assert "https://" not in html_text
    assert "NexSolve" in html_text
    assert "Evidence-backed predictive network intelligence" in html_text
    assert "SUPPORTING" in html_text
    assert "CONTRADICTORY" in html_text


def test_html_report_xss_escaping():
    malicious = {
        "analysis_id": "test-xss",
        "source": {"filename": "<img src=x onerror=alert(1)>.pcap", "size_bytes": 100},
        "validation": {},
        "traffic": {"packets": 10},
        "detection": {
            "threat_level": "LOW",
            "findings": [{"explanation": "<script>alert('xss')</script> and <b>bold</b>"}],
        },
        "quality": {},
    }
    report = assemble_report(malicious)
    html_text = generate_html_report(report)
    
    assert "<script>alert('xss')</script>" not in html_text
    assert "<img src=x onerror=alert(1)>" not in html_text
    assert "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;" in html_text
    assert "&lt;img src=x onerror=alert(1)&gt;" in html_text
    assert "&lt;b&gt;bold&lt;/b&gt;" in html_text
