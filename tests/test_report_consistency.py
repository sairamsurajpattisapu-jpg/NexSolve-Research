"""Regression tests for report consistency across real and short PCAP captures."""
from __future__ import annotations

import json
import pytest

from reporting.report_engine import assemble_report, generate_html_report, generate_json_report


def test_bug1_timestamp_and_duration_consistency():
    """Verify that packet timestamp span and temporal window coverage are properly distinguished."""
    raw_analysis = {
        "analysis_id": "test-small-burst",
        "validation": {
            "rows": 1,
            "window": {
                "unit": "UTC epoch seconds",
                "seconds": 60,
                "start_min": 1726059780,
                "start_max": 1726059780,
                "ordered": True,
            },
        },
        "traffic": {
            "packets": 20,
            "flows": 5,
            "bytes": 2000,
            "packet_timestamp_span_seconds": 0.0,
            "temporal_window_coverage_seconds": 60.0,
            "duration_seconds": 60.0,
            "protocol_counts": {"TCP": 20},
            "rate_trend": "STABLE",
            "churn_trend": "LOW",
        },
        "detection": {"status": "completed", "threat_level": "LOW", "findings": []},
        "quality": {
            "status": "DEGRADED",
            "quality_status": "DEGRADED",
            "packet_loss_ratio": 0.0,
            "malformed_packets": 0,
        },
        "abstention": {
            "abstained": True,
            "status": "INSUFFICIENT_HISTORY",
            "explanation": "Capture has 1 / 8 required windows.",
        },
    }

    report = assemble_report(raw_analysis)
    
    # 1. Network Activity Summary
    assert report.network_activity.packet_timestamp_span_seconds == 0.0
    assert report.network_activity.temporal_window_coverage_seconds == 60.0
    assert report.network_activity.duration_seconds == 60.0
    
    # 2. Temporal Behavior
    assert report.temporal_behavior.packet_timestamp_span_seconds == 0.0
    assert report.temporal_behavior.temporal_window_coverage_seconds == 60.0
    # Latest timestamp reflects the window coverage boundary (start + window_seconds)
    assert report.temporal_behavior.latest_timestamp > report.temporal_behavior.earliest_timestamp
    
    # Check HTML representation
    html_out = generate_html_report(report)
    assert "Packet Timestamp Span: 0.00s" in html_out
    assert "Temporal Window Coverage" in html_out


def test_bug2_capture_quality_and_evidence_consistency():
    """Verify that capture_quality and evidence_chain agree on DEGRADED status without contradiction."""
    raw_analysis = {
        "analysis_id": "test-quality-alignment",
        "quality": {
            "status": "DEGRADED",
            "quality_status": "DEGRADED",
            "packet_loss_ratio": 0.0,
            "malformed_packets": 0,
        },
        "evidence_chain": {
            "evidence_strength": 0.5,
            "evidence_quality": "DEGRADED",
            "supporting": [],
            "contradictory": [],
            "explanation": "Underlying network capture is flagged DEGRADED.",
        },
    }

    report = assemble_report(raw_analysis)
    
    # Both must report DEGRADED
    assert report.capture_quality.quality_status == "DEGRADED"
    assert report.evidence_chain.evidence_quality == "DEGRADED"
    
    json_str = generate_json_report(report)
    data = json.loads(json_str)
    assert data["sections"]["capture_quality"]["quality_status"] == "DEGRADED"
    assert data["sections"]["evidence_chain"]["evidence_quality"] == "DEGRADED"


def test_bug3_abstained_forecast_semantics():
    """Verify that abstained forecast reports do not treat null predictions as zero-attack predictions."""
    raw_analysis = {
        "analysis_id": "test-abstained-forecast",
        "abstention": {
            "abstained": True,
            "reason": "INSUFFICIENT_HISTORY",
            "status": "INSUFFICIENT_HISTORY",
            "explanation": "Only 1 of 8 required 60s windows available.",
            "missing_requirements": ["At least 8 consecutive 60s windows"],
        },
        "forecasts": [],  # No valid forecast points
    }

    report = assemble_report(raw_analysis)
    
    assert report.abstention.abstained is True
    # Verify forecast points have None for probabilities and stages
    for pt in report.forecast.forecast_points:
        assert pt.attack_probability is None
        assert pt.predicted_stage is None
        assert pt.confidence is None
        assert pt.uncertainty is None
    
    html_out = generate_html_report(report)
    assert "WITHHELD (ABSTAINED)" in html_out
    assert "N/A (abstained)" in html_out


def test_bug4_abstained_attack_horizon_semantics():
    """Verify that attack horizon for an abstained forecast exposes clean N/A rather than misleading zeros."""
    raw_analysis = {
        "analysis_id": "test-abstained-horizon",
        "abstention": {
            "abstained": True,
            "reason": "INSUFFICIENT_HISTORY",
            "status": "INSUFFICIENT_HISTORY",
            "explanation": "Capture duration insufficient.",
        },
        "attack_horizon": {
            "state": "ABSTAINED",
            "onset_horizon": None,
            "lead_time_seconds": None,
            "horizon_windows": 0,
            "horizon_seconds": 0,
            "temporal_consistency": 0.0,
            "summary": "Attack horizon evaluation abstained: INSUFFICIENT_HISTORY",
        },
        "confidence": {
            "forecast_score": 0.0,
            "confidence_value": None,
            "confidence_state": "WITHHELD",
            "calibration_status": "UNSUPPORTED",
            "uncertainty_level": "UNKNOWN",
        },
    }

    report = assemble_report(raw_analysis)
    
    assert report.attack_horizon.state == "ABSTAINED"
    assert report.attack_horizon.lead_time_seconds is None
    assert report.attack_horizon.onset_horizon is None
    
    html_out = generate_html_report(report)
    assert "Lead Time: N/A (abstained)" in html_out
    assert "N/A (abstained)" in html_out
    # Raw Model Score should not show misleading 0.0000
    assert "0.0000" not in html_out


def test_real_pcap_end_to_end_small_capture():
    """Verify that a real 20-packet capture in 1 window produces completely consistent reports end-to-end."""
    import tempfile
    from pathlib import Path
    from scapy.all import Ether, IP, TCP, wrpcap
    from model_service.pcap_upload import analyze_uploaded_capture

    base_epoch = 1726059780.0  # 18:23:00 UTC
    packets = []
    for i in range(20):
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src=f"192.168.1.{i % 4 + 1}", dst="10.0.0.1") / TCP(sport=1000 + i, dport=80, flags="S")
        pkt.time = base_epoch + 0.001 * (i % 2)
        packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        content = temp_path.read_bytes()
        analysis = analyze_uploaded_capture("nexsolve_test_small.pcap", content)

        report = assemble_report(analysis)
        report_dict = report.to_dict()

        # 1. Packet count and window count
        assert report_dict["sections"]["network_activity"]["packet_count"] == 20
        assert report_dict["sections"]["temporal_behavior"]["window_count"] == 1

        # 2. Timestamp span vs window coverage
        assert report_dict["sections"]["network_activity"]["packet_timestamp_span_seconds"] < 1.0
        assert report_dict["sections"]["network_activity"]["temporal_window_coverage_seconds"] == 60.0
        assert report_dict["sections"]["temporal_behavior"]["temporal_window_coverage_seconds"] == 60.0

        # 3. Capture quality consistency
        cap_status = report_dict["sections"]["capture_quality"]["quality_status"]
        ev_quality = report_dict["sections"]["evidence_chain"]["evidence_quality"]
        assert cap_status == ev_quality, f"Contradiction: capture_quality is {cap_status} but evidence_quality is {ev_quality}"

        # 4. Forecast abstention semantics
        assert report_dict["sections"]["abstention"]["abstained"] is True
        assert report_dict["sections"]["forecast"]["abstained"] is True
        for pt in report_dict["sections"]["forecast"]["forecast_points"]:
            assert pt["attack_probability"] is None
            assert pt["predicted_stage"] is None

        # 5. Attack horizon semantics
        assert report_dict["sections"]["attack_horizon"]["state"] == "ABSTAINED"
        assert report_dict["sections"]["attack_horizon"]["lead_time_seconds"] is None
        assert report_dict["sections"]["attack_horizon"]["onset_horizon"] is None

        # 6. HTML report rendering
        html_report = generate_html_report(report)
        assert "Packet Timestamp Span:" in html_report
        assert "WITHHELD (ABSTAINED)" in html_report
        assert "N/A (abstained)" in html_report
    finally:
        temp_path.unlink(missing_ok=True)

