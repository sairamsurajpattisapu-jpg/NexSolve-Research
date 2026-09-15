"""Automated End-to-End Test Suite for NexSolve PCAP Demonstration Product.

Verifies:
1. Valid PCAP processing through canonical pipeline (10-window real capture).
2. Strict 45-feature PCAP contract (zero-fabrication of mean_tcp_rtt).
3. Insufficient history (<8 windows) triggers calibrated abstention without crashing.
4. Empty and corrupted PCAP files raise clean, sanitized exceptions.
5. Unified CLI runner (python -m nexsolve forecast) executes with exit code 0.
6. Standalone HTML and JSON reports are generated with complete sections and non-zero size.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from model_service.pcap_upload import analyze_uploaded_capture
from reporting.report_engine import assemble_report, generate_html_report, generate_json_report

ROOT = Path(__file__).resolve().parents[1]
TEST_PCAP = ROOT / "data" / "test_slices" / "friday_10windows_slice.pcap"
SHORT_PCAP = ROOT / "research" / "open_source" / "nfstream" / "nfstream-master" / "tests" / "pcaps" / "1kxun.pcap"


@pytest.mark.skipif(not TEST_PCAP.exists(), reason="Test PCAP slice not found")
def test_valid_pcap_end_to_end_journey():
    """Verify full 16-step user journey on real 10-window capture."""
    content = TEST_PCAP.read_bytes()
    analysis = analyze_uploaded_capture("friday_10windows_slice.pcap", content)

    # 1. Pipeline and Ingestion
    assert analysis["status"] == "completed"
    assert analysis["packet_count"] == 2277
    assert analysis["window_count"] == 10
    assert analysis["duration_seconds"] == 600

    # 2. 45-Feature PCAP Compatibility & Safety Gate
    compat = analysis["model_compatibility"]
    assert compat["model_ready"] is True
    assert compat["schema_variant"] == "45_feature_pcap_compatible"
    assert "flow_features.mean_tcp_rtt" not in compat.get("available_features", [])

    # 3. Forecast Rollout & Monotonic Cumulative Risk
    forecasts = analysis["forecasts"]
    assert len(forecasts) == 5
    cum_risks = [f["cumulativeRisk"] for f in forecasts]
    assert all(r is not None for r in cum_risks)
    for i in range(1, len(cum_risks)):
        assert cum_risks[i] >= cum_risks[i - 1], f"Cumulative risk must be non-decreasing: {cum_risks}"

    # 4. Top Drivers & Explainability
    first_f = forecasts[0]
    assert "topDrivers" in first_f
    assert len(first_f["topDrivers"]) > 0
    assert all("feature" in d and "direction" in d for d in first_f["topDrivers"])

    # 5. Early Warning Score
    assert "early_warning" in analysis
    ew = analysis["early_warning"]
    assert 0 <= ew["early_warning_score"] <= 100
    assert ew["early_warning_level"] in ("NORMAL", "ELEVATED", "HIGH", "CRITICAL")

    # 6. Report Generation
    report = assemble_report(analysis)
    html_out = generate_html_report(report)
    json_out = generate_json_report(report)
    assert len(html_out) > 500
    assert "<!DOCTYPE html>" in html_out
    assert "NexSolve" in html_out
    assert len(json_out) > 500
    parsed_json = json.loads(json_out)
    assert parsed_json["report_id"].startswith("rep-")


@pytest.mark.skipif(not SHORT_PCAP.exists(), reason="Short PCAP file not found")
def test_insufficient_history_abstention():
    """Verify that a capture with < 8 windows abstains gracefully according to safety contract."""
    content = SHORT_PCAP.read_bytes()
    analysis = analyze_uploaded_capture("1kxun.pcap", content)

    assert analysis["status"] == "completed"
    assert analysis["window_count"] < 8
    abstention = analysis.get("abstention") or {}
    assert abstention.get("abstained") is True
    assert abstention.get("reason") == "INSUFFICIENT_HISTORY"


def test_empty_pcap_error_handling():
    """Empty capture raises ValueError with informative message."""
    with pytest.raises(ValueError, match="empty"):
        analyze_uploaded_capture("empty.pcap", b"")


def test_corrupt_pcap_error_handling():
    """Corrupted / non-PCAP bytes raise clean error."""
    with pytest.raises(RuntimeError, match="could not be parsed"):
        analyze_uploaded_capture("corrupt.pcap", b"INVALID_RANDOM_BYTES_1234567890")


def test_cli_forecast_execution():
    """Execute python -m nexsolve forecast via subprocess."""
    cmd = [sys.executable, "-m", "nexsolve", "forecast", str(TEST_PCAP)]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    assert proc.returncode == 0
    assert "AI-Based Network Attack Forecasting" in proc.stdout
    assert "friday_10windows_slice.pcap" in proc.stdout
    assert "T+1" in proc.stdout
    assert "T+5" in proc.stdout


def test_cli_forecast_json_output():
    """Execute python -m nexsolve forecast with --json flag."""
    cmd = [sys.executable, "-m", "nexsolve", "forecast", str(TEST_PCAP), "--json"]
    proc = subprocess.run(cmd, cwd=str(ROOT), capture_output=True, text=True)
    assert proc.returncode == 0
    # Output should parse as valid JSON
    # Strip any scapy warnings printed to stderr or stdout before JSON
    json_start = proc.stdout.find("{")
    assert json_start != -1
    data = json.loads(proc.stdout[json_start:])
    assert "report_id" in data
    assert "sections" in data or "forecast" in data

