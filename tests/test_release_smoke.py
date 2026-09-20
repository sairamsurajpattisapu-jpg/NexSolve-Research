"""Comprehensive release smoke and adversarial validation test suite for NexSolve."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

from model_service.app import app, JOB_MANAGER
from nexsolve_core.config import (
    ALLOWED_EXTENSIONS,
    MAX_PACKETS,
    MAX_UPLOAD_BYTES,
    ResourceLimitExceededError,
    sanitize_error_message,
    sanitize_filename,
)
from ml.forecasting.attack_horizon import AttackHorizonState, compute_attack_horizon

client = TestClient(app)


def make_valid_pcap() -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")])
        return temp_path.read_bytes()
    finally:
        temp_path.unlink(missing_ok=True)


# ==============================================================================
# 1. CORE RELEASE SMOKE PATH
# ==============================================================================

def test_release_smoke_health():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["service_status"] == "ok"
    assert data["model_loaded"] is True
    assert data["feature_count"] == 46
    assert data["K"] == 5



# ==============================================================================
# 3. ATTACK HORIZON BOUNDARY CONDITIONS
# ==============================================================================

def _make_forecast_list(probs: list[float]) -> list[dict]:
    return [
        {
            "horizon": i,
            "attack_probability": p,
            "confidence": 0.85,
            "predicted_stage": "Reconnaissance" if p >= 0.5 else None,
            "abstained": False,
        }
        for i, p in enumerate(probs, 1)
    ]


def test_attack_horizon_boundary_conditions():
    # Exactly at threshold (0.50) -> should be counted in horizon as EARLY_SIGNAL
    h_exact = compute_attack_horizon("2026-01-01T00:00:00Z", _make_forecast_list([0.50, 0.49, 0.40, 0.30, 0.20]), decision_threshold=0.50)
    assert h_exact.state == AttackHorizonState.EARLY_SIGNAL
    assert h_exact.onset_horizon == 1
    assert h_exact.horizon_windows == 1

    # Just below threshold (0.499) -> NO_ATTACK_FORECAST
    h_below = compute_attack_horizon("2026-01-01T00:00:00Z", _make_forecast_list([0.499, 0.45, 0.40, 0.30, 0.20]), decision_threshold=0.50)
    assert h_below.state == AttackHorizonState.NO_ATTACK_FORECAST
    assert h_below.horizon_windows == 0
    assert h_below.onset_horizon is None

    # Just above threshold (0.501) -> EARLY_SIGNAL
    h_above = compute_attack_horizon("2026-01-01T00:00:00Z", _make_forecast_list([0.501, 0.45, 0.40, 0.30, 0.20]), decision_threshold=0.50)
    assert h_above.state == AttackHorizonState.EARLY_SIGNAL
    assert h_above.onset_horizon == 1
    assert h_above.horizon_windows == 1

    # All below threshold -> NO_ATTACK_FORECAST
    h_none = compute_attack_horizon("2026-01-01T00:00:00Z", _make_forecast_list([0.10, 0.15, 0.12, 0.08, 0.05]), decision_threshold=0.50)
    assert h_none.state == AttackHorizonState.NO_ATTACK_FORECAST
    assert h_none.horizon_windows == 0

    # All above threshold -> SUSTAINED_ATTACK_FORECAST spanning 5 windows
    h_all = compute_attack_horizon("2026-01-01T00:00:00Z", _make_forecast_list([0.80, 0.85, 0.95, 0.90, 0.88]), decision_threshold=0.50)
    assert h_all.state == AttackHorizonState.SUSTAINED_ATTACK_FORECAST
    assert h_all.horizon_windows == 5
    assert h_all.lead_time_seconds == 60

    # Single horizon above threshold at step 4 -> lead time is 240 seconds (4 * 60)
    h_single = compute_attack_horizon("2026-01-01T00:00:00Z", _make_forecast_list([0.10, 0.20, 0.30, 0.75, 0.40]), decision_threshold=0.50)
    assert h_single.onset_horizon == 4
    assert h_single.lead_time_seconds == 240


# ==============================================================================
# 4. ADVERSARIAL INPUTS & SECURITY HARDENING
# ==============================================================================

def test_adversarial_nonexistent_and_malformed_job_ids():
    # Nonexistent job ID
    res = client.get("/jobs/job-000000000000")
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()

    # Result for nonexistent job ID
    res = client.get("/jobs/job-000000000000/result")
    assert res.status_code == 404

    # Reports for nonexistent job ID
    res = client.get("/jobs/job-000000000000/report.json")
    assert res.status_code == 404
    res = client.get("/jobs/job-000000000000/report.html")
    assert res.status_code == 404

    # Invalid demo scenario
    res = client.get("/api/demo/scenarios/NONEXISTENT_SCENARIO_XYZ")
    assert res.status_code == 404


def test_adversarial_empty_and_garbage_uploads():
    # Empty file
    res = client.post("/jobs", files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")})
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()

    # Random bytes
    res = client.post("/jobs", files={"file": ("garbage.pcap", b"\xde\xad\xbe\xef" * 64, "application/vnd.tcpdump.pcap")})
    assert res.status_code == 422
    assert "could not be parsed" in res.json()["detail"].lower()

    # Renamed non-PCAP (e.g. text file renamed to .pcap)
    res = client.post("/jobs", files={"file": ("fake.pcap", b"Hello, this is a plain text file!", "application/vnd.tcpdump.pcap")})
    assert res.status_code == 422

    # Unsupported extension
    res = client.post("/jobs", files={"file": ("evil.sh", b"#!/bin/bash\nexit 0", "text/x-shellscript")})
    assert res.status_code == 415


def test_adversarial_filenames_cannot_traverse_or_execute():
    pcap_data = make_valid_pcap()
    adversarial_filenames = [
        "../../evil.pcap",
        "..\\..\\evil.pcap",
        "<script>alert(1)</script>.pcap",
        "\" OR 1=1 --.pcap",
        "test;rm -rf.pcap",
        "test&whoami.pcap",
        "test|whoami.pcap",
    ]

    for fname in adversarial_filenames:
        clean = sanitize_filename(fname)
        # Verify sanitization stripped path traversal and dangerous characters
        assert ".." not in clean
        assert "/" not in clean
        assert "\\" not in clean
        assert clean.endswith((".pcap", ".pcapng"))

        # Verify endpoint handles safely without traceback or shell execution
        res = client.post("/jobs", files={"file": (fname, pcap_data, "application/vnd.tcpdump.pcap")})
        assert res.status_code in (202, 415, 422)
        if res.status_code == 202:
            body = res.json()
            assert "/" not in body["job_id"]
            assert "\\" not in body["job_id"]


def test_adversarial_error_sanitization():
    raw_error = "Traceback in C:\\Users\\Administrator\\NexSolve\\secret.py line 42: DivisionByZero"
    sanitized = sanitize_error_message(raw_error)
    assert "C:\\Users\\" not in sanitized
    assert "secret.py" not in sanitized
    assert "[REDACTED_PATH]" in sanitized
