"""Production Integration Test Suite for NexSolve Final Network World Model v3.0.0.

Verifies:
1. Frozen Artifact Immutability: SHA-256 integrity of all frozen model directories.
2. Backend API Governance: /api/model/info endpoint reflects authoritative frozen status.
3. Job Processing Pipeline: End-to-end PCAP analysis strictly executes the frozen Final Network World Model.
4. Complete Contract Adherence: Output contains observed metrics, 5-horizon forecast, calibrated uncertainty,
   observed network risk indicators, host/communication risk, and explicit abstention.
5. No Fabrication: Under insufficient history or non-contiguous timestamps, the system abstains cleanly
   without generating synthetic forecasts, fake stages, or mock probability values.
"""
from __future__ import annotations

import hashlib
import json
import tempfile
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

from ml.final_production_inference import FinalProductionInferenceEngine
from ml.models.abstention_engine import AbstentionReasonCode, ForecastOperationalTier
from model_service.app import app
from model_service.jobs import JOB_MANAGER

ROOT = Path(__file__).resolve().parents[1]
FRIDAY_PCAP = ROOT / "data" / "test_slices" / "friday_10windows_slice.pcap"


def _verify_manifest(model_dir: Path) -> None:
    """Helper to verify that all files in a model directory match their manifest SHA-256."""
    manifest_path = model_dir / "manifest.json"
    assert manifest_path.exists(), f"Manifest missing in {model_dir}"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    entries = manifest.get("artifact_hashes", manifest.get("files", manifest.get("file_hashes", {})))
    assert len(entries) > 0, f"No file hashes found in manifest for {model_dir}"

    for rel_path, expected_hash in entries.items():
        file_path = model_dir / rel_path
        assert file_path.exists(), f"File {rel_path} missing in {model_dir}"

        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        actual_hash = hasher.hexdigest()
        assert actual_hash == expected_hash, (
            f"SHA256 mismatch for {rel_path} in {model_dir}: expected {expected_hash}, got {actual_hash}"
        )


# ==============================================================================
# 1. Artifact Immutability Tests
# ==============================================================================

def test_frozen_artifacts_sha256_immutability() -> None:
    """Verifies that frozen artifacts have not been modified or corrupted."""
    final_dir = ROOT / "models" / "final_world_model"
    audited_dir = ROOT / "models" / "final_world_model_audited"
    v2_dir = ROOT / "models" / "candidate_v2"

    _verify_manifest(final_dir)
    _verify_manifest(audited_dir)
    _verify_manifest(v2_dir)


# ==============================================================================
# 2. Governance API Endpoint Tests
# ==============================================================================

def test_model_governance_info_endpoint() -> None:
    """Verifies that /api/model/info serves frozen Final World Model v3.0.0 metadata."""
    client = TestClient(app)
    response = client.get("/api/model/info")
    assert response.status_code == 200

    data = response.json()
    assert data["model_name"] == "final_world_model"
    assert data["version"] == "3.0.0"
    assert data["model_status"] == "AUTHORITATIVE_FINAL_MODEL"
    assert data["frozen"] is True
    assert "manifest" in data
    manifest = data["manifest"]
    assert "artifact_hashes" in manifest
    assert len(manifest["artifact_hashes"]) >= 4
    assert "model.npz" in manifest["artifact_hashes"]
    assert "preprocessing.npz" in manifest["artifact_hashes"]


# ==============================================================================
# 3. End-to-End Pipeline Execution via JobManager
# ==============================================================================

def test_production_job_execution_with_final_model() -> None:
    """Tests full job processing of friday_10windows_slice.pcap via JOB_MANAGER."""
    assert FRIDAY_PCAP.exists(), f"Test PCAP not found: {FRIDAY_PCAP}"

    job = JOB_MANAGER.create_job(
        filename="friday_10windows_slice.pcap",
        file_path=FRIDAY_PCAP,
    )

    # Wait for completion (up to 30s)
    deadline = time.time() + 30.0
    while time.time() < deadline:
        current = JOB_MANAGER.get_job(job.job_id)
        if current and current.status in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED"):
            break
        time.sleep(0.2)

    updated_job = JOB_MANAGER.get_job(job.job_id)
    assert updated_job is not None
    assert updated_job.status == "COMPLETED", f"Job failed with error: {updated_job.error}"

    result = updated_job.result
    assert result is not None

    # Verify model attribution
    assert result.get("model_version") == "final_world_model v3.0.0"
    assert result.get("model_name") == "final_world_model"

    # Verify forecast structure (T+1 to T+5)
    forecast = result.get("forecast")
    assert isinstance(forecast, dict)
    for h in ["T+1", "T+2", "T+3", "T+4", "T+5"]:
        assert h in forecast
        point = forecast[h]
        assert "attack_probability" in point
        assert 0.0 <= point["attack_probability"] <= 1.0
        assert "predicted_stage" in point
        assert "predicted_features" in point
        assert "confidence_score" in point

    # Verify final_world_model payload
    fwm = result.get("final_world_model")
    assert isinstance(fwm, dict)
    assert fwm["status"] == "FORECAST_AVAILABLE"

    # Verify risk indicators
    risk_indicators = result.get("network_risk_indicators")
    assert isinstance(risk_indicators, list)
    assert len(risk_indicators) > 0
    first_ind = risk_indicators[0]
    assert "title" in first_ind
    assert "indicator_type" in first_ind
    assert "severity" in first_ind
    assert "observation" in first_ind
    assert "evidence" in first_ind
    assert first_ind["title"].startswith("OBSERVED RISK INDICATOR")

    # Verify abstention status is operational (not abstained)
    abstention = result.get("abstention")
    assert isinstance(abstention, dict)
    assert abstention["abstained"] is False
    assert abstention["operational_tier"] in ("FULL_OPERATIONAL", "DEGRADED_FORECAST")

    # Verify uncertainty diagnostics
    uncertainty = result.get("uncertainty")
    assert isinstance(uncertainty, dict)
    assert "epistemic_uncertainty" in uncertainty
    assert "aleatoric_uncertainty" in uncertainty
    assert "ood_score" in uncertainty


# ==============================================================================
# 4. Clean Abstention Without Fabrication
# ==============================================================================

def test_production_job_clean_abstention_on_timestamp_gap(tmp_path: Path) -> None:
    """Tests that a capture with non-contiguous timestamps completes traffic analysis but abstains from forecasting."""
    # Create a synthetic PCAP with two packets separated by 4000s (> 60s window gap)
    gap_pcap = tmp_path / "gapped_traffic.pcap"
    p1 = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=1024, dport=80, flags="S")
    p1.time = 1700000000.0
    p2 = Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=1024, dport=80, flags="A")
    p2.time = 1700004000.0
    wrpcap(str(gap_pcap), [p1, p2])

    job = JOB_MANAGER.create_job(
        filename="gapped_traffic.pcap",
        file_path=gap_pcap,
    )

    deadline = time.time() + 30.0
    while time.time() < deadline:
        current = JOB_MANAGER.get_job(job.job_id)
        if current and current.status in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED"):
            break
        time.sleep(0.2)

    updated_job = JOB_MANAGER.get_job(job.job_id)
    assert updated_job is not None
    assert updated_job.status == "COMPLETED", f"Job unexpectedly failed: {updated_job.error}"

    result = updated_job.result
    assert result is not None

    # Traffic analysis succeeded
    assert result.get("traffic", {}).get("packets") == 2
    assert result.get("model_version") == "final_world_model v3.0.0"

    # Abstention must be explicit
    abstention = result.get("abstention", {})
    assert abstention.get("abstained") is True
    reason = abstention.get("reason", "")
    assert "TIMESTAMP" in reason or "HISTORY" in reason or "QUALITY" in reason

    # Forecast must indicate abstention, not fabricated numbers
    forecast = result.get("forecast")
    if isinstance(forecast, dict):
        assert len(forecast) == 0 or all(pt.get("attack_probability") is None for pt in forecast.values())
