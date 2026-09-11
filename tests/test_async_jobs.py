"""Unit and integration tests for the NexSolve asynchronous job architecture."""
from __future__ import annotations

import tempfile
import time
from pathlib import Path
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap
import pytest

from model_service.app import app
from model_service.jobs import JOB_MANAGER, JobRecord, STAGE_PROGRESS_MAP
from nexsolve_core.config import ResourceLimitExceededError

client = TestClient(app)


def make_sample_pcap_bytes() -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), [Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")])
        return temp_path.read_bytes()
    finally:
        temp_path.unlink(missing_ok=True)


def test_stage_progress_mapping_is_deterministic_and_monotonic():
    stages = [
        "INGESTION",
        "PARSING",
        "FLOW_RECONSTRUCTION",
        "WINDOWING",
        "NETWORK_STATE",
        "FORECAST",
        "EVIDENCE",
        "REPORT",
        "COMPLETE",
    ]
    progresses = [STAGE_PROGRESS_MAP[s] for s in stages]
    assert progresses == sorted(progresses)
    assert STAGE_PROGRESS_MAP["INGESTION"] == 0.10
    assert STAGE_PROGRESS_MAP["COMPLETE"] == 1.00


def test_job_lifecycle_queued_to_completed():
    pcap_data = make_sample_pcap_bytes()
    response = client.post(
        "/jobs",
        files={"file": ("sample.pcap", pcap_data, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 202
    initial = response.json()
    job_id = initial["job_id"]
    assert initial["status"] in ("QUEUED", "PROCESSING", "COMPLETED")
    assert initial["progress"] >= 0.10
    assert initial["error"] is None

    # Poll until completed (with 10 second timeout)
    start = time.time()
    completed_job = None
    while time.time() - start < 10.0:
        status_resp = client.get(f"/jobs/{job_id}")
        assert status_resp.status_code == 200
        data = status_resp.json()
        if data["status"] in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED"):
            completed_job = data
            break
        time.sleep(0.1)

    assert completed_job is not None, f"Timed out waiting for job. Last state: {data}"
    assert completed_job["error"] is None, f"Job failed with error: {completed_job.get('error')}"
    assert completed_job["status"] == "COMPLETED"
    assert completed_job["stage"] == "COMPLETE"
    assert completed_job["progress"] == 1.00
    assert completed_job["completed_at"] is not None
    assert "packets_processed" in completed_job["processing_statistics"]
    assert completed_job["processing_statistics"]["packets_processed"] == 1

    # Verify result endpoint
    res_resp = client.get(f"/jobs/{job_id}/result")
    assert res_resp.status_code == 200
    body = res_resp.json()
    assert body["status"] == "completed"
    assert body["packet_count"] == 1
    assert "attack_horizon" in body
    assert "evidence_chain" in body
    assert "confidence" in body
    assert "unknown_behavior" in body
    assert "abstention" in body

    # Verify no path leakage
    assert "C:\\Users\\" not in res_resp.text


def test_job_reports_downloadable_after_completion():
    pcap_data = make_sample_pcap_bytes()
    resp = client.post(
        "/jobs",
        files={"file": ("test_rep.pcap", pcap_data, "application/vnd.tcpdump.pcap")},
    )
    job_id = resp.json()["job_id"]

    # Wait for completion
    for _ in range(50):
        if client.get(f"/jobs/{job_id}").json()["status"] == "COMPLETED":
            break
        time.sleep(0.1)

    # Download JSON report
    json_resp = client.get(f"/jobs/{job_id}/report.json")
    assert json_resp.status_code == 200
    assert "application/json" in json_resp.headers["content-type"]
    json_body = json_resp.json()
    assert "sections" in json_body
    assert "executive_summary" in json_body["sections"]
    assert "capture_quality" in json_body["sections"]
    assert "provenance" in json_body["sections"]

    # Download HTML report
    html_resp = client.get(f"/jobs/{job_id}/report.html")
    assert html_resp.status_code == 200
    assert "text/html" in html_resp.headers["content-type"]
    assert "NEXSOLVE" in html_resp.text
    assert "Evidence-backed predictive network intelligence" in html_resp.text
    assert "@media print" in html_resp.text
    assert "http://" not in html_resp.text
    assert "https://" not in html_resp.text


def test_job_resource_limit_exceeded_handling():
    job_id = "job-limit-test-001"
    job = JobRecord(
        job_id=job_id,
        filename="overflow.pcap",
        status="PROCESSING",
        stage="PARSING",
    )
    with JOB_MANAGER._lock:
        JOB_MANAGER._jobs[job_id] = job

    # Simulate limit exception handled by worker
    rle = ResourceLimitExceededError(
        resource="packet_count",
        observed=120_000,
        limit=100_000,
        explanation="Observed packets exceeded 100,000 limit.",
        recoverable=False,
    )
    with JOB_MANAGER._lock:
        job.status = "RESOURCE_LIMIT_EXCEEDED"
        job.error = rle.to_dict()

    status_resp = client.get(f"/jobs/{job_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "RESOURCE_LIMIT_EXCEEDED"
    assert status_resp.json()["error"]["resource"] == "packet_count"

    # Attempting to get result returns 422
    result_resp = client.get(f"/jobs/{job_id}/result")
    assert result_resp.status_code == 422
    assert result_resp.json()["detail"]["status"] == "RESOURCE_LIMIT_EXCEEDED"
