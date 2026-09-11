"""Production deployment validation and real PCAP workflow test suite for NexSolve."""
from __future__ import annotations

import tempfile
import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

from model_service.app import app, JOB_MANAGER
from model_service.database import check_db_health, init_db
from nexsolve_core.config import sanitize_filename

client = TestClient(app)


def make_test_pcap(packet_count: int = 15) -> bytes:
    """Generate a valid, structured PCAP byte sequence with microsecond timestamps."""
    packets = []
    base_epoch = 1700000000.0
    for i in range(packet_count):
        pkt = Ether() / IP(src=f"192.168.1.{10 + (i % 3)}", dst="10.0.0.1") / TCP(
            sport=2000 + i,
            dport=80 if i % 2 == 0 else 443,
            flags="S" if i % 4 == 0 else "A",
        )
        pkt.time = base_epoch + (i * 0.25)
        packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        return temp_path.read_bytes()
    finally:
        temp_path.unlink(missing_ok=True)


# ==============================================================================
# 1. HEALTH & READINESS PROBES
# ==============================================================================

def test_production_health_probe():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["service_status"] == "ok"
    assert data["model_loaded"] is True
    assert data["feature_count"] == 46
    assert data["K"] == 5


def test_production_readiness_probe():
    res = client.get("/ready")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] in ("ready", "not_ready")
    assert data["service"] == "ok"
    assert "database" in data
    assert data["database"]["mode"] in ("DATABASE", "MEMORY")


def test_production_security_response_headers():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.headers.get("x-content-type-options") == "nosniff"
    assert res.headers.get("x-frame-options") == "DENY"
    assert res.headers.get("referrer-policy") == "strict-origin-when-cross-origin"


# ==============================================================================
# 2. FULL REAL PCAP END-TO-END WORKFLOW
# ==============================================================================

def test_real_pcap_end_to_end_pipeline():
    pcap_data = make_test_pcap(25)

    # 1. UPLOAD -> 202 ACCEPTED
    res = client.post(
        "/jobs",
        files={"file": ("incident_sample_01.pcap", pcap_data, "application/vnd.tcpdump.pcap")},
    )
    assert res.status_code == 202
    initial_body = res.json()
    job_id = initial_body["job_id"]
    assert job_id.startswith("job-")
    assert initial_body["status"] in ("QUEUED", "PROCESSING", "COMPLETED")
    assert initial_body["progress"] >= 0.10

    # 2. POLL UNTIL COMPLETED
    timeout = 10.0
    start = time.time()
    job_data = None
    while time.time() - start < timeout:
        poll_res = client.get(f"/jobs/{job_id}")
        assert poll_res.status_code == 200
        job_data = poll_res.json()
        if job_data["status"] in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED"):
            break
        time.sleep(0.02)

    assert job_data is not None
    assert job_data["status"] == "COMPLETED", f"Job failed: {job_data.get('error')}"
    assert job_data["progress"] == 1.0
    assert job_data["stage"] == "COMPLETE"
    assert job_data["processing_statistics"]["packets_processed"] == 25

    # 3. GET RESULT
    result_res = client.get(f"/jobs/{job_id}/result")
    assert result_res.status_code == 200
    result = result_res.json()

    assert result["analysis_id"] == job_id
    assert result["status"] == "completed"
    assert "network_state" in result
    assert "traffic" in result
    assert "detection" in result
    assert "attack_horizon" in result
    assert "evidence_chain" in result
    assert "processing_metrics" in result

    # Check Attack Horizon Rollout
    horizon = result["attack_horizon"]
    assert horizon is not None
    assert "evidence_chain" in horizon or "horizons" in horizon

    # Check Evidence Chain
    evidence = result["evidence_chain"]
    assert "supporting" in evidence or "supporting_evidence" in evidence
    assert "contradictory" in evidence or "contradictory_evidence" in evidence

    # Check Microsecond Timings
    metrics = result["processing_metrics"]
    assert "total_processing_ms" in metrics
    assert "pcap_parsing_ms" in metrics
    assert metrics["total_processing_ms"] > 0

    # 4. DOWNLOAD JSON REPORT
    json_res = client.get(f"/jobs/{job_id}/report.json")
    assert json_res.status_code == 200
    json_report = json_res.json()
    assert "report_id" in json_report
    assert "sections" in json_report

    # 5. DOWNLOAD HTML REPORT
    html_res = client.get(f"/jobs/{job_id}/report.html")
    assert html_res.status_code == 200
    html_report = html_res.text
    assert "<!DOCTYPE html>" in html_report
    assert "NexSolve Report" in html_report
    assert "https://cdn." not in html_report


# ==============================================================================
# 3. ADVERSARIAL REJECTIONS & RESILIENCE
# ==============================================================================

def test_production_rejection_malformed_pcap():
    res = client.post(
        "/jobs",
        files={"file": ("corrupt.pcap", b"GARBAGE_PAYLOAD_NOT_PCAP", "application/vnd.tcpdump.pcap")},
    )
    assert res.status_code == 422
    assert "could not be parsed" in res.json()["detail"]


def test_production_rejection_empty_upload():
    res = client.post(
        "/jobs",
        files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")},
    )
    assert res.status_code == 400
    assert "empty" in res.json()["detail"].lower()


def test_production_rejection_unsupported_extension():
    res = client.post(
        "/jobs",
        files={"file": ("script.sh", b"#!/bin/bash\necho test", "application/x-sh")},
    )
    assert res.status_code == 415


def test_production_path_traversal_filename():
    pcap_data = make_test_pcap(5)
    # Filename with path traversal sequences
    res = client.post(
        "/jobs",
        files={"file": ("../../../../etc/passwd.pcap", pcap_data, "application/vnd.tcpdump.pcap")},
    )
    assert res.status_code in (202, 415)
    if res.status_code == 202:
        body = res.json()
        assert ".." not in body["job_id"]


def test_database_health_check_function():
    health = check_db_health()
    assert "status" in health
    assert "mode" in health
    assert health["mode"] in ("DATABASE", "MEMORY")
