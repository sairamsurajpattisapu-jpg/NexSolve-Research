"""End-to-end pipeline verification test for NexSolve."""
from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap
import pytest

from model_service.app import app

client = TestClient(app)


def test_full_pipeline_upload_to_report():
    # 1. Create a real sample PCAP
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = Path(tf.name)
    try:
        pkts = [
            Ether() / IP(src=f"192.168.1.{i}", dst="10.0.0.1") / TCP(sport=1024 + i, dport=80, flags="S")
            for i in range(1, 10)
        ]
        wrpcap(str(pcap_path), pkts)
        pcap_bytes = pcap_path.read_bytes()
    finally:
        pcap_path.unlink(missing_ok=True)

    # 2. Upload to /jobs
    upload_resp = client.post(
        "/jobs",
        files={"file": ("e2e_capture.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
    )
    assert upload_resp.status_code == 202
    job_info = upload_resp.json()
    job_id = job_info["job_id"]
    assert job_info["status"] in ("QUEUED", "PROCESSING", "COMPLETED")

    # 3. Poll until completion
    start = time.time()
    completed = False
    final_status = None
    while time.time() - start < 15.0:
        st_resp = client.get(f"/jobs/{job_id}")
        assert st_resp.status_code == 200
        final_status = st_resp.json()
        if final_status["status"] == "COMPLETED":
            completed = True
            break
        elif final_status["status"] in ("FAILED", "RESOURCE_LIMIT_EXCEEDED"):
            break
        time.sleep(0.1)

    assert completed, f"Job failed to complete: {final_status}"
    assert final_status["progress"] == 1.00
    assert final_status["stage"] == "COMPLETE"
    assert final_status["processing_statistics"]["packets_processed"] == 9

    # 4. Check Result
    res_resp = client.get(f"/jobs/{job_id}/result")
    assert res_resp.status_code == 200
    result_data = res_resp.json()
    assert result_data["packet_count"] == 9
    assert result_data["attack_horizon"]["state"] in (
        "NO_ATTACK_FORECAST",
        "EARLY_SIGNAL",
        "SUSTAINED_ATTACK_FORECAST",
        "UNCERTAIN_FORECAST",
        "ABSTAINED",
    )
    assert "evidence_chain" in result_data
    assert "confidence" in result_data
    assert result_data["confidence"]["calibration_status"] == "UNSUPPORTED"
    assert "unknown_behavior" in result_data
    assert "abstention" in result_data

    # 5. Check JSON Report
    json_resp = client.get(f"/jobs/{job_id}/report.json")
    assert json_resp.status_code == 200
    report_dict = json_resp.json()
    assert report_dict["report_id"] == f"rep-{job_id}"
    assert "executive_summary" in report_dict["sections"]
    assert "provenance" in report_dict["sections"]

    # 6. Check HTML Report
    html_resp = client.get(f"/jobs/{job_id}/report.html")
    assert html_resp.status_code == 200
    assert "<!DOCTYPE html>" in html_resp.text
    assert "NEXSOLVE" in html_resp.text
    assert "Evidence-backed predictive network intelligence" in html_resp.text
    assert "@media print" in html_resp.text

    # 7. Leakage check
    assert "C:\\Users\\" not in res_resp.text
    assert "C:\\Users\\" not in json_resp.text
    assert "C:\\Users\\" not in html_resp.text
