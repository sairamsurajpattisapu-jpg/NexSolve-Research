"""Tests for canonical backend active analysis state and consistency."""
from __future__ import annotations

import io
import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap

from model_service.active_analysis import (
    PRODUCTION_ANALYSIS_ID,
    get_current_analysis_id,
    reset_to_production,
    set_current_analysis,
)
from model_service.app import app


@pytest.fixture(autouse=True)
def ensure_clean_active_analysis():
    reset_to_production()
    yield
    reset_to_production()


def test_initial_current_analysis_is_production():
    client = TestClient(app)
    assert get_current_analysis_id() == PRODUCTION_ANALYSIS_ID

    resp = client.get("/api/analysis/current")
    assert resp.status_code == 200
    data = resp.json()
    assert data["analysis_id"] == PRODUCTION_ANALYSIS_ID
    assert data["is_production"] is True
    assert data["source"]["kind"] == "production_parquet"

    # Traffic and Alerts should report production analysis
    traffic_resp = client.get("/api/traffic")
    assert traffic_resp.status_code == 200
    assert traffic_resp.json()["analysis_id"] == PRODUCTION_ANALYSIS_ID

    alerts_resp = client.get("/api/alerts")
    assert alerts_resp.status_code == 200
    assert alerts_resp.json()["analysis_id"] == PRODUCTION_ANALYSIS_ID


def test_switch_current_analysis_validates_existence():
    client = TestClient(app)
    # Trying to switch to a nonexistent analysis must return 404
    resp = client.post("/api/analysis/current", json={"analysis_id": "nonexistent-id-999"})
    assert resp.status_code == 404
    assert "Cannot switch to nonexistent analysis" in resp.json()["detail"]


import tempfile
from pathlib import Path


def _make_pcap_bytes(count: int = 15) -> bytes:
    packets = [
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.1", dst="10.0.0.1") / TCP(sport=1000 + i, dport=80, flags="S")
        for i in range(count)
    ]
    for i, p in enumerate(packets):
        p.time = 1726059780.0 + i * 0.01

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), packets)
        return temp_path.read_bytes()
    finally:
        temp_path.unlink(missing_ok=True)


def test_upload_promotes_to_current_active_analysis():
    client = TestClient(app)
    pcap_bytes = _make_pcap_bytes(15)

    upload_resp = client.post(
        "/api/pcap/analyze",
        files={"file": ("test_active.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
    )
    assert upload_resp.status_code == 200
    uploaded_id = upload_resp.json()["analysis_id"]

    # Backend current active analysis must now be the uploaded analysis
    assert get_current_analysis_id() == uploaded_id

    # GET /api/analysis/current must resolve the uploaded capture
    current_resp = client.get("/api/analysis/current")
    assert current_resp.status_code == 200
    current_data = current_resp.json()
    assert current_data["analysis_id"] == uploaded_id
    assert current_data["is_production"] is False
    assert current_data["source"]["name"] == "test_active.pcap"

    # GET /api/traffic must now report the uploaded capture's traffic (15 packets)
    traffic_resp = client.get("/api/traffic")
    assert traffic_resp.status_code == 200
    assert traffic_resp.json()["analysis_id"] == uploaded_id
    assert traffic_resp.json()["packets"] == 15

    # Switch back to production
    switch_resp = client.post("/api/analysis/current", json={"analysis_id": PRODUCTION_ANALYSIS_ID})
    assert switch_resp.status_code == 200
    assert switch_resp.json()["analysis_id"] == PRODUCTION_ANALYSIS_ID
    assert get_current_analysis_id() == PRODUCTION_ANALYSIS_ID

    # Traffic resolves back to production
    traffic_back = client.get("/api/traffic")
    assert traffic_back.json()["analysis_id"] == PRODUCTION_ANALYSIS_ID


def test_async_job_completion_promotes_to_current_analysis():
    import time
    client = TestClient(app)
    pcap_bytes = _make_pcap_bytes(10)

    job_resp = client.post(
        "/jobs",
        files={"file": ("test_async_active.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
    )
    assert job_resp.status_code == 202
    job_id = job_resp.json()["job_id"]

    # Poll until completed
    for _ in range(50):
        status = client.get(f"/jobs/{job_id}").json()["status"]
        if status == "COMPLETED":
            break
        time.sleep(0.1)

    # Job must now be promoted to current active analysis
    assert get_current_analysis_id() == job_id
    current_resp = client.get("/api/analysis/current")
    assert current_resp.status_code == 200
    assert current_resp.json()["analysis_id"] == job_id

    # analysis_for_id can resolve the completed in-memory job
    results_resp = client.get(f"/api/analysis/{job_id}/results")
    assert results_resp.status_code == 200
    assert results_resp.json()["analysis_id"] == job_id


def test_delete_active_analysis_resets_to_production():
    client = TestClient(app)
    # Set a dummy active analysis in cache
    set_current_analysis("temp-to-delete", {"status": "completed", "source": {"name": "temp.pcap", "kind": "uploaded_pcap"}})
    assert get_current_analysis_id() == "temp-to-delete"

    # Delete it
    del_resp = client.delete("/api/analysis/temp-to-delete")
    assert del_resp.status_code == 204
    assert get_current_analysis_id() == PRODUCTION_ANALYSIS_ID
