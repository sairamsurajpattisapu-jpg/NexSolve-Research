"""Deterministic automated regression tests for large-PCAP stress, performance, and resource limits."""
from __future__ import annotations

import tempfile
from pathlib import Path
import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from model_service.jobs import JOB_MANAGER, validate_pcap_bytes
from model_service.pcap_upload import analyze_uploaded_capture
from nexsolve_core.config import (
    MAX_PACKETS,
    MAX_UPLOAD_BYTES,
    ResourceLimitExceededError,
)
from scripts.large_pcap_validation_harness import check_runtime_leaks


def test_case_a_small_pcap_abstains_without_fabrication():
    """Small capture has insufficient history (<8 windows) and strictly abstains."""
    pcap_path = Path(r"C:\Users\saira\Downloads\nexsolve_test_small.pcap")
    if not pcap_path.exists():
        pytest.skip("nexsolve_test_small.pcap not present on host")

    content = pcap_path.read_bytes()
    initial_leaks = check_runtime_leaks()
    job = JOB_MANAGER.create_job(pcap_path.name, content)

    # Wait for completion
    import time
    for _ in range(50):
        rec = JOB_MANAGER.get_job(job.job_id)
        if rec and rec.status in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED"):
            break
        time.sleep(0.1)

    rec = JOB_MANAGER.get_job(job.job_id)
    assert rec is not None
    assert rec.status == "COMPLETED"
    assert rec.processing_statistics["packets_processed"] == 20
    assert rec.processing_statistics["windows_processed"] == 1

    res = rec.result
    assert res["model_compatibility"]["model_ready"] is False
    assert "INSUFFICIENT_HISTORY" in res["model_compatibility"]["reason"]

    # Invariants: 0 fabricated features, 5 abstained points
    forecasts = res["forecasts"]
    assert len(forecasts) == 5
    for pt in forecasts:
        assert pt["attackProbability"] is None
        assert pt["confidence"] is None
        assert "Forecast abstained:" in pt["explanation"][0]

    assert res["attack_horizon"]["state"] == "ABSTAINED"
    import time; time.sleep(0.5); import gc; gc.collect(); assert check_runtime_leaks() - initial_leaks == 0


def test_case_b_real_10windows_pcap_45_feature_pipeline():
    """Real Friday 10-window capture satisfies 45/45 features and executes 5-step rollouts."""
    pcap_path = Path(r"C:\Users\saira\Downloads\friday_10windows_slice.pcap")
    if not pcap_path.exists():
        pytest.skip("friday_10windows_slice.pcap not present on host")

    content = pcap_path.read_bytes()
    initial_leaks = check_runtime_leaks()
    job = JOB_MANAGER.create_job(pcap_path.name, content)

    import time
    for _ in range(120):
        rec = JOB_MANAGER.get_job(job.job_id)
        if rec and rec.status in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED"):
            break
        time.sleep(0.2)

    rec = JOB_MANAGER.get_job(job.job_id)
    assert rec is not None
    assert rec.status == "COMPLETED"
    assert rec.processing_statistics["packets_processed"] == 2277
    assert rec.processing_statistics["windows_processed"] == 10

    res = rec.result
    assert res["model_compatibility"]["model_ready"] is True
    assert res["model_compatibility"]["required_features"] == 45
    assert len(res["model_compatibility"]["missing_features"]) == 0

    forecasts = res["forecasts"]
    assert len(forecasts) == 5
    for pt in forecasts:
        assert pt["attackProbability"] is not None
        assert 0.0 <= pt["attackProbability"] <= 1.0
        assert pt["confidence"] is not None
        assert len(pt["explanation"]) > 0

    ah = res["attack_horizon"]
    assert ah["state"] in ("EARLY_SIGNAL", "SUSTAINED_ATTACK_FORECAST", "NO_ATTACK_FORECAST")
    if ah["state"] != "NO_ATTACK_FORECAST":
        assert ah["lead_time_seconds"] is not None

    # Reports generated
    assert rec.report_json is not None and len(rec.report_json) > 1000
    assert rec.report_html is not None and len(rec.report_html) > 1000
    import time; time.sleep(0.5); import gc; gc.collect(); assert check_runtime_leaks() - initial_leaks == 0
    import time; time.sleep(0.5); import gc; gc.collect(); assert check_runtime_leaks() - initial_leaks <= 2


def test_case_c_high_density_10windows_stress():
    """High-density 10-window PCAP with thousands of packets/flows completes stably."""
    pcap_path = Path(r"C:\Users\saira\Downloads\friday_stress_10windows_9k.pcap")
    if not pcap_path.exists():
        pytest.skip("friday_stress_10windows_9k.pcap not present on host")

    content = pcap_path.read_bytes()
    initial_leaks = check_runtime_leaks()
    job = JOB_MANAGER.create_job(pcap_path.name, content)

    import time
    for _ in range(150):
        rec = JOB_MANAGER.get_job(job.job_id)
        if rec and rec.status in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED"):
            break
        time.sleep(0.3)

    rec = JOB_MANAGER.get_job(job.job_id)
    assert rec is not None
    assert rec.status == "COMPLETED"
    assert rec.processing_statistics["packets_processed"] == 9108
    assert rec.processing_statistics["flows_processed"] >= 1000
    assert rec.processing_statistics["windows_processed"] == 10

    res = rec.result
    assert res["model_compatibility"]["model_ready"] is True
    assert len(res["forecasts"]) == 5
    assert res["attack_horizon"]["state"] in ("SUSTAINED_ATTACK_FORECAST", "EARLY_SIGNAL")
    assert res["attack_horizon"]["state"] in ("SUSTAINED_ATTACK_FORECAST", "EARLY_SIGNAL", "UNCERTAIN_FORECAST")
    import time; time.sleep(0.5); import gc; gc.collect(); assert check_runtime_leaks() - initial_leaks == 0


def test_case_d_oversized_upload_rejection_at_ingress(monkeypatch):
    """Upload exceeding MAX_UPLOAD_BYTES is rejected at ingress before parsing."""
    import model_service.jobs as jobs_mod
    monkeypatch.setattr(jobs_mod, "MAX_UPLOAD_BYTES", 64)
    oversized_content = b"\xd4\xc3\xb2\xa1" + b"\x00" * 70
    with pytest.raises(ResourceLimitExceededError) as exc_info:
        validate_pcap_bytes("large_capture.pcap", oversized_content)

    err = exc_info.value
    assert err.resource == "upload_bytes"
    assert err.limit == 64
    assert err.observed > 64


def test_case_d_packet_count_limit_exceeded(monkeypatch):
    """Capture exceeding MAX_PACKETS raises ResourceLimitExceededError and cleans up tempdir."""
    # Test with small threshold to verify packet limit enforcement logic
    import model_service.jobs as jobs_mod
    monkeypatch.setattr(jobs_mod, "MAX_PACKETS", 15)

    base_epoch = 1700000000.0
    packets = []
    for i in range(25):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1000 + i, dport=80)
        pkt.time = base_epoch + i * 0.1
        packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_pcap = Path(tf.name)
    try:
        wrpcap(str(temp_pcap), packets)
        content = temp_pcap.read_bytes()
        initial_leaks = check_runtime_leaks()
        job = JOB_MANAGER.create_job(temp_pcap.name, content)

        import time
        for _ in range(50):
            rec = JOB_MANAGER.get_job(job.job_id)
            if rec and rec.status in ("COMPLETED", "FAILED", "RESOURCE_LIMIT_EXCEEDED"):
                break
            time.sleep(0.1)

        rec = JOB_MANAGER.get_job(job.job_id)
        assert rec is not None
        assert rec.status == "RESOURCE_LIMIT_EXCEEDED"
        assert rec.error["resource"] == "packet_count"
        assert rec.error["limit"] == 15
        assert rec.error["observed"] == 25
        import time; time.sleep(0.5); import gc; gc.collect(); assert check_runtime_leaks() - initial_leaks == 0
    finally:
        temp_pcap.unlink(missing_ok=True)


def test_case_e_malformed_and_unsupported_inputs():
    """Verify safe rejection of invalid extensions, empty files, and bad magic bytes."""
    # 1. Unsupported extension
    with pytest.raises(ValueError, match="Only .pcap and .pcapng captures are supported."):
        validate_pcap_bytes("test.csv", b"col1,col2\n1,2")

    with pytest.raises(ValueError, match="Only .pcap and .pcapng captures are supported."):
        validate_pcap_bytes("malware.exe", b"MZ\x90\x00")

    # 2. Empty content
    with pytest.raises(ValueError, match="The uploaded capture is empty."):
        validate_pcap_bytes("empty.pcap", b"")

    # 3. Bad magic bytes
    with pytest.raises(RuntimeError, match="The file could not be parsed as a supported PCAP/PCAPNG capture."):
        validate_pcap_bytes("corrupted.pcap", b"RANDOM_NON_PCAP_BYTES_12345")
