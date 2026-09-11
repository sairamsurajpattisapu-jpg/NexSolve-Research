"""Security hardening and input validation tests for NexSolve API."""
from __future__ import annotations

import io
from pathlib import Path
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, TCP, wrpcap
import pytest

from model_service.app import app
from nexsolve_core.config import (
    ALLOWED_EXTENSIONS,
    MAX_UPLOAD_BYTES,
    ResourceLimitExceededError,
    sanitize_error_message,
    sanitize_filename,
)

client = TestClient(app)


import tempfile

def make_valid_pcap_bytes() -> bytes:
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        temp_path = Path(tf.name)
    try:
        wrpcap(str(temp_path), [Ether() / IP(src="192.168.1.10", dst="192.168.1.20") / TCP(sport=5000, dport=80, flags="S")])
        return temp_path.read_bytes()
    finally:
        temp_path.unlink(missing_ok=True)


def test_filename_sanitization_strips_traversal_and_nulls():
    assert sanitize_filename("../../etc/passwd.pcap") == "passwd.pcap"
    assert sanitize_filename("..\\..\\windows\\system32\\calc.pcap") == "calc.pcap"
    assert sanitize_filename("safe_capture_01.pcap") == "safe_capture_01.pcap"
    assert sanitize_filename("bad\x00file.pcapng") == "badfile.pcapng"
    assert sanitize_filename("no_extension") == "no_extension.pcap"
    assert sanitize_filename("") == "capture.pcap"


def test_error_message_sanitizer_removes_paths():
    win_msg = "Error parsing file at C:\\Users\\saira\\secret\\capture.pcap: invalid magic"
    sanitized_win = sanitize_error_message(win_msg)
    assert "C:\\Users\\" not in sanitized_win
    assert "[REDACTED_PATH]" in sanitized_win

    unix_msg = "Failed in /home/runner/work/nexsolve/tmp/test.pcapng: EOF"
    sanitized_unix = sanitize_error_message(unix_msg)
    assert "/home/runner" not in sanitized_unix
    assert "[REDACTED_PATH]" in sanitized_unix


def test_job_upload_rejects_invalid_extension():
    response = client.post(
        "/jobs",
        files={"file": ("malicious.exe", b"MZ\x90\x00", "application/x-msdownload")},
    )
    assert response.status_code == 415
    assert "Only .pcap and .pcapng" in response.json()["detail"]


def test_job_upload_rejects_empty_file():
    response = client.post(
        "/jobs",
        files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()


def test_job_upload_rejects_fake_pcap_magic():
    response = client.post(
        "/jobs",
        files={"file": ("fake.pcap", b"NOT_A_REAL_PCAP_MAGIC", "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 422
    assert "could not be parsed" in response.json()["detail"]


def test_job_upload_rejects_oversized_file(monkeypatch):
    import model_service.app as service_app

    monkeypatch.setattr(service_app, "MAX_UPLOAD_BYTES", 64)
    data = b"X" * 128
    response = client.post(
        "/jobs",
        files={"file": ("large.pcap", data, "application/vnd.tcpdump.pcap")},
    )
    assert response.status_code == 413
    assert "upload limit" in response.json()["detail"].lower()


def test_job_upload_protects_against_path_traversal_filename():
    pcap_data = make_valid_pcap_bytes()
    response = client.post(
        "/jobs",
        files={"file": ("../../etc/shadow.pcap", pcap_data, "application/vnd.tcpdump.pcap")},
    )
    # The endpoint rejects non-basename filenames or sanitizes them safely
    assert response.status_code in (202, 415)
    if response.status_code == 202:
        body = response.json()
        assert "../" not in body["job_id"]


def test_job_not_found_returns_404():
    response = client.get("/jobs/job-nonexistent123")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_job_result_not_found_returns_404():
    response = client.get("/jobs/job-nonexistent123/result")
    assert response.status_code == 404


def test_job_report_json_not_found_returns_404():
    response = client.get("/jobs/job-nonexistent123/report.json")
    assert response.status_code == 404


def test_job_report_html_not_found_returns_404():
    response = client.get("/jobs/job-nonexistent123/report.html")
    assert response.status_code == 404


def test_resource_limit_exceeded_error_serialization():
    exc = ResourceLimitExceededError(
        resource="packet_count",
        observed=150_000,
        limit=100_000,
        explanation="Packet count exceeded safety boundary.",
        recoverable=False,
    )
    d = exc.to_dict()
    assert d["status"] == "RESOURCE_LIMIT_EXCEEDED"
    assert d["resource"] == "packet_count"
    assert d["observed"] == 150_000
    assert d["limit"] == 100_000
    assert d["recoverable"] is False
