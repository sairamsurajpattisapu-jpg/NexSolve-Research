"""Unit and mock integration tests for CLI subcommands."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import pytest

from nexsolve.main import build_parser, main


@pytest.fixture
def sample_pcap(tmp_path: Path) -> Path:
    pcap = tmp_path / "sample.pcap"
    header = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
    pcap.write_bytes(header)
    return pcap





def test_cli_version_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "nexsolve 1.0.0" in captured.out


def test_cli_help_flag(capsys):
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "NexSolve: AI-Based Network Attack Forecasting Platform" in captured.out
    assert "analyze" in captured.out
    assert "status" in captured.out
    assert "report" in captured.out


def test_cli_analyze_validation_failure(capsys):
    ret = main(["analyze", "nonexistent_file_abc.pcap"])
    assert ret == 2
    captured = capsys.readouterr()
    assert "[ERROR]" in captured.err
    assert "not found" in captured.err.lower()


def test_cli_analyze_server_unreachable(sample_pcap: Path, capsys):
    ret = main(["analyze", str(sample_pcap), "--server", "http://127.0.0.1:59998"])
    assert ret == 3
    captured = capsys.readouterr()
    assert "[ERROR]" in captured.err
    assert "cannot connect" in captured.err.lower()


def test_cli_analyze_e2e_mock(sample_pcap: Path, mock_server: str, capsys):
    ret = main([
        "analyze",
        str(sample_pcap),
        "--server", mock_server,
        "--web-url", "http://localhost:5173",
        "--poll-interval", "0.05",
        "--timeout", "5.0",
        "--no-color",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    assert "ANALYSIS COMPLETE" in captured.out
    assert "job-test123456" in captured.out
    assert "http://localhost:5173/console/forecast/job-test123456" in captured.out
    assert "T+1" in captured.out
    assert "ELEVATED" in captured.out


def test_cli_analyze_json_output(sample_pcap: Path, mock_server: str, capsys):
    ret = main([
        "analyze",
        str(sample_pcap),
        "--server", mock_server,
        "--poll-interval", "0.05",
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["analysis_id"] == "job-test123456"
    assert data["status"] == "completed"


def test_cli_analyze_report_download(sample_pcap: Path, mock_server: str, tmp_path: Path, capsys):
    report_file = tmp_path / "out_report.html"
    ret = main([
        "analyze",
        str(sample_pcap),
        "--server", mock_server,
        "--poll-interval", "0.05",
        "--report-out", str(report_file),
        "--no-color",
    ])
    assert ret == 0
    assert report_file.exists()
    assert "NexSolve Test Report" in report_file.read_text(encoding="utf-8")


def test_cli_status_command(mock_server: str, capsys):
    ret = main([
        "status",
        "job-test123456",
        "--server", mock_server,
        "--web-url", "http://localhost:5173",
        "--no-color",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    assert "NEXSOLVE JOB STATUS" in captured.out
    assert "job-test123456" in captured.out
    assert "http://localhost:5173/console/forecast/job-test123456" in captured.out


def test_cli_status_json(mock_server: str, capsys):
    ret = main([
        "status",
        "job-test123456",
        "--server", mock_server,
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["job_id"] == "job-test123456"
    assert data["status"] == "COMPLETED"


def test_cli_report_command_download(mock_server: str, tmp_path: Path, capsys):
    report_file = tmp_path / "downloaded.html"
    ret = main([
        "report",
        "job-test123456",
        "--server", mock_server,
        "--output", str(report_file),
    ])
    assert ret == 0
    assert report_file.exists()
    assert "NexSolve Test Report" in report_file.read_text(encoding="utf-8")


def test_cli_report_command_display(mock_server: str, capsys):
    ret = main([
        "report",
        "job-test123456",
        "--server", mock_server,
        "--web-url", "http://localhost:5173",
        "--no-color",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    assert "NEXSOLVE FORENSIC REPORT" in captured.out
    assert "http://localhost:5173/console/reports/job-test123456" in captured.out
