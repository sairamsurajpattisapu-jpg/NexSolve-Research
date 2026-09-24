"""Comprehensive failure engineering and numerical sanity test suite."""
from __future__ import annotations

import json
import math
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import pytest

from ml.forecasting.forecasting_engine import _explain_feature_change
from nexsolve.client.api import NexSolveClient
from nexsolve.client.models import AnalysisSummary, JobStatus
from nexsolve.errors import (
    AuthenticationError,
    JobError,
    JobTimeoutError,
    NotFoundError,
    ResourceLimitError,
    ServerConnectionError,
    UploadError,
    ValidationError,
)
from nexsolve.main import main


@pytest.fixture
def minimal_pcap(tmp_path: Path) -> Path:
    pcap = tmp_path / "valid.pcap"
    header = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
    pcap.write_bytes(header)
    return pcap


# -----------------------------------------------------------------------------
# 1. Explainability & Numerical Sanity Tests
# -----------------------------------------------------------------------------

def test_explain_feature_change_zero_baseline():
    """Ensure zero-baseline features never produce absurd percentage spikes."""
    direction, rel, importance, interp = _explain_feature_change("proto_udp_count", 0.0, 410.2096)
    assert direction == "increasing"
    assert rel == 410.2096  # natural delta scale, NOT 4,102,096
    assert "410209592" not in interp
    assert "%" not in interp
    assert "newly present in forecast" in interp


def test_explain_feature_change_stable_baseline():
    direction, rel, importance, interp = _explain_feature_change("proto_icmp_count", 0.0, 0.0)
    assert direction == "stable"
    assert importance == "LOW"
    assert "remains stable at baseline" in interp


def test_explain_feature_change_large_ratio():
    direction, rel, importance, interp = _explain_feature_change("generic_feature", 1.0, 25.0)
    assert direction == "increasing"
    assert "25.0x baseline" in interp


def test_analysis_summary_numerical_sanitization():
    raw_result = {
        "analysis_id": "job-test-sanity",
        "detection": {"threat_level": "LOW", "risk_score": float("nan")},
        "early_warning": {"early_warning_score": 10, "early_warning_level": "NORMAL"},
        "attack_progression": {"verdict": "EQUILIBRIUM"},
        "forecasts": [
            {
                "horizon": 1,
                "attackProbability": 1.5,  # should clamp to 1.0
                "cumulativeRisk": 0.8,
                "topDrivers": [
                    {
                        "feature": "proto_udp_count",
                        "current_value": 0.0,
                        "predicted_value": 410.2,
                        "direction": "up",
                        "interpretation": "Feature 'proto_udp_count' increasing by 410209592.8% relative to current state.",
                    }
                ],
            },
            {
                "horizon": 2,
                "attackProbability": -0.2,  # should clamp to 0.0
                "cumulativeRisk": 0.4,  # lower than horizon 1 -> monotonic fix ensures >= 0.8
            },
        ],
    }

    summary = AnalysisSummary.from_result(raw_result, web_base_url="http://localhost:5173")
    assert summary.risk_score == 0.0  # NaN was sanitized to 0.0
    f1 = summary.forecast_points[0]
    f2 = summary.forecast_points[1]

    assert f1["attackProbability"] == 1.0
    assert f2["attackProbability"] == 0.0
    assert f2["cumulativeRisk"] >= f1["cumulativeRisk"]  # monotonic risk maintained

    driver = summary.top_drivers[0]
    assert "410209592" not in driver["interpretation"]
    assert "newly present in forecast" in driver["interpretation"]


# -----------------------------------------------------------------------------
# 2. HTTP Error & Server Failure Engineering
# -----------------------------------------------------------------------------

class FailureHandler(BaseHTTPRequestHandler):
    mode = "ok"

    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == "/health":
            if FailureHandler.mode == "health_500":
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"detail":"internal crash"}')
                return
            if FailureHandler.mode == "health_401":
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"detail":"unauthorized"}')
                return
            if FailureHandler.mode == "malformed_json":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html>502 Bad Gateway from NGINX</html>")
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"service_status": "ok"}).encode())
            return

        if self.path.startswith("/jobs/"):
            if FailureHandler.mode == "job_404":
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'{"detail":"not found"}')
                return
            if FailureHandler.mode == "job_500":
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"detail":"db error"}')
                return
            if FailureHandler.mode == "job_malformed":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{incomplete json...")
                return
            if FailureHandler.mode == "resource_limit":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "job_id": "job-limit",
                    "status": "RESOURCE_LIMIT_EXCEEDED",
                    "stage": "PARSING",
                    "progress": 0.2,
                    "error": {
                        "resource": "packets",
                        "limit": 100000,
                        "observed": 250000,
                        "explanation": "Packet safety cap exceeded: 250,000 pkts > 100,000 limit.",
                    },
                }).encode())
                return
            if FailureHandler.mode == "result_409":
                self.send_response(409)
                self.end_headers()
                self.wfile.write(b'{"detail":"job still running"}')
                return

    def do_POST(self):
        if self.path == "/jobs":
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                self.rfile.read(length)

            if FailureHandler.mode == "upload_400":
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"detail":"Malformed multipart payload"}')
                return
            if FailureHandler.mode == "upload_401":
                self.send_response(401)
                self.end_headers()
                self.wfile.write(b'{"detail":"Invalid API Key"}')
                return
            if FailureHandler.mode == "upload_413":
                self.send_response(413)
                self.end_headers()
                self.wfile.write(b'{"detail":"Payload Too Large"}')
                return
            if FailureHandler.mode == "upload_422":
                self.send_response(422)
                self.end_headers()
                self.wfile.write(b'{"detail":"Unprocessable capture"}')
                return
            if FailureHandler.mode == "upload_500":
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b'{"detail":"Internal Worker Failure"}')
                return
            if FailureHandler.mode == "upload_malformed":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<xml>not json</xml>")
                return


@pytest.fixture
def fail_server():
    server = HTTPServer(("127.0.0.1", 0), FailureHandler)
    host, port = server.server_address
    url = f"http://127.0.0.1:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield url

    server.shutdown()
    server.server_close()


def test_health_http_401(fail_server: str):
    FailureHandler.mode = "health_401"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(AuthenticationError) as exc_info:
        client.check_health()
    assert exc_info.value.exit_code == 4


def test_health_malformed_json(fail_server: str):
    FailureHandler.mode = "malformed_json"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(ServerConnectionError) as exc_info:
        client.check_health()
    assert "invalid json" in exc_info.value.message.lower()


def test_upload_http_400(fail_server: str, minimal_pcap: Path):
    FailureHandler.mode = "upload_400"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(ValidationError) as exc_info:
        client.upload_pcap(minimal_pcap)
    assert exc_info.value.exit_code == 2


def test_upload_http_401(fail_server: str, minimal_pcap: Path):
    FailureHandler.mode = "upload_401"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(AuthenticationError) as exc_info:
        client.upload_pcap(minimal_pcap)
    assert exc_info.value.exit_code == 4


def test_upload_http_413(fail_server: str, minimal_pcap: Path):
    FailureHandler.mode = "upload_413"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(UploadError) as exc_info:
        client.upload_pcap(minimal_pcap)
    assert exc_info.value.exit_code == 5
    assert "limit" in exc_info.value.message.lower()


def test_upload_http_422(fail_server: str, minimal_pcap: Path):
    FailureHandler.mode = "upload_422"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(UploadError) as exc_info:
        client.upload_pcap(minimal_pcap)
    assert exc_info.value.exit_code == 5


def test_upload_http_500(fail_server: str, minimal_pcap: Path):
    FailureHandler.mode = "upload_500"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(ServerConnectionError) as exc_info:
        client.upload_pcap(minimal_pcap)
    assert exc_info.value.exit_code == 3


def test_upload_malformed_json(fail_server: str, minimal_pcap: Path):
    FailureHandler.mode = "upload_malformed"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(ServerConnectionError) as exc_info:
        client.upload_pcap(minimal_pcap)
    assert "invalid json" in exc_info.value.message.lower()


def test_job_status_http_404(fail_server: str):
    FailureHandler.mode = "job_404"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(NotFoundError) as exc_info:
        client.get_job_status("job-missing")
    assert exc_info.value.exit_code == 9


def test_job_status_http_500(fail_server: str):
    FailureHandler.mode = "job_500"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(ServerConnectionError) as exc_info:
        client.get_job_status("job-error")
    assert exc_info.value.exit_code == 3


def test_job_status_malformed_json(fail_server: str):
    FailureHandler.mode = "job_malformed"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(ServerConnectionError) as exc_info:
        client.get_job_status("job-bad-json")
    assert "invalid json" in exc_info.value.message.lower()


def test_job_resource_limit_exceeded(fail_server: str):
    FailureHandler.mode = "resource_limit"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(ResourceLimitError) as exc_info:
        client.poll_job("job-limit", timeout=2.0, interval=0.05)
    assert exc_info.value.exit_code == 7
    assert "safety cap exceeded" in exc_info.value.message.lower()


def test_job_result_http_409(fail_server: str):
    FailureHandler.mode = "result_409"
    client = NexSolveClient(base_url=fail_server)
    with pytest.raises(JobError) as exc_info:
        client.get_job_result("job-running")
    assert "still processing" in exc_info.value.message.lower()


# -----------------------------------------------------------------------------
# 3. UX Polish: Quiet, Verbose, and JSON Purity
# -----------------------------------------------------------------------------

def test_cli_quiet_mode_flag(mock_server: str, minimal_pcap: Path, capsys):
    from cli.tests.conftest import MockNexSolveServerHandler
    MockNexSolveServerHandler.poll_count = 0

    ret = main([
        "analyze",
        str(minimal_pcap),
        "--server", mock_server,
        "--poll-interval", "0.05",
        "-q",
        "--no-color",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    # Banner and intermediate checkmarks should NOT be present
    assert "AI-Based Network Attack Forecasting Platform" not in captured.out
    assert "Capture ingestion completed" not in captured.out
    # SOC summary and visualizer URL must still be present
    assert "CURRENT NETWORK STATE (T0)" in captured.out
    assert "ANALYSIS COMPLETE" in captured.out


def test_cli_status_quiet_mode(mock_server: str, capsys):
    ret = main([
        "status",
        "job-test123456",
        "--server", mock_server,
        "-q",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    # Quiet mode prints single line summary
    assert "job-test123456" in captured.out
    assert "NEXSOLVE JOB STATUS" not in captured.out


def test_cli_verbose_mode_diagnostics(mock_server: str, minimal_pcap: Path, capsys):
    ret = main([
        "analyze",
        str(minimal_pcap),
        "--server", mock_server,
        "--poll-interval", "0.05",
        "--verbose",
        "--no-color",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    # Diagnostic stderr messages must be present
    assert "[DEBUG]" in captured.err
    assert "Local PCAP verified" in captured.err
    assert "Checking connectivity" in captured.err


def test_cli_pure_json_mode(mock_server: str, minimal_pcap: Path, capsys):
    ret = main([
        "analyze",
        str(minimal_pcap),
        "--server", mock_server,
        "--poll-interval", "0.05",
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    # Standard output must be valid JSON and nothing else
    parsed = json.loads(captured.out)
    assert parsed["analysis_id"] == "job-test123456"
    assert "==" not in captured.out
    assert "✓" not in captured.out
    assert "[+]" not in captured.out
