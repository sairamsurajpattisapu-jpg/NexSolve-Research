"""Pytest configuration for CLI test suite."""
from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import pytest

# Ensure monorepo root and cli/src are in sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
cli_src = Path(__file__).resolve().parent.parent / "src"

if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))
if str(cli_src) not in sys.path:
    sys.path.insert(0, str(cli_src))


class MockNexSolveServerHandler(BaseHTTPRequestHandler):
    """Mock handler simulating NexSolve backend API."""

    poll_count = 0

    def log_message(self, format, *args):
        pass  # suppress logging during test execution

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"service_status": "ok", "model_loaded": True}).encode())
        elif self.path == "/jobs/job-test123456":
            MockNexSolveServerHandler.poll_count += 1
            status = "COMPLETED" if MockNexSolveServerHandler.poll_count >= 2 else "PROCESSING"
            stage = "COMPLETE" if status == "COMPLETED" else "WINDOWING"
            progress = 1.0 if status == "COMPLETED" else 0.55

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "job_id": "job-test123456",
                "filename": "sample.pcap",
                "status": status,
                "stage": stage,
                "progress": progress,
                "packets_processed": 100,
                "created_at": "2026-09-24T10:00:00Z",
                "completed_at": "2026-09-24T10:00:02Z" if status == "COMPLETED" else None,
                "error": None,
                "processing_statistics": {"packets_processed": 100},
            }).encode())
        elif self.path == "/jobs/job-test123456/result":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            result = {
                "analysis_id": "job-test123456",
                "status": "completed",
                "source": {"name": "sample.pcap"},
                "detection": {"threat_level": "ELEVATED", "risk_score": 45.0, "detected_events": 3},
                "early_warning": {"early_warning_score": 62, "early_warning_level": "ELEVATED"},
                "attack_progression": {"verdict": "RECONNAISSANCE_SCAN"},
                "traffic": {"packets": 100, "flows": 25, "windows": 8, "duration_seconds": 480},
                "forecasts": [
                    {
                        "horizon": 1,
                        "lookaheadSeconds": 60,
                        "attackProbability": 0.42,
                        "cumulativeRisk": 0.42,
                        "riskLevel": "ELEVATED",
                        "predictedStage": "RECONNAISSANCE",
                        "topDrivers": [
                            {"feature": "flow_count", "direction": "up", "current_value": 25, "predicted_value": 45, "importance": 0.8, "interpretation": "Elevated connection frequency"}
                        ],
                    }
                ],
            }
            self.wfile.write(json.dumps(result).encode())
        elif self.path == "/jobs/job-test123456/report.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<!DOCTYPE html><html><body>NexSolve Test Report</body></html>")
        elif self.path == "/jobs/job-test123456/report.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"report_id": "rep-test123456", "title": "NexSolve Report"}).encode())
        elif self.path == "/jobs/job-abstained":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "job_id": "job-abstained",
                "filename": "abstain_sample.pcap",
                "status": "COMPLETED",
                "stage": "COMPLETE",
                "progress": 1.0,
                "packets_processed": 15,
                "created_at": "2026-09-24T10:00:00Z",
                "completed_at": "2026-09-24T10:00:01Z",
                "error": None,
                "processing_statistics": {"packets_processed": 15},
            }).encode())
        elif self.path == "/jobs/job-abstained/result":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            result = {
                "analysis_id": "job-abstained",
                "status": "completed",
                "source": {"name": "abstain_sample.pcap"},
                "detection": {"threat_level": "LOW", "risk_score": 12.0, "detected_events": 0},
                "early_warning": {"early_warning_score": 10, "early_warning_level": "LOW"},
                "attack_progression": {"verdict": "BASELINE_EQUILIBRIUM"},
                "traffic": {"packets": 15, "flows": 3, "windows": 2, "duration_seconds": 120},
                "forecasts": [],
                "abstention": {
                    "abstained": True,
                    "reason": "INSUFFICIENT_HISTORY",
                    "observed_windows": 2,
                    "required_windows": 8,
                    "explanation": "Forecasting abstained: insufficient history for the selected sequence length (2 / 8 windows observed).",
                },
                "forecast_summary": {
                    "available": False,
                    "status": "INSUFFICIENT_HISTORY",
                    "required_windows": 8,
                    "available_windows": 2,
                },
            }
            self.wfile.write(json.dumps(result).encode())
        elif self.path == "/jobs/job-abstained/report.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<!DOCTYPE html><html><body>Abstention Report</body></html>")
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path == "/jobs":
            # Read and discard uploaded multipart data
            content_length = int(self.headers.get("Content-Length", 0))
            body = b""
            if content_length > 0:
                body = self.rfile.read(content_length)

            MockNexSolveServerHandler.poll_count = 0
            job_id = "job-abstained" if b"abstain" in body.lower() else "job-test123456"
            filename = "abstain_sample.pcap" if job_id == "job-abstained" else "sample.pcap"

            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "job_id": job_id,
                "filename": filename,
                "status": "QUEUED",
                "stage": "INGESTION",
                "progress": 0.1,
            }).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        self.send_response(204)
        self.end_headers()


@pytest.fixture
def mock_server():
    server = HTTPServer(("127.0.0.1", 0), MockNexSolveServerHandler)
    host, port = server.server_address
    url = f"http://127.0.0.1:{port}"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    yield url

    server.shutdown()
    server.server_close()
