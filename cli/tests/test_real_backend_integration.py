"""End-to-end integration test connecting CLI with real FastAPI backend."""
from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
import pytest
import uvicorn

from model_service.app import app
from nexsolve.main import main

ROOT = Path(__file__).resolve().parents[2]
PCAP_SLICE = ROOT / "data" / "test_slices" / "friday_10windows_slice.pcap"


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def live_backend_server():
    """Launch the real FastAPI backend on an ephemeral localhost port."""
    port = get_free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to bind
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)

    url = f"http://127.0.0.1:{port}"
    yield url

    server.should_exit = True
    thread.join(timeout=3.0)


@pytest.mark.skipif(not PCAP_SLICE.exists(), reason="Test PCAP slice not found")
def test_real_backend_e2e_analyze(live_backend_server: str, capsys):
    """Execute 'nexsolve analyze' against the real running FastAPI backend."""
    ret = main([
        "analyze",
        str(PCAP_SLICE),
        "--server", live_backend_server,
        "--web-url", "http://localhost:5173",
        "--poll-interval", "0.2",
        "--timeout", "30.0",
        "--no-color",
    ])
    assert ret == 0
    captured = capsys.readouterr()

    # Verify UX stages and completion
    assert "PCAP validated" in captured.out
    assert "Upload completed" in captured.out
    assert "Analysis started" in captured.out
    assert "ANALYSIS COMPLETE" in captured.out
    assert "Analysis ID:" in captured.out
    assert "http://localhost:5173/console/forecast/job-" in captured.out
    assert "http://localhost:5173/console/reports/job-" in captured.out

    # Verify SOC metrics from real processing
    assert "Observed Threat Level:" in captured.out
    assert "Current Risk Score:" in captured.out
    assert "Early Warning Score:" in captured.out
    assert "T+1" in captured.out
    assert "T+5" in captured.out


@pytest.mark.skipif(not PCAP_SLICE.exists(), reason="Test PCAP slice not found")
def test_real_backend_e2e_json_output(live_backend_server: str, capsys):
    """Execute 'nexsolve analyze --json' against the real running FastAPI backend."""
    ret = main([
        "analyze",
        str(PCAP_SLICE),
        "--server", live_backend_server,
        "--poll-interval", "0.2",
        "--timeout", "30.0",
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()

    import json
    data = json.loads(captured.out)
    assert data["status"] == "completed"
    assert data["analysis_id"].startswith("job-")
    assert data["packet_count"] == 2277
    assert data["window_count"] == 10
    assert "forecasts" in data
    assert len(data["forecasts"]) == 5


@pytest.mark.skipif(not PCAP_SLICE.exists(), reason="Test PCAP slice not found")
def test_real_backend_complete_analyst_workflow(live_backend_server: str, tmp_path: Path, capsys):
    """Execute complete 9-step real product workflow against live FastAPI backend."""
    import json

    # 1. Analyze & capture job ID
    ret = main([
        "analyze",
        str(PCAP_SLICE),
        "--server", live_backend_server,
        "--poll-interval", "0.2",
        "--timeout", "30.0",
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    job_id = data["analysis_id"]
    assert job_id.startswith("job-")

    # 2. Status
    ret_stat = main(["status", job_id, "--server", live_backend_server, "--json"])
    assert ret_stat == 0
    capsys.readouterr()

    # 3. Progression
    ret_prog = main(["progression", job_id, "--server", live_backend_server, "--json"])
    assert ret_prog == 0
    prog_json = json.loads(capsys.readouterr().out)
    assert "canonical_stage" in prog_json
    assert "timeline" in prog_json

    # 4. Evidence
    ret_ev = main(["evidence", job_id, "--server", live_backend_server, "--json"])
    assert ret_ev == 0
    capsys.readouterr()

    # 5. Explain
    ret_exp = main(["explain", job_id, "--server", live_backend_server, "--json"])
    assert ret_exp == 0
    exp_json = json.loads(capsys.readouterr().out)
    assert "decision" in exp_json
    assert "sensor_agreement" in exp_json

    # 6. Investigate
    ret_inv = main(["investigate", job_id, "--server", live_backend_server, "--json"])
    assert ret_inv == 0
    inv_json = json.loads(capsys.readouterr().out)
    assert "capture" in inv_json
    assert "threat" in inv_json
    assert "forecast" in inv_json

    # 7. Report
    report_file = tmp_path / "downloaded_report.html"
    ret_rep = main(["report", job_id, "--server", live_backend_server, "-o", str(report_file)])
    assert ret_rep == 0
    assert report_file.exists()

    # 8. Export Markdown
    md_file = tmp_path / "exported_report.md"
    ret_export = main(["export", job_id, "--server", live_backend_server, "--format", "markdown", "-o", str(md_file)])
    assert ret_export == 0
    assert md_file.exists()
    md_content = md_file.read_text(encoding="utf-8")
    assert "## 01 — Executive Summary" in md_content
    assert "## 06 — Attack Progression" in md_content

