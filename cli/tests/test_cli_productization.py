"""Test suite for Master Productization CLI commands: investigate, explain, export, version, doctor.

Verifies:
- nexsolve investigate (terminal & JSON modes)
- nexsolve explain (terminal & JSON modes)
- nexsolve export (HTML, Markdown, and JSON report export)
- nexsolve version (terminal & JSON modes)
- nexsolve doctor (diagnostic tiers and states)
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from model_service.pcap_upload import analyze_uploaded_capture
from nexsolve.main import main


PCAP_PATH = Path("data/test_slices/friday_10windows_slice.pcap")


@pytest.fixture(scope="module")
def analysis_file(tmp_path_factory) -> Path:
    tmp_dir = tmp_path_factory.mktemp("prod_test")
    pcap_data = PCAP_PATH.read_bytes()
    analysis = analyze_uploaded_capture(PCAP_PATH.name, pcap_data)
    file_path = tmp_dir / "friday_analysis.json"
    file_path.write_text(json.dumps(analysis, default=str), encoding="utf-8")
    return file_path


def test_cli_version_terminal(capsys):
    ret = main(["version", "--no-color"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "NEXSOLVE PLATFORM & SYSTEM VERSION" in out
    assert "CLI Tooling:" in out
    assert "Python Runtime:" in out


def test_cli_version_json(capsys):
    ret = main(["version", "--json"])
    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert "nexsolve_version" in payload
    assert "cli_version" in payload
    assert "model_version" in payload
    assert "feature_schemas" in payload
    assert "python_version" in payload


def test_cli_doctor_terminal(capsys):
    ret = main(["doctor", "--no-color"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "NEXSOLVE SYSTEM DIAGNOSTICS & DOCTOR" in out
    assert "Core Engine Libraries: (REQUIRED)" in out
    assert "Deep Forensics & External Sensors: (OPTIONAL)" in out
    assert "Predictive Models & Checkpoints: (REQUIRED)" in out
    assert "Filesystem Permissions & Storage (REQUIRED)" in out
    assert "Resource Governance & Limits (REQUIRED)" in out


def test_cli_doctor_json(capsys):
    ret = main(["doctor", "--json"])
    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert "libraries" in payload
    assert "sensors" in payload
    assert "filesystem" in payload
    assert "configuration" in payload


def test_cli_investigate_terminal(analysis_file: Path, capsys):
    ret = main(["investigate", str(analysis_file), "--no-color"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "NEXSOLVE 360-DEGREE ANALYST INVESTIGATION" in out
    assert "[1] CAPTURE IDENTITY" in out
    assert "[2] THREAT POSTURE" in out
    assert "[3] ATTACK PROGRESSION" in out
    assert "[4] MULTI-HORIZON ATTACK FORECAST" in out
    assert "[5] EVIDENTIARY CORROBORATION" in out
    assert "[6] MITRE ATT&CK GROUNDING" in out
    assert "[7] UNCERTAINTY & ABSTENTION" in out
    assert "[8] FORENSIC REPORTS & VISUALIZATION" in out


def test_cli_investigate_json(analysis_file: Path, capsys):
    ret = main(["investigate", str(analysis_file), "--json"])
    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert "capture" in payload
    assert "threat" in payload
    assert "attack_state" in payload
    assert "progression" in payload
    assert "forecast" in payload
    assert "evidence" in payload
    assert "mitre" in payload
    assert "uncertainty" in payload
    assert "reports" in payload
    assert "web_console" in payload


def test_cli_explain_terminal(analysis_file: Path, capsys):
    ret = main(["explain", str(analysis_file), "--no-color"])
    assert ret == 0
    out = capsys.readouterr().out
    assert "NEXSOLVE DECISION EXPLAINABILITY & PROVENANCE" in out
    assert "[1] ANALYTICAL CONCLUSION & STAGE REASONING" in out
    assert "[2] TOP NETWORK FEATURE DRIVERS" in out
    assert "[3] MULTI-SENSOR AGREEMENT" in out
    assert "[4] GROUNDED MITRE ATT&CK TECHNIQUES" in out
    assert "[5] ATTACK TRANSITION KINEMATICS" in out
    assert "[6] UNCERTAINTY & METHODOLOGICAL BOUNDARIES" in out


def test_cli_explain_json(analysis_file: Path, capsys):
    ret = main(["explain", str(analysis_file), "--json"])
    assert ret == 0
    payload = json.loads(capsys.readouterr().out)
    assert "decision" in payload
    assert "top_feature_drivers" in payload
    assert "sensor_agreement" in payload
    assert "grounded_techniques" in payload
    assert "stage_reasoning" in payload
    assert "transition_kinematics" in payload
    assert "uncertainty_boundaries" in payload


def test_cli_export_markdown(analysis_file: Path, tmp_path: Path, capsys):
    md_out = tmp_path / "exported_report.md"
    ret = main(["export", str(analysis_file), "--format", "markdown", "-o", str(md_out)])
    assert ret == 0
    assert md_out.exists()
    content = md_out.read_text(encoding="utf-8")
    assert "## 01 — Executive Summary [INFERRED]" in content
    assert "## 06 — Attack Progression [INFERRED]" in content
    assert "## 07 — Attack Horizon [FORECAST]" in content
    assert "## 11 — Sensor Agreement [OBSERVED]" in content
    assert "## 16 — Limitations & Governance [OBSERVED]" in content


def test_cli_export_html(analysis_file: Path, tmp_path: Path, capsys):
    html_out = tmp_path / "exported_report.html"
    ret = main(["export", str(analysis_file), "--format", "html", "-o", str(html_out)])
    assert ret == 0
    assert html_out.exists()
    content = html_out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in content
    assert "01 &mdash; EXECUTIVE ASSESSMENT" in content
    assert "Sensor Agreement & Cross-Modal Corroboration" in content


def test_cli_export_json(analysis_file: Path, tmp_path: Path, capsys):
    json_out = tmp_path / "exported_report.json"
    ret = main(["export", str(analysis_file), "--format", "json", "-o", str(json_out)])
    assert ret == 0
    assert json_out.exists()
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert "report_id" in data
    assert "sections" in data
