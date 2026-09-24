"""Tests for NexSolve CLI V3 Subcommands (doctor, compare, evidence)."""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from nexsolve.main import main


def test_cli_doctor_text(capsys):
    ret = main(["doctor", "--no-color"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "NEXSOLVE SYSTEM DIAGNOSTICS & DOCTOR" in captured.out
    assert "Host Environment:" in captured.out
    assert "Core Engine Libraries:" in captured.out
    assert "Deep Forensics & External Sensors:" in captured.out
    assert "Predictive Models & Checkpoints:" in captured.out
    assert "Diagnostic Verdict:" in captured.out


def test_cli_doctor_json(capsys):
    ret = main(["doctor", "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "environment" in payload
    assert "libraries" in payload
    assert "torch" in payload["libraries"]
    assert "sensors" in payload
    assert "zeek" in payload["sensors"]


def test_cli_compare_local_files(tmp_path: Path, capsys):
    job_a_file = tmp_path / "analysis_a.json"
    job_b_file = tmp_path / "analysis_b.json"

    data_a = {
        "analysis_id": "job-test-alpha",
        "source": {"name": "clean_traffic.pcap"},
        "detection": {"threat_level": "LOW", "risk_score": 10.0, "detected_events": 0},
        "early_warning": {"early_warning_score": 5},
        "attack_progression": {"verdict": "BASELINE_EQUILIBRIUM"},
        "traffic": {"packets": 200, "flows": 25},
        "forecasts": [
            {"horizon": 1, "lookaheadSeconds": 60, "attackProbability": 0.05, "cumulativeRisk": 0.05, "predictedStage": "NORMAL"},
        ],
    }
    data_b = {
        "analysis_id": "job-test-beta",
        "source": {"name": "ddos_attack.pcap"},
        "detection": {"threat_level": "HIGH", "risk_score": 75.0, "detected_events": 8},
        "early_warning": {"early_warning_score": 80},
        "attack_progression": {"verdict": "CONFIRMED_COMPROMISE"},
        "traffic": {"packets": 5000, "flows": 300},
        "forecasts": [
            {"horizon": 1, "lookaheadSeconds": 60, "attackProbability": 0.82, "cumulativeRisk": 0.82, "predictedStage": "EXFILTRATION"},
        ],
    }

    job_a_file.write_text(json.dumps(data_a), encoding="utf-8")
    job_b_file.write_text(json.dumps(data_b), encoding="utf-8")

    # Text mode
    ret = main(["compare", str(job_a_file), str(job_b_file), "--no-color"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "FORENSIC ANALYSIS COMPARISON" in captured.out
    assert "ESCALATION" in captured.out
    assert "Threat Level:        LOW -> HIGH (CHANGED)" in captured.out

    # JSON mode
    ret = main(["compare", str(job_a_file), str(job_b_file), "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["comparison_verdict"] == "ESCALATION"
    assert res["delta_risk_score"] == 65.0


def test_cli_evidence_local_file(tmp_path: Path, capsys):
    job_file = tmp_path / "analysis_evidence.json"
    data = {
        "analysis_id": "job-ev-999",
        "source": {"name": "sample_capture.pcap", "sha256": "abcdef0123456789" * 4},
        "upload": {"format": "pcap", "size_bytes": 102400},
        "fingerprint": {
            "sha256": "abcdef0123456789" * 4,
            "format": "pcap",
            "link_type": "Ethernet",
            "file_size_bytes": 102400,
            "capabilities": {
                "packet_count_sampled": 150,
                "has_ipv4": True,
                "has_tcp": True,
                "ipv4_count": 150,
                "tcp_count": 150,
            },
        },
        "threat_assessment": {
            "evidence": [
                {
                    "modality": "HEURISTIC",
                    "polarity": "SUPPORTING",
                    "confidence": 0.95,
                    "description": "SYN flood signature anomaly detected on port 80",
                },
                {
                    "modality": "BEHAVIORAL",
                    "polarity": "CONTRADICTORY",
                    "description": "Payload size variance matches regular telemetry",
                },
            ],
            "observed_techniques": ["T1498"],
            "forecast_techniques": ["T1499"],
        },
        "network_intelligence": {
            "evidence_summary": {
                "observed_modalities": ["HEURISTIC", "BEHAVIORAL"],
                "observed_techniques": ["T1498"],
                "forecast_techniques": ["T1499"],
            },
        },
        "prioritized_threats": [
            {"entity": "192.168.1.100", "priority": "CRITICAL", "score": 95.0},
        ],
    }
    job_file.write_text(json.dumps(data), encoding="utf-8")

    # Text mode
    ret = main(["evidence", str(job_file), "--no-color"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "EVIDENCE & CAPTURE PROVENANCE" in captured.out
    assert "SHA-256:" in captured.out
    assert "Supporting Indicators (1):" in captured.out
    assert "Contradictory / Disconfirming Signals (1):" in captured.out
    assert "192.168.1.100" in captured.out

    # JSON mode
    ret = main(["evidence", str(job_file), "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["analysis_id"] == "job-ev-999"
    assert "fingerprint" in res
    assert len(res["evidence_items"]) == 2
