"""Tests for NexSolve CLI V4 Forecasting Science & Evaluation Subcommands (evaluate, benchmark)."""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from nexsolve.main import main


def test_cli_evaluate_help(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["evaluate", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Evaluate model forecasting performance" in captured.out
    assert "--horizons" in captured.out
    assert "--embargo-seconds" in captured.out


def test_cli_benchmark_help(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["benchmark", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Run standardized input-parity benchmark" in captured.out
    assert "--horizons" in captured.out
    assert "--embargo-seconds" in captured.out


def test_cli_evaluate_json(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "exp_eval"
    ret = main([
        "evaluate",
        "unsw",
        "--horizons", "1,2",
        "--output", str(out_dir / "placeholder"),
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["dataset"] == "UNSW-NB15"
    assert "experiment_id" in payload
    assert "metrics_by_horizon" in payload
    assert "1" in payload["metrics_by_horizon"]


def test_cli_benchmark_json(tmp_path: Path, capsys) -> None:
    out_dir = tmp_path / "exp_benchmark"
    ret = main([
        "benchmark",
        "unsw",
        "--horizons", "1,2",
        "--output", str(out_dir / "placeholder"),
        "--json",
    ])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["dataset_name"] == "UNSW-NB15"
    assert "PersistenceBaseline" in payload["models_evaluated"]
    assert "LogisticRegressionBaseline" in payload["models_evaluated"]
    assert "horizon_metrics" in payload


def test_cli_progression_help(capsys) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["progression", "--help"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "Inspect 15-stage canonical attack progression" in captured.out
    assert "--json" in captured.out
    assert "--no-color" in captured.out
    assert "--quiet" in captured.out


def test_cli_progression_json_and_quiet(tmp_path: Path, capsys) -> None:
    # Create sample analysis JSON with attack progression payload
    sample_file = tmp_path / "sample_analysis.json"
    sample_data = {
        "analysis_id": "test-job-prog-001",
        "source": {"filename": "attack_scan.pcap"},
        "attack_progression": {
            "canonical_stage": "RECONNAISSANCE",
            "observed_state": "RECONNAISSANCE",
            "classification": "OBSERVED",
            "stage_confidence": 0.88,
            "technique_confidence": 0.85,
            "observed_techniques": ["T1046"],
            "verdict": "ACTIVE_RECONNAISSANCE",
            "timeline": [
                {
                    "stage": "RECONNAISSANCE",
                    "classification": "OBSERVED",
                    "primary_techniques": ["T1046"],
                    "confidence": 0.88,
                    "stage_confidence": 0.88,
                    "supporting_evidence_count": 2,
                    "horizon_label": "T0",
                }
            ],
            "transitions": [
                {
                    "from_stage": "RECONNAISSANCE",
                    "to_stage": "INITIAL_ACCESS",
                    "transition_type": "FORECAST",
                    "status": "VALID",
                    "confidence": 0.75,
                    "reason": "Sequential progression step",
                }
            ],
            "validation": {
                "valid": True,
                "issues": [],
                "warnings": [],
                "event_count": 1,
                "transition_count": 1,
            },
        },
    }
    sample_file.write_text(json.dumps(sample_data), encoding="utf-8")

    # 1. Test --json flag
    ret = main(["progression", str(sample_file), "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["canonical_stage"] == "RECONNAISSANCE"
    assert payload["classification"] == "OBSERVED"
    assert payload["validation"]["valid"] is True

    # 2. Test --quiet flag
    ret_q = main(["progression", str(sample_file), "--quiet"])
    assert ret_q == 0
    captured_q = capsys.readouterr()
    assert captured_q.out.strip() == "RECONNAISSANCE"

    # 3. Test standard human-readable terminal rendering
    ret_term = main(["progression", str(sample_file), "--no-color"])
    assert ret_term == 0
    captured_term = capsys.readouterr()
    assert "DYNAMIC ATTACK PROGRESSION & 15-STAGE LIFECYCLE ENGINE" in captured_term.out
    assert "RECONNAISSANCE" in captured_term.out
    assert "T1046" in captured_term.out
    assert "PASSED (VALID)" in captured_term.out
