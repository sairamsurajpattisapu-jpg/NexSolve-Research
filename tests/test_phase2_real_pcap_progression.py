"""End-to-End Real PCAP Validation for Phase 2 Dynamic Attack Progression Engine.

Tests:
1. Ingest real 10-window capture: data/test_slices/friday_10windows_slice.pcap.
2. Verify full 15-stage canonical progression output from pipeline.
3. Validate timeline events, separated confidences, and state transitions.
4. Execute CLI `nexsolve progression` command against real analysis payload.
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from model_service.pcap_upload import analyze_uploaded_capture
from ml.forecasting.attack_stages import AttackStage
from nexsolve.main import main


PCAP_PATH = Path("data/test_slices/friday_10windows_slice.pcap")


@pytest.mark.skipif(not PCAP_PATH.exists(), reason="friday_10windows_slice.pcap test fixture missing")
def test_real_pcap_progression_pipeline_and_cli(tmp_path: Path, capsys) -> None:
    content = PCAP_PATH.read_bytes()
    analysis = analyze_uploaded_capture(filename=PCAP_PATH.name, content=content)

    assert "attack_progression" in analysis
    prog = analysis["attack_progression"]

    # 1. Verify Canonical Stage & Classification
    assert "canonical_stage" in prog
    assert prog["canonical_stage"] in [s.value for s in AttackStage]
    assert prog["classification"] in ("OBSERVED", "INFERRED", "FORECAST", "UNKNOWN")

    # 2. Verify Separated Confidences (not conflated)
    assert 0.0 <= prog["stage_confidence"] <= 1.0
    assert 0.0 <= prog["technique_confidence"] <= 1.0

    # 3. Verify Timeline Events across Horizons
    assert "timeline" in prog
    assert len(prog["timeline"]) >= 1
    for ev in prog["timeline"]:
        assert "stage" in ev
        assert "classification" in ev
        assert 0.0 <= ev["confidence"] <= 1.0
        assert 0.0 <= ev["stage_confidence"] <= 1.0
        assert 0.0 <= ev["technique_confidence"] <= 1.0

    # 4. Verify Validated Transitions
    assert "transitions" in prog
    for tr in prog["transitions"]:
        assert "from_stage" in tr
        assert "to_stage" in tr
        assert tr["status"] in ("VALID", "VALID_BUT_UNUSUAL", "INSUFFICIENT_EVIDENCE", "CONTRADICTORY", "INVALID")
        assert 0.0 <= tr["confidence"] <= 1.0

    # 5. Verify Progression Timeline Validation Audit
    assert "validation" in prog
    val = prog["validation"]
    assert isinstance(val["valid"], bool)
    assert isinstance(val["issues"], list)
    assert isinstance(val["warnings"], list)

    # 6. Save Analysis JSON and test CLI `nexsolve progression`
    analysis_file = tmp_path / "friday_analysis.json"
    analysis_file.write_text(json.dumps(analysis, default=str), encoding="utf-8")

    # CLI Test: --json
    ret_json = main(["progression", str(analysis_file), "--json"])
    assert ret_json == 0
    captured_json = capsys.readouterr()
    payload = json.loads(captured_json.out)
    assert payload["canonical_stage"] == prog["canonical_stage"]
    assert payload["validation"]["valid"] == val["valid"]

    # CLI Test: --quiet
    ret_quiet = main(["progression", str(analysis_file), "--quiet"])
    assert ret_quiet == 0
    captured_quiet = capsys.readouterr()
    assert captured_quiet.out.strip() == prog["canonical_stage"]

    # CLI Test: Human-Readable Terminal View
    ret_term = main(["progression", str(analysis_file), "--no-color"])
    assert ret_term == 0
    captured_term = capsys.readouterr()
    assert "DYNAMIC ATTACK PROGRESSION & 15-STAGE LIFECYCLE ENGINE" in captured_term.out
    assert prog["canonical_stage"] in captured_term.out
