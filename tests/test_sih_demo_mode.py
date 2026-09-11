"""Verification test suite for NexSolve SIH Demo Mode and Deterministic Scenarios."""
from __future__ import annotations

import json
from fastapi.testclient import TestClient
import pytest

from demo.scenarios import (
    DEMO_SCENARIO_METADATA,
    get_demo_report_html,
    get_demo_report_json,
    get_demo_scenario,
    get_demo_scenarios_metadata,
)
from model_service.app import app

client = TestClient(app)

EXPECTED_SCENARIO_IDS = [
    "NORMAL_TRAFFIC",
    "EARLY_ATTACK_SIGNAL",
    "SUSTAINED_ATTACK_FORECAST",
    "CONTRADICTORY_EVIDENCE",
    "UNKNOWN_BEHAVIOR",
    "FORECAST_ABSTAINED",
    "POOR_CAPTURE_QUALITY",
]


def test_demo_scenarios_metadata_registry():
    metas = get_demo_scenarios_metadata()
    assert len(metas) == 7
    ids = [m["id"] for m in metas]
    assert ids == EXPECTED_SCENARIO_IDS

    for meta in metas:
        assert "name" in meta
        assert "badge" in meta
        assert "tone" in meta
        assert "description" in meta
        assert "expected_behavior" in meta


def test_api_list_demo_scenarios():
    resp = client.get("/api/demo/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 7
    assert [d["id"] for d in data] == EXPECTED_SCENARIO_IDS


@pytest.mark.parametrize("scenario_id", EXPECTED_SCENARIO_IDS)
def test_all_scenarios_payload_conformance(scenario_id: str):
    # 1. API route
    resp = client.get(f"/api/demo/scenarios/{scenario_id}")
    assert resp.status_code == 200
    data = resp.json()

    # Base metadata and flags
    assert data["is_demo"] is True
    assert data["demo_scenario_id"] == scenario_id
    assert data["status"] == "completed"
    assert data["analysis_id"] == f"demo-{scenario_id.lower()}"
    assert "[DEMO MODE]" in data["source"]["name"]

    # Canonical components
    assert "traffic" in data
    assert "detection" in data
    assert "quality" in data
    assert "validation" in data

    # Trust Layer contracts
    assert "attack_horizon" in data
    assert "evidence_chain" in data
    assert "confidence" in data
    assert "unknown_behavior" in data
    assert "abstention" in data
    assert "forecasts" in data
    assert len(data["forecasts"]) == 5

    # Processing metrics present
    assert "processing_metrics" in data
    assert "total_processing_ms" in data["processing_metrics"]


def test_scenario_specific_behavior_contracts():
    # 1. NORMAL_TRAFFIC
    normal = client.get("/api/demo/scenarios/NORMAL_TRAFFIC").json()
    assert normal["attack_horizon"]["state"] == "NO_ATTACK_FORECAST"
    assert normal["abstention"]["abstained"] is False
    assert normal["unknown_behavior"]["classification"] == "KNOWN_PATTERN"

    # 2. EARLY_ATTACK_SIGNAL
    early = client.get("/api/demo/scenarios/EARLY_ATTACK_SIGNAL").json()
    assert early["attack_horizon"]["state"] == "EARLY_SIGNAL"
    assert early["attack_horizon"]["onset_horizon"] == 1
    assert early["attack_horizon"]["lead_time_seconds"] == 60
    assert early["confidence"]["calibration_status"] == "UNSUPPORTED"

    # 3. SUSTAINED_ATTACK_FORECAST
    sust = client.get("/api/demo/scenarios/SUSTAINED_ATTACK_FORECAST").json()
    assert sust["attack_horizon"]["state"] == "SUSTAINED_ATTACK_FORECAST"
    assert sust["attack_horizon"]["horizon_windows"] == 3
    assert sust["attack_horizon"]["horizon_seconds"] == 180
    assert sust["evidence_chain"]["supporting_feature_count"] >= 3

    # 4. CONTRADICTORY_EVIDENCE
    contra = client.get("/api/demo/scenarios/CONTRADICTORY_EVIDENCE").json()
    assert contra["attack_horizon"]["state"] == "UNCERTAIN_FORECAST"
    assert contra["evidence_chain"]["contradictory_feature_count"] >= 2
    assert contra["confidence"]["uncertainty_level"] == "HIGH"

    # 5. UNKNOWN_BEHAVIOR
    ood = client.get("/api/demo/scenarios/UNKNOWN_BEHAVIOR").json()
    assert ood["unknown_behavior"]["classification"] == "UNKNOWN_BEHAVIOR"
    assert ood["unknown_behavior"]["abstain_recommended"] is True
    # Crucial scientific check: unknown behavior is NOT labeled an attack
    assert "UNKNOWN_BEHAVIOR" in ood["unknown_behavior"]["classification"]

    # 6. FORECAST_ABSTAINED
    abst = client.get("/api/demo/scenarios/FORECAST_ABSTAINED").json()
    assert abst["attack_horizon"]["state"] == "ABSTAINED"
    assert abst["abstention"]["abstained"] is True
    assert abst["abstention"]["status"] == "FORECAST_UNAVAILABLE"
    assert len(abst["abstention"]["missing_requirements"]) >= 1

    # 7. POOR_CAPTURE_QUALITY
    qual = client.get("/api/demo/scenarios/POOR_CAPTURE_QUALITY").json()
    assert qual["quality"]["status"] == "DEGRADED"
    assert qual["quality"]["packet_loss_ratio"] > 0.15
    assert qual["abstention"]["abstained"] is True
    assert qual["abstention"]["reason"] == "CAPTURE_QUALITY_DEGRADED"


def test_demo_reports_generation():
    # Test JSON Report
    json_resp = client.get("/api/demo/scenarios/SUSTAINED_ATTACK_FORECAST/report.json")
    assert json_resp.status_code == 200
    report = json_resp.json()
    assert report["report_id"] == "rep-demo-sustained_attack_forecast"
    assert "executive_summary" in report["sections"]
    assert "attack_horizon" in report["sections"]
    assert "provenance" in report["sections"]

    # Test HTML Report
    html_resp = client.get("/api/demo/scenarios/SUSTAINED_ATTACK_FORECAST/report.html")
    assert html_resp.status_code == 200
    assert "<!DOCTYPE html>" in html_resp.text
    assert "NEXSOLVE" in html_resp.text
    assert "@media print" in html_resp.text
    assert "cdn." not in html_resp.text  # No external CDNs


def test_jobs_fallback_route_for_demo():
    # Result endpoint
    res_resp = client.get("/jobs/demo-early_attack_signal/result")
    assert res_resp.status_code == 200
    assert res_resp.json()["attack_horizon"]["state"] == "EARLY_SIGNAL"

    # Status endpoint
    status_resp = client.get("/jobs/demo-early_attack_signal")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "COMPLETED"

    # HTML Report endpoint
    html_resp = client.get("/jobs/demo-early_attack_signal/report.html")
    assert html_resp.status_code == 200
    assert "<!DOCTYPE html>" in html_resp.text

    # JSON Report endpoint
    json_resp = client.get("/jobs/demo-early_attack_signal/report.json")
    assert json_resp.status_code == 200
    assert json_resp.json()["report_id"] == "rep-demo-early_attack_signal"


def test_deterministic_reproducibility():
    # Query scenario multiple times and assert exact equality
    res1 = get_demo_scenario("SUSTAINED_ATTACK_FORECAST")
    res2 = get_demo_scenario("SUSTAINED_ATTACK_FORECAST")
    assert json.dumps(res1, sort_keys=True) == json.dumps(res2, sort_keys=True)
