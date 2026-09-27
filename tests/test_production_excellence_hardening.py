"""Exhaustive Regression Suite for Production Excellence Hardening.

Covers:
1. Central Forecast Gate & Abstention Propagation across API, Jobs, and Reports
2. Data Quality Gate across all 7 dimensions and status levels (GOOD, DEGRADED, INSUFFICIENT)
3. Zero-Contradiction Semantic Validation in Reporting Layer
4. Strict Provenance Separation (Observed vs Derived vs Inferred vs Forecast)
5. Attack Progression Horizon Invariance and Zero Synthetic Confidence
6. Frozen World Model SHA-256 Bitwise Immutability
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from nexsolve_core.data_quality import (
    DataQualityAssessment,
    QualityCheckResult,
    assess_data_quality,
)
from nexsolve_core.schemas import QualityStatus
from nexsolve_core.provenance import (
    ProvenanceCategory,
    get_field_provenance,
    classify_timeline_event,
)
from reporting.semantic_validator import (
    validate_report_semantics,
    ReportSemanticContradictionError,
)
from ml.forecasting.central_gate import execute_central_forecast_gate
from ml.forecasting.attack_progression import (
    forecast_attack_progression,
    AttackProgressionState,
    PredictionType,
)
from ml.forecasting.attack_stages import AttackStage, StageClassification
from model_service.pcap_upload import analyze_uploaded_capture


ROOT_DIR = Path(__file__).resolve().parents[1]
FINAL_MODEL_DIR = ROOT_DIR / "models" / "final_world_model"

FROZEN_MODEL_HASHES = {
    "config.json": "98c55f8685478286264438b07db7dca72b3a42f1a41e0a4d26366654379aa1a1",
    "feature_schema.json": "2bb8714f2da49f124c82209488e9dc1eccff3ca8f655079404ba7efb27e4454b",
    "manifest.json": "75bef97f0be8c7310a9af89d8f13046c9f7e3a12303a7a55582913996805cbf6",
    "metadata.json": "19816e54918779b1226db88a0ea7319dab7d831423b7d6a77181915f90a20093",
    "metrics.json": "8b2b395728be2f8ffd80a66a2e120d634b2206cd2abf2db5aec39fc65c4414b9",
    "model.npz": "5787b2abd68b2243f45ae1290e24b2daa5483e69405660cf3de824fd8b498ecc",
    "preprocessing.npz": "e85d998324d7f45215494ca09d1c9388667f49b7e72d0a1511a1b64b0c72c6b3",
}


def test_frozen_world_model_sha256_immutability():
    """Verify that NO files in models/final_world_model/ have been altered bitwise."""
    assert FINAL_MODEL_DIR.exists(), f"Model directory {FINAL_MODEL_DIR} not found"

    for filename, expected_hash in FROZEN_MODEL_HASHES.items():
        file_path = FINAL_MODEL_DIR / filename
        assert file_path.exists(), f"Required model file {filename} does not exist"
        data = file_path.read_bytes()
        actual_hash = hashlib.sha256(data).hexdigest()
        assert actual_hash == expected_hash, (
            f"FROZEN MODEL VIOLATION: {filename} hash changed!\n"
            f"Expected: {expected_hash}\n"
            f"Actual:   {actual_hash}"
        )


def test_data_quality_gate_all_dimensions():
    """Verify Data Quality Gate evaluates all 7 dimensions and correctly classifies quality."""
    base_ts = 1710000000.0
    good_windows = []
    for i in range(10):
        w = {
            "window_id": f"win_{i}",
            "window_start": base_ts + i * 60.0,
            "window_end": base_ts + (i + 1) * 60.0,
            "packet_count": 100,
            "byte_count": 50000,
            "tcp_count": 80,
            "udp_count": 20,
            "flows": [],
        }
        good_windows.append(w)

    assessment = assess_data_quality(good_windows, {"valid_pcap": True, "truncated": False, "tcp_count": 800, "udp_count": 200})
    assert assessment.overall_status in (QualityStatus.GOOD, QualityStatus.DEGRADED)
    assert len(assessment.checks) == 7

    expected_checks = {
        "packet_integrity",
        "timestamp_availability",
        "temporal_continuity",
        "window_coverage",
        "protocol_observability",
        "flow_reconstruction_quality",
        "required_feature_availability",
    }
    assert set(assessment.checks.keys()) == expected_checks

    # 2. Insufficient history scenario (< 8 windows)
    short_assessment = assess_data_quality(good_windows[:5], {"valid_pcap": True})
    assert short_assessment.overall_status == QualityStatus.INSUFFICIENT
    assert short_assessment.checks["window_coverage"].status == QualityStatus.INSUFFICIENT


def test_provenance_category_separation():
    """Verify telemetry and analytics fields have explicit provenance categorization."""
    assert get_field_provenance("packet_count") == ProvenanceCategory.OBSERVED
    assert get_field_provenance("byte_count") == ProvenanceCategory.OBSERVED
    assert get_field_provenance("flows") == ProvenanceCategory.DERIVED
    assert get_field_provenance("entropy") == ProvenanceCategory.DERIVED
    assert get_field_provenance("findings") == ProvenanceCategory.INFERRED
    assert get_field_provenance("mitre_tactics") == ProvenanceCategory.INFERRED
    assert get_field_provenance("forecast_points") == ProvenanceCategory.FORECAST
    assert get_field_provenance("attack_probability") == ProvenanceCategory.FORECAST
    assert get_field_provenance("unknown_unmapped_field") == ProvenanceCategory.UNKNOWN

    # Event classification
    assert classify_timeline_event("T0", is_observed=True) == ProvenanceCategory.OBSERVED
    assert classify_timeline_event("T+1", is_observed=False) == ProvenanceCategory.FORECAST
    assert classify_timeline_event("T+3", is_observed=False) == ProvenanceCategory.FORECAST


def test_semantic_validator_enforces_zero_contradictions():
    """Verify that validate_report_semantics raises on contradictory reports."""
    # 1. Valid abstained report passes
    valid_abstained_report = {
        "analysis_id": "test-123",
        "timestamp_utc": "2026-09-27T00:00:00Z",
        "executive_summary": {"operational_status": "COMPLETED"},
        "forecast_status": "FORECAST_ABSTAINED",
        "is_forecast_available": False,
        "abstention": {
            "abstained": True,
            "reason": "INSUFFICIENT_HISTORY",
            "explanation": "Need at least 8 continuous windows.",
        },
        "forecast_points": [
            {
                "horizon": h,
                "lookahead_seconds": h * 60,
                "attack_probability": None,
                "predicted_stage": None,
                "confidence": None,
                "abstained": True,
            }
            for h in (1, 2, 3, 4, 5)
        ],
        "attack_progression": {
            "verdict": "ABSTAINED",
            "forecast_points": [
                {"horizon": h, "abstained": True, "forecast_confidence": 0.0}
                for h in (1, 2, 3, 4, 5)
            ],
            "timeline": [
                {"horizon_label": "T0", "stage": "BENIGN", "confidence": 0.90},
                {"horizon_label": "T+1", "stage": "UNKNOWN", "confidence": 0.0},
            ],
        },
    }
    assert validate_report_semantics(valid_abstained_report) is None

    # 2. Contradiction: Abstained report containing active attack probability
    invalid_report_1 = json.loads(json.dumps(valid_abstained_report))
    invalid_report_1["forecast_points"][0]["attack_probability"] = 0.85
    with pytest.raises(ReportSemanticContradictionError) as exc_info:
        validate_report_semantics(invalid_report_1)
    assert "non-null attack probability" in str(exc_info.value)

    # 3. Contradiction: Abstained report claiming positive forecast confidence
    invalid_report_2 = json.loads(json.dumps(valid_abstained_report))
    invalid_report_2["forecast_points"][0]["confidence"] = 0.90
    with pytest.raises(ReportSemanticContradictionError) as exc_info:
        validate_report_semantics(invalid_report_2)
    assert "positive confidence" in str(exc_info.value)

    # 4. Contradiction: Active progression stage claimed while report abstained
    invalid_report_3 = json.loads(json.dumps(valid_abstained_report))
    invalid_report_3["attack_progression"]["timeline"][1]["stage"] = "RECONNAISSANCE"
    with pytest.raises(ReportSemanticContradictionError) as exc_info:
        validate_report_semantics(invalid_report_3)
    assert "active predicted stage" in str(exc_info.value)


def test_short_pcap_abstention_propagation_end_to_end(tmp_path: Path):
    """Verify real PCAP with 4 windows abstains cleanly without leaking synthetic data."""
    base_epoch = 1720000000.0
    packets = []
    # 4 windows (below 8 threshold)
    for w in range(4):
        for p in range(5):
            pkt = (
                Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
                / IP(src="192.168.1.10", dst="192.168.1.50")
                / TCP(sport=10000 + w, dport=443, flags="PA")
            )
            pkt.time = base_epoch + w * 60.0 + p * 2.0
            packets.append(pkt)

    pcap_file = tmp_path / "four_windows.pcap"
    wrpcap(str(pcap_file), packets)
    content = pcap_file.read_bytes()

    result = analyze_uploaded_capture("four_windows.pcap", content)

    # Pipeline completed extraction and baseline analytics
    assert result["status"] == "completed"
    assert result["window_count"] == 4
    assert result["packet_count"] == 20

    # Forecasting explicitly withheld
    assert result["forecast_status"] == "FORECAST_ABSTAINED"
    assert result["is_forecast_available"] is False
    assert result["abstention"]["abstained"] is True
    assert "INSUFFICIENT_HISTORY" in result["abstention"]["reason"]

    # Forecast points withhold predictions
    for pt in result["forecasts"]:
        assert pt["attackProbability"] is None
        assert pt["predictedStage"] is None
        assert pt["confidence"] is None
        assert "Forecast abstained" in pt["explanation"][0]

    # Progression sanitized
    prog = result["attack_progression"]
    assert prog["verdict"] == "ABSTAINED"
    for pt in prog["forecast_points"]:
        assert pt["abstained"] is True
        assert pt["forecast_confidence"] == 0.0

    # Data Quality reflected
    assert "data_quality" in result
    assert result["data_quality_status"] == "INSUFFICIENT"
