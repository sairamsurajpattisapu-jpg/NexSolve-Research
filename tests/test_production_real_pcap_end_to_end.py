"""Production End-to-End Real-PCAP Integration Test.

Tests the real PCAP ingestion, feature extraction, canonical 45-feature state,
safety gate, world model rollouts, and attack progression forecast pipeline
using the slice PCAP: C:\\Users\\saira\\Downloads\\friday_10windows_slice.pcap.

Documents and tests:
- Ingestion of real capture without demo mocks.
- 46 -> 45 schema safety gate: activates safely due to unobserved TCP RTT.
- No fabricated mean_tcp_rtt; zero missing features under canonical 45-feature schema.
- World model 5-step recursive LSTM rollouts.
- Empirical Markovian attack progression:
  - Observed state: RECONNAISSANCE, Observed technique: T1046
  - K in {1, 3, 5}: STATE_PERSISTENCE (ongoing continuation, empty forecast_techniques)
  - K in {10, 15}: ABSTAINED (UNSUPPORTED_HORIZON)
- Evidence fusion and strict temporal scope separation.
- Full JSON serialization compatibility for REST API consumption.
- Explicit production limitation:
  Slice PCAP provides 10 windows (600s). Supervised (L=8, K=5) training/eval pair
  requires at least L + K = 13 windows (780s). Thus, this 10-window slice validates
  real-time rollout inference (L=10 >= 8), but cannot form an (L=8, K=5) evaluation pair.
"""
from pathlib import Path
import json
import pytest

from model_service.pcap_upload import analyze_uploaded_capture


REAL_PCAP_PATH = Path(r"C:\Users\saira\Downloads\friday_10windows_slice.pcap")


@pytest.mark.skipif(not REAL_PCAP_PATH.exists(), reason="Real test PCAP slice not found")
def test_production_real_pcap_end_to_end_pipeline():
    """Execute end-to-end analysis on friday_10windows_slice.pcap."""
    pcap_bytes = REAL_PCAP_PATH.read_bytes()
    assert len(pcap_bytes) > 0, "PCAP file is empty"

    # Ingest and analyze through real production entrypoint
    result = analyze_uploaded_capture(REAL_PCAP_PATH.name, pcap_bytes)

    # 1. Pipeline Completion and General Metrics
    assert result["status"] == "completed"
    assert result["packet_count"] == 2277
    assert result["window_count"] == 10
    assert result["traffic"]["flows"] == 283

    # 2. Model Schema & Safety Gate
    compat = result["model_compatibility"]
    assert compat["model_ready"] is True
    assert compat["active_schema"] == "MODEL_SCHEMA_45"
    assert compat["schema_variant"] == "45_feature_pcap_compatible"
    assert len(compat["unavailable_features"]) == 0
    assert result["network_state"]["candidate_count"] == 10
    assert result["network_state"]["history"]["status"] == "READY"
    # Lookback window length is 8 (last 8 contiguous windows out of 10)
    assert len(result["network_state"]["history"]["window_ids"]) == 8

    # 3. Recursive Forecasting Rollouts
    forecasts = result["forecasts"]
    assert len(forecasts) == 5
    for idx, f in enumerate(forecasts, start=1):
        assert f["horizon"] == idx
        assert 0.0 <= f["attackProbability"] <= 1.0
        assert f["confidence"] is not None
        assert len(f["explanation"]) > 0

    # 4. Attack Progression Forecaster
    prog = result.get("attack_progression")
    assert prog is not None, "attack_progression missing from analysis result"
    assert result.get("attackProgression") is not None, "CamelCase alias missing"

    assert prog["verdict"] == "PARTIALLY_SUPPORTED"
    assert prog["observed_state"] == "RECONNAISSANCE"
    assert "T1046" in prog["observed_techniques"]

    points = prog["forecast_points"]
    assert len(points) == 5

    # Horizions K=1, 3, 5: STATE_PERSISTENCE (ongoing continuation, empty forecast_techniques)
    k_map = {pt["horizon_minutes"]: pt for pt in points}
    for k in (1, 3, 5):
        pt = k_map[k]
        assert pt["abstained"] is False
        assert pt["prediction_type"] == "STATE_PERSISTENCE"
        assert pt["predicted_state"] == "RECONNAISSANCE"
        assert pt["predicted_technique"] == "T1046"
        assert pt["forecast_techniques"] == []  # Crucial: No fabricated future techniques during persistence
        assert pt["transition_probability"] > 0.80

    # Horizions K=10, 15: ABSTAINED (Empirically unsupported horizons)
    for k in (10, 15):
        pt = k_map[k]
        assert pt["abstained"] is True
        assert pt["prediction_type"] == "ABSTAINED"
        assert pt["abstention_reason"].startswith("UNSUPPORTED_HORIZON")

    # 5. Evidence Fusion & Strict Scope Separation
    threat = result["threat_assessment"]
    assert "T1046" in threat["observed_techniques"]
    # Since observed state is persistence and no downstream transitions occurred,
    # forecast_techniques must be empty
    assert threat["forecast_techniques"] == []

    # 6. JSON Serialization Verification (Ensures API response can be cleanly transported)
    serialized = json.dumps(result)
    assert len(serialized) > 0
    deserialized = json.loads(serialized)
    assert deserialized["status"] == "completed"
    assert deserialized["attack_progression"]["verdict"] == "PARTIALLY_SUPPORTED"


def test_empty_pcap_rejected_safely():
    """Verify empty captures are rejected cleanly with ValueError."""
    with pytest.raises(ValueError, match="uploaded capture is empty"):
        analyze_uploaded_capture("empty.pcap", b"")


def test_malformed_pcap_rejected_safely():
    """Verify malformed captures without valid magic bytes are rejected cleanly."""
    with pytest.raises(RuntimeError, match="could not be parsed as a supported PCAP/PCAPNG capture"):
        analyze_uploaded_capture("malformed.pcap", b"NOT_PCAP_MAGIC_BYTES_HERE")


def test_insufficient_history_triggers_calibrated_abstention(tmp_path):
    """Verify captures with fewer than 8 windows trigger clean model compatibility abstention."""
    from scapy.all import Ether, IP, TCP, wrpcap

    # Generate 3 contiguous 60s windows (fewer than required 8 windows)
    base_epoch = 1700000000.0
    packets = []
    for w in range(3):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=5000 + w, dport=80, flags="S")
        pkt.time = base_epoch + w * 60.0
        packets.append(pkt)

    capture_path = tmp_path / "short_capture.pcap"
    wrpcap(str(capture_path), packets)

    result = analyze_uploaded_capture("short_capture.pcap", capture_path.read_bytes())

    assert result["status"] == "completed"
    assert result["window_count"] == 3
    # Model compatibility must safely abstain due to insufficient history
    assert result["model_compatibility"]["model_ready"] is False
    assert any("Temporal history is not ready" in r for r in result["model_compatibility"]["reasons"])
    assert result["forecast_summary"]["status"] == "INSUFFICIENT_HISTORY"
    assert result["forecast_summary"]["available"] is False
    # All 5 forecast points must be abstained without fabrication
    for pt in result["forecasts"]:
        assert pt["attackProbability"] is None
        assert pt["confidence"] is None
    # Attack progression must reflect abstention or bounded analysis
    prog = result["attack_progression"]
    assert prog is not None
    assert prog["verdict"] in ("PARTIALLY_SUPPORTED", "ABSTAINED")

