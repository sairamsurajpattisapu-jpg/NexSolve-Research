"""End-to-end integration test combining Zeek + RITA + NFStream + Suricata on real PCAP slice."""
from pathlib import Path
import pytest
from ml.data.pcap_extractor import extract_canonical_capture
from model_service.pcap_upload import analyze_uploaded_capture
from nexsolve_core.state import MODEL_SCHEMA_45, build_network_state_candidates, evaluate_model_compatibility


REAL_PCAP_PATH = Path(r"C:\Users\saira\Downloads\friday_10windows_slice.pcap")


@pytest.mark.skipif(not REAL_PCAP_PATH.exists(), reason="Real PCAP slice not present")
def test_full_open_source_intelligence_on_real_pcap():
    """Verify entire pipeline with Zeek, RITA, NFStream, and Suricata intelligence."""
    pcap_bytes = REAL_PCAP_PATH.read_bytes()
    res = analyze_uploaded_capture(REAL_PCAP_PATH.name, pcap_bytes)

    assert res["status"] == "completed"
    assert res["packet_count"] == 2277
    assert res["window_count"] == 10

    # 1. Model Compatibility & Contract Preservation
    compat = res["model_compatibility"]
    assert compat["model_ready"] is True
    assert compat["active_schema"] == "MODEL_SCHEMA_45"
    assert len(compat["unavailable_features"]) == 0
    assert "mean_tcp_rtt" not in compat["available_features"]

    # 2. Network Intelligence Container
    net_intel = res.get("network_intelligence")
    assert net_intel is not None
    assert "session_state" in net_intel
    assert "periodicity" in net_intel
    assert "flow_statistics" in net_intel
    assert "signature_evidence" in net_intel
    assert "evidence_summary" in net_intel

    # 3. Zeek Session Telemetry
    sess = net_intel["session_state"]
    assert sess["total_tcp_sessions"] > 0
    assert sess["established_sessions"] > 0
    assert sess["failed_connection_ratio"] == 0.0

    # 4. RITA Periodicity Telemetry
    periodicity = net_intel["periodicity"]
    assert periodicity is not None
    assert periodicity["total_groups_evaluated"] > 0
    # On real traffic, check that insufficient/irregular groups are categorized honestly
    assert (periodicity["insufficient_groups"] + periodicity["irregular_groups"] +
            periodicity["weakly_periodic_groups"] + periodicity["periodic_groups"] +
            periodicity["highly_periodic_groups"]) == periodicity["total_groups_evaluated"]

    # 5. NFStream Flow Statistics
    flows = net_intel["flow_statistics"]
    assert flows["total_flows"] > 0
    assert 0.0 <= flows["single_packet_flow_ratio"] <= 1.0
    assert flows["mean_packet_rate"] >= 0.0

    # 6. Suricata Evidence
    sig = net_intel["signature_evidence"]
    assert sig["status"] == "NO_SURICATA_EVIDENCE_AVAILABLE"
    assert sig["alert_count"] == 0

    # 7. Threat Assessment & Evidence Fusion
    threat = res["threat_assessment"]
    assert threat is not None
    assert "evidence" in threat
    assert threat["current_risk"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    # All evidence items must have strictly OBSERVED or FORECAST scope
    for e in threat["evidence"]:
        assert e["temporal_scope"] in ("OBSERVED", "FORECAST")
