"""Comprehensive test suite for:
1. Native Behavioral Intelligence (RITA-inspired beaconing & periodicity)
2. Decoupled Provider boundaries (Zeek & Suricata)
3. Arkime-inspired Session Investigation data model
4. Fused Threat Assessment & Observed vs Forecast separation
5. Extended Feature Registry (72 candidate features)
"""
import tempfile
from pathlib import Path
import pytest
from scapy.all import Ether, IP, TCP, wrpcap

from nexsolve_core.behavior import (
    analyze_beaconing,
    compute_shannon_entropy,
    analyze_behavioral_intelligence,
    BeaconingSignal,
)
from nexsolve_core.providers import (
    NativeProtocolProvider,
    ZeekProtocolProvider,
    NativeSignatureProvider,
    SuricataSignatureProvider,
)
from nexsolve_core.investigation import (
    build_session_investigation_records,
    SessionInvestigationRecord,
)
from nexsolve_core.fusion import (
    fuse_threat_assessment,
    TemporalScope,
    EvidenceModality,
)
from nexsolve_core.state import (
    FLOW_NAMES_45,
    FLOW_NAMES_EXTENDED,
    CANDIDATE_EXTENDED_FEATURES_72,
    EXTENDED_MODEL_SCHEMA_72,
    feature_registry,
    extended_feature_registry,
)
from nexsolve_core.schemas import FlowRecord, Provenance, PacketRecord
from model_service.pcap_upload import analyze_uploaded_capture


def test_beaconing_detection_identifies_robotic_intervals():
    """Verify RITA-style coefficient of variation detects periodic beaconing."""
    base_time = 1700000000.0
    # Simulate a beacon with strictly periodic 10s intervals (low CV)
    flows = []
    for i in range(10):
        t = base_time + i * 10.0
        flows.append(FlowRecord(
            flow_id=f"flow-{i}",
            start_timestamp=t,
            end_timestamp=t + 0.1,
            duration_seconds=0.1,
            src_ip="192.168.1.100",
            src_port=49152 + i,
            dst_ip="203.0.113.5",
            dst_port=443,
            protocol="TCP",
            forward_packet_count=2,
            reverse_packet_count=2,
            total_packet_count=4,
            forward_bytes=100,
            reverse_bytes=200,
            total_bytes=300,
            packet_rate=40.0,
            byte_rate=3000.0,
            syn_count=1,
            ack_count=3,
            fin_count=0,
            rst_count=0,
            retransmission_count=0,
            completeness="COMPLETE",
            provenance=Provenance("test_cap"),
        ))

    signals = analyze_beaconing(flows)
    assert len(signals) == 1
    sig = signals[0]
    assert sig.src_ip == "192.168.1.100"
    assert sig.dst_ip == "203.0.113.5"
    assert sig.connection_count == 10
    assert abs(sig.mean_interval_seconds - 10.0) < 0.01
    assert sig.coefficient_of_variation < 0.01  # Metronomic periodicity
    assert sig.score >= 0.95
    assert sig.is_beaconing is True


def test_shannon_entropy_calculation():
    """Verify Shannon entropy differentiates low-entropy words from high-entropy strings."""
    low_entropy = compute_shannon_entropy("aaaaaaa")
    assert low_entropy == 0.0

    normal_domain = compute_shannon_entropy("google.com")
    dga_domain = compute_shannon_entropy("xkj1298zlkq091823lkasdj908")
    assert dga_domain > normal_domain


def test_provider_boundaries_fail_safe():
    """External providers must return status='UNAVAILABLE' without crashing when uninstalled."""
    zeek_prov = ZeekProtocolProvider()
    res = zeek_prov.analyze(packets=(), flows=(), pcap_path=None)
    assert res.provider_name == "zeek"
    assert res.status == "UNAVAILABLE"
    assert "not installed" in res.reason or "Valid PCAP" in res.reason

    suricata_prov = SuricataSignatureProvider()
    s_res = suricata_prov.inspect(pcap_path=None, eve_json_path=None)
    assert s_res.provider_name == "suricata"
    assert s_res.status == "UNAVAILABLE"
    assert s_res.alert_count == 0

    native_proto = NativeProtocolProvider()
    n_res = native_proto.analyze(packets=(), flows=())
    assert n_res.status == "AVAILABLE"


def test_session_investigation_record_construction():
    """Verify Arkime-style session investigation records are generated from flows."""
    flow = FlowRecord(
        flow_id="session-001",
        start_timestamp=1700000000.0,
        end_timestamp=1700000015.0,
        duration_seconds=15.0,
        src_ip="10.0.0.5",
        src_port=52341,
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        forward_packet_count=5,
        reverse_packet_count=4,
        total_packet_count=9,
        forward_bytes=500,
        reverse_bytes=1200,
        total_bytes=1700,
        packet_rate=0.6,
        byte_rate=113.3,
        syn_count=1,
        ack_count=1,
        fin_count=1,
        rst_count=0,
        retransmission_count=0,
        completeness="COMPLETE",
        provenance=Provenance("test"),
    )
    records = build_session_investigation_records([flow])
    assert len(records) == 1
    rec = records[0]
    assert rec.session_id == "session-001"
    assert rec.src_ip == "10.0.0.5"
    assert rec.dst_port == 80
    assert rec.total_bytes == 1700


def test_threat_assessment_observed_vs_forecast_separation():
    """Verify ThreatAssessment strictly isolates OBSERVED from FORECAST evidence."""
    observed = [{
        "finding_id": "win-1",
        "timestamp": "2026-09-13T12:00:00Z",
        "attack_category": "network_reconnaissance",
        "severity": "high",
        "confidence": 0.9,
        "detection_method": "heuristics",
        "evidence": [{"metric": "port_scan_score", "value": 0.85}],
        "explanation": ["High port scan pressure detected"],
    }]
    forecast = [
        {"horizon": 1, "attackProbability": 0.80, "confidence": 0.60},
        {"horizon": 2, "attackProbability": 0.70, "confidence": 0.40},
    ]

    threat = fuse_threat_assessment(
        observed_findings=observed,
        behavioral_report=None,
        forecast_points=forecast,
        attack_horizon={"lead_time_seconds": 60},
    )

    assert threat.current_risk == "HIGH"
    assert threat.future_risk == "HIGH"
    assert "T1046" in threat.observed_techniques
    assert any("T1071" in t for t in threat.forecast_techniques)

    # Check that individual evidence items maintain scope
    obs_items = [e for e in threat.evidence if e.temporal_scope == TemporalScope.OBSERVED]
    fc_items = [e for e in threat.evidence if e.temporal_scope == TemporalScope.FORECAST]

    assert len(obs_items) == 1
    assert obs_items[0].mitre_technique_id == "T1046"
    assert len(fc_items) == 2
    assert fc_items[0].modality == EvidenceModality.FORECAST


def test_extended_candidate_feature_registry():
    """Verify the 72 candidate extended features are registered and documented."""
    assert len(CANDIDATE_EXTENDED_FEATURES_72) == 72
    reg = extended_feature_registry()
    for feat in FLOW_NAMES_EXTENDED:
        key = f"flow_features.{feat}"
        assert key in reg, f"Missing feature registration for {key}"
        assert reg[key].units != ""
        assert reg[key].computation != ""


def test_end_to_end_pcap_analysis_includes_new_intelligence():
    """End-to-end integration test confirming pcap analysis populates behavioral, investigation, and threat fields."""
    packets = []
    base_time = 1700000000.0
    for w in range(2):
        for p in range(4):
            t = base_time + w * 60.0 + p * 0.5
            pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="192.168.1.5", dst="192.168.1.1") / TCP(sport=5000 + w, dport=80, flags="S") / b"hi"
            pkt.time = t
            packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
        pcap_path = Path(tf.name)
    try:
        wrpcap(str(pcap_path), packets)
        content = pcap_path.read_bytes()
        res = analyze_uploaded_capture(pcap_path.name, content)

        assert res["status"] == "completed"
        assert "behavioral_intelligence" in res
        assert "investigation_sessions" in res
        assert "threat_assessment" in res
        assert res["threat_assessment"]["current_risk"] in ("LOW", "MEDIUM", "HIGH")
    finally:
        pcap_path.unlink(missing_ok=True)
