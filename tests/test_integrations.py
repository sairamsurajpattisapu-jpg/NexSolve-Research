"""Tests for Open-Source Adapters, Normalized Telemetry, and Comparison Engine."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

import pytest

from integrations.comparison import compare_analyses
from integrations.nfstream_adapter import NFStreamAdapter, convert_flow, convert_flow_batch
from integrations.scapy_adapter import ScapyAdapter
from integrations.suricata_adapter import SuricataAdapter
from integrations.zeek_adapter import ZeekAdapter
from nexsolve_core.normalized_telemetry import AlertRecord, DNSRecord, NormalizedTelemetry, TLSRecord
from nexsolve_core.provenance import CaptureFingerprint, FeatureProvenanceTracker, compute_pcap_sha256


def test_provenance_and_sha256_computation(tmp_path: Path) -> None:
    test_file = tmp_path / "sample.bin"
    test_file.write_bytes(b"NexSolve Forensic Telemetry Verification Payload\x00\x01\x02")

    sha256 = compute_pcap_sha256(test_file)
    assert len(sha256) == 64
    assert isinstance(sha256, str)

    tracker = FeatureProvenanceTracker(capture_id="cap-001")
    rec = tracker.register(
        feature_name="flow_features.flow_duration_mean",
        value=1.452,
        window_index=0,
        start_ts=100.0,
        end_ts=160.0,
        source_telemetry="PCAP_FLOW_MOMENT",
        aggregation_method="STREAMING_WELFOD",
        contributing_packets=120,
        contributing_flows=14,
        reliability=0.98,
        sample_indices=(1, 2, 3),
    )
    assert rec.feature_name == "flow_features.flow_duration_mean"
    assert rec.reliability == 0.98

    retrieved = tracker.get_provenance(0, "flow_features.flow_duration_mean")
    assert retrieved is not None
    assert retrieved.contributing_packet_count == 120

    win_prov = tracker.get_window_provenance(0)
    assert "flow_features.flow_duration_mean" in win_prov


def test_scapy_adapter_capabilities(tmp_path: Path) -> None:
    adapter = ScapyAdapter()
    assert adapter.available is True

    # Test with non-existent file
    missing_res = adapter.probe_capture_capabilities(tmp_path / "missing.pcap")
    assert missing_res["available"] is False

    # Create dummy file with PCAP magic
    pcap_file = tmp_path / "dummy.pcap"
    # PCAP header: magic(4), v_major(2), v_minor(2), thiszone(4), sigfigs(4), snaplen(4), network(4)
    pcap_hdr = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\x01\x00\x00\x00"
    pcap_file.write_bytes(pcap_hdr)

    res = adapter.probe_capture_capabilities(pcap_file)
    assert "packet_count_sampled" in res
    assert res["packet_count_sampled"] == 0

    # Fingerprint generation
    fp = CaptureFingerprint.from_pcap(pcap_file, packet_count=0, duration_seconds=0.0, capabilities=res)
    assert fp.format == "pcap"
    assert fp.magic == "0xd4c3b2a1"
    assert fp.link_type == "Ethernet"
    assert len(fp.sha256) == 64


def test_zeek_adapter_parsing(tmp_path: Path) -> None:
    adapter = ZeekAdapter()

    # Mock conn.log TSV
    conn_log = tmp_path / "conn.log"
    conn_log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\n"
        "1710000000.100\tC1234\t192.168.1.10\t45000\t10.0.0.1\t80\ttcp\thttp\t0.45\t1200\t4500\tSF\tShADadFf\n"
        "1710000001.200\tC1235\t192.168.1.10\t45002\t10.0.0.1\t443\ttcp\tssl\t1.20\t2400\t8900\tSF\tShADadFf\n",
        encoding="utf-8",
    )

    # Mock dns.log TSV
    dns_log = tmp_path / "dns.log"
    dns_log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\ttrans_id\trcode_name\tquery\tqtype_name\n"
        "1710000000.050\tD1111\t192.168.1.10\t53000\t8.8.8.8\t53\tudp\t101\tNOERROR\tc2.malicious-domain.com\tA\n",
        encoding="utf-8",
    )

    # Mock ssl.log TSV
    ssl_log = tmp_path / "ssl.log"
    ssl_log.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tversion\tserver_name\n"
        "1710000001.250\tS2222\t192.168.1.10\t45002\t10.0.0.1\t443\tTLSv13\texfiltrate.secure.org\n",
        encoding="utf-8",
    )

    telemetry = adapter.parse_directory_into_telemetry(tmp_path)
    assert len(telemetry.flows) == 2
    assert len(telemetry.dns_records) == 1
    assert len(telemetry.tls_records) == 1

    dns = telemetry.dns_records[0]
    assert dns.query_name == "c2.malicious-domain.com"
    assert dns.client_ip == "192.168.1.10"

    tls = telemetry.tls_records[0]
    assert tls.sni == "exfiltrate.secure.org"


def test_suricata_adapter_parsing(tmp_path: Path) -> None:
    adapter = SuricataAdapter()

    eve_json = tmp_path / "eve.json"
    records = [
        {
            "timestamp": "2026-03-10T12:00:00.123456+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.50",
            "src_port": 49200,
            "dest_ip": "10.0.0.5",
            "dest_port": 445,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2010001,
                "rev": 1,
                "signature": "ET EXPLOIT SMBv1 Potential EternalBlue Remote Code Execution",
                "category": "Attempted Administrator Privilege Gain",
                "severity": 1,
                "metadata": {
                    "mitre_technique_id": ["T1210"],
                    "mitre_tactic_name": ["Lateral Movement"],
                },
            },
        },
        {
            "timestamp": "2026-03-10T12:00:05.654321+0000",
            "event_type": "dns",
            "src_ip": "192.168.1.50",
            "src_port": 53211,
            "dest_ip": "1.1.1.1",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "query",
                "id": 4321,
                "rrname": "suspicious-beacon.biz",
                "rrtype": "A",
                "rcode": "NOERROR",
            },
        },
    ]

    with open(eve_json, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

    report = adapter.parse_eve_log(eve_json)
    assert report.total_alerts == 1
    assert report.critical_count == 1
    assert report.severity_distribution.get("CRITICAL", 0) == 1
    assert "T1210" in report.mitre_techniques

    telemetry = adapter.parse_into_telemetry(eve_json)
    assert len(telemetry.alerts) == 1
    assert len(telemetry.dns_records) == 1
    assert telemetry.alerts[0].severity == "CRITICAL"
    assert telemetry.dns_records[0].query_name == "suspicious-beacon.biz"


def test_nfstream_adapter_conversion() -> None:
    adapter = NFStreamAdapter()

    # Synthetic NFStream flow record mock
    class MockNFStreamFlow:
        id = 101
        src_ip = "192.168.1.100"
        src_port = 54321
        dst_ip = "172.16.0.2"
        dst_port = 8080
        protocol = 6
        bidirectional_first_seen_ms = 1710000000000
        bidirectional_last_seen_ms = 1710000005000
        bidirectional_duration_ms = 5000
        bidirectional_packets = 50
        bidirectional_bytes = 25000
        src2dst_packets = 25
        dst2src_packets = 25
        src2dst_bytes = 10000
        dst2src_bytes = 15000
        bidirectional_min_ps = 60
        bidirectional_mean_ps = 500.0
        bidirectional_stddev_ps = 200.0
        bidirectional_max_ps = 1500
        bidirectional_min_piat_ms = 5
        bidirectional_mean_piat_ms = 100.0
        bidirectional_stddev_piat_ms = 30.0
        bidirectional_max_piat_ms = 250
        bidirectional_syn_packets = 2
        bidirectional_ack_packets = 48
        bidirectional_fin_packets = 2
        bidirectional_rst_packets = 0
        src2dst_syn_packets = 1
        dst2src_syn_packets = 1

    mock_flow = MockNFStreamFlow()
    flow_record = convert_flow(mock_flow)
    assert flow_record.src_ip == "192.168.1.100"
    assert flow_record.dst_port == 8080
    assert flow_record.total_packet_count == 50
    assert flow_record.total_bytes == 25000
    assert flow_record.duration_seconds == 5.0

    batch = convert_flow_batch([mock_flow])
    assert len(batch) == 1
    assert batch[0].flow_id == "101"

    mapping = adapter.mapping_matrix
    assert "bidirectional_mean_piat_ms" in mapping


def test_analysis_comparison_engine() -> None:
    analysis_baseline = {
        "analysis_id": "job-baseline-001",
        "source": {"name": "baseline_normal.pcap"},
        "detection": {"threat_level": "LOW", "risk_score": 12.5, "detected_events": 0},
        "early_warning": {"early_warning_score": 10},
        "attack_progression": {"verdict": "BASELINE_EQUILIBRIUM"},
        "traffic": {"packets": 500, "flows": 40},
        "forecasts": [
            {"horizon": 1, "lookaheadSeconds": 60, "attackProbability": 0.08, "cumulativeRisk": 0.08, "predictedStage": "NORMAL"},
            {"horizon": 2, "lookaheadSeconds": 120, "attackProbability": 0.09, "cumulativeRisk": 0.16, "predictedStage": "NORMAL"},
        ],
    }

    analysis_incident = {
        "analysis_id": "job-incident-002",
        "source": {"name": "active_attack.pcap"},
        "detection": {"threat_level": "CRITICAL", "risk_score": 88.0, "detected_events": 14},
        "early_warning": {"early_warning_score": 92},
        "attack_progression": {"verdict": "CONFIRMED_COMPROMISE"},
        "traffic": {"packets": 8500, "flows": 450},
        "forecasts": [
            {"horizon": 1, "lookaheadSeconds": 60, "attackProbability": 0.85, "cumulativeRisk": 0.85, "predictedStage": "LATERAL_PROPAGATION"},
            {"horizon": 2, "lookaheadSeconds": 120, "attackProbability": 0.94, "cumulativeRisk": 0.99, "predictedStage": "EXFILTRATION"},
        ],
    }

    report = compare_analyses(analysis_baseline, analysis_incident)
    assert report.comparison_verdict == "ESCALATION"
    assert report.threat_level_changed is True
    assert report.threat_level_a == "LOW"
    assert report.threat_level_b == "CRITICAL"
    assert report.delta_risk_score == pytest.approx(75.5, 0.1)
    assert report.delta_early_warning_score == 82
    assert report.packet_delta == 8000
    assert report.flow_delta == 410

    assert len(report.horizon_deltas) == 2
    h1 = report.horizon_deltas[0]
    assert h1.delta_p_atk == pytest.approx(0.77, 0.01)
    assert h1.stage_changed is True

    rep_dict = report.to_dict()
    assert rep_dict["comparison_verdict"] == "ESCALATION"
    assert "ESCALATION" in rep_dict["summary_text"]


def test_compare_api_endpoint() -> None:
    from fastapi.testclient import TestClient
    from model_service.app import app, set_current_analysis

    # Register two analyses into in-memory store
    data_a = {
        "analysis_id": "job-api-test-a",
        "status": "completed",
        "source": {"name": "sample_a.pcap"},
        "upload": {"filename": "sample_a.pcap"},
        "detection": {"threat_level": "LOW", "risk_score": 15.0},
        "early_warning": {"early_warning_score": 10},
        "attack_progression": {"verdict": "BASELINE_EQUILIBRIUM"},
        "traffic": {"packets": 100, "flows": 10},
        "forecasts": [],
    }
    data_b = {
        "analysis_id": "job-api-test-b",
        "status": "completed",
        "source": {"name": "sample_b.pcap"},
        "upload": {"filename": "sample_b.pcap"},
        "detection": {"threat_level": "HIGH", "risk_score": 85.0},
        "early_warning": {"early_warning_score": 75},
        "attack_progression": {"verdict": "ESCALATION"},
        "traffic": {"packets": 900, "flows": 80},
        "forecasts": [],
    }
    set_current_analysis("job-api-test-a", data_a)
    set_current_analysis("job-api-test-b", data_b)

    client = TestClient(app)
    resp = client.get("/api/analysis/compare?job_a=job-api-test-a&job_b=job-api-test-b")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["comparison_verdict"] == "ESCALATION"
    assert payload["delta_risk_score"] == 70.0

    # Test 404 for missing analysis
    bad_resp = client.get("/api/analysis/compare?job_a=nonexistent-x&job_b=job-api-test-b")
    assert bad_resp.status_code == 404
