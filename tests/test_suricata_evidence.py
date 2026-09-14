"""Tests for native Suricata EVE JSON parser and signature evidence normalizer."""
import json
import pytest
from nexsolve_core.evidence.suricata import (
    build_suricata_evidence_items,
    parse_suricata_eve_json,
)
from nexsolve_core.fusion import EvidenceModality, TemporalScope


def test_no_suricata_evidence_available_when_none_provided():
    """Verify clean NO_SURICATA_EVIDENCE_AVAILABLE status when no input is given."""
    report = parse_suricata_eve_json(None)
    assert report.status == "NO_SURICATA_EVIDENCE_AVAILABLE"
    assert report.alert_count == 0
    assert report.alerts == ()
    assert build_suricata_evidence_items(report) == ()


def test_parse_valid_suricata_eve_json():
    """Verify parsing valid Suricata alert entries with MITRE metadata."""
    sample_eve = (
        '{"timestamp":"2026-09-10T12:00:00.000000+0000","event_type":"alert","src_ip":"192.168.1.50","src_port":54321,'
        '"dest_ip":"10.0.0.1","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2001219,'
        '"rev":2,"signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2,'
        '"metadata":{"mitre_technique_id":["T1046"]}}}\n'
    )
    report = parse_suricata_eve_json(sample_eve)
    assert report.status == "AVAILABLE"
    assert report.alert_count == 1
    assert "T1046" in report.observed_techniques

    items = build_suricata_evidence_items(report)
    assert len(items) == 1
    item = items[0]
    assert item.temporal_scope == TemporalScope.OBSERVED
    assert item.modality == EvidenceModality.SIGNATURE
    assert item.mitre_technique_id == "T1046"
    assert item.source == "suricata_eve_engine"
    assert item.severity == "HIGH"


def test_malformed_eve_json_safely_handled():
    """Corrupted lines in EVE JSON do not cause unhandled exceptions."""
    corrupt_content = "NOT_JSON\n{\"event_type\": \"flow\"}\n"
    report = parse_suricata_eve_json(corrupt_content)
    assert report.status == "NO_SURICATA_EVIDENCE_AVAILABLE"
    assert report.alert_count == 0
