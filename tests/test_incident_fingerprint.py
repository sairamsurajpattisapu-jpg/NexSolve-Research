import pytest
from nexsolve_core.intelligence.incident_fingerprint import IncidentFingerprint, extract_incident_fingerprint

def test_extract_incident_fingerprint():
    findings = [
        {'source_ip': '192.168.1.100', 'attack_category': 'Port Scan', 'mitre_technique_id': 'T1046'},
        {'source_ip': '192.168.1.100', 'attack_category': 'Brute Force', 'mitre_technique_id': 'T1110'},
    ]
    traffic_summary = {
        'protocol_counts': {'TCP': 10, 'UDP': 2},
        'packets': 550,
        'flows': 12,
    }
    profiles = {
        '192.168.1.100': {'role_summary': 'SUSPECT', 'roles': ['RECON_SOURCE']}
    }

    class MockSession:
        dst_ip = '10.0.0.5'
        dst_port = 80

    fp = extract_incident_fingerprint(
        incident_id='inc_test_1',
        capture_id='cap_test_1',
        traffic_summary=traffic_summary,
        observed_findings=findings,
        entity_profiles=profiles,
        tcp_sessions=[MockSession()],
    )

    assert fp.incident_id == 'inc_test_1'
    assert fp.capture_id == 'cap_test_1'
    assert '192.168.1.100' in fp.actor_entities
    assert '10.0.0.5' in fp.target_entities
    assert 80 in fp.targeted_ports
    assert 'RECONNAISSANCE' in fp.attack_states
    assert 'T1046' in fp.observed_mitre_techniques
    assert 'T1110' in fp.observed_mitre_techniques
    assert fp.total_packets == 550
    assert fp.total_flows == 12

    as_dict = fp.to_dict()
    assert as_dict['incident_id'] == 'inc_test_1'
    assert 'provenance' in as_dict
