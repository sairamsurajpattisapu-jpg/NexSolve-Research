import pytest
from nexsolve_core.intelligence.incident_fingerprint import IncidentFingerprint
from nexsolve_core.intelligence.campaign_correlation import (
    correlate_incidents,
    correlate_incident_set,
    build_campaign_clusters,
    CorrelationRelationship,
    CampaignEvolutionState,
)

def make_fp(incident_id, actors, targets, ports, protos, states, techniques, episodes, dominant='Reconnaissance'):
    return IncidentFingerprint(
        incident_id=incident_id,
        capture_id=f'cap_{incident_id}',
        actor_entities=actors,
        target_entities=targets,
        actor_roles=['SUSPECT'],
        targeted_ports=ports,
        protocol_distribution=protos,
        active_windows=[1, 2],
        total_packets=1000,
        total_sessions=10,
        total_flows=10,
        fan_out_ratio=1.5,
        failure_ratio=0.1,
        attack_states=states,
        observed_mitre_techniques=techniques,
        episode_types=episodes,
        dominant_category=dominant,
        provenance={'source': 'unit_test'}
    )

def test_identical_fingerprints():
    fp1 = make_fp('inc1', ['10.0.0.1'], ['192.168.1.10'], [80, 443], {'TCP': 10}, ['RECONNAISSANCE'], ['T1046'], ['SCAN'])
    fp2 = make_fp('inc2', ['10.0.0.1'], ['192.168.1.10'], [80, 443], {'TCP': 10}, ['RECONNAISSANCE'], ['T1046'], ['SCAN'])
    corr = correlate_incidents(fp1, fp2)
    assert corr.relationship == CorrelationRelationship.RELATED_CAMPAIGN
    assert 'ENTITY_OVERLAP' in corr.supporting_dimensions
    assert 'PORT_PATTERN_SIMILARITY' in corr.supporting_dimensions

def test_changing_infrastructure():
    # Different actors, but identical target, ports, states, techniques, and episodes
    fp1 = make_fp('inc1', ['10.0.0.1'], ['192.168.1.10'], [80, 443], {'TCP': 10}, ['RECONNAISSANCE', 'EXPLOITATION'], ['T1046', 'T1110'], ['BRUTEFORCE'])
    fp2 = make_fp('inc2', ['10.0.0.99'], ['192.168.1.10'], [80, 443], {'TCP': 10}, ['RECONNAISSANCE', 'EXPLOITATION'], ['T1046', 'T1110'], ['BRUTEFORCE'])
    corr = correlate_incidents(fp1, fp2)
    assert corr.relationship == CorrelationRelationship.RELATED_CAMPAIGN
    assert corr.evolution == CampaignEvolutionState.CHANGING_INFRASTRUCTURE
    assert 'NO_ACTOR_OVERLAP' in corr.neutral_dimensions
    assert 'TARGET_OVERLAP' in corr.supporting_dimensions
    assert 'ENTITY_OVERLAP' not in corr.supporting_dimensions

def test_unrelated_incidents():
    fp1 = make_fp('inc1', ['10.0.0.1'], ['192.168.1.10'], [80], {'TCP': 10}, ['RECONNAISSANCE'], ['T1046'], ['SCAN'], dominant='Recon')
    fp2 = make_fp('inc2', ['172.16.0.5'], ['10.10.10.10'], [53], {'UDP': 10}, ['EXFILTRATION'], ['T1041'], ['EXFIL'], dominant='Exfiltration')
    corr = correlate_incidents(fp1, fp2)
    assert corr.relationship == CorrelationRelationship.UNRELATED

def test_cluster_building():
    fp1 = make_fp('inc1', ['10.0.0.1'], ['192.168.1.10'], [80, 443], {'TCP': 10}, ['RECONNAISSANCE'], ['T1046'], ['SCAN'])
    fp2 = make_fp('inc2', ['10.0.0.1'], ['192.168.1.10'], [80, 443], {'TCP': 10}, ['RECONNAISSANCE'], ['T1046'], ['SCAN'])
    fp3 = make_fp('inc3', ['172.16.0.5'], ['10.10.10.10'], [53], {'UDP': 10}, ['EXFILTRATION'], ['T1041'], ['EXFIL'], dominant='Exfiltration')
    
    fingerprints = [fp1, fp2, fp3]
    correlations = correlate_incident_set(fingerprints)
    assert len(correlations) == 3 # 3 pairs: (1,2), (1,3), (2,3)
    
    clusters = build_campaign_clusters(fingerprints, correlations)
    assert len(clusters) == 1 # only 1 and 2 cluster together
    assert set(clusters[0].member_incidents) == {'inc1', 'inc2'}
