import pytest
from nexsolve_core.investigation_model import (
    InvestigationContext,
    InvestigationSubject,
    InvestigationSubjectType,
    InvestigationFinding,
    InvestigationTimelineEvent,
    InvestigationRelationship,
    RelationshipType,
)
from nexsolve_core.intelligence import (
    build_entity_timeline,
    discover_entity_relationships,
    detect_contradictions,
    decompose_threat_risk,
    investigate_entity,
    investigate_campaign,
    correlate_attack_campaigns,
    build_entity_behavior_profiles,
    generate_mitigation_recommendations,
    build_incident_investigation,
    MitigationActionType,
)
from nexsolve_core.network import TCPSessionRecord, TCPConnectionState, ObservationBoundaryStatus
from nexsolve_core.behavior import BehavioralEpisode, EpisodeSeverity, BehaviorChangeSignal, ChangeType


def test_investigation_model_structures():
    subj = InvestigationSubject(
        subject_id="subj_1",
        subject_type=InvestigationSubjectType.ENTITY,
        label="192.168.1.50",
        first_seen=0.0,
        last_seen=120.0,
        active_windows=(0, 1),
        primary_roles=("SCANNER",),
        inferred_attack_state="RECONNAISSANCE",
        current_priority="P2_HIGH",
        associated_campaign_ids=("cmp_1",),
        associated_pattern_ids=("pat_1",),
        summary="Test scanner",
    )
    assert subj.label == "192.168.1.50"
    d = subj.to_dict()
    assert d["subject_type"] == "ENTITY"
    assert d["current_priority"] == "P2_HIGH"


def test_timeline_engine_chronology_and_separation():
    events = build_entity_timeline(
        entity="192.168.1.50",
        observed_findings=[
            {"finding_id": "f1", "source_ip": "192.168.1.50", "window_index": 1, "attack_category": "PortScan"},
        ],
        forecast_points=[
            {"horizon": 1, "attackProbability": 0.85},
            {"horizon": 2, "attackProbability": 0.85},
        ],
    )
    assert len(events) >= 2
    # Ensure timestamps are non-decreasing
    ts = [e.timestamp for e in events]
    assert ts == sorted(ts)
    # Check OBSERVED vs FORECAST separation
    scopes = {e.observed_or_forecast for e in events}
    assert "OBSERVED" in scopes
    assert "FORECAST" in scopes


def test_entity_relationships_discovery():
    sessions = [
        TCPSessionRecord(
            session_id="s1",
            src_ip="192.168.1.50",
            dst_ip="10.0.0.1",
            src_port=44552,
            dst_port=80,
            first_seen=10.0,
            last_seen=20.0,
            duration_seconds=10.0,
            forward_packets=5,
            reverse_packets=5,
            total_packets=10,
            forward_bytes=100,
            reverse_bytes=200,
            total_bytes=300,
            orig_syn=True,
            orig_ack=True,
            orig_fin=False,
            orig_rst=False,
            resp_syn=True,
            resp_ack=True,
            resp_fin=False,
            resp_rst=False,
            handshake_completed=True,
            connection_state=TCPConnectionState.ESTABLISHED,
            boundary_status=ObservationBoundaryStatus.COMPLETE_LIFECYCLE,
            zeek_equivalent_state="S1",
            history_string="ShADadFf",
        )
    ]

    rels = discover_entity_relationships(
        entity="192.168.1.50",
        tcp_sessions=sessions,
    )
    assert len(rels) == 1
    assert rels[0].source_entity == "192.168.1.50"
    assert rels[0].target_entity == "10.0.0.1"
    assert rels[0].relationship_type == RelationshipType.COMMUNICATES_WITH


def test_contradictions_and_risk_breakdown():
    # Test risk breakdown
    rb = decompose_threat_risk("192.168.1.50")
    assert rb.entity == "192.168.1.50"
    assert rb.final_score >= 0
    assert rb.priority_level is not None

    # Test full entity investigation
    inv = investigate_entity(
        entity="192.168.1.50",
        window_count=2,
    )
    assert isinstance(inv, InvestigationContext)
    assert inv.subject.label == "192.168.1.50"
    assert len(inv.recommended_action) > 0


def test_campaign_investigation():
    ep = BehavioralEpisode(
        episode_id="ep_1",
        title="Recon Episode",
        start_window=0,
        end_window=1,
        duration_seconds=60.0,
        primary_entity="192.168.1.50",
        source_ips=("192.168.1.50",),
        destination_ips=("10.0.0.1",),
        destination_ports=(80,),
        flow_count=5,
        session_count=5,
        findings=(),
        behavior_signals=(),
        protocol_signals=(),
        anomaly_signals=(),
        attack_states=("RECONNAISSANCE",),
        mitre_techniques=("T1046",),
        severity=EpisodeSeverity.HIGH,
        description="Recon sweep",
    )

    cmps = correlate_attack_campaigns(episodes=[ep])
    assert len(cmps) == 1
    c_inv = investigate_campaign(cmps[0], all_episodes=[ep])
    assert c_inv.campaign.campaign_id == cmps[0].campaign_id
    assert len(c_inv.key_findings) > 0


def test_mitigations_and_incident_investigation():
    inv = investigate_entity("192.168.1.50", window_count=3)
    recs = generate_mitigation_recommendations("192.168.1.50", window_count=3)
    assert len(recs) > 0
    assert any(r.action_type == MitigationActionType.COLLECT_MORE_TELEMETRY for r in recs)

    inc = build_incident_investigation(
        primary_entity="192.168.1.50",
        entity_investigation=inv,
        window_count=3,
    )
    assert inc.primary_entities == ("192.168.1.50",)
    assert inc.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")
    assert len(inc.recommended_actions) > 0
    d = inc.to_dict()
    assert "headline" in d
    assert "timeline" in d
