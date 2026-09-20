from __future__ import annotations

import pytest
from nexsolve_core.intelligence.incident_reconstruction import (
    IncidentEventEpistemicStatus,
    IncidentPhaseType,
    IncidentEventType,
    IncidentUncertaintyLevel,
    IncidentStory,
    IncidentPhase,
    IncidentEvent,
    build_incident_story,
)
from nexsolve_core.intelligence.threat_differentiation import EvidenceGroundingState


def test_empty_input_returns_none():
    story = build_incident_story(
        windows=[],
        all_flows=[],
        tcp_sessions=[],
        observed_findings=[],
    )
    assert story is None


def test_single_observation_incident_reconstruction():
    findings = [
        {
            "finding_id": "f1",
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "attack_category": "Port Scan",
            "window_index": 1,
            "description": "SYN sweep on port 80, 443",
            "mitre_technique_id": "T1046",
        }
    ]
    windows = [{"window_index": 0}, {"window_index": 1}]

    class DummyProfile:
        roles = ["EXTERNAL_CLIENT"]
        packet_volume = 120
        connection_attempts = 15
        first_seen_window = 0
        last_seen_window = 1

    story = build_incident_story(
        windows=windows,
        observed_findings=findings,
        entity_profiles={"192.168.1.100": DummyProfile()},
        window_count=2,
    )
    assert story is not None
    assert story.assessment.classification == "NETWORK_SERVICE_RECONNAISSANCE"
    assert len(story.actors) >= 1
    assert story.actors[0].entity == "192.168.1.100"
    assert story.actors[0].epistemic_status == IncidentEventEpistemicStatus.OBSERVED
    assert len(story.phases) >= 1
    assert any(p.phase_type == IncidentPhaseType.RECONNAISSANCE for p in story.phases)


def test_temporal_event_ordering():
    findings = [
        {"finding_id": "f2", "source_ip": "192.168.1.50", "attack_category": "Scan", "window_index": 3},
        {"finding_id": "f1", "source_ip": "192.168.1.50", "attack_category": "Anomaly", "window_index": 1},
    ]
    windows = [{"window_index": i} for i in range(5)]

    story = build_incident_story(
        windows=windows,
        observed_findings=findings,
        window_count=5,
    )
    assert story is not None
    windows_in_order = [e.window_index for e in story.events]
    assert windows_in_order == sorted(windows_in_order)


def test_observed_vs_inferred_separation():
    findings = [
        {"finding_id": "f1", "source_ip": "192.168.1.50", "attack_category": "Scan", "window_index": 1}
    ]
    class DummyCampaign:
        campaign_id = "cmp_1"
        title = "Coordinated Sweep"
        primary_entities = ["192.168.1.50"]
        target_entities = ["10.0.0.1"]
        start_window = 1
        end_window = 3
        duration_seconds = 120.0
        attack_states = ["RECONNAISSANCE"]
        mitre_techniques = ["T1046"]

    story = build_incident_story(
        windows=[{"window_index": 0}, {"window_index": 1}, {"window_index": 2}],
        observed_findings=findings,
        campaigns=[DummyCampaign()],
        window_count=3,
    )
    assert story is not None

    # Finding event must be OBSERVED
    find_evt = next(e for e in story.events if e.event_type == IncidentEventType.PORT_SCAN_STARTED)
    assert find_evt.epistemic_status == IncidentEventEpistemicStatus.OBSERVED

    # Campaign convergence must be INFERRED
    cmp_evt = next(e for e in story.events if e.event_type == IncidentEventType.CAMPAIGN_CONVERGENCE)
    assert cmp_evt.epistemic_status == IncidentEventEpistemicStatus.INFERRED


def test_forecast_separation():
    findings = [
        {"finding_id": "f1", "source_ip": "192.168.1.50", "attack_category": "Scan", "window_index": 1}
    ]
    class DummyProgression:
        verdict = "SUPPORTED"
        class DummyPoint:
            predicted_state = "RECONNAISSANCE"
            transition_probability = 0.975
            predicted_technique = "T1046"
        forecast_points = [DummyPoint()]

    story = build_incident_story(
        windows=[{"window_index": 0}, {"window_index": 1}],
        observed_findings=findings,
        attack_progression=DummyProgression(),
        window_count=2,
    )
    assert story is not None
    fc_evt = next(e for e in story.events if e.event_type == IncidentEventType.FORECAST_AVAILABLE)
    assert fc_evt.epistemic_status == IncidentEventEpistemicStatus.FORECAST
    assert fc_evt.grounding == EvidenceGroundingState.FORECAST_ONLY
    # Window index for forecast must be beyond total_windows
    assert fc_evt.window_index > 2


def test_active_behavior_at_capture_boundary_not_terminated():
    findings = [
        {"finding_id": "f_end", "source_ip": "192.168.1.50", "attack_category": "Port Scan", "window_index": 4}
    ]
    windows = [{"window_index": i} for i in range(5)]

    story = build_incident_story(
        windows=windows,
        observed_findings=findings,
        window_count=5,
    )
    assert story is not None
    # Must NOT claim termination if active in window 4
    assert story.assessment.termination_status == "TERMINATION_NOT_OBSERVED_CAPTURE_BOUNDARY"
    assert "termination is not observed" in story.narrative_paragraphs[-1].lower()


def test_provenance_and_mitre_strictly_observed():
    findings = [
        {"finding_id": "f_t1046", "source_ip": "192.168.1.50", "attack_category": "Port Scan", "window_index": 1, "mitre_technique_id": "T1046"}
    ]
    story = build_incident_story(
        windows=[{"window_index": 0}, {"window_index": 1}],
        observed_findings=findings,
        window_count=2,
    )
    assert story is not None
    # MITRE T1046 should be listed as observed
    assert any("T1046" in t for t in story.observed_mitre_techniques)
    assert len(story.inferred_mitre_techniques) == 0  # No invented techniques
    # Ensure event has provenance
    evt = next(e for e in story.events if e.mitre_technique == "T1046")
    assert "f_t1046" in evt.supporting_evidence_ids


def test_serialization_deterministic():
    findings = [
        {"finding_id": "f1", "source_ip": "192.168.1.50", "attack_category": "Port Scan", "window_index": 1}
    ]
    story1 = build_incident_story(windows=[{"window_index": 0}, {"window_index": 1}], observed_findings=findings, window_count=2)
    story2 = build_incident_story(windows=[{"window_index": 0}, {"window_index": 1}], observed_findings=findings, window_count=2)

    assert story1.to_dict() == story2.to_dict()


def test_multi_horizon_and_escalation_events():
    findings = [
        {"finding_id": "f1", "source_ip": "192.168.1.50", "attack_category": "Port Scan", "window_index": 1}
    ]

    class DummyForecastPoint:
        def __init__(self, h, state="RECONNAISSANCE", prob=0.95):
            self.horizon_minutes = h
            self.horizon = h
            self.predicted_state = state
            self.predicted_technique = "T1046"
            self.prediction_type = "STATE_PERSISTENCE"
            self.transition_probability = prob
            self.lead_time_seconds = h * 60
            self.abstained = False
            self.supporting_evidence = ("dummy_evidence",)

    class DummyProgression:
        verdict = "SUPPORTED"
        forecast_points = [DummyForecastPoint(1), DummyForecastPoint(2), DummyForecastPoint(3)]

    class DummyAttackHorizon:
        state = "SUSTAINED_ATTACK_FORECAST"
        escalation_horizon = 2
        lead_time_to_escalation_seconds = 120
        lead_time_seconds = 60
        horizon_windows = 4

    story = build_incident_story(
        windows=[{"window_index": 0}, {"window_index": 1}],
        observed_findings=findings,
        attack_progression=DummyProgression(),
        attack_horizon=DummyAttackHorizon(),
        window_count=2,
    )
    assert story is not None

    # Check forecast events generated for horizons T+1, T+2, T+3
    fc_events = [e for e in story.events if e.event_type == IncidentEventType.FORECAST_AVAILABLE]
    assert len(fc_events) == 3
    assert [e.window_index for e in fc_events] == [3, 4, 5]

    # Check dedicated escalation event
    esc_events = [e for e in story.events if e.event_type == IncidentEventType.ESCALATION_PREDICTED]
    assert len(esc_events) == 1
    assert esc_events[0].window_index == 4  # total_windows(2) + escalation_horizon(2)
    assert "SUSTAINED_ATTACK_FORECAST" in esc_events[0].observed_facts[0]
    assert "120s" in esc_events[0].observed_facts[0]

    # Check narrative paragraphs include multi-step forecast and attack horizon notes
    assert any("Multi-step Markovian progression" in p for p in story.narrative_paragraphs)
    assert any("Attack Horizon determination confirms state SUSTAINED_ATTACK_FORECAST" in p for p in story.narrative_paragraphs)
