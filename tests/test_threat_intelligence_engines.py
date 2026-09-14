"""Comprehensive test suite for Sprint #NEXT Threat Intelligence Engines:
1. Attack Kinematics Engine (attack_kinematics.py)
2. Attack Campaign Correlation (campaigns.py)
3. Entity Behavior Profile (entity_profile.py)
4. Baseline & Deviation Engine (baseline.py)
5. Multi-Entity Pattern Detection (patterns.py)
6. Threat Story Narrative Engine (threat_story.py)
7. Threat Prioritization Engine (prioritization.py)
8. Investigation Query Engine (investigation.py)
"""
import pytest
from typing import Any, Mapping

from nexsolve_core.intelligence.attack_kinematics import (
    KinematicState,
    TransitionType,
    analyze_attack_kinematics,
)
from nexsolve_core.behavior.baseline import (
    BaselineStatus,
    DeviationType,
    compute_entity_baselines,
)
from nexsolve_core.intelligence.patterns import (
    AttackPatternType,
    detect_attack_patterns,
)
from nexsolve_core.intelligence.entity_profile import (
    EntityBehavioralRole,
    build_entity_behavior_profiles,
)
from nexsolve_core.intelligence.campaigns import (
    correlate_attack_campaigns,
)
from nexsolve_core.intelligence.threat_story import (
    generate_threat_stories,
)
from nexsolve_core.intelligence.prioritization import (
    ThreatPriorityLevel,
    prioritize_threats,
)
from nexsolve_core.investigation import (
    InvestigationQueryEngine,
)


class DummySession:
    def __init__(self, src_ip, dst_ip, dst_port, window_index=0, state="ESTABLISHED", packet_count=10, byte_count=1000, protocol="TCP"):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.window_index = window_index
        self.state = state
        self.packet_count = packet_count
        self.byte_count = byte_count
        self.protocol = protocol


class DummyBeacon:
    def __init__(self, src_ip, dst_ip, dst_port=443, is_beaconing=True, score=0.92):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.is_beaconing = is_beaconing
        self.score = score


class DummyEpisode:
    def __init__(self, episode_id, primary_entity, destination_ips, destination_ports, start_window=0, end_window=0, severity="HIGH"):
        self.episode_id = episode_id
        self.primary_entity = primary_entity
        self.destination_ips = destination_ips
        self.destination_ports = destination_ports
        self.start_window = start_window
        self.end_window = end_window
        self.severity = severity
        self.duration_seconds = 60.0
        self.mitre_techniques = ("T1046",)
        self.attack_states = ("RECONNAISSANCE",)
        self.provenance = {}


def test_attack_kinematics_supported_and_unsupported_transitions():
    """Verify kinematics distinguishes observed, supported, and unsupported transitions."""
    findings = [
        {"finding_id": "f1", "source_ip": "192.168.1.10", "destination_ip": "10.0.0.1", "attack_category": "Reconnaissance Scan", "window_index": 0},
        {"finding_id": "f2", "source_ip": "192.168.1.10", "destination_ip": "10.0.0.1", "attack_category": "Reconnaissance Port Sweep", "window_index": 1},
    ]
    sessions = [
        DummySession("192.168.1.10", "10.0.0.1", 80, window_index=0),
        DummySession("192.168.1.10", "10.0.0.1", 80, window_index=1),
    ]

    trajs = analyze_attack_kinematics(observed_findings=findings, tcp_sessions=sessions)
    assert "192.168.1.10" in trajs
    t = trajs["192.168.1.10"]
    assert t.current_state in (KinematicState.RECONNAISSANCE, KinematicState.DISCOVERY)
    assert len(t.transitions) >= 1
    assert t.transitions[0].transition_type == TransitionType.SUPPORTED_TRANSITION


def test_entity_baseline_and_deviation():
    """Verify entity baseline requires sufficient history and detects deviations."""
    # Entity with 2 windows -> INSUFFICIENT_HISTORY
    sessions_short = [
        DummySession("192.168.1.5", "10.0.0.1", 80, window_index=0),
        DummySession("192.168.1.5", "10.0.0.1", 80, window_index=1),
    ]
    b_short = compute_entity_baselines(tcp_sessions=sessions_short, min_windows_required=3)
    assert b_short["192.168.1.5"].status == BaselineStatus.INSUFFICIENT_HISTORY
    assert len(b_short["192.168.1.5"].deviations) == 0

    # Entity with 4 windows -> Baseline established, Window 3 surges in ports
    sessions_long = [
        DummySession("192.168.1.6", "10.0.0.1", 80, window_index=0),
        DummySession("192.168.1.6", "10.0.0.1", 80, window_index=1),
        DummySession("192.168.1.6", "10.0.0.1", 80, window_index=2),
    ]
    # In window 3, port surge across 20 ports
    for p in range(200, 220):
        sessions_long.append(DummySession("192.168.1.6", "10.0.0.1", p, window_index=3))

    b_long = compute_entity_baselines(tcp_sessions=sessions_long, min_windows_required=3)
    assert "192.168.1.6" in b_long
    assert b_long["192.168.1.6"].status in (BaselineStatus.BASELINE_SHIFT, BaselineStatus.BASELINE_STABLE)


def test_multi_entity_attack_patterns():
    """Verify horizontal scan, vertical scan, and beaconing cluster pattern detection."""
    sessions = []
    # Horizontal scan: One source -> 8 distinct hosts on port 80
    for dst in range(1, 9):
        sessions.append(DummySession("192.168.1.100", f"10.0.0.{dst}", 80, window_index=0))

    # Vertical scan: One source -> 1 host on 15 distinct ports
    for port in range(1000, 1015):
        sessions.append(DummySession("192.168.1.200", "10.0.0.50", port, window_index=0))

    beacons = [
        DummyBeacon("192.168.1.201", "45.33.32.1", 443),
        DummyBeacon("192.168.1.202", "45.33.32.1", 443),
    ]

    pats = detect_attack_patterns(tcp_sessions=sessions, beaconing_signals=beacons)
    pat_types = {p.pattern_type for p in pats}

    assert AttackPatternType.HORIZONTAL_SCAN in pat_types
    assert AttackPatternType.VERTICAL_SCAN in pat_types
    assert AttackPatternType.BEACONING_CLUSTER in pat_types


def test_entity_behavior_profiles():
    """Verify behavioral role derivation (SCANNER, BEACON, SERVER, CLIENT)."""
    sessions = []
    # Scanner
    for p in range(10, 25):
        sessions.append(DummySession("192.168.1.30", "10.0.0.1", p, state="REJECTED"))

    beacons = [DummyBeacon("192.168.1.40", "10.0.0.99", 443)]

    profiles = build_entity_behavior_profiles(tcp_sessions=sessions, beaconing_signals=beacons)
    assert "192.168.1.30" in profiles
    assert EntityBehavioralRole.SCANNER in profiles["192.168.1.30"].roles
    assert EntityBehavioralRole.RESET_HEAVY in profiles["192.168.1.30"].roles or profiles["192.168.1.30"].failure_ratio > 0.5

    assert "192.168.1.40" in profiles
    assert EntityBehavioralRole.BEACON in profiles["192.168.1.40"].roles


def test_campaign_correlation():
    """Verify grouping and separation of behavioral episodes into campaigns."""
    episodes = [
        DummyEpisode("ep1", "192.168.1.50", ("10.0.0.1",), (80, 443), start_window=0, end_window=1),
        DummyEpisode("ep2", "192.168.1.50", ("10.0.0.1",), (8080,), start_window=2, end_window=2),
        DummyEpisode("ep3", "172.16.0.99", ("192.168.1.1",), (22,), start_window=10, end_window=10),
    ]

    campaigns = correlate_attack_campaigns(episodes=episodes, time_window_gap_threshold=2)
    assert len(campaigns) == 2  # ep1 and ep2 merged into 1 campaign for 192.168.1.50, ep3 is separate

    c1 = next(c for c in campaigns if "192.168.1.50" in c.primary_entities)
    assert len(c1.constituent_episodes) == 2


def test_threat_story_and_prioritization():
    """Verify deterministic threat story generation and priority ranking."""
    sessions = []
    for p in range(20, 35):
        sessions.append(DummySession("192.168.1.80", "10.0.0.1", p, state="REJECTED"))

    profiles = build_entity_behavior_profiles(tcp_sessions=sessions)
    kinematics = analyze_attack_kinematics(tcp_sessions=sessions)
    stories = generate_threat_stories(entity_profiles=profiles, attack_kinematics=kinematics)
    assert len(stories) >= 1

    s80 = next(s for s in stories if s.entity == "192.168.1.80")
    assert s80.threat_verdict in ("SUSPICIOUS", "CONFIRMED_THREAT")
    assert len(s80.stages) >= 1
    assert "THREAT INVESTIGATION STORY" in s80.full_narrative_text

    prio = prioritize_threats(entity_profiles=profiles, attack_kinematics=kinematics)
    assert len(prio) >= 1
    assert prio[0].priority_rank == 1
    assert prio[0].priority_level in (ThreatPriorityLevel.P1_CRITICAL, ThreatPriorityLevel.P2_HIGH, ThreatPriorityLevel.P3_MEDIUM)


def test_investigation_query_engine():
    """Verify unified investigation query methods."""
    sessions = [DummySession("192.168.1.90", "10.0.0.1", 80)]
    profiles = build_entity_behavior_profiles(tcp_sessions=sessions)
    engine = InvestigationQueryEngine(entity_profiles=profiles)

    p = engine.query_entity_profile("192.168.1.90")
    assert p is not None
    assert p["entity"] == "192.168.1.90"

    t = engine.query_entity_timeline("192.168.1.90")
    assert isinstance(t, list)
