"""Tests for Temporal Network World Model & Intelligence State Engine."""
from __future__ import annotations

import pytest
from nexsolve_core.temporal.world_state import (
    EntityTemporalState,
    EntityWindowPresence,
    RelationshipStatus,
    RelationshipTemporalState,
    TemporalNetworkWindow,
    TemporalNetworkWorldState,
    WorldStateDiff,
    WorldStateSnapshot,
    build_temporal_network_world_state,
    diff_snapshots,
)
from nexsolve_core.schemas import TemporalWindow
from nexsolve_core.temporal.entity_history import TemporalEntityHistory


def test_temporal_world_domain_models():
    ent = EntityTemporalState(
        entity_key="192.168.1.50",
        entity_type="IP",
        presence=EntityWindowPresence.NEWLY_EMERGED,
        window_index=0,
        attack_state="RECONNAISSANCE",
        fanout=12,
        port_diversity=25,
        bytes_sent=1500,
        bytes_recv=400,
        packets=18,
        failure_ratio=0.75,
        active_peers=("10.0.0.1", "10.0.0.2"),
        active_ports=(80, 443, 22),
        is_expanding_peers=True,
        is_expanding_ports=True,
        associated_findings_count=3,
        composite_risk_score=85.0,
    )
    d = ent.to_dict()
    assert d["entity_key"] == "192.168.1.50"
    assert d["presence"] == "NEWLY_EMERGED"
    assert d["attack_state"] == "RECONNAISSANCE"
    assert d["fanout"] == 12
    assert d["failure_ratio"] == 0.75

    rel = RelationshipTemporalState(
        relationship_id="192.168.1.50->10.0.0.1:80/TCP",
        src_entity="192.168.1.50",
        dst_entity="10.0.0.1",
        dst_port=80,
        protocol="TCP",
        status=RelationshipStatus.NEW,
        first_seen_window=0,
        last_seen_window=0,
        window_index=0,
        packet_count=6,
        byte_count=500,
        connection_count=1,
        failed_attempts=0,
    )
    assert rel.to_dict()["status"] == "NEW"


def test_deterministic_diff_snapshots():
    ent_a = EntityTemporalState(
        entity_key="192.168.1.50",
        entity_type="IP",
        presence=EntityWindowPresence.ACTIVE,
        window_index=0,
        attack_state="BENIGN",
        fanout=2,
        port_diversity=1,
        bytes_sent=200,
        bytes_recv=200,
        packets=4,
        failure_ratio=0.0,
        active_peers=("10.0.0.1",),
        active_ports=(80,),
    )
    snap_a = WorldStateSnapshot(
        window_index=0,
        window_id="win_0",
        start_time=0.0,
        end_time=60.0,
        duration_seconds=60.0,
        packet_count=4,
        flow_count=1,
        entities={"192.168.1.50": ent_a},
        relationships={},
        behavior_changes=(),
        attack_states=(),
        evidence_keys=(),
    )

    ent_b1 = EntityTemporalState(
        entity_key="192.168.1.50",
        entity_type="IP",
        presence=EntityWindowPresence.ACTIVE,
        window_index=1,
        attack_state="RECONNAISSANCE",  # Changed state!
        fanout=10,  # Surge!
        port_diversity=15,
        bytes_sent=2000,
        bytes_recv=500,
        packets=25,
        failure_ratio=0.8,
        active_peers=("10.0.0.1", "10.0.0.2", "10.0.0.3"),
        active_ports=(80, 443, 22),
    )
    ent_b2 = EntityTemporalState(
        entity_key="192.168.1.99",
        entity_type="IP",
        presence=EntityWindowPresence.NEWLY_EMERGED,
        window_index=1,
        attack_state="BENIGN",
        fanout=1,
        port_diversity=1,
        bytes_sent=100,
        bytes_recv=50,
        packets=2,
        failure_ratio=0.0,
        active_peers=("10.0.0.1",),
        active_ports=(53,),
    )
    snap_b = WorldStateSnapshot(
        window_index=1,
        window_id="win_1",
        start_time=60.0,
        end_time=120.0,
        duration_seconds=60.0,
        packet_count=27,
        flow_count=3,
        entities={"192.168.1.50": ent_b1, "192.168.1.99": ent_b2},
        relationships={},
        behavior_changes=(),
        attack_states=(),
        evidence_keys=("ev_t1046",),
    )

    diff = diff_snapshots(snap_a, snap_b, 0, 1)
    d = diff.to_dict()

    assert "192.168.1.99" in d["entities_added"]
    assert "192.168.1.50" in d["entities_persisted"]
    assert len(d["attack_state_transitions"]) == 1
    assert d["attack_state_transitions"][0]["from_state"] == "BENIGN"
    assert d["attack_state_transitions"][0]["to_state"] == "RECONNAISSANCE"
    assert len(d["fanout_surges"]) == 1
    assert d["fanout_surges"][0]["entity"] == "192.168.1.50"
    assert "ev_t1046" in d["new_evidence_keys"]


def test_build_temporal_network_world_state_epistemic_separation():
    # Mock continuous windows
    windows = [
        {"window_id": "win_0", "start_timestamp": 0.0, "end_timestamp": 60.0, "tcp_retransmission_rate": 0.01},
        {"window_id": "win_1", "start_timestamp": 60.0, "end_timestamp": 120.0, "tcp_retransmission_rate": 0.02},
        {"window_id": "win_2", "start_timestamp": 120.0, "end_timestamp": 180.0, "tcp_retransmission_rate": 0.05},
    ]
    flows = [
        {"src_ip": "208.111.178.163", "dst_ip": "192.168.10.50", "dst_port": 80, "protocol": "TCP", "packets": 5, "bytes": 400, "window_index": 0},
        {"src_ip": "208.111.178.163", "dst_ip": "192.168.10.51", "dst_port": 443, "protocol": "TCP", "packets": 8, "bytes": 600, "window_index": 1},
        {"src_ip": "208.111.178.163", "dst_ip": "192.168.10.52", "dst_port": 22, "protocol": "TCP", "packets": 12, "bytes": 900, "window_index": 2},
    ]
    hist = {
        "208.111.178.163": TemporalEntityHistory(
            entity_key="208.111.178.163",
            entity_type="IP",
            first_seen_window=0,
            last_seen_window=2,
            active_windows=(0, 1, 2),
            activity_count=3,
            unique_peers=("192.168.10.50", "192.168.10.51", "192.168.10.52"),
            unique_ports=(80, 443, 22),
            total_packets=25,
            total_bytes=1900,
            session_count=3,
            findings_count=1,
            observed_states=("ESTABLISHED",),
            is_expanding_peers=False,
            is_expanding_ports=False,
        )
    }
    forecast_points = [
        {"horizon_step": 1, "predicted_stage": "RECONNAISSANCE", "attack_probability": 0.78, "scope": "FORECAST"}
    ]

    world = build_temporal_network_world_state(
        capture_id="test_analysis_1",
        windows=windows,
        flows=flows,
        entity_histories=hist,
        forecast_points=forecast_points,
    )

    d = world.to_dict()
    assert d["total_windows"] == 3
    assert len(d["windows"]) == 3
    assert len(d["snapshots"]) == 3

    # Check window 2 is capture boundary
    assert d["windows"][2]["is_capture_boundary"] is True
    assert d["windows"][0]["is_capture_boundary"] is False

    # Check presence semantics
    snap0 = world.get_snapshot(0)
    snap2 = world.get_snapshot(2)
    assert snap0 is not None and snap2 is not None
    assert snap0.entities["208.111.178.163"].presence == EntityWindowPresence.NEWLY_EMERGED
    assert snap2.entities["208.111.178.163"].presence == EntityWindowPresence.LAST_OBSERVED_AT_CAPTURE_BOUNDARY

    # Check forecast segregation: historical snapshots contain 0 forecast points
    for snap in world.snapshots.values():
        for ent in snap.entities.values():
            assert ent.presence != "FORECAST"

    assert len(world.forecast_points) == 1
    assert world.forecast_points[0]["scope"] == "FORECAST"
