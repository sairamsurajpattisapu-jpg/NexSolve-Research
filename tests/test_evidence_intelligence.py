"""Comprehensive test suite for NexSolve Evidence Intelligence engine."""
from __future__ import annotations

import pytest

from ml.forecasting.attack_horizon import AttackHorizonResult, AttackHorizonState, compute_attack_horizon
from ml.forecasting.evidence_intelligence import (
    HIGH_CHANGE,
    LOW_CHANGE,
    MEDIUM_CHANGE,
    EvidenceChain,
    EvidenceDirection,
    EvidenceItem,
    EvidenceQuality,
    EvidenceSeverity,
    EvidenceType,
    build_evidence_chain,
)
from nexsolve_core.schemas import CaptureQuality, QualityStatus
from world_model import FLOW_NAMES, FEATURE_NAMES, NetworkState


def _make_dummy_state(
    timestamp: int = 1700000000,
    flow_mult: float = 1.0,
    packet_available: bool = False,
    extra_flow: dict[str, float] | None = None,
) -> NetworkState:
    flow = {
        "flow_count": 100.0 * flow_mult,
        "total_src_bytes": 50000.0 * flow_mult,
        "total_dst_bytes": 100000.0 * flow_mult,
        "total_packets": 1000.0 * flow_mult,
        "mean_duration": 1.5,
        "mean_flow_bytes": 1500.0,
        "mean_flow_packets": 10.0,
        "mean_sttl": 64.0,
        "mean_dttl": 64.0,
        "mean_swin": 255.0,
        "mean_dwin": 255.0,
        "mean_iat": 0.05,
        "mean_tcp_rtt": 0.02,
        "unique_src_ports": 20.0 * flow_mult,
        "unique_dst_ports": 15.0 * flow_mult,
        "proto_tcp_count": 80.0 * flow_mult,
        "proto_udp_count": 20.0 * flow_mult,
        "proto_other_count": 0.0,
    }
    if extra_flow:
        flow.update(extra_flow)

    packet = {}
    if packet_available:
        packet = {
            "packet_count": 1000.0 * flow_mult,
            "mean_packet_size": 150.0,
            "std_packet_size": 20.0,
            "min_packet_size": 40.0,
            "max_packet_size": 1500.0,
            "tcp_syn_count": 50.0 * flow_mult,
            "retransmission_count": 5.0 * flow_mult,
        }

    temporal = {
        "delta_flow_count": 10.0 * flow_mult,
        "delta_total_bytes": 5000.0 * flow_mult,
        "delta_total_packets": 50.0 * flow_mult,
        "delta_ports": 2.0 * flow_mult,
        "delta_iat": 0.0,
        "rolling_total_bytes": 150000.0 * flow_mult,
    }
    return NetworkState(timestamp, flow, packet, temporal, 0, packet_available)


# 1. Empty history
def test_1_empty_history():
    chain = build_evidence_chain([])
    assert chain.supporting_feature_count == 0
    assert chain.contradictory_feature_count == 0
    assert chain.evidence_strength == 0.0
    assert chain.evidence_quality == EvidenceQuality.INSUFFICIENT


# 2. Insufficient history (single state, no previous baseline)
def test_2_single_state_history():
    s0 = _make_dummy_state(flow_mult=1.0)
    chain = build_evidence_chain([s0])
    assert chain.current_timestamp != ""
    assert isinstance(chain.supporting, list)


# 3. Stable traffic (no meaningful changes)
def test_3_stable_traffic():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(8)]
    chain = build_evidence_chain(seq)
    # Under stable baseline, relative changes are near 0.0 -> no anomalous change items
    assert len(chain.contradictory) == 0


# 4. Significant flow increase
def test_4_significant_flow_increase():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(7)]
    # 8th state has 80% flow increase
    seq.append(_make_dummy_state(flow_mult=1.8, extra_flow={"flow_count": 180.0}))

    # Under an attack hypothesis
    horizon = compute_attack_horizon(seq[-1].timestamp, [{"horizon": 1, "attack_probability": 0.85}])
    chain = build_evidence_chain(seq, forecast_horizon_result=horizon)

    flow_items = [e for e in chain.supporting if e["feature_name"] == "flow_count"]
    assert len(flow_items) == 1
    assert flow_items[0]["direction"] == EvidenceDirection.INCREASE.value
    assert flow_items[0]["relative_change"] >= 0.50


# 5. Significant byte increase
def test_5_significant_byte_increase():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(7)]
    seq.append(_make_dummy_state(extra_flow={"total_src_bytes": 200000.0}))  # 4x increase
    horizon = compute_attack_horizon(seq[-1].timestamp, [{"horizon": 1, "attack_probability": 0.80}])
    chain = build_evidence_chain(seq, forecast_horizon_result=horizon)

    byte_items = [e for e in chain.supporting if e["feature_name"] == "total_src_bytes"]
    assert len(byte_items) == 1
    assert byte_items[0]["evidence_type"] == EvidenceType.BYTE_RATE_CHANGE.value


# 6. Significant packet increase
def test_6_significant_packet_increase():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(7)]
    seq.append(_make_dummy_state(extra_flow={"total_packets": 5000.0}))  # 5x increase
    horizon = compute_attack_horizon(seq[-1].timestamp, [{"horizon": 1, "attack_probability": 0.80}])
    chain = build_evidence_chain(seq, forecast_horizon_result=horizon)

    pkt_items = [e for e in chain.supporting if e["feature_name"] == "total_packets"]
    assert len(pkt_items) == 1
    assert pkt_items[0]["evidence_type"] == EvidenceType.PACKET_RATE_CHANGE.value


# 7. Port diversity increase
def test_7_port_diversity_increase():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(7)]
    seq.append(_make_dummy_state(extra_flow={"unique_dst_ports": 90.0}))  # 6x increase
    horizon = compute_attack_horizon(seq[-1].timestamp, [{"horizon": 1, "attack_probability": 0.85}])
    chain = build_evidence_chain(seq, forecast_horizon_result=horizon)

    port_items = [e for e in chain.supporting if e["feature_name"] == "unique_dst_ports"]
    assert len(port_items) == 1
    assert port_items[0]["evidence_type"] == EvidenceType.PORT_DIVERSITY.value
    assert port_items[0]["severity"] == EvidenceSeverity.HIGH.value


# 8. Multiple supporting signals
def test_8_multiple_supporting_signals():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(7)]
    seq.append(_make_dummy_state(flow_mult=2.5))  # flow, bytes, packets, ports all surge
    horizon = compute_attack_horizon(
        seq[-1].timestamp,
        [{"horizon": 1, "attack_probability": 0.85}, {"horizon": 2, "attack_probability": 0.88}],
    )
    chain = build_evidence_chain(seq, forecast_horizon_result=horizon)
    assert chain.supporting_feature_count >= 4
    assert chain.evidence_strength >= 0.70


# 9. Contradictory signals
def test_9_contradictory_signals():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(7)]
    # Traffic collapses to almost 0 during an attack forecast
    seq.append(_make_dummy_state(flow_mult=0.1))
    horizon = compute_attack_horizon(seq[-1].timestamp, [{"horizon": 1, "attack_probability": 0.90}])
    chain = build_evidence_chain(seq, forecast_horizon_result=horizon)

    assert chain.contradictory_feature_count >= 2
    assert any("decreased" in e["explanation"].lower() for e in chain.contradictory)


# 10. Forecast persistence evidence
def test_10_forecast_persistence_evidence():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(8)]
    horizon = compute_attack_horizon(
        seq[-1].timestamp,
        [
            {"horizon": 1, "attack_probability": 0.80},
            {"horizon": 2, "attack_probability": 0.85},
            {"horizon": 3, "attack_probability": 0.82},
        ],
    )
    chain = build_evidence_chain(seq, forecast_horizon_result=horizon)
    support_types = [e["evidence_type"] for e in chain.supporting]
    assert EvidenceType.FORECAST_SUPPORT.value in support_types


# 11 & 12. Missing / Unavailable features: MUST NOT BE FABRICATED
def test_11_12_unavailable_features_never_become_evidence():
    # packet_available is FALSE
    seq = [_make_dummy_state(flow_mult=1.0, packet_available=False) for _ in range(8)]
    chain = build_evidence_chain(seq)

    all_evidence = chain.supporting + chain.contradictory
    all_features = [e["feature_name"] for e in all_evidence]

    # Explicit check: packet-only features like tcp_syn_count or mean_packet_size must NOT appear!
    assert "tcp_syn_count" not in all_features
    assert "mean_packet_size" not in all_features
    assert "retransmission_count" not in all_features


# 13. Provenance propagation
def test_13_provenance_propagation():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(7)]
    seq.append(_make_dummy_state(flow_mult=2.0))
    prov = {"capture_id": "test-pcap-001", "window_id": "w-08"}
    chain = build_evidence_chain(seq, provenance_info=prov)

    assert chain.provenance_complete is True
    if chain.supporting:
        assert chain.supporting[0]["provenance"]["capture_id"] == "test-pcap-001"


# 14 & 15. Poor capture quality and timestamp uncertainty
def test_14_15_capture_quality_and_timestamp_uncertainty():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(8)]
    quality = CaptureQuality(
        total_packets_observed=100,
        parsed_packets=90,
        malformed_packets=2,
        unsupported_packets=0,
        truncated_packets=8,
        timestamp_anomalies=5,
        duplicate_packets=0,
        ipv4_count=90,
        ipv6_count=0,
        tcp_count=90,
        udp_count=0,
        icmp_count=0,
        arp_count=0,
        vlan_count=0,
        fragmented_packet_count=0,
        incomplete_flow_count=0,
        status=QualityStatus.DEGRADED,
        reason="Timestamp anomalies detected",
        capture_id="cap-qual-1",
    )
    chain = build_evidence_chain(seq, capture_quality=quality)
    assert chain.evidence_quality == EvidenceQuality.DEGRADED
    assert any(e["evidence_type"] == EvidenceType.CAPTURE_QUALITY.value for e in chain.contradictory)
    assert any("timestamp anomalies" in lim for lim in chain.limitations)


# 16. Deterministic evidence strength
def test_16_deterministic_evidence_strength():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(7)]
    seq.append(_make_dummy_state(flow_mult=1.8))
    c1 = build_evidence_chain(seq)
    c2 = build_evidence_chain(seq)
    assert c1.evidence_strength == c2.evidence_strength
    assert 0.0 <= c1.evidence_strength <= 1.0


# 17. No fabricated evidence
def test_17_no_fabricated_evidence():
    # Empty flow features
    s = NetworkState(1700000000, {}, {}, {}, 0, False)
    chain = build_evidence_chain([s])
    assert len(chain.supporting) == 0
    assert len(chain.contradictory) == 0


# 18. Repeated execution produces identical output
def test_18_repeated_execution():
    seq = [_make_dummy_state(flow_mult=1.0) for _ in range(7)]
    seq.append(_make_dummy_state(flow_mult=2.2))
    horizon = compute_attack_horizon(seq[-1].timestamp, [{"horizon": 1, "attack_probability": 0.85}])
    c1 = build_evidence_chain(seq, forecast_horizon_result=horizon).to_dict()
    c2 = build_evidence_chain(seq, forecast_horizon_result=horizon).to_dict()
    assert c1 == c2
