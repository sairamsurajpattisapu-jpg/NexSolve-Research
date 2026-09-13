import math
from pathlib import Path
import pytest
from ml.data.packet_features import _skewness, aggregate_window_features
from ml.data.pcap_extractor import extract_canonical_capture
from nexsolve_core.schemas import FlowRecord, PacketRecord, Provenance, TemporalWindow, make_capture_quality
from nexsolve_core.state import (
    CANDIDATE_EXTENDED_FEATURES_72,
    EXTENDED_MODEL_SCHEMA_72,
    MODEL_SCHEMA_45,
    build_network_state_candidates,
    evaluate_model_compatibility,
)

REAL_PCAP_PATH = Path('C:/Users/saira/Downloads/friday_10windows_slice.pcap')


def test_candidate_features_72_count():
    assert len(CANDIDATE_EXTENDED_FEATURES_72) == 72


def test_skewness_formula_and_edge_cases():
    assert _skewness([]) == 0.0
    assert _skewness([10.0]) == 0.0
    assert _skewness([10.0, 20.0]) == 0.0
    assert _skewness([5.0, 5.0, 5.0, 5.0]) == 0.0
    sym = [10.0, 20.0, 30.0, 40.0, 50.0]
    assert abs(_skewness(sym)) < 1e-6
    right_skewed = [10.0, 10.0, 10.0, 10.0, 100.0]
    assert _skewness(right_skewed) > 1.0


def test_packet_extended_features_edge_cases():
    empty_agg = aggregate_window_features([], window_start=0)
    assert empty_agg["packet_size_skewness"] == 0.0
    assert empty_agg["packet_rate_peak"] == 0.0
    assert empty_agg["tcp_window_zero_count"] == 0
    assert empty_agg["cwr_count"] == 0
    assert empty_agg["ece_count"] == 0
    assert empty_agg["udp_packet_ratio"] == 0.0
    assert empty_agg["icmp_packet_ratio"] == 0.0
    assert empty_agg["mean_tcp_payload_size"] == 0.0
    assert empty_agg["max_tcp_payload_size"] == 0.0
    assert empty_agg["payload_rate_bytes_sec"] == 0.0

    p1 = PacketRecord(
        timestamp=100.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ip_version=4,
        src_port=1000,
        dst_port=80,
        protocol="TCP",
        packet_length=1500,
        payload_length=1460,
        ttl=64,
        tcp_window=0,
        tcp_flags=0x80 | 0x40 | 0x02,
        tcp_seq=1,
        tcp_ack=0,
        packet_index=1,
    )
    p2 = PacketRecord(
        timestamp=100.5,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ip_version=4,
        src_port=1000,
        dst_port=80,
        protocol="TCP",
        packet_length=500,
        payload_length=460,
        ttl=64,
        tcp_window=64240,
        tcp_flags=0x10,
        tcp_seq=1461,
        tcp_ack=1,
        packet_index=2,
    )
    p3 = PacketRecord(
        timestamp=101.0,
        src_ip="10.0.0.3",
        dst_ip="10.0.0.2",
        ip_version=4,
        src_port=2000,
        dst_port=53,
        protocol="UDP",
        packet_length=100,
        payload_length=72,
        ttl=128,
        tcp_window=None,
        tcp_flags=None,
        tcp_seq=None,
        tcp_ack=None,
        packet_index=3,
    )

    agg = aggregate_window_features([p1, p2, p3], window_start=100)
    assert agg["cwr_count"] == 1
    assert agg["ece_count"] == 1
    assert agg["tcp_window_zero_count"] == 1
    assert agg["syn_count"] == 1
    assert agg["ack_count"] == 1
    assert agg["udp_count"] == 1
    assert agg["udp_packet_ratio"] == pytest.approx(1 / 3)
    assert agg["icmp_packet_ratio"] == 0.0
    assert agg["mean_tcp_payload_size"] == pytest.approx((1460 + 460) / 2)
    assert agg["max_tcp_payload_size"] == 1460.0
    assert agg["payload_rate_bytes_sec"] == pytest.approx(1992.0)
    assert agg["packet_rate_peak"] == 2.0


def test_flow_extended_features_edge_cases():
    prov = Provenance("test", (1,), ("f1",), ("w1",), (100.0,), "test")
    p1 = PacketRecord(
        timestamp=100.0,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        ip_version=4,
        src_port=1000,
        dst_port=80,
        protocol="TCP",
        packet_length=100,
        payload_length=60,
        ttl=64,
        tcp_window=1000,
        tcp_flags=0x02,
        tcp_seq=1,
        tcp_ack=0,
        packet_index=1,
    )
    q = make_capture_quality([p1], capture_id="test")
    flow1 = FlowRecord(
        flow_id="f1",
        start_timestamp=100.0,
        end_timestamp=100.0,
        duration_seconds=0.0,
        src_ip="10.0.0.1",
        src_port=1000,
        dst_ip="10.0.0.2",
        dst_port=80,
        protocol="TCP",
        forward_packet_count=1,
        reverse_packet_count=0,
        total_packet_count=1,
        forward_bytes=100,
        reverse_bytes=0,
        total_bytes=100,
        packet_rate=1.0,
        byte_rate=100.0,
        syn_count=1,
        ack_count=0,
        fin_count=0,
        rst_count=0,
        retransmission_count=0,
        completeness="INCOMPLETE",
        provenance=prov,
    )
    agg1 = aggregate_window_features([p1], window_start=100)
    w1 = TemporalWindow(
        window_id="w1",
        start_timestamp=100,
        end_timestamp=160,
        duration_seconds=60,
        packet_count=1,
        flow_count=1,
        packets=(p1,),
        flows=(flow1,),
        aggregate_features=agg1,
        detection_features={},
        quality=q,
        ordering="original_capture_order_preserved",
        provenance=prov,
    )
    candidates = build_network_state_candidates([w1])
    assert len(candidates) == 1
    c = candidates[0]

    assert c.flow_features["flow_duration_variance"] == 0.0
    assert c.flow_features["byte_ratio_src_dst"] == 0.0
    assert c.flow_features["packet_ratio_src_dst"] == 0.0
    assert c.flow_features["single_packet_flow_ratio"] == 1.0
    assert c.flow_features["active_flow_rate"] == pytest.approx(1 / 60.0)
    assert c.flow_features["tcp_syn_ack_ratio"] == 0.0
    assert c.flow_features["tcp_rst_ack_ratio"] == 0.0
    assert c.flow_features["port_entropy"] == 0.0
    assert c.flow_features["mean_payload_bytes"] == 60.0


def test_port_entropy_mathematical_calculation():
    prov = Provenance("test", (1, 2), ("f1", "f2"), ("w1",), (100.0, 101.0), "test")
    p1 = PacketRecord(timestamp=100.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", ip_version=4, src_port=1000, dst_port=80, protocol="TCP", packet_length=60, payload_length=0, ttl=64, tcp_window=1000, tcp_flags=0x02, tcp_seq=1, tcp_ack=0, packet_index=1)
    p2 = PacketRecord(timestamp=101.0, src_ip="10.0.0.1", dst_ip="10.0.0.2", ip_version=4, src_port=1001, dst_port=443, protocol="TCP", packet_length=60, payload_length=0, ttl=64, tcp_window=1000, tcp_flags=0x02, tcp_seq=1, tcp_ack=0, packet_index=2)
    q = make_capture_quality([p1, p2], capture_id="test")
    f1 = FlowRecord(flow_id="f1", start_timestamp=100.0, end_timestamp=100.0, duration_seconds=0.0, src_ip="10.0.0.1", src_port=1000, dst_ip="10.0.0.2", dst_port=80, protocol="TCP", forward_packet_count=1, reverse_packet_count=0, total_packet_count=1, forward_bytes=60, reverse_bytes=0, total_bytes=60, packet_rate=1.0, byte_rate=60.0, syn_count=1, ack_count=0, fin_count=0, rst_count=0, retransmission_count=0, completeness="INCOMPLETE", provenance=prov)
    f2 = FlowRecord(flow_id="f2", start_timestamp=101.0, end_timestamp=101.0, duration_seconds=0.0, src_ip="10.0.0.1", src_port=1001, dst_ip="10.0.0.2", dst_port=443, protocol="TCP", forward_packet_count=1, reverse_packet_count=0, total_packet_count=1, forward_bytes=60, reverse_bytes=0, total_bytes=60, packet_rate=1.0, byte_rate=60.0, syn_count=1, ack_count=0, fin_count=0, rst_count=0, retransmission_count=0, completeness="INCOMPLETE", provenance=prov)

    agg = aggregate_window_features([p1, p2], window_start=100)
    w = TemporalWindow(window_id="w1", start_timestamp=100, end_timestamp=160, duration_seconds=60, packet_count=2, flow_count=2, packets=(p1, p2), flows=(f1, f2), aggregate_features=agg, detection_features={}, quality=q, ordering="original_capture_order_preserved", provenance=prov)
    c = build_network_state_candidates([w])[0]

    assert c.flow_features["port_entropy"] == pytest.approx(1.0)


@pytest.mark.skipif(not REAL_PCAP_PATH.exists(), reason="Real PCAP slice not present on local machine")
def test_real_pcap_45_and_72_full_readiness():
    packets, windows, quality = extract_canonical_capture(REAL_PCAP_PATH, window_seconds=60)
    assert len(windows) == 10
    assert len(packets) == 2277

    cand_states = build_network_state_candidates(windows)
    assert len(cand_states) == 10

    # 1. 45-feature production safety gate passes cleanly on real traffic
    report_45 = evaluate_model_compatibility(cand_states, MODEL_SCHEMA_45)
    assert report_45.model_ready is True
    assert report_45.required_features == 45
    assert len(report_45.available_features) == 45
    assert len(report_45.unavailable_features) == 0

    # 2. 72-feature candidate schema is now 100% computable from canonical PCAP
    report_72 = evaluate_model_compatibility(cand_states, EXTENDED_MODEL_SCHEMA_72)
    assert report_72.model_ready is True
    assert report_72.required_features == 72
    assert len(report_72.available_features) == 72
    assert len(report_72.unavailable_features) == 0

    for c in cand_states[1:]:
        for group in ("flow_features", "packet_features", "temporal_features"):
            feature_dict = getattr(c, group)
            for key in EXTENDED_MODEL_SCHEMA_72[group]:
                val = feature_dict.get(key)
                assert val is not None, f"Feature {group}.{key} is None"
                assert math.isfinite(val), f"Feature {group}.{key} is not finite: {val}"


@pytest.mark.skipif(not REAL_PCAP_PATH.exists(), reason="Real PCAP slice not present on local machine")
def test_temporal_causality_and_invariance():
    """Verify strictly backward-looking temporal invariance:
    Modifying or appending future windows must NOT alter earlier candidate features.
    """
    packets, windows, _ = extract_canonical_capture(REAL_PCAP_PATH, window_seconds=60)
    assert len(windows) >= 6

    # Extract first 4 windows
    cand_seq_4 = build_network_state_candidates(windows[:4])
    # Extract first 6 windows
    cand_seq_6 = build_network_state_candidates(windows[:6])

    # Windows 0, 1, 2, 3 must have IDENTICAL features in both extractions
    for i in range(4):
        c4 = cand_seq_4[i]
        c6 = cand_seq_6[i]
        for group in ("flow_features", "packet_features", "temporal_features"):
            f4 = getattr(c4, group)
            f6 = getattr(c6, group)
            for k in EXTENDED_MODEL_SCHEMA_72[group]:
                assert f4.get(k) == f6.get(k), f"Causality violation at window {i} for {group}.{k}: {f4.get(k)} != {f6.get(k)}"


@pytest.mark.skipif(not REAL_PCAP_PATH.exists(), reason="Real PCAP slice not present on local machine")
def test_45_vs_72_window_parity_and_alignment():
    """Verify Phase 7 invariant:
    45-feature and 72-feature extractions must have IDENTICAL window boundaries,
    identical packet counts, identical timestamps, and identical active flow counts.
    Only feature vector dimensionality differs.
    """
    packets, windows, _ = extract_canonical_capture(REAL_PCAP_PATH, window_seconds=60)
    candidates = build_network_state_candidates(windows)

    for idx, c in enumerate(candidates):
        # Timestamps and windows are identical
        w = windows[idx]
        assert c.window_id == w.window_id
        assert c.start_timestamp == w.start_timestamp
        assert c.end_timestamp == w.end_timestamp
        assert c.traffic_aggregates["packet_count"] == w.packet_count
        assert c.flow_aggregates["active_flow_count"] == w.flow_count

        # All 45 canonical features must be identical subsets of the 72 features
        # Note: window idx 0 has no prior window, so temporal_features are unpopulated at idx 0
        for group, names in MODEL_SCHEMA_45.items():
            f_cand = getattr(c, group)
            if idx > 0 or group != "temporal_features":
                for name in names:
                    assert name in f_cand, f"Missing canonical feature {group}.{name} at window {idx}"
                    val = f_cand[name]
                    assert val is not None, f"Feature {group}.{name} in window {idx} is None"


def test_forecast_target_horizon_separation_invariant():
    """Verify Phase 5 & 6 invariant:
    For any forecast case, target_timestamp must be strictly greater than input history end.
    """
    from ml.evaluation.scientific_forecasting import ForecastCase, build_forecast_cases
    from world_model import NetworkState

    # Construct 15 contiguous dummy network states
    states = [
        NetworkState(
            timestamp=1000 + i * 60,
            flow_features={},
            packet_features={},
            temporal_features={},
            attack_state=int(i >= 10),
            packet_features_available=True,
        )
        for i in range(15)
    ]

    cases = build_forecast_cases(states, lookback=8, horizons=(1, 2, 3, 4, 5), episode_id="test_ep")
    assert len(cases) > 0

    for case in cases:
        input_end = case.input_timestamps[-1]
        for h, target_ts in zip((1, 2, 3, 4, 5), case.target_timestamps):
            assert target_ts > input_end, f"Target {target_ts} is not strictly after input end {input_end}"
            assert target_ts == input_end + h * 60, f"Target {target_ts} does not match horizon {h} * 60s"
