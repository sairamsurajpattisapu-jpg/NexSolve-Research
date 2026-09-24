"""Unit tests for the Canonical Evidence Intelligence Engine (ml/forecasting/evidence_engine.py).

Verifies:
- Finite timestamp and bounded confidence enforcement.
- Verified MITRE technique validation.
- Zero-baseline percentage safety (no +410209592% bugs).
- Multi-sensor agreement classification and confidence modifiers.
- Transparent evidence fusion (supporting, contradictory, neutral).
- Canonical EvidenceGraph node and edge semantics and backward tracing.
"""
from __future__ import annotations

import math
import pytest

from ml.forecasting.evidence_engine import (
    EvidenceEdgeType,
    EvidenceGraph,
    EvidenceItem,
    EvidenceNodeType,
    EvidencePolarity,
    EvidenceSource,
    FeatureChangeType,
    SensorAgreementLevel,
    build_canonical_evidence_graph,
    evaluate_sensor_agreement,
    explain_feature_change,
    fuse_evidence,
)


def test_evidence_item_valid_construction() -> None:
    item = EvidenceItem(
        evidence_id="ev_001",
        timestamp=1710000000.0,
        source=EvidenceSource.SURICATA,
        modality="IDS_ALERT",
        polarity=EvidencePolarity.SUPPORTING,
        description="ET SCAN Potential Nmap Port Scan",
        confidence=0.88,
        technique_id="T1046",
        stage="RECONNAISSANCE",
    )
    assert item.evidence_id == "ev_001"
    assert item.confidence == 0.88
    d = item.to_dict()
    assert d["source"] == "SURICATA"
    assert d["polarity"] == "SUPPORTING"
    assert d["technique_id"] == "T1046"


def test_evidence_item_rejects_non_finite_timestamp() -> None:
    with pytest.raises(ValueError, match="Invalid timestamp"):
        EvidenceItem(
            evidence_id="ev_bad_time_nan",
            timestamp=float("nan"),
            source=EvidenceSource.PCAP,
            modality="PACKET",
            polarity=EvidencePolarity.NEUTRAL,
            description="Bad timestamp",
        )

    with pytest.raises(ValueError, match="Invalid timestamp"):
        EvidenceItem(
            evidence_id="ev_bad_time_inf",
            timestamp=float("inf"),
            source=EvidenceSource.PCAP,
            modality="PACKET",
            polarity=EvidencePolarity.NEUTRAL,
            description="Bad timestamp",
        )


def test_evidence_item_rejects_out_of_bounds_confidence() -> None:
    with pytest.raises(ValueError, match="Evidence confidence must be in"):
        EvidenceItem(
            evidence_id="ev_bad_conf_high",
            timestamp=1710000000.0,
            source=EvidenceSource.HEURISTIC,
            modality="FLOW",
            polarity=EvidencePolarity.SUPPORTING,
            description="High confidence",
            confidence=1.2,
        )

    with pytest.raises(ValueError, match="Evidence confidence must be in"):
        EvidenceItem(
            evidence_id="ev_bad_conf_low",
            timestamp=1710000000.0,
            source=EvidenceSource.HEURISTIC,
            modality="FLOW",
            polarity=EvidencePolarity.SUPPORTING,
            description="Low confidence",
            confidence=-0.1,
        )


def test_evidence_item_rejects_unverified_mitre_technique() -> None:
    with pytest.raises(ValueError, match="Invalid or unverified MITRE ATT&CK technique"):
        EvidenceItem(
            evidence_id="ev_bad_tech",
            timestamp=1710000000.0,
            source=EvidenceSource.MODEL,
            modality="DETECTION",
            polarity=EvidencePolarity.SUPPORTING,
            description="Bogus technique",
            technique_id="T99999_FABRICATED",
        )


def test_zero_baseline_never_produces_percentage_overflow() -> None:
    # Baseline is 0.0, current is positive -> NEWLY_PRESENT, magnitude is None
    exp_pos = explain_feature_change(
        feature="syn_ratio",
        current_value=0.92,
        historical_baseline=0.0,
        window=1,
    )
    assert exp_pos.change_type == FeatureChangeType.NEWLY_PRESENT
    assert exp_pos.magnitude is None
    assert "newly present in window" in exp_pos.interpretation
    assert "+410209592%" not in exp_pos.interpretation

    # Baseline is 0.0, current is 0.0 -> STABLE, magnitude is 0.0
    exp_zero = explain_feature_change(
        feature="rst_ratio",
        current_value=0.0,
        historical_baseline=0.0,
        window=1,
    )
    assert exp_zero.change_type == FeatureChangeType.STABLE
    assert exp_zero.magnitude == 0.0

    # Baseline is None -> INSUFFICIENT_BASELINE
    exp_none = explain_feature_change(
        feature="dns_queries",
        current_value=45.0,
        historical_baseline=None,
    )
    assert exp_none.change_type == FeatureChangeType.INSUFFICIENT_BASELINE
    assert exp_none.magnitude is None


def test_non_zero_baseline_delta_classification() -> None:
    # 3% change is within 5% envelope -> STABLE
    exp_stable = explain_feature_change(
        feature="flow_bytes_per_sec",
        current_value=103.0,
        historical_baseline=100.0,
    )
    assert exp_stable.change_type == FeatureChangeType.STABLE
    assert exp_stable.magnitude is not None
    assert abs(exp_stable.magnitude - 0.03) < 1e-4

    # 25% increase -> INCREASED
    exp_inc = explain_feature_change(
        feature="flow_bytes_per_sec",
        current_value=125.0,
        historical_baseline=100.0,
    )
    assert exp_inc.change_type == FeatureChangeType.INCREASED
    assert exp_inc.magnitude is not None
    assert abs(exp_inc.magnitude - 0.25) < 1e-4

    # 30% decrease -> DECREASED
    exp_dec = explain_feature_change(
        feature="flow_bytes_per_sec",
        current_value=70.0,
        historical_baseline=100.0,
    )
    assert exp_dec.change_type == FeatureChangeType.DECREASED
    assert exp_dec.magnitude is not None
    assert abs(exp_dec.magnitude - (-0.30)) < 1e-4


def test_sensor_agreement_evaluation() -> None:
    # Empty items
    agr_empty = evaluate_sensor_agreement([])
    assert agr_empty.agreement_level == SensorAgreementLevel.UNKNOWN

    # Multi-sensor supporting -> STRONG
    suricata_item = EvidenceItem(
        evidence_id="s1",
        timestamp=100.0,
        source=EvidenceSource.SURICATA,
        modality="IDS_ALERT",
        polarity=EvidencePolarity.SUPPORTING,
        description="Suricata portscan alert",
        technique_id="T1046",
    )
    zeek_item = EvidenceItem(
        evidence_id="z1",
        timestamp=100.0,
        source=EvidenceSource.ZEEK,
        modality="CONN_SUMMARY",
        polarity=EvidencePolarity.SUPPORTING,
        description="Zeek scan connections",
        technique_id="T1046",
    )
    agr_strong = evaluate_sensor_agreement([suricata_item, zeek_item])
    assert agr_strong.agreement_level == SensorAgreementLevel.STRONG
    assert agr_strong.confidence_modifier == 1.15
    assert set(agr_strong.supporting_sources) == {"SURICATA", "ZEEK"}

    # Single sensor supporting, no others -> PARTIAL
    agr_partial = evaluate_sensor_agreement([suricata_item])
    assert agr_partial.agreement_level == SensorAgreementLevel.PARTIAL
    assert agr_partial.confidence_modifier == 1.0

    # Supporting + Neutral -> MIXED
    neutral_item = EvidenceItem(
        evidence_id="n1",
        timestamp=100.0,
        source=EvidenceSource.PCAP,
        modality="PACKET",
        polarity=EvidencePolarity.NEUTRAL,
        description="Normal background packet rate",
    )
    agr_mixed = evaluate_sensor_agreement([suricata_item, neutral_item])
    assert agr_mixed.agreement_level == SensorAgreementLevel.MIXED

    # Supporting + Contradictory -> CONFLICTING
    contra_item = EvidenceItem(
        evidence_id="c1",
        timestamp=100.0,
        source=EvidenceSource.NFSTREAM,
        modality="FLOW",
        polarity=EvidencePolarity.CONTRADICTORY,
        description="No anomalous flow volume detected",
    )
    agr_conflicting = evaluate_sensor_agreement([suricata_item, contra_item])
    assert agr_conflicting.agreement_level == SensorAgreementLevel.CONFLICTING
    assert agr_conflicting.confidence_modifier < 0.5


def test_fuse_evidence_synthesis() -> None:
    item1 = EvidenceItem(
        evidence_id="e1",
        timestamp=100.0,
        source=EvidenceSource.SURICATA,
        modality="IDS_ALERT",
        polarity=EvidencePolarity.SUPPORTING,
        description="Suricata scan",
        confidence=0.8,
    )
    item2 = EvidenceItem(
        evidence_id="e2",
        timestamp=101.0,
        source=EvidenceSource.SCAPY,
        modality="FLOW",
        polarity=EvidencePolarity.SUPPORTING,
        description="Scapy SYN surge",
        confidence=0.7,
    )
    item_neut = EvidenceItem(
        evidence_id="e3",
        timestamp=102.0,
        source=EvidenceSource.PCAP,
        modality="PACKET",
        polarity=EvidencePolarity.NEUTRAL,
        description="Packet length nominal",
        confidence=0.5,
    )

    fused = fuse_evidence([item1, item2, item_neut])
    assert fused.supporting_count == 2
    assert fused.neutral_count == 1
    assert fused.contradictory_count == 0
    assert fused.source_diversity == 3
    assert 0.0 <= fused.confidence <= 1.0
    assert fused.sensor_agreement.agreement_level == SensorAgreementLevel.STRONG

    # If contradiction is added, penalty is applied
    contra = EvidenceItem(
        evidence_id="e4",
        timestamp=103.0,
        source=EvidenceSource.HEURISTIC,
        modality="FEATURE",
        polarity=EvidencePolarity.CONTRADICTORY,
        description="Entropy is low",
        confidence=0.6,
    )
    fused_with_contra = fuse_evidence([item1, item2, item_neut, contra])
    assert fused_with_contra.contradictory_count == 1
    assert fused_with_contra.confidence < fused.confidence


def test_evidence_graph_and_backward_trace() -> None:
    graph = EvidenceGraph()

    # Add 9-tier mock nodes
    pcap_node = graph.add_node("node:pcap:1", EvidenceNodeType.PCAP, "test.pcap")
    win_node = graph.add_node("node:win:0", EvidenceNodeType.WINDOW, "Window 0")
    feat_node = graph.add_node("node:feat:syn_ratio", EvidenceNodeType.FEATURE, "syn_ratio")
    stage_node = graph.add_node("node:stage:recon", EvidenceNodeType.STAGE, "RECONNAISSANCE")
    fc_node = graph.add_node("node:fc:t1", EvidenceNodeType.FORECAST, "T+1: EXPLOITATION")

    # Add edges
    graph.add_edge(win_node.id, pcap_node.id, EvidenceEdgeType.DERIVED_FROM)
    graph.add_edge(feat_node.id, win_node.id, EvidenceEdgeType.DERIVED_FROM)
    graph.add_edge(stage_node.id, feat_node.id, EvidenceEdgeType.DERIVED_FROM)
    graph.add_edge(fc_node.id, stage_node.id, EvidenceEdgeType.FORECASTS)

    assert len(graph.nodes) == 5
    assert len(graph.edges) == 4

    # Trace backward from forecast node
    trace = graph.trace_backward(fc_node.id)
    assert len(trace) >= 4
    traced_ids = [step["node_id"] for step in trace]
    assert fc_node.id in traced_ids
    assert stage_node.id in traced_ids
    assert feat_node.id in traced_ids
    assert win_node.id in traced_ids

    # Test build_canonical_evidence_graph wrapper
    canonical_graph = build_canonical_evidence_graph(
        pcap_sha256="abc123hash",
        pcap_filename="sample.pcap",
        windows=[{"window_idx": 0, "features": {"syn_ratio": 0.8}}],
        findings=[{"technique_id": "T1046", "confidence": 0.85}],
        attack_progression={"current_stage": "RECONNAISSANCE", "stage_confidence": 0.85},
        forecast_points=[{"horizon_step": 1, "predicted_stage": "EXPLOITATION", "probability": 0.72}],
    )
    cg_dict = canonical_graph.to_dict()
    assert cg_dict["node_count"] > 0
    assert cg_dict["edge_count"] > 0
    types = {n["node_type"] for n in cg_dict["nodes"]}
    assert "PCAP" in types
    assert "WINDOW" in types
    assert "STAGE" in types
    assert "FORECAST" in types
