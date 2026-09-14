"""Tests for the Evidence Intelligence Graph engine (nexsolve_core.graph).

Verifies:
1. Deterministic node and edge IDs based on SHA-256 hash.
2. In-memory property graph construction, query indices, and idempotence.
3. Strict separation between OBSERVED and FORECAST nodes/chains.
4. Edge validation (source/target must exist).
5. Chain extraction linking observed findings and multi-step forecasts.
6. Real PCAP execution on friday_10windows_slice.pcap via analyze_uploaded_capture.
7. Preservation of MODEL_SCHEMA_45 contract and zero fabricated features.
"""
from pathlib import Path
import pytest

from nexsolve_core.graph import (
    EdgeType,
    EvidenceChain,
    EvidenceGraph,
    GraphEdge,
    GraphNode,
    NodeType,
    RULES,
    Scope,
    build_evidence_intelligence_graph,
    deterministic_id,
)
from model_service.pcap_upload import analyze_uploaded_capture


REAL_PCAP_PATH = Path(r"C:\Users\saira\Downloads\friday_10windows_slice.pcap")


def test_deterministic_id_generation():
    """Deterministic IDs must produce stable, 12-char SHA-256 prefixes for identical inputs."""
    id1 = deterministic_id("finding", "PortScan", 1, "192.168.1.1", "10.0.0.1")
    id2 = deterministic_id("finding", "PortScan", 1, "192.168.1.1", "10.0.0.1")
    id3 = deterministic_id("finding", "PortScan", 2, "192.168.1.1", "10.0.0.1")

    assert id1 == id2
    assert id1 != id3
    assert id1.startswith("finding_")
    assert len(id1.split("_")[1]) == 12


def test_graph_node_and_edge_deduplication():
    """Graph must reject duplicate node and edge IDs idempotently."""
    g = EvidenceGraph()

    node1 = GraphNode(
        id="ip_1",
        node_type=NodeType.IP,
        entity_key="192.168.1.10",
        label="IP: 192.168.1.10",
        scope=Scope.OBSERVED,
    )
    node2 = GraphNode(
        id="port_80",
        node_type=NodeType.PORT,
        entity_key="80",
        label="Port: 80",
        scope=Scope.OBSERVED,
    )

    assert g.add_node(node1) is True
    assert g.add_node(node1) is False
    assert g.node_count == 1

    assert g.add_node(node2) is True
    assert g.node_count == 2

    edge = GraphEdge(
        id="edge_1",
        source_id="ip_1",
        target_id="port_80",
        edge_type=EdgeType.USES_PORT,
        scope=Scope.OBSERVED,
        reason="Entity connects to port 80",
        rule_id="R002",
    )

    assert g.add_edge(edge) is True
    assert g.add_edge(edge) is False
    assert g.edge_count == 1


def test_graph_edge_validation_missing_nodes():
    """Adding an edge with non-existent source or target must raise ValueError."""
    g = EvidenceGraph()
    node = GraphNode(
        id="ip_1",
        node_type=NodeType.IP,
        entity_key="192.168.1.10",
        label="IP: 192.168.1.10",
        scope=Scope.OBSERVED,
    )
    g.add_node(node)

    edge = GraphEdge(
        id="edge_bad",
        source_id="ip_1",
        target_id="non_existent",
        edge_type=EdgeType.COMMUNICATES_WITH,
        scope=Scope.OBSERVED,
        reason="Invalid target test",
    )
    with pytest.raises(ValueError, match="does not exist"):
        g.add_edge(edge)


def test_scope_isolation_observed_vs_forecast():
    """EvidenceGraph must maintain strict isolation between OBSERVED and FORECAST nodes."""
    g = EvidenceGraph()

    obs_node = GraphNode(
        id="obs_finding_1",
        node_type=NodeType.FINDING,
        entity_key="192.168.1.50",
        label="PortScan",
        scope=Scope.OBSERVED,
    )
    fc_node = GraphNode(
        id="fc_point_1",
        node_type=NodeType.FORECAST_SIGNAL,
        entity_key="network_forecast",
        label="Forecast K=1m",
        scope=Scope.FORECAST,
    )

    g.add_node(obs_node)
    g.add_node(fc_node)

    observed_nodes = g.get_nodes_by_scope(Scope.OBSERVED)
    forecast_nodes = g.get_nodes_by_scope(Scope.FORECAST)

    assert len(observed_nodes) == 1
    assert observed_nodes[0].id == "obs_finding_1"

    assert len(forecast_nodes) == 1
    assert forecast_nodes[0].id == "fc_point_1"


def test_precedence_and_supporting_evidence_queries():
    """Preceding and supporting queries must follow edge directions accurately."""
    g = EvidenceGraph()

    ip_node = GraphNode(id="ip_src", node_type=NodeType.IP, entity_key="10.0.0.1", label="10.0.0.1", scope=Scope.OBSERVED)
    sig_node = GraphNode(id="sig_proto", node_type=NodeType.PROTOCOL_SIGNAL, entity_key="10.0.0.1", label="SYN Flood", scope=Scope.OBSERVED)
    finding_node = GraphNode(id="find_scan", node_type=NodeType.FINDING, entity_key="10.0.0.1", label="PortScan Finding", scope=Scope.OBSERVED)
    fc_node = GraphNode(id="fc_k1", node_type=NodeType.FORECAST_SIGNAL, entity_key="net", label="Forecast K=1", scope=Scope.FORECAST)

    for n in (ip_node, sig_node, finding_node, fc_node):
        g.add_node(n)

    # sig_proto SUPPORTS find_scan
    g.add_edge(GraphEdge(
        id="e_supp",
        source_id="sig_proto",
        target_id="find_scan",
        edge_type=EdgeType.SUPPORTS,
        scope=Scope.OBSERVED,
        reason="Protocol signal supports finding",
        rule_id="R005",
    ))

    # find_scan TEMPORALLY_PRECEDES fc_k1
    g.add_edge(GraphEdge(
        id="e_prec",
        source_id="find_scan",
        target_id="fc_k1",
        edge_type=EdgeType.TEMPORALLY_PRECEDES,
        scope=Scope.FORECAST,
        reason="Observed finding strictly precedes forecast",
        rule_id="R008",
    ))

    supp = g.get_supporting_evidence("find_scan")
    assert len(supp) == 1
    assert supp[0].id == "sig_proto"

    prec = g.get_preceding_evidence("fc_k1")
    assert len(prec) == 1
    assert prec[0].id == "find_scan"

    # Build evidence chains
    chains = g.build_evidence_chains()
    assert len(chains) == 2  # One observed finding chain, one forecast chain
    obs_chain = [c for c in chains if c.scope == Scope.OBSERVED][0]
    assert "sig_proto" in obs_chain.node_ids
    assert "find_scan" in obs_chain.node_ids

    fc_chain = [c for c in chains if c.scope == Scope.FORECAST][0]
    assert "find_scan" in fc_chain.node_ids
    assert "fc_k1" in fc_chain.node_ids


def test_rule_registry_completeness():
    """Rule registry must define all canonical rules R001 through R012."""
    assert len(RULES) >= 10
    rule_ids = {r.rule_id for r in RULES.values()}
    for i in range(1, 13):
        expected_id = f"R{i:03d}"
        assert expected_id in rule_ids


@pytest.mark.skipif(not REAL_PCAP_PATH.exists(), reason="Real PCAP slice not present on host")
def test_evidence_graph_on_real_pcap_upload():
    """Full pipeline execution on friday_10windows_slice.pcap produces a complete Evidence Graph."""
    content = REAL_PCAP_PATH.read_bytes()
    res = analyze_uploaded_capture(REAL_PCAP_PATH.name, content)

    assert res["status"] == "completed"
    assert "evidence_graph" in res
    eg = res["evidence_graph"]
    assert eg is not None

    stats = eg["statistics"]
    assert stats["total_nodes"] > 50
    assert stats["total_edges"] > 50
    assert stats["total_chains"] > 0
    assert stats["observed_node_count"] > 0
    assert stats["forecast_node_count"] == 5  # Horizons K=1..5

    # Check node categories
    by_type = stats["nodes_by_type"]
    assert "IP" in by_type
    assert "PORT" in by_type
    assert "TCP_SESSION" in by_type
    assert "FORECAST_SIGNAL" in by_type

    # Verify chains are structured cleanly
    for chain in eg["chains"]:
        assert chain["chain_id"]
        assert chain["scope"] in ("OBSERVED", "FORECAST")
        assert len(chain["node_ids"]) > 0
        assert chain["explanation"]

    # Verify no mean_tcp_rtt in model contract
    compat = res["model_compatibility"]
    assert "mean_tcp_rtt" not in compat["available_features"]
    assert compat["active_schema"] == "MODEL_SCHEMA_45"