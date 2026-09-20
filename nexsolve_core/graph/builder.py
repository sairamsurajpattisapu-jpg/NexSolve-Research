"Deterministic builder connecting raw PCAP extractions, behavioral signals, protocol state, and forecasts into the EvidenceGraph."
from __future__ import annotations

from typing import Any, Mapping, Sequence

from nexsolve_core.graph.graph import EvidenceGraph
from nexsolve_core.graph.models import EdgeType, GraphEdge, GraphNode, NodeType, Scope, deterministic_id
from nexsolve_core.graph.rules import RULES


def build_evidence_intelligence_graph(
    flows: Sequence[Any] | None = None,
    tcp_sessions: Sequence[Any] | None = None,
    behavioral_report: Any = None,
    flow_statistics: Any = None,
    suricata_report: Any = None,
    observed_findings: Sequence[Mapping[str, Any]] | None = None,
    forecast_points: Sequence[Mapping[str, Any]] | None = None,
    attack_progression: Any = None,
    episodes: Sequence[Any] | None = None,
    change_signals: Sequence[Any] | None = None,
    campaigns: Sequence[Any] | None = None,
    patterns: Sequence[Any] | None = None,
    attack_kinematics: Mapping[str, Any] | None = None,
    baselines: Mapping[str, Any] | None = None,
) -> EvidenceGraph:
    "Build a deterministic in-memory property graph from all multi-modal telemetry."
    g = EvidenceGraph()

    observed_finding_node_ids: list[str] = []

    # 1. Ingest Observable Findings
    if observed_findings:
        for f in observed_findings:
            cat = str(f.get('attack_category', 'Anomaly')).strip()
            w_idx = f.get('window_index')
            src_ip = f.get('source_ip', '')
            dst_ip = f.get('destination_ip', '')
            fid = deterministic_id('finding', cat, w_idx, src_ip, dst_ip)
            mitre_id = 'T1046' if ('recon' in cat.lower() or 'scan' in cat.lower()) else ('T1498' if 'dos' in cat.lower() else None)

            f_node = GraphNode(
                id=fid,
                node_type=NodeType.FINDING,
                entity_key=dst_ip or src_ip or 'network',
                label=f"Finding: {cat}",
                scope=Scope.OBSERVED,
                timestamp=f.get('timestamp'),
                window_id=w_idx,
                properties={
                    'attack_category': cat,
                    'severity': f.get('severity', 'MEDIUM'),
                    'mitre_technique_id': mitre_id,
                },
                provenance={'source': 'ml_detection_engine', 'details': dict(f)},
            )
            g.add_node(f_node)
            observed_finding_node_ids.append(fid)

            # If MITRE mapping exists, add MITRE node and MAPS_TO_TECHNIQUE edge
            if mitre_id:
                m_node_id = deterministic_id('mitre', mitre_id)
                g.add_node(GraphNode(
                    id=m_node_id,
                    node_type=NodeType.MITRE_TECHNIQUE,
                    entity_key=mitre_id,
                    label=f"MITRE {mitre_id}",
                    scope=Scope.METADATA,
                    properties={'technique_id': mitre_id},
                ))
                g.add_edge(GraphEdge(
                    id=deterministic_id('edge', fid, m_node_id, EdgeType.MAPS_TO_TECHNIQUE.value),
                    source_id=fid,
                    target_id=m_node_id,
                    edge_type=EdgeType.MAPS_TO_TECHNIQUE,
                    scope=Scope.OBSERVED,
                    reason=f"Finding categorized as {cat} maps to technique {mitre_id}",
                    rule_id='R007',
                ))

    # 2. Ingest Representative Sample of Distinct Entities & Sessions
    if tcp_sessions:
        for s in tcp_sessions:
            src_ip = getattr(s, 'src_ip', None) or 'unknown'
            dst_ip = getattr(s, 'dst_ip', None) or 'unknown'
            dst_port = getattr(s, 'dst_port', None)
            proto_state = getattr(s, 'state', 'OTH')
            sid = getattr(s, 'session_id', None) or deterministic_id('session', src_ip, dst_ip, dst_port)

            src_node_id = deterministic_id('ip', src_ip)
            dst_node_id = deterministic_id('ip', dst_ip)
            g.add_node(GraphNode(
                id=src_node_id,
                node_type=NodeType.IP,
                entity_key=src_ip,
                label=f"IP: {src_ip}",
                scope=Scope.OBSERVED,
            ))
            g.add_node(GraphNode(
                id=dst_node_id,
                node_type=NodeType.IP,
                entity_key=dst_ip,
                label=f"IP: {dst_ip}",
                scope=Scope.OBSERVED,
            ))

            if dst_port is not None:
                port_node_id = deterministic_id('port', dst_port)
                g.add_node(GraphNode(
                    id=port_node_id,
                    node_type=NodeType.PORT,
                    entity_key=str(dst_port),
                    label=f"Port: {dst_port}",
                    scope=Scope.OBSERVED,
                ))

            sess_node_id = deterministic_id('sess', sid)
            g.add_node(GraphNode(
                id=sess_node_id,
                node_type=NodeType.TCP_SESSION,
                entity_key=f"{src_ip}->{dst_ip}:{dst_port}",
                label=f"Session: {proto_state}",
                scope=Scope.OBSERVED,
                properties={'proto_state': proto_state, 'packets': getattr(s, 'packet_count', 0)},
            ))

            g.add_edge(GraphEdge(
                id=deterministic_id('edge', src_node_id, sess_node_id, EdgeType.COMMUNICATES_WITH.value),
                source_id=src_node_id,
                target_id=sess_node_id,
                edge_type=EdgeType.COMMUNICATES_WITH,
                scope=Scope.OBSERVED,
                reason="Source IP initiated TCP conversation",
                rule_id='R001',
            ))

            if dst_port is not None:
                port_node_id = deterministic_id('port', dst_port)
                g.add_edge(GraphEdge(
                    id=deterministic_id('edge', sess_node_id, port_node_id, EdgeType.USES_PORT.value),
                    source_id=sess_node_id,
                    target_id=port_node_id,
                    edge_type=EdgeType.USES_PORT,
                    scope=Scope.OBSERVED,
                    reason="TCP session targets destination port",
                    rule_id='R002',
                ))

            # Explicit link from session to destination IP
            g.add_edge(GraphEdge(
                id=deterministic_id('edge', sess_node_id, dst_node_id, EdgeType.TARGETS.value),
                source_id=sess_node_id,
                target_id=dst_node_id,
                edge_type=EdgeType.TARGETS,
                scope=Scope.OBSERVED,
                reason="TCP session targets destination IP host",
                rule_id='R001',
            ))

    # 3. Ingest Behavioral & Periodicity Signals (RITA-inspired)
    if behavioral_report and hasattr(behavioral_report, 'periodicity_summary'):
        psum = behavioral_report.periodicity_summary
        if psum and hasattr(psum, 'groups'):
            for grp in psum.groups:
                src_ip = getattr(grp, 'src_ip', '')
                dst_ip = getattr(grp, 'dst_ip', '')
                cls_val = getattr(getattr(grp, 'classification', None), 'value', str(getattr(grp, 'classification', 'IRREGULAR')))

                if cls_val in ('PERIODIC', 'HIGHLY_PERIODIC', 'WEAKLY_PERIODIC'):
                    sig_id = deterministic_id('sig_rit', src_ip, dst_ip, cls_val)
                    g.add_node(GraphNode(
                        id=sig_id,
                        node_type=NodeType.BEHAVIOR_SIGNAL,
                        entity_key=f"{src_ip}->{dst_ip}",
                        label=f"Periodicity: {cls_val}",
                        scope=Scope.OBSERVED,
                        properties={
                            'regularity_score': getattr(grp, 'regularity_score', 0.0),
                            'classification': cls_val,
                            'median_interval_seconds': getattr(grp, 'median_interval_seconds', None),
                        },
                        provenance={'source': 'rita_periodicity_analyzer', 'method': 'bowley_skewness_mad'},
                    ))

                    src_node_id = deterministic_id('ip', src_ip)
                    if g.get_node(src_node_id):
                        g.add_edge(GraphEdge(
                            id=deterministic_id('edge', src_node_id, sig_id, EdgeType.INDICATES.value),
                            source_id=src_node_id,
                            target_id=sig_id,
                            edge_type=EdgeType.INDICATES,
                            scope=Scope.OBSERVED,
                            reason=f"Host exhibits {cls_val} interval regularity",
                            rule_id='R006',
                        ))

    # 4. Ingest Episodes & Change Signals
    if episodes:
        for ep in episodes:
            ep_node_id = deterministic_id('ep_node', ep.episode_id)
            g.add_node(GraphNode(
                id=ep_node_id,
                node_type=NodeType.EPISODE,
                entity_key=ep.primary_entity,
                label=ep.title,
                scope=Scope.OBSERVED,
                properties={
                    'start_window': ep.start_window,
                    'end_window': ep.end_window,
                    'severity': ep.severity.value,
                    'duration_seconds': ep.duration_seconds,
                },
                provenance=ep.provenance,
            ))
            for fid in observed_finding_node_ids:
                edge_id = deterministic_id('edge', fid, ep_node_id, EdgeType.PART_OF_EPISODE.value)
                g.add_edge(GraphEdge(
                    id=edge_id,
                    source_id=fid,
                    target_id=ep_node_id,
                    edge_type=EdgeType.PART_OF_EPISODE,
                    scope=Scope.OBSERVED,
                    reason="Finding belongs to temporal behavioral episode",
                    rule_id='R011',
                ))

    if change_signals:
        for cs in change_signals:
            cs_node_id = deterministic_id('cs_node', cs.change_id)
            g.add_node(GraphNode(
                id=cs_node_id,
                node_type=NodeType.CHANGE_SIGNAL,
                entity_key=cs.entity,
                label=f"Change: {cs.change_type.value}",
                scope=Scope.OBSERVED,
                properties={
                    'magnitude': cs.magnitude,
                    'window_before': cs.window_before,
                    'window_after': cs.window_after,
                },
                provenance=cs.provenance,
            ))
            ip_node_id = deterministic_id('ip', cs.entity)
            if g.get_node(ip_node_id):
                edge_id = deterministic_id('edge', ip_node_id, cs_node_id, EdgeType.MANIFESTS_CHANGE.value)
                g.add_edge(GraphEdge(
                    id=edge_id,
                    source_id=ip_node_id,
                    target_id=cs_node_id,
                    edge_type=EdgeType.MANIFESTS_CHANGE,
                    scope=Scope.OBSERVED,
                    reason=cs.description,
                    rule_id='R012',
                ))

    # 5. Ingest Campaigns
    if campaigns:
        for cmp in campaigns:
            cmp_node_id = deterministic_id('cmp_node', cmp.campaign_id)
            g.add_node(GraphNode(
                id=cmp_node_id,
                node_type=NodeType.CAMPAIGN,
                entity_key=cmp.primary_entities[0] if cmp.primary_entities else 'network',
                label=cmp.title,
                scope=Scope.OBSERVED,
                properties={
                    'severity': cmp.severity,
                    'start_window': cmp.start_window,
                    'end_window': cmp.end_window,
                },
                provenance=cmp.provenance,
            ))
            for ep_id in cmp.constituent_episodes:
                ep_node_id = deterministic_id('ep_node', ep_id)
                if g.get_node(ep_node_id):
                    edge_id = deterministic_id('edge', ep_node_id, cmp_node_id, EdgeType.PART_OF_CAMPAIGN.value)
                    g.add_edge(GraphEdge(
                        id=edge_id,
                        source_id=ep_node_id,
                        target_id=cmp_node_id,
                        edge_type=EdgeType.PART_OF_CAMPAIGN,
                        scope=Scope.OBSERVED,
                        reason="Behavioral episode is part of attack campaign",
                        rule_id='R013',
                    ))

    # 6. Ingest Attack Patterns
    if patterns:
        for pat in patterns:
            pat_node_id = deterministic_id('pat_node', pat.pattern_id)
            g.add_node(GraphNode(
                id=pat_node_id,
                node_type=NodeType.PATTERN,
                entity_key=pat.primary_entities[0] if pat.primary_entities else 'network',
                label=f"Pattern: {pat.pattern_type.value}",
                scope=Scope.OBSERVED,
                properties={
                    'severity': pat.severity,
                    'pattern_type': pat.pattern_type.value,
                },
                provenance=pat.provenance,
            ))
            for ent in pat.primary_entities:
                ent_node_id = deterministic_id('ip', ent)
                if g.get_node(ent_node_id):
                    edge_id = deterministic_id('edge', ent_node_id, pat_node_id, EdgeType.PARTICIPATES_IN_PATTERN.value)
                    g.add_edge(GraphEdge(
                        id=edge_id,
                        source_id=ent_node_id,
                        target_id=pat_node_id,
                        edge_type=EdgeType.PARTICIPATES_IN_PATTERN,
                        scope=Scope.OBSERVED,
                        reason=pat.explanation,
                        rule_id='R015',
                    ))

    # 7. Ingest Baseline Deviations
    if baselines:
        for ent, b_prof in baselines.items():
            for dev in getattr(b_prof, "deviations", ()):
                dev_node_id = deterministic_id('dev_node', dev.deviation_id)
                g.add_node(GraphNode(
                    id=dev_node_id,
                    node_type=NodeType.BASELINE_CHANGE,
                    entity_key=ent,
                    label=f"Deviation: {dev.deviation_type.value}",
                    scope=Scope.OBSERVED,
                    properties={
                        'metric': dev.metric_name,
                        'z_score': dev.z_score,
                    },
                    provenance=dev.provenance,
                ))
                ip_node_id = deterministic_id('ip', ent)
                if g.get_node(ip_node_id):
                    edge_id = deterministic_id('edge', ip_node_id, dev_node_id, EdgeType.DEVIATES_FROM.value)
                    g.add_edge(GraphEdge(
                        id=edge_id,
                        source_id=ip_node_id,
                        target_id=dev_node_id,
                        edge_type=EdgeType.DEVIATES_FROM,
                        scope=Scope.OBSERVED,
                        reason=dev.explanation,
                        rule_id='R016',
                    ))

    # 8. Ingest Kinematic Transitions
    if attack_kinematics:
        for ent, traj in attack_kinematics.items():
            for trans in getattr(traj, "transitions", ()):
                # Link from_state to to_state
                s1_id = deterministic_id('kin_st', ent, trans.window_before, trans.from_state.value)
                s2_id = deterministic_id('kin_st', ent, trans.window_after, trans.to_state.value)
                g.add_node(GraphNode(
                    id=s1_id,
                    node_type=NodeType.ATTACK_STATE,
                    entity_key=ent,
                    label=f"State: {trans.from_state.value}",
                    scope=Scope.OBSERVED,
                ))
                g.add_node(GraphNode(
                    id=s2_id,
                    node_type=NodeType.ATTACK_STATE,
                    entity_key=ent,
                    label=f"State: {trans.to_state.value}",
                    scope=Scope.OBSERVED,
                ))
                edge_id = deterministic_id('edge', s1_id, s2_id, EdgeType.TRANSITIONS_TO.value)
                g.add_edge(GraphEdge(
                    id=edge_id,
                    source_id=s1_id,
                    target_id=s2_id,
                    edge_type=EdgeType.TRANSITIONS_TO,
                    scope=Scope.OBSERVED,
                    reason=trans.explanation,
                    rule_id='R014',
                ))

                # Explicitly link entity IP to the attack state
                ip_node_id = deterministic_id('ip', ent)
                if g.get_node(ip_node_id):
                    g.add_edge(GraphEdge(
                        id=deterministic_id('edge', ip_node_id, s2_id, EdgeType.EXHIBITS_STATE.value),
                        source_id=ip_node_id,
                        target_id=s2_id,
                        edge_type=EdgeType.EXHIBITS_STATE,
                        scope=Scope.OBSERVED,
                        reason=f"Entity {ent} exhibits attack state {trans.to_state.value}",
                        rule_id='R017',
                    ))

    # 9. Ingest Forecast Signals (Strictly FORECAST scope)
    if forecast_points:
        for pt in forecast_points:
            h = pt.get('horizon', 1)
            prob = pt.get('attackProbability')
            fid = deterministic_id('fc', h)
            g.add_node(GraphNode(
                id=fid,
                node_type=NodeType.FORECAST_SIGNAL,
                entity_key='network_forecast',
                label=f"Forecast K={h}m",
                scope=Scope.FORECAST,
                properties={
                    'horizon_minutes': h,
                    'attack_probability': prob,
                    'confidence': pt.get('confidence'),
                },
                provenance={'model': 'models/nexsolve_world_model_45'},
            ))

            for obs_fid in observed_finding_node_ids:
                edge_id = deterministic_id('edge', obs_fid, fid, EdgeType.TEMPORALLY_PRECEDES.value)
                g.add_edge(GraphEdge(
                    id=edge_id,
                    source_id=obs_fid,
                    target_id=fid,
                    edge_type=EdgeType.TEMPORALLY_PRECEDES,
                    scope=Scope.FORECAST,
                    reason=f"Observed finding precedes forecast horizon K={h}m",
                    rule_id='R008',
                ))

    # 10. Build High-Level Evidence Chains
    g.build_evidence_chains()
    return g


