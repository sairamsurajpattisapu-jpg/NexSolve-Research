"""Deterministic Query Execution Engine across NexSolve Intelligence Stores."""
from __future__ import annotations
import time
from typing import Any, Mapping, Sequence

from nexsolve_core.graph.models import NodeType, Scope
from nexsolve_core.graph.graph import EvidenceGraph
from nexsolve_core.intelligence.query_model import (
    EpistemicScope,
    QueryMatch,
    QueryOperator,
    QueryPredicate,
    QueryRequest,
    QueryResult,
    QueryTarget,
    TemporalRelation,
)
from nexsolve_core.intelligence.query_registry import get_field_descriptor

class IntelligenceQueryEngine:
    """Deterministic Query Execution Engine across NexSolve Intelligence Stores."""

    def __init__(self, analysis_payload: Mapping[str, Any], graph: EvidenceGraph | None = None) -> None:
        self.payload = dict(analysis_payload)
        self.graph = graph

        self.entities: dict[str, Any] = self.payload.get('entity_profiles', {})
        self.investigations: dict[str, Any] = self.payload.get('entity_investigations', {})
        self.prioritized_threats: list[dict[str, Any]] = self.payload.get('prioritized_threats', [])
        self.findings: list[dict[str, Any]] = self.payload.get('detection', {}).get('findings', [])
        self.incident_story: dict[str, Any] | None = self.payload.get('incident_story')
        self.campaign_clusters: list[dict[str, Any]] = self.payload.get('campaign_clusters', [])
        self.correlations: list[dict[str, Any]] = self.payload.get('incident_correlations', [])
        self.decisions: list[dict[str, Any]] = self.payload.get('analyst_decisions', [])

        self._priority_map: dict[str, str] = {}
        self._risk_map: dict[str, float] = {}
        for pt in self.prioritized_threats:
            ent = pt.get('entity')
            if ent:
                self._priority_map[ent] = pt.get('priority', 'P3')
                self._risk_map[ent] = float(pt.get('composite_risk_score', 0.0))

        self._decision_map: dict[str, str] = {}
        for d in self.decisions:
            ent = d.get('target_entity')
            if ent:
                self._decision_map[ent] = d.get('decision_id')

    def execute_query(self, request: QueryRequest) -> QueryResult:
        start_t = time.perf_counter()
        uncertainties: list[str] = []

        matches: list[QueryMatch] = []
        if request.target == QueryTarget.ENTITY:
            matches = self._query_entities(request, uncertainties)
        elif request.target == QueryTarget.EVENT:
            matches = self._query_events(request, uncertainties)
        elif request.target == QueryTarget.PHASE:
            matches = self._query_phases(request, uncertainties)
        elif request.target == QueryTarget.EVIDENCE:
            matches = self._query_evidence(request, uncertainties)
        elif request.target == QueryTarget.CAMPAIGN:
            matches = self._query_campaigns(request, uncertainties)
        elif request.target == QueryTarget.GRAPH_NEIGHBOR:
            matches = self._query_graph_neighbors(request, uncertainties)
        elif request.target == QueryTarget.EXPLANATION:
            matches = self._query_explanation(request, uncertainties)
        else:
            uncertainties.append(f'Target {request.target.value} evaluated with fallback entity indexing.')
            matches = self._query_entities(request, uncertainties)

        if request.sort_by:
            def sort_key(m: QueryMatch):
                val = m.properties.get(request.sort_by, m.match_score)
                return (val is not None, val)
            matches.sort(key=sort_key, reverse=request.sort_descending)

        total = len(matches)
        paged_matches = matches[request.offset : request.offset + request.limit]
        truncated = total > (request.offset + request.limit)

        duration_ms = (time.perf_counter() - start_t) * 1000.0
        summary = f'Found {total} {request.target.value.lower()} match(es) across {len(request.predicates)} predicate(s).'

        return QueryResult(
            query_id=request.query_id,
            target=request.target,
            total_matches=total,
            matches=tuple(paged_matches),
            truncated=truncated,
            execution_duration_ms=duration_ms,
            query_summary=summary,
            uncertainties=tuple(uncertainties),
            applied_epistemic_scope=request.epistemic_scope.value,
        )

    def _eval_op(self, actual: Any, op: QueryOperator, target_val: Any, target_to: Any = None) -> bool:
        if actual is None:
            return op == QueryOperator.NOT_EXISTS
        if op == QueryOperator.EXISTS:
            return True
        if op == QueryOperator.NOT_EXISTS:
            return False
        if op == QueryOperator.EQUALS:
            return str(actual).lower() == str(target_val).lower()
        if op == QueryOperator.NOT_EQUALS:
            return str(actual).lower() != str(target_val).lower()
        if op == QueryOperator.CONTAINS:
            if isinstance(actual, (list, tuple, set)):
                return any(str(target_val).lower() in str(x).lower() for x in actual)
            return str(target_val).lower() in str(actual).lower()
        if op == QueryOperator.STARTS_WITH:
            return str(actual).lower().startswith(str(target_val).lower())
        if op == QueryOperator.ENDS_WITH:
            return str(actual).lower().endswith(str(target_val).lower())
        if op == QueryOperator.IN:
            if isinstance(target_val, (list, tuple, set)):
                return actual in target_val or str(actual) in [str(x) for x in target_val]
            return str(actual) in str(target_val)
        if op == QueryOperator.NOT_IN:
            if isinstance(target_val, (list, tuple, set)):
                return actual not in target_val and str(actual) not in [str(x) for x in target_val]
            return str(actual) not in str(target_val)
        try:
            act_num = float(actual)
            tgt_num = float(target_val)
            if op == QueryOperator.GREATER_THAN:
                return act_num > tgt_num
            if op == QueryOperator.GREATER_THAN_OR_EQUAL:
                return act_num >= tgt_num
            if op == QueryOperator.LESS_THAN:
                return act_num < tgt_num
            if op == QueryOperator.LESS_THAN_OR_EQUAL:
                return act_num <= tgt_num
            if op == QueryOperator.BETWEEN and target_to is not None:
                tgt_to_num = float(target_to)
                return act_num >= tgt_num and act_num <= tgt_to_num
        except (ValueError, TypeError):
            return False
        return False

    def _query_entities(self, request: QueryRequest, uncertainties: list[str]) -> list[QueryMatch]:
        matches: list[QueryMatch] = []
        if not self.entities:
            uncertainties.append('No active entity behavioral profiles recorded in capture.')
            return matches

        for ip, prof in self.entities.items():
            inv = self.investigations.get(ip, {})
            risk = self._risk_map.get(ip, 0.0)
            priority = self._priority_map.get(ip, 'P3')

            fanout = prof.get('peer_count', 0)
            ports_count = prof.get('targeted_ports_count', 0)
            failure_ratio = prof.get('failure_ratio', 0.0)
            pkt_vol = prof.get('packet_volume', 0)
            role = prof.get('role_summary', 'SUSPECT')
            beacon = prof.get('beaconing_detected', False)
            change = prof.get('volume_anomalies_detected', False)
            mitre_techs = prof.get('mitre_techniques', [])

            attack_state = 'BENIGN'
            if inv and 'attack_state' in inv:
                attack_state = inv['attack_state'].get('state', 'BENIGN')
            elif role in ('RECON_SOURCE', 'SUSPECT') and (ports_count >= 5 or fanout >= 5):
                attack_state = 'RECONNAISSANCE'

            matched_preds: list[str] = []
            passes = True
            for p in request.predicates:
                field_val = None
                if p.field == 'entity.ip':
                    field_val = ip
                elif p.field == 'entity.role':
                    field_val = role
                elif p.field == 'entity.attack_state':
                    field_val = attack_state
                elif p.field == 'entity.priority':
                    field_val = priority
                elif p.field == 'entity.risk_score':
                    field_val = risk
                elif p.field == 'entity.fanout':
                    field_val = fanout
                elif p.field == 'entity.port_diversity':
                    field_val = ports_count
                elif p.field == 'entity.failure_ratio':
                    field_val = failure_ratio
                elif p.field == 'entity.packet_volume':
                    field_val = pkt_vol
                elif p.field == 'entity.behavior_change':
                    field_val = change
                elif p.field == 'entity.beaconing':
                    field_val = beacon
                elif p.field == 'evidence.technique':
                    field_val = mitre_techs

                if self._eval_op(field_val, p.operator, p.value, p.value_to):
                    matched_preds.append(f'{p.field} {p.operator.value} {p.value}')
                else:
                    passes = False
                    break

            # Temporal filtering
            if passes and request.temporal and request.temporal.relation != TemporalRelation.ANY:
                fw = prof.get('first_seen_window', 0)
                lw = prof.get('last_seen_window', 0)
                if request.temporal.relation == TemporalRelation.DURING and request.temporal.window_range:
                    w1, w2 = request.temporal.window_range
                    if lw < w1 or fw > w2:
                        passes = False
                elif request.temporal.relation == TemporalRelation.BEFORE and request.temporal.reference_window is not None:
                    if fw >= request.temporal.reference_window:
                        passes = False
                elif request.temporal.relation == TemporalRelation.AFTER and request.temporal.reference_window is not None:
                    if lw <= request.temporal.reference_window:
                        passes = False

            if passes:
                supp_ev: list[str] = []
                if ports_count >= 5:
                    supp_ev.append(f'Targeted {ports_count} distinct destination ports')
                if fanout >= 5:
                    supp_ev.append(f'Contacted {fanout} distinct destination hosts')
                if failure_ratio > 0.5:
                    supp_ev.append(f'High connection rejection ratio ({failure_ratio*100:.0f}%)')
                if change:
                    supp_ev.append('Significant baseline volume/anomaly deviation observed')
                if beacon:
                    supp_ev.append('Periodic inter-arrival beaconing confirmed')
                for t in mitre_techs:
                    supp_ev.append(f'MITRE Technique: {t}')

                graph_node_ids: list[str] = [f'ip_{ip}']
                evidence_path: list[str] = [f'ENTITY:{ip}']
                if self.graph:
                    neighbors = self.graph.get_entity_neighbors(ip)
                    for n in neighbors[:5]:
                        graph_node_ids.append(n['id'])
                        evidence_path.append(f"{n['node_type']}:{n['label']}")

                next_q = None
                if inv and inv.get('next_investigation_questions'):
                    next_q = inv['next_investigation_questions'][0].get('question')

                m = QueryMatch(
                    match_id=f'match_ent_{ip}',
                    target=QueryTarget.ENTITY,
                    entity_key=ip,
                    label=f'Host {ip} ({role})',
                    primary_category=attack_state,
                    semantic_state='SUPPORTED_RECONNAISSANCE' if attack_state == 'RECONNAISSANCE' else 'ANOMALY',
                    epistemic_status='OBSERVED',
                    match_score=risk if risk > 0 else float(ports_count + fanout),
                    time_window=(prof.get('first_seen_window', 0), prof.get('last_seen_window', 0)),
                    matched_predicates=tuple(matched_preds),
                    supporting_evidence=tuple(supp_ev),
                    contradicting_evidence=(),
                    uncertainties=('Capture boundary: host activity observed until capture end.',) if prof.get('last_seen_window', 0) >= 9 else (),
                    graph_node_ids=tuple(graph_node_ids),
                    graph_evidence_path=tuple(evidence_path),
                    properties={
                        'fanout': fanout,
                        'port_diversity': ports_count,
                        'failure_ratio': failure_ratio,
                        'packet_volume': pkt_vol,
                        'risk_score': risk,
                        'priority': priority,
                        'role': role,
                        'mitre_techniques': mitre_techs,
                    },
                    analyst_decision_id=self._decision_map.get(ip),
                    next_question=next_q,
                )
                matches.append(m)

        return matches

    def _query_events(self, request: QueryRequest, uncertainties: list[str]) -> list[QueryMatch]:
        matches: list[QueryMatch] = []
        if not self.incident_story or not self.incident_story.get('events'):
            uncertainties.append('No reconstructed incident events available.')
            return matches

        events = self.incident_story.get('events', [])
        for ev in events:
            ev_type = ev.get('event_type', '')
            phase = ev.get('phase_type', '')
            entity = ev.get('primary_entity')
            w_idx = ev.get('window_index', 0)
            ev_id = ev.get('event_id', str(w_idx))

            matched_preds: list[str] = []
            passes = True
            for p in request.predicates:
                field_val = None
                if p.field == 'event.type':
                    field_val = ev_type
                elif p.field == 'event.phase':
                    field_val = phase
                elif p.field == 'entity.ip':
                    field_val = entity

                if self._eval_op(field_val, p.operator, p.value, p.value_to):
                    matched_preds.append(f'{p.field} {p.operator.value} {p.value}')
                else:
                    passes = False
                    break

            if passes and request.temporal and request.temporal.relation != TemporalRelation.ANY:
                if request.temporal.relation == TemporalRelation.DURING and request.temporal.window_range:
                    w1, w2 = request.temporal.window_range
                    if w_idx < w1 or w_idx > w2:
                        passes = False
                elif request.temporal.relation == TemporalRelation.BEFORE and request.temporal.reference_window is not None:
                    if w_idx >= request.temporal.reference_window:
                        passes = False
                elif request.temporal.relation == TemporalRelation.AFTER and request.temporal.reference_window is not None:
                    if w_idx <= request.temporal.reference_window:
                        passes = False

            if passes:
                m = QueryMatch(
                    match_id=f'match_ev_{ev_id}',
                    target=QueryTarget.EVENT,
                    entity_key=entity,
                    label=ev.get('headline', ev_type),
                    primary_category=phase,
                    semantic_state='OBSERVED_EVENT',
                    epistemic_status=ev.get('epistemic_status', 'OBSERVED'),
                    match_score=float(10.0 - w_idx),
                    time_window=(w_idx, w_idx),
                    matched_predicates=tuple(matched_preds),
                    supporting_evidence=tuple(ev.get('supporting_signals', ())),
                    contradicting_evidence=(),
                    uncertainties=tuple(ev.get('uncertainties', ())),
                    graph_node_ids=(f'event_{ev_id}',),
                    graph_evidence_path=(f'EVENT:{ev_type}', f'PHASE:{phase}'),
                    properties={
                        'event_type': ev_type,
                        'phase': phase,
                        'window_index': w_idx,
                        'summary': ev.get('detailed_narrative', ''),
                    },
                    analyst_decision_id=self._decision_map.get(entity),
                    next_question=None,
                )
                matches.append(m)

        return matches

    def _query_phases(self, request: QueryRequest, uncertainties: list[str]) -> list[QueryMatch]:
        matches: list[QueryMatch] = []
        if not self.incident_story or not self.incident_story.get('phases'):
            uncertainties.append('No reconstructed incident phases found.')
            return matches

        for ph in self.incident_story.get('phases', []):
            ph_type = ph.get('phase_type', '')
            ph_id = ph.get('phase_id', ph_type)
            matched_preds: list[str] = []
            passes = True
            for p in request.predicates:
                field_val = ph_type if p.field == 'phase.state' else None
                if self._eval_op(field_val, p.operator, p.value, p.value_to):
                    matched_preds.append(f'{p.field} {p.operator.value} {p.value}')
                else:
                    passes = False
                    break

            if passes:
                m = QueryMatch(
                    match_id=f'match_ph_{ph_id}',
                    target=QueryTarget.PHASE,
                    entity_key=None,
                    label=ph.get('name', ph_type),
                    primary_category=ph_type,
                    semantic_state='PHASE',
                    epistemic_status=ph.get('epistemic_status', 'OBSERVED'),
                    match_score=1.0,
                    time_window=tuple(ph.get('window_range', [0, 0])),
                    matched_predicates=tuple(matched_preds),
                    supporting_evidence=tuple(ph.get('key_events', ())),
                    contradicting_evidence=(),
                    uncertainties=(),
                    graph_node_ids=(f'phase_{ph_id}',),
                    graph_evidence_path=(f'PHASE:{ph_type}',),
                    properties={'phase_type': ph_type, 'narrative': ph.get('narrative', '')},
                )
                matches.append(m)

        return matches

    def _query_evidence(self, request: QueryRequest, uncertainties: list[str]) -> list[QueryMatch]:
        matches: list[QueryMatch] = []
        findings = self.findings
        if not findings:
            uncertainties.append('No heuristic or rule-based findings present.')
            return matches

        for f in findings:
            tech = f.get('mitre_technique_id') or f.get('rule_id') or ('T1046' if 'Scan' in f.get('attack_category', '') or 'Reconnaissance' in f.get('attack_category', '') else 'UNKNOWN')
            fid = f.get('finding_id', 'id')

            matched_preds: list[str] = []
            passes = True
            for p in request.predicates:
                field_val = None
                if p.field == 'evidence.technique':
                    field_val = tech
                elif p.field == 'evidence.source':
                    field_val = f.get('detection_method', 'HEURISTIC')
                elif p.field == 'entity.ip':
                    field_val = f.get('source_ip')

                if self._eval_op(field_val, p.operator, p.value, p.value_to):
                    matched_preds.append(f'{p.field} {p.operator.value} {p.value}')
                else:
                    passes = False
                    break

            if passes:
                m = QueryMatch(
                    match_id=f'match_evid_{fid}',
                    target=QueryTarget.EVIDENCE,
                    entity_key=f.get('source_ip'),
                    label=f.get('attack_category', 'Finding'),
                    primary_category=tech,
                    semantic_state='OBSERVED_EVIDENCE',
                    epistemic_status='OBSERVED',
                    match_score=float(f.get('risk_score', 50.0)),
                    time_window=(0, 9),
                    matched_predicates=tuple(matched_preds),
                    supporting_evidence=(f.get('recommendation', ''),),
                    contradicting_evidence=(),
                    uncertainties=(),
                    graph_node_ids=(f'finding_{fid}',),
                    graph_evidence_path=(f'FINDING:{tech}',),
                    properties={'severity': f.get('severity'), 'prediction': f.get('prediction')},
                )
                matches.append(m)

        return matches

    def _query_campaigns(self, request: QueryRequest, uncertainties: list[str]) -> list[QueryMatch]:
        matches: list[QueryMatch] = []
        clusters = self.campaign_clusters
        if not clusters:
            uncertainties.append('Capture analyzed in isolation: Single Incident Session (no independent cross-incident captures ingested).')
            return matches

        for cl in clusters:
            cid = cl.get('cluster_id', 'c1')
            m = QueryMatch(
                match_id=f'match_camp_{cid}',
                target=QueryTarget.CAMPAIGN,
                entity_key=None,
                label=cl.get('label', 'Campaign Cluster'),
                primary_category='Campaign',
                semantic_state='CAMPAIGN_CLUSTER',
                epistemic_status='SUPPORTED',
                match_score=1.0,
                time_window=(0, 0),
                matched_predicates=(),
                supporting_evidence=tuple(cl.get('shared_characteristics', ())),
                contradicting_evidence=tuple(cl.get('contradictions', ())),
                uncertainties=tuple([cl.get('uncertainty', '')]),
                graph_node_ids=(f'cluster_{cid}',),
                graph_evidence_path=(f"CLUSTER:{cl.get('label')}",),
                properties=cl,
            )
            matches.append(m)

        return matches

    def _query_graph_neighbors(self, request: QueryRequest, uncertainties: list[str]) -> list[QueryMatch]:
        matches: list[QueryMatch] = []
        entity = request.graph.entity_key
        if not entity:
            uncertainties.append('Graph neighbor search requires entity_key.')
            return matches

        if not self.graph:
            uncertainties.append('Evidence Intelligence Graph instance not mounted in query engine.')
            return matches

        neighbors = self.graph.get_entity_neighbors(entity)
        for n in neighbors:
            m = QueryMatch(
                match_id=f"match_neighbor_{n['id']}",
                target=QueryTarget.GRAPH_NEIGHBOR,
                entity_key=n['entity_key'],
                label=n['label'],
                primary_category=n['node_type'],
                semantic_state='GRAPH_NEIGHBOR',
                epistemic_status=n['scope'],
                match_score=1.0,
                time_window=(0, 9),
                matched_predicates=(f'neighbor_of={entity}',),
                supporting_evidence=(f"Direct edge connection to {entity}",),
                contradicting_evidence=(),
                uncertainties=(),
                graph_node_ids=(n['id'],),
                graph_evidence_path=(f"NEIGHBOR:{n['label']}",),
                properties=n['properties'],
            )
            matches.append(m)

        return matches

    def _query_explanation(self, request: QueryRequest, uncertainties: list[str]) -> list[QueryMatch]:
        matches: list[QueryMatch] = []
        entity = request.graph.entity_key
        if not entity:
            uncertainties.append('Explanation queries require target entity_key.')
            return matches

        prof = self.entities.get(entity, {})
        inv = self.investigations.get(entity, {})
        risk = self._risk_map.get(entity, 0.0)
        ports = prof.get('targeted_ports_count', 0)
        fanout = prof.get('peer_count', 0)
        role = prof.get('role_summary', 'SUSPECT')

        reasons = []
        reasons.append(f'Assigned role {role} with triage priority {self._priority_map.get(entity, "P3")}')
        if ports >= 5:
            reasons.append(f'Targeted {ports} destination ports across sweep windows')
        if fanout >= 5:
            reasons.append(f'Probed {fanout} internal subnet destination hosts')

        m = QueryMatch(
            match_id=f'match_why_{entity}',
            target=QueryTarget.EXPLANATION,
            entity_key=entity,
            label=f'Explanation: Why {entity} is prioritized ({role})',
            primary_category='EXPLANATION',
            semantic_state='EXPLAINABLE_ATTRIBUTION',
            epistemic_status='SUPPORTED',
            match_score=risk,
            time_window=(prof.get('first_seen_window', 0), prof.get('last_seen_window', 0)),
            matched_predicates=(f'entity={entity}',),
            supporting_evidence=tuple(reasons),
            contradicting_evidence=(),
            uncertainties=('Historical observation only: future rollouts strictly segregated.',),
            graph_node_ids=(f'ip_{entity}',),
            graph_evidence_path=(f'ENTITY:{entity}', 'REASONING_CHAIN'),
            properties={'risk_score': risk, 'ports': ports, 'fanout': fanout},
            analyst_decision_id=self._decision_map.get(entity),
            next_question='What was the service impact on targeted destination hosts?',
        )
        matches.append(m)
        return matches