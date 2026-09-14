import { useState, useMemo } from 'react'
import type {
  QueryRequestPayload,
  QueryResultPayload,
  QueryMatchPayload,
  HuntTemplatePayload,
  FieldDescriptorPayload,
  QueryPredicatePayload,
  QueryTargetType,
  EpistemicScopeType,
} from '../../types/api'
import { Panel } from '../Ui'
import { api } from '../../services/api'
import {
  Search,
  Crosshair,
  Sliders,
  Plus,
  Trash2,
  Play,
  RotateCcw,
  ArrowRight,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Sparkles,
} from 'lucide-react'

interface ThreatHuntingWorkspaceProps {
  analysisId?: string
  templates?: HuntTemplatePayload[] | null
  predicates?: FieldDescriptorPayload[] | null
  initialQuery?: QueryRequestPayload
  initialResults?: QueryResultPayload | null
  onSelectEntity?: (entityIp: string) => void
  onSelectDecision?: (decisionId: string) => void
}

const DEFAULT_TEMPLATES: HuntTemplatePayload[] = [
  {
    template_id: 'hunt_recon_fanout',
    name: 'High Destination-Port & Host Fan-Out',
    category: 'Reconnaissance',
    description: 'Identify network entities engaging in horizontal host scans or high destination port sweeping.',
    target: 'ENTITY',
    mitre_techniques: ['T1046'],
    default_predicates: [{ field: 'entity.port_diversity', operator: '>=', value: 5 }],
    suggested_epistemic_scope: 'OBSERVED_ONLY',
  },
  {
    template_id: 'hunt_recon_state',
    name: 'Confirmed Reconnaissance Entities',
    category: 'Reconnaissance',
    description: 'Find entities with empirically supported or inferred RECONNAISSANCE attack states.',
    target: 'ENTITY',
    mitre_techniques: ['T1595', 'T1046'],
    default_predicates: [{ field: 'entity.attack_state', operator: '=', value: 'RECONNAISSANCE' }],
    suggested_epistemic_scope: 'OBSERVED_ONLY',
  },
  {
    template_id: 'hunt_behavior_change',
    name: 'Significant Behavioral Changes',
    category: 'Behavioral Shifts',
    description: 'Locate entities with sudden velocity, volume, or structural connection shifts.',
    target: 'ENTITY',
    mitre_techniques: [],
    default_predicates: [{ field: 'entity.behavior_change', operator: 'EXISTS' }],
    suggested_epistemic_scope: 'OBSERVED_ONLY',
  },
  {
    template_id: 'hunt_beaconing_c2',
    name: 'Periodic Beaconing & Low-Jitter C2',
    category: 'Command & Control',
    description: 'Search for entities exhibiting low-jitter periodic communications (RITA-style score >= 0.75).',
    target: 'ENTITY',
    mitre_techniques: ['T1071'],
    default_predicates: [{ field: 'entity.beaconing', operator: '>=', value: 0.75 }],
    suggested_epistemic_scope: 'OBSERVED_ONLY',
  },
  {
    template_id: 'hunt_t1046_evidence',
    name: 'Network Service Scanning (T1046)',
    category: 'Reconnaissance',
    description: 'Extract all evidence nodes specifically grounded in MITRE technique T1046.',
    target: 'EVIDENCE',
    mitre_techniques: ['T1046'],
    default_predicates: [{ field: 'evidence.technique', operator: '=', value: 'T1046' }],
    suggested_epistemic_scope: 'OBSERVED_ONLY',
  },
  {
    template_id: 'hunt_handshake_failures',
    name: 'High Handshake Failure Concentration',
    category: 'Anomalies',
    description: 'Isolate hosts where TCP handshake failure ratio exceeds 60%, characteristic of scanning or dead targets.',
    target: 'ENTITY',
    mitre_techniques: ['T1046'],
    default_predicates: [{ field: 'entity.failure_ratio', operator: '>=', value: 0.6 }],
    suggested_epistemic_scope: 'OBSERVED_ONLY',
  },
]

export function ThreatHuntingWorkspace({
  analysisId,
  templates,
  predicates: _propPredicates,
  initialQuery,
  initialResults,
  onSelectEntity,
  onSelectDecision,
}: ThreatHuntingWorkspaceProps) {
  const effectiveTemplates = templates && templates.length > 0 ? templates : DEFAULT_TEMPLATES

  // Query state
  const [selectedTarget, setSelectedTarget] = useState<QueryTargetType>(initialQuery?.target || 'ENTITY')
  const [epistemicScope, setEpistemicScope] = useState<EpistemicScopeType>(
    initialQuery?.epistemic_scope || 'OBSERVED_ONLY'
  )
  const [predicates, setPredicates] = useState<QueryPredicatePayload[]>(
    initialQuery?.predicates || [{ field: 'entity.port_diversity', operator: '>=', value: 5 }]
  )
  const [searchFilter, setSearchFilter] = useState<string>('')
  const [activeTemplateId, setActiveTemplateId] = useState<string | null>(null)

  // Execution state
  const [running, setRunning] = useState<boolean>(false)
  const [queryResult, setQueryResult] = useState<QueryResultPayload | null>(initialResults || null)
  const [selectedMatch, setSelectedMatch] = useState<QueryMatchPayload | null>(
    initialResults?.matches && initialResults.matches.length > 0 ? initialResults.matches[0] : null
  )
  const [error, setError] = useState<string | null>(null)
  const [showBuilder, setShowBuilder] = useState<boolean>(true)

  const handleApplyTemplate = (tpl: HuntTemplatePayload) => {
    setActiveTemplateId(tpl.template_id)
    setSelectedTarget(tpl.target)
    setEpistemicScope(tpl.suggested_epistemic_scope || 'OBSERVED_ONLY')
    setPredicates(tpl.default_predicates.length > 0 ? [...tpl.default_predicates] : [])
    setError(null)
    executeHunt({
      target: tpl.target,
      epistemic_scope: tpl.suggested_epistemic_scope || 'OBSERVED_ONLY',
      predicates: tpl.default_predicates,
      analysis_id: analysisId,
    })
  }

  const handleAddPredicate = () => {
    setPredicates((prev) => [
      ...prev,
      { field: 'entity.port_diversity', operator: '>=', value: 5 },
    ])
  }

  const handleRemovePredicate = (idx: number) => {
    setPredicates((prev) => prev.filter((_, i) => i !== idx))
  }

  const handleUpdatePredicate = (idx: number, patch: Partial<QueryPredicatePayload>) => {
    setPredicates((prev) =>
      prev.map((p, i) => (i === idx ? { ...p, ...patch } : p))
    )
  }

  const executeHunt = async (overrideReq?: Partial<QueryRequestPayload>) => {
    setRunning(true)
    setError(null)
    try {
      const reqPayload: QueryRequestPayload = {
        query_id: `q_hunt_${Date.now()}`,
        analysis_id: analysisId,
        target: overrideReq?.target || selectedTarget,
        epistemic_scope: overrideReq?.epistemic_scope || epistemicScope,
        predicates: overrideReq?.predicates || predicates,
        limit: 100,
        explain: true,
      }
      const res = await api.runIntelligenceQuery(reqPayload)
      setQueryResult(res)
      if (res.matches && res.matches.length > 0) {
        setSelectedMatch(res.matches[0])
      } else {
        setSelectedMatch(null)
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Hunt query execution failed.'
      setError(msg)
    } finally {
      setRunning(false)
    }
  }

  const filteredMatches = useMemo(() => {
    if (!queryResult?.matches) return []
    if (!searchFilter.trim()) return queryResult.matches
    const q = searchFilter.toLowerCase()
    return queryResult.matches.filter(
      (m) =>
        m.label.toLowerCase().includes(q) ||
        (m.entity_key && m.entity_key.toLowerCase().includes(q)) ||
        m.semantic_state.toLowerCase().includes(q) ||
        m.primary_category.toLowerCase().includes(q) ||
        m.matched_predicates.some((p) => p.toLowerCase().includes(q))
    )
  }, [queryResult, searchFilter])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* 1. Header Banner */}
      <Panel className="threat-hunting-header" style={{ padding: '20px 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
              <Crosshair size={18} color="var(--accent)" />
              <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
                Deterministic Query Engine
              </span>
              <span
                style={{
                  background: 'var(--accent-muted)',
                  color: 'var(--accent)',
                  border: '1px solid var(--accent)',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontSize: '10px',
                  fontFamily: 'var(--mono)',
                  fontWeight: 700,
                }}
              >
                PROD INTELLIGENCE
              </span>
            </div>
            <h2 style={{ margin: 0, fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
              Threat Hunting & Multi-Modal Intelligence Query
            </h2>
            <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-muted)' }}>
              Query entities, events, evidence chains, and graph traversals across all captured network states with strict epistemic boundaries.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              className="btn btn-secondary btn-sm"
              onClick={() => setShowBuilder(!showBuilder)}
              style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Sliders size={14} />
              <span>{showBuilder ? 'Collapse Builder' : 'Query Builder'}</span>
              {showBuilder ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
            </button>
            <button
              className="btn btn-primary btn-sm"
              onClick={() => executeHunt()}
              disabled={running}
              style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Play size={14} />
              <span>{running ? 'Executing...' : 'Run Query'}</span>
            </button>
          </div>
        </div>

        {/* 2. Reusable Hunt Templates Strip */}
        <div style={{ marginTop: '16px', borderTop: '1px solid var(--border)', paddingTop: '12px' }}>
          <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '8px', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Sparkles size={13} color="var(--accent)" />
            <span>PRE-BUILT HUNT PACKS:</span>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
            {effectiveTemplates.map((tpl) => {
              const active = activeTemplateId === tpl.template_id
              return (
                <button
                  key={tpl.template_id}
                  onClick={() => handleApplyTemplate(tpl)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '5px 10px',
                    borderRadius: '6px',
                    border: `1px solid ${active ? 'var(--accent)' : 'var(--border)'}`,
                    background: active ? 'var(--accent-muted)' : 'rgba(255, 255, 255, 0.03)',
                    color: active ? 'var(--accent)' : 'var(--text-primary)',
                    fontSize: '11px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                  title={tpl.description}
                >
                  <Crosshair size={12} />
                  <span>{tpl.name}</span>
                </button>
              )
            })}
          </div>
        </div>
      </Panel>

      {/* 3. Structured Query Builder */}
      {showBuilder && (
        <Panel style={{ padding: '16px 20px', background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '16px', alignItems: 'center', marginBottom: '16px' }}>
            {/* Target Selector */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>QUERY TARGET</label>
              <select
                value={selectedTarget}
                onChange={(e) => setSelectedTarget(e.target.value as QueryTargetType)}
                style={{
                  background: 'var(--input-bg)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                  padding: '6px 10px',
                  fontSize: '12px',
                  fontFamily: 'var(--mono)',
                }}
              >
                <option value="ENTITY">ENTITY (Host / IP)</option>
                <option value="EVENT">EVENT (Chronology / Packet)</option>
                <option value="EVIDENCE">EVIDENCE (Findings / MITRE)</option>
                <option value="PHASE">PHASE (Attack Progression)</option>
                <option value="CAMPAIGN">CAMPAIGN (Cluster)</option>
                <option value="GRAPH_NEIGHBOR">GRAPH_NEIGHBOR (Traversals)</option>
                <option value="EXPLANATION">EXPLANATION (Attribution)</option>
              </select>
            </div>

            {/* Epistemic Scope */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: 600 }}>EPISTEMIC SCOPE</label>
              <select
                value={epistemicScope}
                onChange={(e) => setEpistemicScope(e.target.value as EpistemicScopeType)}
                style={{
                  background: 'var(--input-bg)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                  padding: '6px 10px',
                  fontSize: '12px',
                  fontFamily: 'var(--mono)',
                }}
              >
                <option value="OBSERVED_ONLY">OBSERVED_ONLY (Ground Truth)</option>
                <option value="INFERRED_AND_SUPPORTED">INFERRED_AND_SUPPORTED</option>
                <option value="FORECAST_ONLY">FORECAST_ONLY</option>
                <option value="ALL">ALL (Full Fusion)</option>
              </select>
            </div>

            {/* Reset / Actions */}
            <div style={{ marginLeft: 'auto', display: 'flex', gap: '8px', alignItems: 'flex-end', paddingTop: '16px' }}>
              <button
                className="btn btn-secondary btn-sm"
                onClick={handleAddPredicate}
                style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}
              >
                <Plus size={13} />
                <span>Add Filter</span>
              </button>
              <button
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  setPredicates([])
                  setActiveTemplateId(null)
                }}
                style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}
              >
                <RotateCcw size={13} />
                <span>Clear</span>
              </button>
            </div>
          </div>

          {/* Predicate Rows */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {predicates.length === 0 ? (
              <div style={{ padding: '12px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px', border: '1px dashed var(--border)', borderRadius: '4px' }}>
                No active filter predicates. Query will return all {selectedTarget} records matching epistemic scope.
              </div>
            ) : (
              predicates.map((p, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                    background: 'var(--bg-surface)',
                    padding: '8px 12px',
                    borderRadius: '4px',
                    border: '1px solid var(--border)',
                  }}
                >
                  <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', width: '20px' }}>
                    #{idx + 1}
                  </span>
                  {/* Field */}
                  <input
                    type="text"
                    value={p.field}
                    onChange={(e) => handleUpdatePredicate(idx, { field: e.target.value })}
                    placeholder="e.g. entity.port_diversity"
                    style={{
                      background: 'var(--input-bg)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      padding: '4px 8px',
                      fontSize: '12px',
                      fontFamily: 'var(--mono)',
                      flex: '1 1 200px',
                    }}
                  />
                  {/* Operator */}
                  <select
                    value={p.operator}
                    onChange={(e) => handleUpdatePredicate(idx, { operator: e.target.value as any })}
                    style={{
                      background: 'var(--input-bg)',
                      color: 'var(--text-primary)',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      padding: '4px 8px',
                      fontSize: '12px',
                      fontFamily: 'var(--mono)',
                      width: '120px',
                    }}
                  >
                    <option value="=">=</option>
                    <option value="!=">!=</option>
                    <option value=">">&gt;</option>
                    <option value=">=">&gt;=</option>
                    <option value="<">&lt;</option>
                    <option value="<=">&lt;=</option>
                    <option value="CONTAINS">CONTAINS</option>
                    <option value="EXISTS">EXISTS</option>
                    <option value="NOT_EXISTS">NOT_EXISTS</option>
                  </select>
                  {/* Value */}
                  {!['EXISTS', 'NOT_EXISTS'].includes(p.operator) && (
                    <input
                      type="text"
                      value={p.value !== undefined ? String(p.value) : ''}
                      onChange={(e) => handleUpdatePredicate(idx, { value: e.target.value })}
                      placeholder="Value"
                      style={{
                        background: 'var(--input-bg)',
                        color: 'var(--text-primary)',
                        border: '1px solid var(--border)',
                        borderRadius: '4px',
                        padding: '4px 8px',
                        fontSize: '12px',
                        fontFamily: 'var(--mono)',
                        flex: '1 1 140px',
                      }}
                    />
                  )}
                  {/* Delete button */}
                  <button
                    onClick={() => handleRemovePredicate(idx)}
                    style={{
                      background: 'transparent',
                      border: 'none',
                      color: 'var(--text-muted)',
                      cursor: 'pointer',
                      padding: '4px',
                    }}
                    title="Remove Filter"
                  >
                    <Trash2 size={14} />
                  </button>
                </div>
              ))
            )}
          </div>
        </Panel>
      )}

      {/* 4. Execution / Error Banner */}
      {error && (
        <div
          style={{
            padding: '12px 16px',
            background: 'rgba(239, 68, 68, 0.12)',
            borderLeft: '4px solid var(--danger)',
            borderRadius: '4px',
            fontSize: '12px',
            color: 'var(--danger)',
          }}
        >
          {error}
        </div>
      )}

      {/* 5. Results Section */}
      {queryResult && (
        <div style={{ display: 'grid', gridTemplateColumns: selectedMatch ? '1.2fr 1fr' : '1fr', gap: '16px' }}>
          {/* Matches List */}
          <Panel style={{ padding: '16px 20px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
              <div>
                <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
                  {queryResult.applied_epistemic_scope}
                </span>
                <h3 style={{ margin: '2px 0 0 0', fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Matches ({queryResult.total_matches})
                </h3>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div style={{ position: 'relative', width: '160px' }}>
                  <Search size={13} style={{ position: 'absolute', left: '8px', top: '7px', color: 'var(--text-muted)' }} />
                  <input
                    type="text"
                    value={searchFilter}
                    onChange={(e) => setSearchFilter(e.target.value)}
                    placeholder="Filter results..."
                    style={{
                      width: '100%',
                      padding: '4px 8px 4px 26px',
                      background: 'var(--input-bg)',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      fontSize: '11px',
                      color: 'var(--text-primary)',
                    }}
                  />
                </div>
                <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                  {queryResult.execution_duration_ms} ms
                </span>
              </div>
            </div>

            {/* Summary & Uncertainties */}
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '0 0 12px 0' }}>
              {queryResult.query_summary}
            </p>

            {queryResult.uncertainties && queryResult.uncertainties.length > 0 && (
              <div style={{ marginBottom: '12px', padding: '8px 10px', background: 'var(--surface-ground)', borderRadius: '4px', borderLeft: '3px solid var(--warning)' }}>
                {queryResult.uncertainties.map((u, i) => (
                  <div key={i} style={{ fontSize: '11px', color: 'var(--warning)', fontFamily: 'var(--mono)' }}>
                    &bull; {u}
                  </div>
                ))}
              </div>
            )}

            {filteredMatches.length === 0 ? (
              <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '12px' }}>
                No matches found satisfying query criteria.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '500px', overflowY: 'auto' }}>
                {filteredMatches.map((m) => {
                  const isSelected = selectedMatch?.match_id === m.match_id
                  return (
                    <div
                      key={m.match_id}
                      onClick={() => setSelectedMatch(m)}
                      style={{
                        padding: '10px 12px',
                        borderRadius: '6px',
                        background: isSelected ? 'var(--accent-muted)' : 'var(--bg-secondary)',
                        border: `1px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}`,
                        cursor: 'pointer',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '2px' }}>
                          <span style={{ fontSize: '12px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                            {m.label}
                          </span>
                          <span
                            style={{
                              fontSize: '10px',
                              fontFamily: 'var(--mono)',
                              padding: '1px 6px',
                              borderRadius: '3px',
                              background: 'rgba(255, 255, 255, 0.06)',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            {m.semantic_state}
                          </span>
                          <span
                            style={{
                              fontSize: '10px',
                              fontFamily: 'var(--mono)',
                              padding: '1px 6px',
                              borderRadius: '3px',
                              background: m.epistemic_status === 'OBSERVED' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                              color: m.epistemic_status === 'OBSERVED' ? 'var(--success)' : 'var(--warning)',
                            }}
                          >
                            {m.epistemic_status}
                          </span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          {m.primary_category} &middot; Predicates: {m.matched_predicates.join(', ') || 'Target match'}
                        </div>
                      </div>

                      <div style={{ textAlign: 'right' }}>
                        <div style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--accent)' }}>
                          Score: {m.match_score.toFixed(1)}
                        </div>
                        {m.properties?.failure_ratio !== undefined && (
                          <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                            fail: {(Number(m.properties.failure_ratio) * 100).toFixed(0)}%
                          </span>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </Panel>

          {/* Selected Match Drilldown Drawer */}
          {selectedMatch && (
            <Panel style={{ padding: '16px 20px', background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div>
                  <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
                    MATCH INSPECTOR
                  </span>
                  <h3 style={{ margin: '2px 0 0 0', fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
                    {selectedMatch.label}
                  </h3>
                </div>
                {selectedMatch.entity_key && onSelectEntity && (
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => onSelectEntity(selectedMatch.entity_key!)}
                    style={{ display: 'flex', alignItems: 'center', gap: '4px', fontSize: '11px' }}
                  >
                    <span>Inspect Entity</span>
                    <ExternalLink size={12} />
                  </button>
                )}
              </div>

              {/* Status Tags */}
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginBottom: '12px' }}>
                <span style={{ fontSize: '11px', padding: '2px 6px', borderRadius: '4px', background: 'var(--surface-ground)', color: 'var(--text-secondary)', fontFamily: 'var(--mono)' }}>
                  Target: {selectedMatch.target}
                </span>
                <span style={{ fontSize: '11px', padding: '2px 6px', borderRadius: '4px', background: 'var(--surface-ground)', color: 'var(--text-secondary)', fontFamily: 'var(--mono)' }}>
                  State: {selectedMatch.semantic_state}
                </span>
                <span style={{ fontSize: '11px', padding: '2px 6px', borderRadius: '4px', background: 'rgba(104, 225, 216, 0.1)', color: 'var(--accent)', fontFamily: 'var(--mono)' }}>
                  Score: {selectedMatch.match_score}
                </span>
              </div>

              {/* WHY THIS MATCHED */}
              <div style={{ marginBottom: '16px' }}>
                <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                  WHY THIS MATCHED:
                </div>
                <div style={{ background: 'var(--bg-surface)', padding: '8px 12px', borderRadius: '4px', border: '1px solid var(--border)' }}>
                  {selectedMatch.matched_predicates.length > 0 ? (
                    selectedMatch.matched_predicates.map((mp, i) => (
                      <div key={i} style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--success)' }}>
                        &bull; {mp}
                      </div>
                    ))
                  ) : (
                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Target type matched query scope.</div>
                  )}
                </div>
              </div>

              {/* Supporting Evidence */}
              {selectedMatch.supporting_evidence && selectedMatch.supporting_evidence.length > 0 && (
                <div style={{ marginBottom: '16px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    SUPPORTING EVIDENCE ({selectedMatch.supporting_evidence.length}):
                  </div>
                  <div style={{ maxHeight: '120px', overflowY: 'auto', background: 'var(--bg-surface)', padding: '6px 10px', borderRadius: '4px', border: '1px solid var(--border)' }}>
                    {selectedMatch.supporting_evidence.map((ev, i) => (
                      <div key={i} style={{ fontSize: '11px', color: 'var(--text-primary)', marginBottom: '4px' }}>
                        &bull; {ev}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Graph Neighborhood / Evidence Path */}
              {selectedMatch.graph_evidence_path && selectedMatch.graph_evidence_path.length > 0 && (
                <div style={{ marginBottom: '16px' }}>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    GRAPH PATH / ATTRIBUTION:
                  </div>
                  <div style={{ background: 'var(--bg-surface)', padding: '8px', borderRadius: '4px', border: '1px solid var(--border)', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                    {selectedMatch.graph_evidence_path.join(' -> ')}
                  </div>
                </div>
              )}

              {/* Analyst Decision Link */}
              {selectedMatch.analyst_decision_id && onSelectDecision && (
                <div style={{ marginTop: '12px', paddingTop: '12px', borderTop: '1px solid var(--border)' }}>
                  <button
                    className="btn btn-primary btn-sm"
                    onClick={() => onSelectDecision(selectedMatch.analyst_decision_id!)}
                    style={{ display: 'flex', alignItems: 'center', gap: '6px', width: '100%', justifyContent: 'center' }}
                  >
                    <span>Jump to Analyst Decision ({selectedMatch.analyst_decision_id})</span>
                    <ArrowRight size={13} />
                  </button>
                </div>
              )}
            </Panel>
          )}
        </div>
      )}
    </div>
  )
}
