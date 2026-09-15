import { useState, useEffect } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  Binary,
  Cpu,
  FileCode,
  Info,
  Layers,
  Search,
} from 'lucide-react'
import { EmptyState, ErrorState, LoadingState, Panel, SectionHeading } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { api } from '../services/api'
import type { CanonicalAnalysis, EvidenceItemNode } from '../types/canonical'
import { adaptToCanonical } from '../utils/canonicalAdapter'

export function Evidence() {
  const { jobId } = useParams<{ jobId?: string }>()
  const { data, loading: storeLoading, error: storeError } = useProductionData()
  const [analysis, setAnalysis] = useState<CanonicalAnalysis | null>(null)
  const [filterType, setFilterType] = useState<'all' | 'supporting' | 'contradictory'>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedNode, setSelectedNode] = useState<EvidenceItemNode | null>(null)

  useEffect(() => {
    if (jobId) {
      void api.getJobResult(jobId).then((res) => {
        setAnalysis(adaptToCanonical(res, jobId))
      }).catch(() => {
        if (data?.results) {
          setAnalysis(adaptToCanonical(data.results, data.results.analysis_id))
        }
      })
    } else if (data?.results) {
      setAnalysis(adaptToCanonical(data.results, data.results.analysis_id))
    }
  }, [jobId, data])

  if (storeLoading && !analysis) return <LoadingState message="Loading technical evidence..." />
  if (storeError && !analysis) return <ErrorState message={storeError} />
  if (!analysis) return <LoadingState message="Retrieving canonical evidence..." />

  const { evidence, input, processing } = analysis
  const chain = evidence.chain
  const allNodes: EvidenceItemNode[] = [...chain.supporting, ...chain.contradictory]

  const filteredNodes = allNodes.filter((node) => {
    if (filterType === 'supporting' && !node.isSupporting) return false
    if (filterType === 'contradictory' && node.isSupporting) return false
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      return node.name.toLowerCase().includes(q) || node.explanation.toLowerCase().includes(q)
    }
    return true
  })

  return (
    <div className="page-stack page-enter" style={{ maxWidth: '1180px', margin: '0 auto', width: '100%' }}>
      {/* Header */}
      <SectionHeading
        eyebrow="SCIENTIFIC AUDIT & TECHNICAL PROVENANCE"
        title="Evidence Chain & Attribution Explorer"
        description="Full transparency into feature contracts, model architectures, temporal context, and feature perturbation drivers."
        action={
          <div className="heading-actions">
            <Link to={jobId ? `/console/forecast/${jobId}` : '/console/forecast'} className="button button-quiet">
              View Forecast Console
            </Link>
          </div>
        }
      />

      {/* Provenance Tag */}
      <div
        className={`provenance-banner ${analysis.isDemo ? 'demo-mode' : analysis.provenance === 'live' ? 'live-mode' : 'reference-mode'}`}
      >
        <div className="provenance-badge-group">
          <span className="provenance-pill status-pill">{analysis.provenanceLabel}</span>
          <span className="provenance-pill dataset-pill">{input.filename}</span>
          <span className="provenance-pill reference-pill">SCHEMA: 45-DIM CANONICAL</span>
        </div>
        <div className="provenance-details">
          <p>
            {analysis.isDemo
              ? `Evaluation sandbox: ${analysis.demoScenarioId ?? 'Deterministic Scenario'}. Validating feature perturbation drivers and evidence separation without live traffic dependency.`
              : `Active forensic evidence derived directly from capture ${input.filename}. All features and attribution weights are extracted without synthetic imputation.`}
          </p>
        </div>
      </div>

      {/* 1. INPUT & FEATURE CONTRACT (Section 15 & 17) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        {/* Input Details */}
        <Panel>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <FileCode size={16} color="var(--accent)" />
            <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>1. Input Telemetry</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Source File:</span>
              <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>{input.filename}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Format Contract:</span>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--accent)' }}>{input.format.toUpperCase()} (Passive Tap)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Capture Duration:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>{input.captureDurationSeconds}s ({input.windowCount} windows)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Observed Volume:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>{input.packetCount.toLocaleString()} pkts / {input.flowCount.toLocaleString()} flows</span>
            </div>
          </div>
        </Panel>

        {/* Feature Contract */}
        <Panel>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Binary size={16} color="var(--accent)" />
            <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>2. Feature Contract</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Schema Version:</span>
              <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>{evidence.configuration.schemaVersion}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Feature Dimension:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>45 continuous features (17 flow, 22 pkt, 6 temporal)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>RTT Exclusion Policy:</span>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--accent)' }}>Withheld (0% synthetic imputation)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Compatibility:</span>
              <span style={{ fontFamily: 'var(--mono)', color: processing.isCompatible ? 'var(--accent)' : 'var(--warning)' }}>
                {processing.isCompatible ? 'COMPATIBLE (VERIFIED)' : 'WITHHELD'}
              </span>
            </div>
          </div>
        </Panel>

        {/* Temporal Model Context */}
        <Panel>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Layers size={16} color="var(--accent)" />
            <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>3. Temporal Model Context</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Windowing Method:</span>
              <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>60s Tumbling Windows</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Required History:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>8 continuous windows (480s)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Forecast Rollout Horizons:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>T+1 .. T+5 (+60s .. +300s)</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Decay Handling:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>Empirical transition matrix divergence</span>
            </div>
          </div>
        </Panel>

        {/* Model Architecture */}
        <Panel>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <Cpu size={16} color="var(--accent)" />
            <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>4. Model Specifications</h3>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12.5px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Champion Model:</span>
              <strong style={{ color: 'var(--text-primary)', fontSize: '11px' }}>{evidence.model.champion}</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Candidate Model:</span>
              <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>{evidence.model.researchHold}</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', paddingBottom: '6px' }}>
              <span style={{ color: 'var(--text-muted)' }}>Inference Mode:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>Deterministic world model rollout</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Decision Threshold:</span>
              <span style={{ fontFamily: 'var(--mono)' }}>P &ge; {evidence.model.decisionThreshold}</span>
            </div>
          </div>
        </Panel>
      </div>

      {/* 2. EVIDENCE CHAIN & FEATURE ATTRIBUTION (Section 15) */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
              FEATURE PERTURBATION ATTRIBUTION &middot; FEATURE LEVEL
            </span>
            <h3 style={{ margin: '2px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
              Evidence Nodes: Supporting vs Contradictory Drivers
            </h3>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Attribution method: {analysis.explanations.method}
            </span>
          </div>

          {/* Filter & Search */}
          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '2px' }}>
              <button
                type="button"
                className={`button button-quiet ${filterType === 'all' ? 'active' : ''}`}
                onClick={() => setFilterType('all')}
                style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', border: 0 }}
              >
                All ({allNodes.length})
              </button>
              <button
                type="button"
                className={`button button-quiet ${filterType === 'supporting' ? 'active' : ''}`}
                onClick={() => setFilterType('supporting')}
                style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', border: 0, color: 'var(--danger)' }}
              >
                Supporting ({chain.supporting.length})
              </button>
              <button
                type="button"
                className={`button button-quiet ${filterType === 'contradictory' ? 'active' : ''}`}
                onClick={() => setFilterType('contradictory')}
                style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', border: 0, color: '#eda850' }}
              >
                Contradictory ({chain.contradictory.length})
              </button>
            </div>

            <div style={{ position: 'relative' }}>
              <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Search features..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  padding: '6px 10px 6px 30px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  fontSize: '12px',
                  color: 'var(--text-primary)',
                  width: '180px',
                }}
              />
            </div>
          </div>
        </div>

        {filteredNodes.length === 0 ? (
          <EmptyState
            title="No evidence items match filter"
            message="No feature nodes matched the selected filter or search query."
          />
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: selectedNode ? '1fr 360px' : '1fr', gap: '16px' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {filteredNodes.map((item) => {
                const isSelected = selectedNode?.name === item.name
                const isSupp = item.isSupporting

                return (
                  <div
                    key={item.name}
                    onClick={() => setSelectedNode(item)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '12px 14px',
                      background: isSelected ? 'var(--button-secondary-bg)' : 'var(--bg-secondary)',
                      border: isSelected ? '1px solid var(--accent)' : '1px solid var(--border)',
                      borderLeft: `4px solid ${isSupp ? 'var(--danger)' : '#eda850'}`,
                      borderRadius: '6px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <code style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text-primary)', fontSize: '13px' }}>
                          {item.name}
                        </code>
                        <span
                          style={{
                            fontSize: '10px',
                            fontFamily: 'var(--mono)',
                            padding: '1px 6px',
                            borderRadius: '3px',
                            background: isSupp ? 'rgba(237, 128, 111, 0.15)' : 'rgba(237, 168, 80, 0.15)',
                            color: isSupp ? 'var(--danger)' : '#eda850',
                            fontWeight: 600,
                          }}
                        >
                          {isSupp ? 'SUPPORTING' : 'CONTRADICTORY'}
                        </span>
                      </div>
                      <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
                        {item.explanation}
                      </p>
                    </div>

                    <div style={{ textAlign: 'right', flexShrink: 0 }}>
                      <span style={{ display: 'block', fontFamily: 'var(--mono)', fontSize: '12px', fontWeight: 700, color: isSupp ? 'var(--danger)' : 'var(--accent)' }}>
                        {item.delta !== null ? (item.delta > 0 ? `+${item.delta}` : item.delta) : '—'}
                      </span>
                      <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                        rel: {(item.reliability * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>

            {/* Drilldown Drawer */}
            {selectedNode && (
              <div
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  padding: '16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <code style={{ fontFamily: 'var(--mono)', fontWeight: 700, fontSize: '14px', color: 'var(--accent)' }}>
                    {selectedNode.name}
                  </code>
                  <button
                    type="button"
                    onClick={() => setSelectedNode(null)}
                    className="button button-quiet"
                    style={{ fontSize: '11px', height: '24px', padding: '0 6px' }}
                  >
                    Close
                  </button>
                </div>

                <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {selectedNode.explanation}
                </p>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px', fontSize: '12px' }}>
                  <div style={{ background: 'var(--bg-surface)', padding: '8px 10px', borderRadius: '4px', border: '1px solid var(--border)' }}>
                    <span style={{ display: 'block', fontSize: '10px', color: 'var(--text-muted)' }}>OBSERVED</span>
                    <strong style={{ fontFamily: 'var(--mono)' }}>{selectedNode.observed}</strong>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', padding: '8px 10px', borderRadius: '4px', border: '1px solid var(--border)' }}>
                    <span style={{ display: 'block', fontSize: '10px', color: 'var(--text-muted)' }}>BASELINE</span>
                    <strong style={{ fontFamily: 'var(--mono)' }}>{selectedNode.baseline ?? '0.00'}</strong>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', padding: '8px 10px', borderRadius: '4px', border: '1px solid var(--border)' }}>
                    <span style={{ display: 'block', fontSize: '10px', color: 'var(--text-muted)' }}>DELTA SHIFT</span>
                    <strong style={{ fontFamily: 'var(--mono)', color: selectedNode.isSupporting ? 'var(--danger)' : '#eda850' }}>
                      {selectedNode.delta !== null ? selectedNode.delta : '—'}
                    </strong>
                  </div>
                  <div style={{ background: 'var(--bg-surface)', padding: '8px 10px', borderRadius: '4px', border: '1px solid var(--border)' }}>
                    <span style={{ display: 'block', fontSize: '10px', color: 'var(--text-muted)' }}>RELIABILITY</span>
                    <strong style={{ fontFamily: 'var(--mono)' }}>{(selectedNode.reliability * 100).toFixed(0)}%</strong>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </Panel>

      {/* Dynamic Graph Structural Attribution Panel */}
      {analysis.temporalGraph && (
        <Panel>
          <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                  GRAPH STRUCTURAL ATTRIBUTION &middot; TOPOLOGICAL EVIDENCE
                </span>
                <h3 style={{ margin: '2px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
                  Network Graph Structural Signals ({analysis.temporalGraph.observed_snapshots.length} Snapshots)
                </h3>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Structural evidence extracted from graph interaction dynamics across 60s windows.
                </span>
              </div>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', border: '1px solid var(--border)', padding: '2px 8px', borderRadius: '4px' }}>
                STATUS: {analysis.temporalGraph.status}
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px' }}>
              <div style={{ background: 'var(--bg-secondary)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                  Dominant High-Activity Nodes
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {analysis.temporalGraph.top_high_activity_nodes.slice(0, 5).map((node) => (
                    <div key={node.node_id} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--mono)' }}>
                      <span>{node.ip}</span>
                      <span style={{ color: 'var(--text-muted)' }}>
                        Fan-out: {node.fan_out} | Score: {(node.activity_score * 100).toFixed(0)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: 'var(--bg-secondary)', padding: '14px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
                  Top Structural Change Nodes
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {analysis.temporalGraph.top_structural_change_nodes.slice(0, 5).map((node) => (
                    <div key={node.node_id} style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--mono)' }}>
                      <span>{node.ip}</span>
                      <span style={{ color: 'var(--text-muted)' }}>
                        &Delta; {(node.structural_change_score * 100).toFixed(0)}% | Links: {node.total_degree}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </Panel>
      )}

      {/* 3. SCIENTIFIC LIMITATIONS & MEASUREMENT BOUNDARIES */}

      <Panel>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '10px' }}>
          <Info size={16} color="var(--accent)" />
          <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--text-primary)' }}>
            Scientific Measurement Boundaries & Limitations
          </h3>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '13px', color: 'var(--text-secondary)' }}>
          {chain.limitations.map((lim, idx) => (
            <div
              key={idx}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '8px',
                background: 'var(--bg-secondary)',
                padding: '10px 14px',
                borderRadius: '6px',
                border: '1px solid var(--border)',
              }}
            >
              <span style={{ color: 'var(--accent)', fontWeight: 700 }}>&bull;</span>
              <span>{lim}</span>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  )
}
