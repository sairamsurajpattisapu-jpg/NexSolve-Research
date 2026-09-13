import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  GitCommit,
  Info,
  Layers,
  Search,
  ShieldAlert,
} from 'lucide-react'
import { EmptyState, ErrorState, LoadingState, MetricCard, Panel, SectionHeading } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import type { EvidenceItemPayload, UploadedAnalysisResponse } from '../types/api'

export function Evidence() {
  const { data, loading, error, analysisSource, provenance } = useProductionData()
  const [filterType, setFilterType] = useState<'all' | 'supporting' | 'contradictory'>('all')
  const [selectedItem, setSelectedItem] = useState<EvidenceItemPayload | null>(null)
  const [searchQuery, setSearchQuery] = useState('')

  if (loading && !data) return <LoadingState />
  if (error || !data) return <ErrorState message={error ?? 'Unable to load evidence data.'} />

  const results = data.results as unknown as UploadedAnalysisResponse
  const evidenceChain = results.evidence_chain ?? results.evidenceChain
  const isDemo = provenance === 'demo' || results.is_demo
  const isUploaded = !isDemo && (provenance === 'uploaded' || analysisSource === 'uploaded')

  const supporting = evidenceChain?.supporting ?? []
  const contradictory = evidenceChain?.contradictory ?? []
  const allItems: EvidenceItemPayload[] = [...supporting, ...contradictory]

  const filteredItems = allItems.filter((item) => {
    if (filterType === 'supporting' && !item.is_supporting) return false
    if (filterType === 'contradictory' && item.is_supporting) return false
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase()
      const matchName = item.feature_name.toLowerCase().includes(q)
      const matchExp = item.explanation.toLowerCase().includes(q)
      const matchType = item.evidence_type.toLowerCase().includes(q)
      if (!matchName && !matchExp && !matchType) return false
    }
    return true
  })

  return (
    <div className="page-stack page-enter">
      {/* Header */}
      <SectionHeading
        eyebrow={
          isDemo
            ? 'DEMO DATA · CAUSAL ATTRIBUTION'
            : isUploaded
            ? 'LIVE PCAP EVIDENCE CHAIN'
            : 'REFERENCE BENCHMARK · EVIDENCE AUDIT'
        }
        title="Evidence Chain & Attribution Explorer"
        description="Forensic attribution mapping observed telemetry shifts to predictive forecast decisions. Features are segregated into supporting vs contradictory evidence nodes."
        action={
          <div className="heading-actions">
            <Link to="/forecast" className="button button-quiet">
              View Forecast Rollout
            </Link>
            <Link to="/analyze" className="button button-quiet">
              Analyze PCAP
            </Link>
          </div>
        }
      />

      {/* Provenance Banner */}
      <div
        className={`provenance-banner ${isDemo ? 'demo-mode' : isUploaded ? 'live-mode' : 'reference-mode'}`}
        data-testid="evidence-provenance-banner"
      >
        <div className="provenance-badge-group">
          <span className="provenance-pill status-pill">
            {isDemo ? 'DEMO DATA' : isUploaded ? 'LIVE PCAP ANALYSIS' : 'VERIFIED REFERENCE'}
          </span>
          <span className="provenance-pill dataset-pill">
            {results.source?.name || (isDemo ? 'Evaluation Scenario' : 'CIC-IDS2017')}
          </span>
          <span className="provenance-pill reference-pill">
            STRENGTH: {((evidenceChain?.evidence_strength ?? 0.8) * 100).toFixed(0)}%
          </span>
        </div>
        <div className="provenance-details">
          <p>
            {isDemo
              ? `Demonstration causal attribution graph for scenario: ${results.demo_scenario_name ?? 'Evaluation Scenario'}.`
              : isUploaded
              ? `Live evidence attribution derived from capture ${results.source?.name ?? 'Uploaded PCAP'}.`
              : 'Displaying reference causal attribution indicators from the CIC-IDS2017 baseline dataset.'}
          </p>
        </div>
      </div>

      {/* Metric Cards Summary */}
      <div className="metric-grid">
        <MetricCard
          label="Supporting features"
          value={evidenceChain?.supporting_feature_count ?? supporting.length}
          detail="Strengthens attack hypothesis"
          tone="danger"
          icon={<ShieldAlert size={16} />}
        />
        <MetricCard
          label="Contradictory features"
          value={evidenceChain?.contradictory_feature_count ?? contradictory.length}
          detail="Weakens attack hypothesis"
          tone="warning"
          icon={<AlertTriangle size={16} />}
        />
        <MetricCard
          label="Evidence strength"
          value={`${((evidenceChain?.evidence_strength ?? 0.85) * 100).toFixed(0)}%`}
          detail={`Quality: ${evidenceChain?.evidence_quality ?? 'HIGH'}`}
          tone="accent"
          icon={<GitCommit size={16} />}
        />
        <MetricCard
          label="Forecasting horizon"
          value={`T+${evidenceChain?.forecast_horizon ?? 5}`}
          detail="Target prediction window"
          icon={<Layers size={16} />}
        />
      </div>

      {/* Evidence Chain Explorer Workspace */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <span className="eyebrow">CAUSAL ATTRIBUTION NODES</span>
            <h3 style={{ margin: '4px 0 0 0', color: 'var(--text-primary)' }}>Feature Attribution Directory</h3>
          </div>

          <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap' }}>
            <div style={{ display: 'flex', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '2px' }}>
              <button
                type="button"
                className={`button button-quiet ${filterType === 'all' ? 'active' : ''}`}
                onClick={() => setFilterType('all')}
                style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', border: 0 }}
              >
                All ({allItems.length})
              </button>
              <button
                type="button"
                className={`button button-quiet ${filterType === 'supporting' ? 'active' : ''}`}
                onClick={() => setFilterType('supporting')}
                style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', border: 0, color: 'var(--danger)' }}
              >
                Supporting ({supporting.length})
              </button>
              <button
                type="button"
                className={`button button-quiet ${filterType === 'contradictory' ? 'active' : ''}`}
                onClick={() => setFilterType('contradictory')}
                style={{ fontSize: '11px', padding: '4px 10px', height: 'auto', border: 0, color: 'var(--warning)' }}
              >
                Contradictory ({contradictory.length})
              </button>
            </div>

            <div style={{ position: 'relative' }}>
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
              <Search size={14} style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            </div>
          </div>
        </div>

        {filteredItems.length === 0 ? (
          <EmptyState
            title="No evidence items found"
            message="No features matched the selected filter or search criteria."
          />
        ) : (
          <div style={{ display: 'grid', gridTemplateColumns: selectedItem ? '1fr 380px' : '1fr', gap: '16px', alignItems: 'start' }}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
              {filteredItems.map((item) => {
                const isSelected = selectedItem?.evidence_id === item.evidence_id
                const isSupp = item.is_supporting
                const isInc = item.direction === 'INCREASE'

                return (
                  <div
                    key={item.evidence_id || item.feature_name}
                    onClick={() => setSelectedItem(item)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '12px 16px',
                      background: isSelected ? 'var(--accent-muted)' : 'var(--bg-secondary)',
                      border: `1px solid ${isSelected ? 'var(--accent)' : 'var(--border)'}`,
                      borderRadius: '8px',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div
                        style={{
                          width: '28px',
                          height: '28px',
                          borderRadius: '6px',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          background: isSupp ? 'rgba(237, 128, 111, 0.15)' : 'rgba(242, 187, 113, 0.15)',
                          color: isSupp ? 'var(--danger)' : 'var(--warning)',
                        }}
                      >
                        {isInc ? <ArrowUpRight size={16} /> : <ArrowDownRight size={16} />}
                      </div>

                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <strong style={{ fontFamily: 'var(--mono)', fontSize: '13px', color: 'var(--text-primary)' }}>
                            {item.feature_name}
                          </strong>
                          <span
                            className="provenance-pill"
                            style={{
                              fontSize: '9.5px',
                              background: isSupp ? 'rgba(237, 128, 111, 0.15)' : 'rgba(242, 187, 113, 0.15)',
                              color: isSupp ? 'var(--danger)' : 'var(--warning)',
                            }}
                          >
                            {isSupp ? 'SUPPORTING' : 'CONTRADICTORY'}
                          </span>
                        </div>
                        <p style={{ margin: '3px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
                          {item.explanation}
                        </p>
                      </div>
                    </div>

                    <div style={{ textAlign: 'right', minWidth: '100px' }}>
                      <div style={{ fontFamily: 'var(--mono)', fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                        {typeof item.observed_value === 'number' ? item.observed_value.toLocaleString(undefined, { maximumFractionDigits: 2 }) : item.observed_value}
                      </div>
                      {item.relative_change !== null && (
                        <small
                          style={{
                            fontFamily: 'var(--mono)',
                            fontSize: '11px',
                            color: isSupp ? 'var(--danger)' : 'var(--warning)',
                          }}
                        >
                          {item.relative_change > 0 ? `+${(item.relative_change * 100).toFixed(0)}%` : `${(item.relative_change * 100).toFixed(0)}%`}
                        </small>
                      )}
                    </div>
                  </div>
                )
              })}
            </div>

            {/* Feature Inspection Drawer / Modal Card */}
            {selectedItem && (
              <Panel style={{ border: '1px solid var(--accent)', background: 'var(--bg-surface)', padding: '20px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '14px' }}>
                  <div>
                    <span className="eyebrow" style={{ color: selectedItem.is_supporting ? 'var(--danger)' : 'var(--warning)' }}>
                      {selectedItem.is_supporting ? 'SUPPORTING ATTRIBUTION' : 'CONTRADICTORY ATTRIBUTION'}
                    </span>
                    <h4 style={{ margin: '4px 0 0 0', fontFamily: 'var(--mono)', fontSize: '15px', color: 'var(--text-primary)' }}>
                      {selectedItem.feature_name}
                    </h4>
                  </div>
                  <button
                    type="button"
                    className="button button-quiet"
                    onClick={() => setSelectedItem(null)}
                    style={{ padding: '4px 8px', fontSize: '11px' }}
                  >
                    Close
                  </button>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '13px' }}>
                  <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                    <span className="eyebrow" style={{ fontSize: '10px' }}>FORENSIC RATIONALE</span>
                    <p style={{ margin: '4px 0 0 0', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                      {selectedItem.explanation}
                    </p>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '10px' }}>
                    <div style={{ background: 'var(--bg-secondary)', padding: '10px', borderRadius: '6px' }}>
                      <span className="eyebrow" style={{ fontSize: '10px' }}>OBSERVED VALUE</span>
                      <strong style={{ display: 'block', fontFamily: 'var(--mono)', marginTop: '2px', color: 'var(--text-primary)' }}>
                        {selectedItem.observed_value}
                      </strong>
                    </div>

                    <div style={{ background: 'var(--bg-secondary)', padding: '10px', borderRadius: '6px' }}>
                      <span className="eyebrow" style={{ fontSize: '10px' }}>BASELINE VALUE</span>
                      <strong style={{ display: 'block', fontFamily: 'var(--mono)', marginTop: '2px', color: 'var(--text-primary)' }}>
                        {selectedItem.baseline_value ?? '0.00'}
                      </strong>
                    </div>

                    <div style={{ background: 'var(--bg-secondary)', padding: '10px', borderRadius: '6px' }}>
                      <span className="eyebrow" style={{ fontSize: '10px' }}>DELTA SHIFT</span>
                      <strong style={{ display: 'block', fontFamily: 'var(--mono)', marginTop: '2px', color: selectedItem.is_supporting ? 'var(--danger)' : 'var(--warning)' }}>
                        {selectedItem.delta !== null ? selectedItem.delta.toFixed(2) : '—'}
                      </strong>
                    </div>

                    <div style={{ background: 'var(--bg-secondary)', padding: '10px', borderRadius: '6px' }}>
                      <span className="eyebrow" style={{ fontSize: '10px' }}>RELIABILITY</span>
                      <strong style={{ display: 'block', fontFamily: 'var(--mono)', marginTop: '2px', color: 'var(--accent)' }}>
                        {(selectedItem.reliability * 100).toFixed(0)}%
                      </strong>
                    </div>
                  </div>

                  <div style={{ background: 'var(--bg-secondary)', padding: '10px', borderRadius: '6px' }}>
                    <span className="eyebrow" style={{ fontSize: '10px' }}>DIRECTION</span>
                    <span style={{ display: 'block', fontFamily: 'var(--mono)', marginTop: '2px', color: 'var(--text-secondary)' }}>
                      {selectedItem.direction} ({selectedItem.evidence_type})
                    </span>
                  </div>
                </div>
              </Panel>
            )}
          </div>
        )}
      </Panel>

      {/* Limitations & Verification Boundaries */}
      {evidenceChain?.limitations && evidenceChain.limitations.length > 0 && (
        <Panel>
          <SectionHeading
            eyebrow="FORENSIC BOUNDARIES"
            title="Evidence Scope & Limitations"
            description="Verified measurement boundaries of the causal attribution system."
          />
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '10px' }}>
            {evidenceChain.limitations.map((lim, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '10px',
                  background: 'var(--bg-secondary)',
                  padding: '10px 14px',
                  borderRadius: '6px',
                  border: '1px solid var(--border)',
                  fontSize: '13px',
                  color: 'var(--text-secondary)',
                }}
              >
                <Info size={16} color="var(--accent)" />
                <span>{typeof lim === 'string' ? lim : lim.description}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}
    </div>
  )
}
