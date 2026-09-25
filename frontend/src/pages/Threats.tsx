import { ChevronDown, ChevronRight, Search, SlidersHorizontal } from 'lucide-react'
import { useState } from 'react'
import { ForecastTrustPanel } from '../components/ForecastTrustPanel'
import { EmptyState, ErrorState, LoadingState, Panel, SectionHeading, SeverityPill } from '../components/Ui'
import { formatTimestamp } from '../utils/format'
import { useProductionData } from '../hooks/useProductionData'

export function Threats() {
  const { data, loading, error, reload } = useProductionData()
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  if (loading) return <LoadingState message="Loading detection findings" />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />

  const normalizedQuery = query.trim().toLowerCase().replaceAll('_', ' ')
  const findings = data.results.detection.findings.filter(
    (finding) =>
      `${finding.attack_category.replaceAll('_', ' ')} ${finding.prediction.replaceAll('_', ' ')} ${finding.evidence.map((item) => `${item.rule_id ?? ''} ${item.type.replaceAll('_', ' ')} ${item.message}`).join(' ')}`
        .toLowerCase()
        .includes(normalizedQuery) && (severity === 'all' || finding.severity === severity)
  )

  const trustResponse =
    data.results.attack_horizon ||
    data.results.abstention ||
    data.results.evidence_chain ||
    data.results.forecasts ||
    data.results.attack_progression ||
    data.results.attackProgression
      ? {
          currentState: {
            timestamp: new Date().toISOString(),
            attackProbability: null,
            predictedStage: null,
            confidence: null,
            uncertainty: null,
            explanation: [],
          },
          forecasts: data.results.forecasts ?? [],
          attack_horizon: data.results.attack_horizon ?? data.results.attackHorizon,
          attack_progression: data.results.attack_progression ?? data.results.attackProgression,
          evidence_chain: data.results.evidence_chain ?? data.results.evidenceChain,
          confidence: data.results.confidence,
          unknown_behavior: data.results.unknown_behavior ?? data.results.unknownBehavior,
          abstention: data.results.abstention,
        }
      : undefined

  return (
    <div className="page-stack page-enter" style={{ width: '100%', padding: '20px 0 40px 0' }}>
      <SectionHeading
        eyebrow="Threat Assessment"
        title="Detection Findings & Evidence Trail"
        description={`Traffic-derived adversary indicators, confidence levels, and grounded MITRE techniques from ${data.results.source?.name ?? 'active telemetry'}.`}
        action={
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              fontWeight: 700,
              padding: '3px 8px',
              borderRadius: '4px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              color: 'var(--text-primary)',
            }}
          >
            {findings.length} THREAT SIGNALS
          </span>
        }
      />

      {/* Forecast Trust Panel (Grounded Evidence Chain) */}
      <ForecastTrustPanel initialResponse={trustResponse} allowFixtureSwitching={!trustResponse} />

      {/* Filter and Search Bar */}
      <Panel className="filter-panel" style={{ padding: '12px 16px', marginBottom: '16px' }}>
        <div className="search-field" style={{ flex: 1 }}>
          <Search size={15} color="var(--text-muted)" />
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search findings or evidence"
            aria-label="Search findings"
            style={{ background: 'transparent', border: 'none', color: 'var(--text-primary)', outline: 'none', width: '100%', fontSize: '13px' }}
          />
        </div>
        <div className="select-wrap" style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <SlidersHorizontal size={14} color="var(--text-muted)" />
          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
            aria-label="Filter severity"
            style={{
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              color: 'var(--text-primary)',
              borderRadius: '4px',
              padding: '4px 8px',
              fontSize: '12px',
              fontFamily: 'var(--mono)',
            }}
          >
            <option value="all">All severity</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <span className="filter-count" style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
          {findings.length} shown
        </span>
      </Panel>

      {/* Data-Oriented Findings Table / List */}
      {findings.length === 0 ? (
        <Panel>
          <EmptyState
            title={data.results.detection.findings.length === 0 ? 'No threats detected' : 'No matching findings'}
            message={
              data.results.detection.findings.length === 0
                ? 'The completed analysis returned no evidence-based findings.'
                : 'Try a different search or severity filter.'
            }
          />
        </Panel>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {findings.map((finding) => {
            const isExpanded = expandedId === finding.finding_id
            return (
              <Panel
                key={finding.finding_id}
                style={{
                  padding: '14px 18px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  transition: 'border-color 0.15s ease',
                }}
              >
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '12px',
                    cursor: 'pointer',
                  }}
                  onClick={() => setExpandedId(isExpanded ? null : finding.finding_id)}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '240px' }}>
                    <button
                      type="button"
                      style={{ background: 'none', border: 'none', padding: 0, cursor: 'pointer', color: 'var(--text-muted)' }}
                      aria-label={isExpanded ? 'Collapse finding details' : 'Expand finding details'}
                    >
                      {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </button>
                    <SeverityPill severity={finding.severity} />
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
                          {finding.attack_category.replaceAll('_', ' ')}
                        </h3>
                        <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                          {finding.finding_id}
                        </span>
                      </div>
                      <p style={{ margin: '2px 0 0 0', fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                        {finding.recommendation}
                      </p>
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>
                        RISK SCORE
                      </span>
                      <strong
                        style={{
                          fontSize: '13px',
                          fontFamily: 'var(--mono)',
                          color: Number.isFinite(finding.risk_score) && finding.risk_score > 0.6 ? 'var(--danger)' : 'var(--text-primary)',
                        }}
                      >
                        {Number.isFinite(finding.risk_score) ? finding.risk_score.toFixed(1) : 'Unavailable'}
                      </strong>
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>
                        TIMESTAMP
                      </span>
                      <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                        {formatTimestamp(finding.timestamp)}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Progressive Disclosure: Expanded Evidence & Detection Method */}
                {isExpanded && (
                  <div
                    style={{
                      marginTop: '14px',
                      paddingTop: '12px',
                      borderTop: '1px solid var(--border)',
                      display: 'flex',
                      flexDirection: 'column',
                      gap: '8px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '11.5px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                      <span>Detection Method: <strong style={{ color: 'var(--text-primary)' }}>{finding.detection_method ?? data.results.detection.detection_method ?? data.results.detection.detection_mode}</strong></span>
                      {finding.prediction && (
                        <>
                          <span>&middot;</span>
                          <span>Inferred Stage: <strong style={{ color: 'var(--text-primary)' }}>{finding.prediction.replaceAll('_', ' ')}</strong></span>
                        </>
                      )}
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '4px' }}>
                      <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                        Supporting Telemetry Evidence
                      </span>
                      {finding.evidence.map((item, idx) => (
                        <div
                          key={item.rule_id ?? `${item.type}-${idx}`}
                          style={{
                            padding: '8px 12px',
                            background: 'var(--bg-elevated)',
                            borderRadius: '4px',
                            border: '1px solid var(--border)',
                            fontSize: '12px',
                            display: 'flex',
                            justifyContent: 'space-between',
                            alignItems: 'center',
                            flexWrap: 'wrap',
                            gap: '8px',
                          }}
                        >
                          <div>
                            <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-muted)', fontSize: '10.5px', marginRight: '6px' }}>
                              [{item.rule_id ?? item.type.replaceAll('_', ' ')}]
                            </span>
                            <strong style={{ color: 'var(--text-primary)' }}>{item.message}</strong>
                          </div>
                          {(item.metric || item.threshold !== undefined) && (
                            <small style={{ fontFamily: 'var(--mono)', color: 'var(--text-muted)', fontSize: '10.5px' }}>
                              {item.metric ? `Metric: ${item.metric}` : ''}
                              {item.metric && item.threshold !== undefined ? ` | Threshold: ${item.threshold}` : ''}
                            </small>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </Panel>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default Threats
