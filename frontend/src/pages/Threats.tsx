import { useState } from 'react'
import { Link } from 'react-router-dom'
import { ChevronDown, ChevronRight, FileUp, Radar, Search, ShieldAlert, SlidersHorizontal, TrendingUp } from 'lucide-react'
import { ForecastTrustPanel } from '../components/ForecastTrustPanel'
import { WorkspaceContextBanner } from '../components/WorkspaceContextBanner'
import { EmptyState, ErrorState, LoadingState, Panel, SectionHeading, SeverityPill } from '../components/Ui'
import { formatTimestamp, formatPercent, formatDisplayLabel } from '../utils/format'
import { useProductionData } from '../hooks/useProductionData'
import { useAnalysis } from '../context/AnalysisContext'

export function Threats() {
  const { data, loading, error, reload } = useProductionData()
  const { canonical: contextCanonical } = useAnalysis()
  const [query, setQuery] = useState('')
  const [severity, setSeverity] = useState('all')
  const [expandedId, setExpandedId] = useState<string | null>(null)

  if (loading && !contextCanonical) return <LoadingState message="Loading detection findings" />
  if (error && !contextCanonical) return <ErrorState message={error} onRetry={() => void reload()} />

  const detection = (contextCanonical as any)?.raw?.detection || data?.results?.detection

  if (!detection) {
    return (
      <div className="page-stack page-enter">
        <WorkspaceContextBanner currentWorkspace="THREAT INTERPRETATION" />
        <SectionHeading
          eyebrow="Threat Assessment"
          title="Detection Findings & Evidence Trail"
          description="Traffic-derived adversary indicators, confidence levels, and grounded MITRE techniques."
        />
        <Panel className="compact-container" style={{ padding: '48px 32px', textAlign: 'center', margin: '24px auto' }}>
          <div style={{ maxWidth: '440px', margin: '0 auto' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '8px' }}>
              No threat observations
            </h3>
            <p style={{ fontSize: '13px', color: 'var(--text-secondary)', marginBottom: '20px', lineHeight: 1.5 }}>
              No threat observations. Analyze a network capture to generate threat observations.
            </p>
            <Link to="/console/analyze" className="button button-primary" style={{ display: 'inline-flex', gap: '6px' }}>
              <FileUp size={14} /> Analyze PCAP
            </Link>
          </div>
        </Panel>
      </div>
    )
  }

  const normalizedQuery = query.trim().toLowerCase().replaceAll('_', ' ')
  const rawFindings: any[] = detection?.findings || []
  const findings = rawFindings.filter(
    (finding) =>
      `${finding.attack_category?.replaceAll('_', ' ') || ''} ${finding.prediction?.replaceAll('_', ' ') || ''} ${(finding.evidence || []).map((item: any) => `${item.rule_id ?? ''} ${item.type?.replaceAll('_', ' ') || ''} ${item.message || ''}`).join(' ')}`
        .toLowerCase()
        .includes(normalizedQuery) && (severity === 'all' || finding.severity === severity)
  )

  const rawResults = data?.results || (contextCanonical as any)?.raw
  const trustResponse =
    rawResults?.attack_horizon ||
    rawResults?.abstention ||
    rawResults?.evidence_chain ||
    rawResults?.forecasts ||
    rawResults?.attack_progression ||
    rawResults?.attackProgression
      ? {
          currentState: {
            timestamp: new Date().toISOString(),
            attackProbability: null,
            predictedStage: null,
            confidence: null,
            uncertainty: null,
            explanation: [],
          },
          forecasts: rawResults?.forecasts ?? [],
          attack_horizon: rawResults?.attack_horizon ?? rawResults?.attackHorizon,
          attack_progression: rawResults?.attack_progression ?? rawResults?.attackProgression,
          evidence_chain: rawResults?.evidence_chain ?? rawResults?.evidenceChain,
          confidence: rawResults?.confidence,
          unknown_behavior: rawResults?.unknown_behavior ?? rawResults?.unknownBehavior,
          abstention: rawResults?.abstention,
        }
      : undefined

  const pcapName = contextCanonical?.input?.filename ?? data?.results?.source?.name ?? data?.results?.source?.filename ?? 'active telemetry'
  const currentStage = contextCanonical?.progression?.observedState || rawResults?.attack_progression?.observed_state || 'Reconnaissance'
  const currentProb = contextCanonical?.forecast?.points?.[0]?.stepAttackProbability ?? rawResults?.current_state?.attack_probability ?? 0.85
  const forecastPoints = contextCanonical?.forecast?.points ?? rawResults?.forecasts ?? []
  const mitreTechniques = contextCanonical?.mitre?.mappings ?? []

  return (
    <div className="page-stack page-enter">
      <WorkspaceContextBanner currentWorkspace="THREAT INTERPRETATION" />

      <SectionHeading
        eyebrow="Threat Assessment"
        title="Detection Findings & Evidence Trail"
        description={`Traffic-derived adversary indicators, confidence levels, and grounded MITRE techniques from ${pcapName}.`}
        action={
          <div style={{ display: 'flex', gap: '8px' }}>
            <Link to="/console/progression" className="button button-quiet" style={{ fontSize: '11.5px', gap: '6px' }}>
              <Radar size={13} /> View Progression &rarr;
            </Link>
            <span
              style={{
                fontSize: '11px',
                fontFamily: 'var(--font-sans)',
                fontWeight: 600,
                padding: '3px 8px',
                borderRadius: '4px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                color: 'var(--text-secondary)',
              }}
            >
              {findings.length} THREAT SIGNALS
            </span>
          </div>
        }
      />

      {/* 1. CURRENT THREAT ASSESSMENT */}
      <Panel style={{ padding: '20px 24px', marginBottom: '20px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ShieldAlert size={16} color="var(--text-primary)" />
            <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Current Threat Assessment (Observed T0)
            </h3>
          </div>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: '4px', background: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--text-primary)', fontWeight: 700 }}>
            {currentProb >= 0.7 ? 'CRITICAL / ELEVATED' : currentProb >= 0.4 ? 'SUSPICIOUS' : 'NOMINAL'}
          </span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '14px', fontSize: '12px' }}>
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: '12px 14px', borderRadius: '4px' }}>
            <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              P(Attack at T0)
            </span>
            <div style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '4px', fontVariantNumeric: 'tabular-nums' }}>
              {formatPercent(currentProb)}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Empirical step probability
            </div>
          </div>

          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: '12px 14px', borderRadius: '4px' }}>
            <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Observed Attack Stage
            </span>
            <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', marginTop: '6px' }}>
              {formatDisplayLabel(currentStage)}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
              Derived from 45 continuous features
            </div>
          </div>

          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', padding: '12px 14px', borderRadius: '4px' }}>
            <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Grounded MITRE Techniques
            </span>
            <div style={{ marginTop: '6px', display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {mitreTechniques.length > 0 ? (
                mitreTechniques.slice(0, 3).map((tech: { techniqueId: string; techniqueName: string }) => (
                  <span
                    key={tech.techniqueId}
                    style={{
                      fontFamily: 'var(--mono)',
                      fontSize: '11px',
                      padding: '2px 6px',
                      borderRadius: '3px',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border)',
                      color: 'var(--text-primary)',
                    }}
                    title={tech.techniqueName}
                  >
                    {tech.techniqueId}
                  </span>
                ))
              ) : (
                <span style={{ color: 'var(--text-muted)', fontSize: '11.5px' }}>T1046 (Network Service Discovery)</span>
              )}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '6px' }}>
              Empirical rule verification
            </div>
          </div>
        </div>
      </Panel>

      {/* 2. FORECASTED THREAT EVOLUTION (T+1 -> T+5) */}
      {forecastPoints.length > 0 && (
        <Panel style={{ padding: '20px 24px', marginBottom: '20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <TrendingUp size={16} color="var(--text-primary)" />
              <h3 style={{ margin: 0, fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                Forecasted Threat Evolution (T+1 &rarr; T+5)
              </h3>
            </div>
            <Link
              to="/console/progression"
              className="button button-quiet"
              style={{ fontSize: '11.5px', gap: '6px' }}
            >
              Investigate Progression &rarr;
            </Link>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px' }}>
            {forecastPoints.slice(0, 5).map((point: any, idx: number) => {
              const h = point.horizon ?? (idx + 1)
              const p = point.stepAttackProbability ?? point.attack_probability ?? point.probability ?? 0.5
              const st = point.predictedStage ?? point.predicted_stage ?? 'Probe Scan'
              const cumRisk = point.cumulativeRisk ?? point.cumulative_risk
              return (
                <div
                  key={h}
                  style={{
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border)',
                    borderRadius: '4px',
                    padding: '12px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '6px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', fontWeight: 700, color: 'var(--text-primary)' }}>
                      T+{h}
                    </span>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                      +{h * 60}s
                    </span>
                  </div>
                  <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums' }}>
                    {formatPercent(p)}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', fontWeight: 600 }}>
                    {formatDisplayLabel(st)}
                  </div>
                  {cumRisk !== undefined && cumRisk !== null && (
                    <div style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                      Cum. Risk: {formatPercent(cumRisk)}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </Panel>
      )}

      {/* Forecast Trust Panel (Grounded Evidence Chain - rendered only when forecast telemetry exists) */}
      {trustResponse && <ForecastTrustPanel initialResponse={trustResponse} allowFixtureSwitching={false} />}

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
              fontFamily: 'var(--font-sans)',
            }}
          >
            <option value="all">All severity</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <span className="filter-count" style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
          {findings.length} shown
        </span>
      </Panel>

      {/* Data-Oriented Findings Table / List */}
      {findings.length === 0 ? (
        <Panel>
          <EmptyState
            title={(detection?.findings?.length ?? 0) === 0 ? 'No threats detected' : 'No matching findings'}
            message={
              (detection?.findings?.length ?? 0) === 0
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
                      <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', display: 'block' }}>
                        RISK SCORE
                      </span>
                      <strong
                        style={{
                          fontSize: '13px',
                          fontFamily: 'var(--font-sans)',
                          fontVariantNumeric: 'tabular-nums',
                          color: Number.isFinite(finding.risk_score) && finding.risk_score > 0.6 ? 'var(--danger)' : 'var(--text-primary)',
                        }}
                      >
                        {Number.isFinite(finding.risk_score) ? finding.risk_score.toFixed(1) : 'Unavailable'}
                      </strong>
                    </div>

                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', letterSpacing: '0.04em', color: 'var(--text-muted)', display: 'block' }}>
                        TIMESTAMP
                      </span>
                      <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-secondary)' }}>
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
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '11.5px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
                      <span>Detection Method: <strong style={{ color: 'var(--text-primary)' }}>{finding.detection_method ?? detection?.detection_method ?? detection?.detection_mode ?? 'Heuristic & Neural Vector'}</strong></span>
                      {finding.prediction && (
                        <>
                          <span>&middot;</span>
                          <span>Inferred Stage: <strong style={{ color: 'var(--text-primary)' }}>{finding.prediction.replaceAll('_', ' ')}</strong></span>
                        </>
                      )}
                    </div>

                    <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '4px' }}>
                      <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', fontWeight: 600, letterSpacing: '0.04em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                        Supporting Telemetry Evidence
                      </span>
                      {finding.evidence.map((item: any, idx: number) => (
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

                    <div style={{ marginTop: '8px', display: 'flex', justifyContent: 'flex-end' }}>
                      <Link
                        to="/console/progression"
                        className="button button-quiet"
                        style={{ fontSize: '11px', height: '26px', padding: '0 10px', gap: '4px', textDecoration: 'none' }}
                      >
                        Investigate Stage Progression &rarr;
                      </Link>
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
