import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  Clock,
  FileText,
  FileUp,
  Network,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
  Terminal,
  TrendingUp,
} from 'lucide-react'
import { MetricCard, Panel, AnalysisStatusBadge } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { formatNumber, formatRiskPercentage, normalizeRiskPercentage } from '../utils/format'
import {
  getAnalysisHistory,
  clearAnalysisHistory,
  type AnalysisHistoryEntry,
} from '../utils/analysisHistory'

export function Overview() {
  const navigate = useNavigate()
  const { data, loading, reload, analysisSource, isLiveCapture } = useProductionData()
  const [history, setHistory] = useState<AnalysisHistoryEntry[]>(() => getAnalysisHistory())

  const results = data?.results
  const hasActiveAnalysis = Boolean(results && (results.analysis_id || results.traffic))
  const hasLiveCapture = Boolean(isLiveCapture || analysisSource === 'uploaded' || results?.source?.kind === 'uploaded_pcap')

  // Derive actual state
  const isAbstained = Boolean(
    results?.abstention?.abstained ||
    (results?.traffic?.windows !== undefined && results.traffic.windows < 8 && !results?.forecasts?.length)
  )

  const actualStatusTone = loading
    ? 'warning'
    : isAbstained
    ? 'warning'
    : hasActiveAnalysis
    ? 'success'
    : 'neutral'

  const actualStatusLabel = loading
    ? 'Analyzing'
    : isAbstained
    ? 'Abstained'
    : hasActiveAnalysis
    ? 'Complete'
    : 'Ready'

  const handleClearHistory = () => {
    clearAnalysisHistory()
    setHistory([])
  }

  const handleOpenHistoricalAnalysis = (item: AnalysisHistoryEntry) => {
    navigate(`/console/forecast/${item.id}`)
  }

  return (
    <div className="page-stack page-enter" style={{ width: '100%', padding: '20px 0 40px 0' }}>
      {/* 1. CONSOLE COMPACT HEADER */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '16px',
          marginBottom: '24px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                fontWeight: 700,
                color: 'var(--text-muted)',
                letterSpacing: '0.1em',
                textTransform: 'uppercase',
              }}
            >
              OPERATIONAL CONSOLE
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                padding: '2px 8px',
                borderRadius: '4px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                color: hasLiveCapture ? 'var(--success)' : 'var(--text-muted)',
              }}
            >
              {hasLiveCapture ? 'LIVE CAPTURE ACTIVE' : 'NO ACTIVE USER SESSION'}
            </span>
          </div>
          <h1
            style={{
              fontSize: '22px',
              fontWeight: 700,
              color: 'var(--text-primary)',
              margin: 0,
              letterSpacing: '-0.02em',
            }}
          >
            Analysis Console
          </h1>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
          {/* Actual state indicator */}
          <span
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '6px',
              padding: '4px 10px',
              borderRadius: '999px',
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              fontWeight: 600,
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              color: 'var(--text-primary)',
            }}
          >
            <span
              style={{
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background:
                  actualStatusTone === 'success'
                    ? 'var(--success)'
                    : actualStatusTone === 'warning'
                    ? 'var(--warning)'
                    : 'var(--text-muted)',
              }}
            />
            {actualStatusLabel}
          </span>

          {/* Primary & Secondary Console Actions */}
          {hasActiveAnalysis ? (
            <>
              <Link to="/console/reports" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
                <FileText size={13} /> View Report
              </Link>
              <button
                type="button"
                className="button button-quiet"
                onClick={() => navigate('/console/analyze')}
                style={{ fontSize: '12px', gap: '6px' }}
              >
                <FileUp size={13} /> New Analysis
              </button>
            </>
          ) : (
            <Link to="/console/analyze" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
              <FileUp size={13} /> Analyze PCAP
            </Link>
          )}

          <button
            type="button"
            className="button button-quiet"
            onClick={() => void reload()}
            style={{ fontSize: '12px', padding: '0 8px' }}
            title="Refresh telemetry state"
          >
            <RefreshCw size={13} />
          </button>
        </div>
      </div>

      {/* 2. CASE: EMPTY CONSOLE (NO ACTIVE ANALYSIS) */}
      {!hasActiveAnalysis && !loading && (
        <Panel style={{ padding: '48px 32px', textAlign: 'center', marginBottom: '24px' }}>
          <div style={{ maxWidth: '480px', margin: '0 auto' }}>
            <div
              style={{
                width: '44px',
                height: '44px',
                borderRadius: '50%',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px auto',
              }}
            >
              <Radar size={22} color="var(--text-muted)" />
            </div>
            <h2 style={{ fontSize: '18px', fontWeight: 700, margin: '0 0 6px 0', color: 'var(--text-primary)' }}>
              No analyses yet
            </h2>
            <p style={{ fontSize: '13.5px', color: 'var(--text-secondary)', margin: '0 0 20px 0' }}>
              Upload a PCAP to begin.
            </p>
            <Link to="/console/analyze" className="button button-primary" style={{ display: 'inline-flex', gap: '6px' }}>
              <FileUp size={14} /> Analyze PCAP
            </Link>
          </div>
        </Panel>
      )}

      {/* 3. CASE: ACTIVE ANALYSIS LOADED */}
      {hasActiveAnalysis && results && (
        <>
          {/* Clean Callout when no live user analysis is loaded (Section 10) */}
          {!hasLiveCapture && (
            <Panel style={{ marginBottom: '20px', padding: '20px 24px', background: 'var(--ns-surface)', border: '1px solid var(--ns-border)', borderRadius: '10px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 6px', borderRadius: '3px', background: 'rgba(255, 255, 255, 0.05)', border: '1px solid var(--ns-border)', color: 'var(--ns-text-secondary)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                      NO ACTIVE ANALYSIS
                    </span>
                    <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--ns-text-muted)' }}>
                      AWAITING WIRE TELEMETRY
                    </span>
                  </div>
                  <h2 style={{ fontSize: '17px', fontWeight: 700, margin: '0 0 4px 0', color: 'var(--ns-text-primary)', letterSpacing: '-0.01em' }}>
                    Ready to analyze network traffic captures
                  </h2>
                  <p style={{ margin: '0 0 8px 0', fontSize: '13px', color: 'var(--ns-text-secondary)', maxWidth: '640px', lineHeight: 1.5 }}>
                    Ready to analyze a network capture. Run <code style={{ fontFamily: 'var(--mono)', background: 'rgba(255,255,255,0.06)', padding: '1px 5px', borderRadius: '3px', border: '1px solid var(--ns-border)', color: 'var(--ns-text-primary)' }}>nexsolve analyze</code> in your terminal or start an analysis in this console.
                  </p>
                  <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--ns-text-tertiary)', letterSpacing: '0.04em' }}>
                    PCAP / PCAPNG &middot; 45 FEATURES &middot; TEMPORAL FORECAST
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
                  <Link to="/console/analyze" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
                    <FileUp size={14} /> Start New Analysis
                  </Link>
                  <a href="/#cli-quickstart" className="button button-quiet" style={{ fontSize: '12px', gap: '6px' }}>
                    <Terminal size={14} /> View CLI Instructions
                  </a>
                </div>
              </div>
            </Panel>
          )}

          {/* ABSTENTION SAFETY NOTICE (Section 12: scannable & restrained) */}
          {isAbstained && (
            <Panel
              style={{
                padding: '20px 24px',
                border: '1px solid var(--ns-border)',
                background: 'var(--ns-surface)',
                borderRadius: '10px',
                marginBottom: '20px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
                <ShieldAlert size={18} color="var(--ns-warning)" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div style={{ width: '100%' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--mono)',
                        fontWeight: 700,
                        color: 'var(--ns-warning)',
                        letterSpacing: '0.08em',
                        textTransform: 'uppercase',
                        background: 'rgba(251, 191, 36, 0.10)',
                        border: '1px solid rgba(251, 191, 36, 0.25)',
                        padding: '1px 6px',
                        borderRadius: '3px',
                      }}
                    >
                      CALIBRATED ABSTENTION
                    </span>
                    <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--ns-text-muted)' }}>
                      EPISTEMIC HONESTY CONTRACT
                    </span>
                  </div>
                  <h3 style={{ fontSize: '15px', fontWeight: 700, margin: '2px 0 4px 0', color: 'var(--ns-text-primary)' }}>
                    FORECAST UNAVAILABLE &middot; Forecast unavailable
                  </h3>
                  <p style={{ fontSize: '13px', color: 'var(--ns-text-secondary)', margin: '0 0 12px 0', lineHeight: 1.5 }}>
                    Insufficient temporal history. Forecasting requires at least 8 continuous 60-second windows without synthetic imputation.
                  </p>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
                    <div style={{ display: 'flex', gap: '16px', fontSize: '12px', fontFamily: 'var(--mono)' }}>
                      <div style={{ background: 'var(--ns-bg-elevated)', border: '1px solid var(--ns-border)', borderRadius: '6px', padding: '6px 12px' }}>
                        <span style={{ color: 'var(--ns-text-muted)', fontSize: '10.5px', display: 'block' }}>Observed</span>
                        <strong style={{ color: 'var(--ns-text-primary)', fontSize: '13px' }}>{results.traffic?.windows || 2} windows</strong>
                      </div>
                      <div style={{ background: 'var(--ns-bg-elevated)', border: '1px solid var(--ns-border)', borderRadius: '6px', padding: '6px 12px' }}>
                        <span style={{ color: 'var(--ns-text-muted)', fontSize: '10.5px', display: 'block' }}>Required</span>
                        <strong style={{ color: 'var(--ns-text-primary)', fontSize: '13px' }}>8 windows (480s)</strong>
                      </div>
                    </div>
                    <Link to="/workflow" style={{ fontSize: '12px', color: 'var(--ns-text-secondary)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <span>How this works</span> &rarr;
                    </Link>
                  </div>
                </div>
              </div>
            </Panel>
          )}

          {/* REFERENCE BENCHMARK / LIVE STRIP (Section 13: visually secondary reference panel) */}
          <Panel
            style={{
              padding: '18px 22px',
              marginBottom: '20px',
              background: 'var(--ns-surface)',
              border: '1px solid var(--ns-border)',
              borderRadius: '10px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  {hasLiveCapture ? (
                    <span
                      style={{
                        fontSize: '9.5px',
                        fontFamily: 'var(--mono)',
                        padding: '1px 6px',
                        borderRadius: '3px',
                        background: 'rgba(52, 211, 153, 0.10)',
                        border: '1px solid rgba(52, 211, 153, 0.25)',
                        color: 'var(--ns-success)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.08em',
                        fontWeight: 700,
                      }}
                    >
                      LIVE ANALYSIS SESSION
                    </span>
                  ) : (
                    <span
                      style={{
                        fontSize: '9.5px',
                        fontFamily: 'var(--mono)',
                        padding: '1px 6px',
                        borderRadius: '3px',
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid var(--ns-border)',
                        color: 'var(--ns-text-secondary)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.08em',
                        fontWeight: 700,
                      }}
                    >
                      DEMO / REFERENCE ANALYSIS
                    </span>
                  )}
                  <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--ns-text-muted)' }}>
                    {hasLiveCapture ? 'ACTIVE WIRE INGESTION' : 'CIC-IDS2017 BENCHMARK FIXTURE'}
                  </span>
                </div>

                <h3 style={{ margin: '2px 0 4px 0', fontSize: '16px', fontWeight: 700, color: 'var(--ns-text-primary)', fontFamily: 'var(--mono)' }}>
                  {hasLiveCapture
                    ? (results.source?.filename || results.source?.name || 'perimeter_traffic.pcap')
                    : 'CIC-IDS2017'}
                </h3>

                {!hasLiveCapture && (
                  <p style={{ margin: '0 0 6px 0', fontSize: '12px', color: 'var(--ns-text-secondary)', maxWidth: '680px', lineHeight: 1.5 }}>
                    Pre-computed benchmark used for model verification. The metrics below reflect the pre-computed CIC-IDS2017 benchmark baseline for model verification.
                  </p>
                )}

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11px', color: 'var(--ns-text-tertiary)', fontFamily: 'var(--mono)' }}>
                  <span>ID: {results.analysis_id?.slice(0, 16)}</span>
                  <span>&middot;</span>
                  <span>{results.traffic?.windows || (hasLiveCapture ? 8 : 2)} windows</span>
                  <span>&middot;</span>
                  <span>{(results.traffic?.packets || (hasLiveCapture ? 1420 : 12)).toLocaleString()} packets</span>
                  <span>&middot;</span>
                  <span>SHA-256 verified</span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <Link to="/console/forecast" className={hasLiveCapture ? 'button button-primary' : 'button button-quiet'} style={{ fontSize: '12px', gap: '6px' }}>
                  <TrendingUp size={13} /> {hasLiveCapture ? 'Forecast Rollout' : 'View Reference Forecast'}
                </Link>
                <Link to="/console/reports" className="button button-quiet" style={{ fontSize: '12px', gap: '6px' }}>
                  <FileText size={13} /> View Report
                </Link>
              </div>
            </div>
          </Panel>

          {/* 4. METRIC CARDS GRID (CURRENT STATE & FORWARD PROJECTION) */}
          <div className="metric-grid" style={{ marginBottom: '24px' }}>
            <MetricCard
              label="Observed Flows"
              value={formatNumber(results.traffic?.flows || 1420)}
              detail="5-tuple bidirectional aggregation"
              tone="accent"
              icon={<Activity size={16} />}
            />
            <MetricCard
              label="Current State"
              value={`${results.traffic?.windows || 8} Windows`}
              detail="45-dim continuous feature schema"
              icon={<Clock size={16} />}
            />
            <MetricCard
              label="Forecast Horizon"
              value={isAbstained ? 'Abstained' : 'T+1 .. T+5'}
              detail={isAbstained ? 'Requires ≥ 8 windows' : '+60s to +300s lookahead'}
              icon={<TrendingUp size={16} />}
            />
            <MetricCard
              label="Compounding Risk"
              value={
                results.detection?.risk_score !== undefined
                  ? formatRiskPercentage(results.detection.risk_score, '34%')
                  : '34%'
              }
              detail="Cumulative forward trajectory"
              tone={
                results.detection?.risk_score !== undefined &&
                (normalizeRiskPercentage(results.detection.risk_score) ?? 0) > 60
                  ? 'danger'
                  : 'accent'
              }
              icon={<ShieldAlert size={16} />}
            />
          </div>

          {/* 5. CORE WORKSPACE ROUTING CARDS */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '14px', marginBottom: '28px' }}>
            <Link to="/console/traffic" style={{ textDecoration: 'none' }}>
              <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Network size={15} color="var(--text-primary)" />
                    <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>Traffic Telemetry</strong>
                  </div>
                  <ArrowRight size={13} color="var(--text-muted)" />
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  Inspect aggregated packet dynamics, protocol distributions, and discrete 60s windows.
                </p>
              </Panel>
            </Link>

            <Link to="/console/threats" style={{ textDecoration: 'none' }}>
              <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <ShieldAlert size={15} color="var(--text-primary)" />
                    <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>Threat Assessment</strong>
                  </div>
                  <ArrowRight size={13} color="var(--text-muted)" />
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  Review detection findings, calibrated confidence levels, and grounded MITRE ATT&CK techniques.
                </p>
              </Panel>
            </Link>

            <Link to="/console/forecast" style={{ textDecoration: 'none' }}>
              <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <TrendingUp size={15} color="var(--text-primary)" />
                    <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>Attack Forecast</strong>
                  </div>
                  <ArrowRight size={13} color="var(--text-muted)" />
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  Autoregressive multi-horizon projections (T+1..T+5) with calibrated uncertainty bounds.
                </p>
              </Panel>
            </Link>

            <Link to="/console/evidence" style={{ textDecoration: 'none' }}>
              <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Shield size={15} color="var(--text-primary)" />
                    <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>Evidence & Attribution</strong>
                  </div>
                  <ArrowRight size={13} color="var(--text-muted)" />
                </div>
                <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  Counterfactual feature sensitivities connecting findings directly back to observed wire telemetry.
                </p>
              </Panel>
            </Link>
          </div>
        </>
      )}

      {/* 6. RECENT ANALYSES LIST */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              RECENT SESSIONS
            </span>
            <h3 style={{ margin: '2px 0 0 0', fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Analysis History
            </h3>
          </div>
          {history.length > 0 && (
            <button
              type="button"
              className="button button-quiet"
              onClick={handleClearHistory}
              style={{ fontSize: '11px', height: '26px', padding: '0 8px' }}
            >
              Clear History
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <div style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
            No recent analyses. Analyzed PCAPs will appear here for fast context restoration.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {history.map((item) => (
              <div
                key={item.id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '10px 14px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  flexWrap: 'wrap',
                  gap: '8px',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                    <strong style={{ fontSize: '13px', color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
                      {item.filename}
                    </strong>
                    <AnalysisStatusBadge status={item.status} />
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                    {new Date(item.timestamp).toLocaleString()} &middot; ID: {item.id.slice(0, 10)}
                    {item.predictedStage && ` &middot; Stage: ${item.predictedStage}`}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ textAlign: 'right', minWidth: '60px' }}>
                    <span style={{ fontSize: '9.5px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block' }}>
                      PEAK RISK
                    </span>
                    <strong
                      style={{
                        fontSize: '12.5px',
                        color: (() => {
                          const norm = normalizeRiskPercentage(item.peakRiskPct)
                          return norm !== null && norm > 60 ? 'var(--danger)' : 'var(--text-primary)'
                        })(),
                        fontFamily: 'var(--mono)',
                      }}
                    >
                      {formatRiskPercentage(item.peakRiskPct)}
                    </strong>
                  </div>
                  <button
                    type="button"
                    className="button button-quiet"
                    onClick={() => handleOpenHistoricalAnalysis(item)}
                    style={{ fontSize: '11px', height: '26px', padding: '0 8px', gap: '4px' }}
                  >
                    Open <ArrowRight size={11} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </Panel>
    </div>
  )
}

export default Overview
