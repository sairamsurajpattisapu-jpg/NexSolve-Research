import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  Clock,
  FileText,
  FileUp,
  Network,
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
  const { data, loading, reload } = useProductionData()
  const [history, setHistory] = useState<AnalysisHistoryEntry[]>(() => getAnalysisHistory())

  const results = data?.results
  const hasActiveAnalysis = Boolean(results && (results.analysis_id || results.traffic))

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
    <div className="page-stack page-enter">
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
                fontSize: '11px',
                fontFamily: 'var(--font-sans)',
                fontWeight: 600,
                color: 'var(--text-muted)',
                letterSpacing: '0.08em',
                textTransform: 'uppercase',
              }}
            >
              OPERATIONAL CONSOLE
            </span>
            <span
              style={{
                fontSize: '10.5px',
                fontFamily: 'var(--font-sans)',
                fontWeight: 600,
                padding: '2px 8px',
                borderRadius: '4px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                color: hasActiveAnalysis ? 'var(--success)' : 'var(--text-muted)',
              }}
            >
              {hasActiveAnalysis ? 'LIVE CAPTURE ACTIVE' : 'NO ACTIVE ANALYSIS'}
            </span>
          </div>
          <h1
            style={{
              fontSize: '22px',
              fontWeight: 700,
              color: 'var(--text-primary)',
              margin: 0,
              letterSpacing: '-0.025em',
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
              fontFamily: 'var(--font-sans)',
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
        <Panel style={{ marginBottom: '24px', padding: '32px 36px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '10px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '20px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-sans)', padding: '2px 8px', borderRadius: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
                  NO ACTIVE ANALYSIS
                </span>
                <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
                  AWAITING WIRE TELEMETRY
                </span>
              </div>
              <h2 style={{ fontSize: '18px', fontWeight: 700, margin: '0 0 6px 0', color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                Ready to analyze network traffic captures
              </h2>
              <p style={{ margin: '0 0 12px 0', fontSize: '13.5px', color: 'var(--text-secondary)', maxWidth: '640px', lineHeight: 1.6 }}>
                Ready to analyze a network capture. Run <code style={{ fontFamily: 'var(--mono)', background: 'var(--bg-secondary)', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--border)', color: 'var(--text-primary)' }}>nexsolve analyze</code> in your terminal or start an analysis in this console.
              </p>
              <div style={{ fontSize: '11.5px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)', letterSpacing: '0.02em' }}>
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

      {/* 3. CASE: ACTIVE ANALYSIS LOADED */}
      {hasActiveAnalysis && results && (
        <>
          {/* ABSTENTION SAFETY NOTICE (renders only when active analysis has insufficient windows < 8) */}
          {isAbstained && (
            <Panel
              style={{
                padding: '20px 24px',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                borderRadius: '10px',
                marginBottom: '20px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
                <ShieldAlert size={18} color="var(--warning)" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div style={{ width: '100%' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span
                      style={{
                        fontSize: '10.5px',
                        fontFamily: 'var(--font-sans)',
                        fontWeight: 600,
                        color: 'var(--warning)',
                        letterSpacing: '0.04em',
                        textTransform: 'uppercase',
                        background: 'rgba(251, 191, 36, 0.08)',
                        border: '1px solid rgba(251, 191, 36, 0.20)',
                        padding: '2px 7px',
                        borderRadius: '4px',
                      }}
                    >
                      CALIBRATED ABSTENTION
                    </span>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
                      EPISTEMIC HONESTY CONTRACT
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span
                      style={{
                        fontFamily: 'var(--mono)',
                        fontSize: '11px',
                        fontWeight: 700,
                        letterSpacing: '0.08em',
                        color: 'var(--text-primary)',
                        textTransform: 'uppercase',
                      }}
                    >
                      ANALYSIS COMPLETE
                    </span>
                    <span style={{ color: 'var(--border)' }}>&middot;</span>
                    <span style={{ fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'var(--font-sans)' }}>
                      Static traffic analysis completed.
                    </span>
                  </div>
                  <h3 style={{ fontSize: '14.5px', fontWeight: 600, margin: '2px 0 4px 0', color: 'var(--text-primary)' }}>
                    Forecast unavailable &middot; Insufficient temporal history.
                  </h3>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '0 0 12px 0', lineHeight: 1.5 }}>
                    This capture contains only {results.traffic?.windows ?? 0} usable temporal {(results.traffic?.windows ?? 0) === 1 ? 'window' : 'windows'}. Forecasting requires at least 8 continuous 60-second windows without synthetic imputation.
                  </p>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
                    <div style={{ display: 'flex', gap: '16px', fontSize: '12px', fontFamily: 'var(--font-sans)' }}>
                      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', padding: '6px 12px' }}>
                        <span style={{ color: 'var(--text-muted)', fontSize: '11px', display: 'block' }}>Observed</span>
                        <strong style={{ color: 'var(--text-primary)', fontSize: '13px', fontVariantNumeric: 'tabular-nums' }}>{results.traffic?.windows ?? 0} windows</strong>
                      </div>
                      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '6px', padding: '6px 12px' }}>
                        <span style={{ color: 'var(--text-muted)', fontSize: '11px', display: 'block' }}>Required</span>
                        <strong style={{ color: 'var(--text-primary)', fontSize: '13px', fontVariantNumeric: 'tabular-nums' }}>8 windows (480s)</strong>
                      </div>
                    </div>
                    <Link to="/workflow" style={{ fontSize: '12px', color: 'var(--text-secondary)', textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                      <span>How this works</span> &rarr;
                    </Link>
                  </div>
                </div>
              </div>
            </Panel>
          )}

          {/* ACTIVE ANALYSIS BANNER */}
          <Panel
            style={{
              padding: '20px 24px',
              marginBottom: '20px',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: '10px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                  <span
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--font-sans)',
                      padding: '2px 7px',
                      borderRadius: '4px',
                      background: 'rgba(52, 211, 153, 0.08)',
                      border: '1px solid rgba(52, 211, 153, 0.20)',
                      color: 'var(--success)',
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                      fontWeight: 600,
                    }}
                  >
                    ACTIVE ANALYSIS SESSION
                  </span>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
                    ACTIVE WIRE INGESTION
                  </span>
                </div>

                <h3 style={{ margin: '2px 0 6px 0', fontSize: '17px', fontWeight: 600, color: 'var(--text-primary)', letterSpacing: '-0.015em' }}>
                  {results.source?.filename || results.source?.name || 'Active Capture'}
                </h3>

                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11.5px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
                  <span>ID: <code style={{ fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>{results.analysis_id?.slice(0, 16)}</code></span>
                  <span>&middot;</span>
                  <span>{results.traffic?.windows ?? 0} windows</span>
                  <span>&middot;</span>
                  <span>{(results.traffic?.packets ?? 0).toLocaleString()} packets</span>
                  <span>&middot;</span>
                  <span>SHA-256 verified</span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <Link to="/console/forecast" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
                  <TrendingUp size={13} /> Forecast Rollout
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
              value={results.traffic?.flows !== undefined ? formatNumber(results.traffic.flows) : '—'}
              detail="5-tuple bidirectional aggregation"
              tone="accent"
              icon={<Activity size={16} />}
            />
            <MetricCard
              label="Current State"
              value={`${results.traffic?.windows ?? 0} Windows`}
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
                  ? formatRiskPercentage(results.detection.risk_score, '—')
                  : '—'
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
          <div className="card-grid" style={{ marginBottom: '28px' }}>
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
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
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
                    <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)', fontFamily: 'var(--font-sans)', fontWeight: 600 }}>
                      {item.filename}
                    </strong>
                    <AnalysisStatusBadge status={item.status} />
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)' }}>
                    {new Date(item.timestamp).toLocaleString()} &middot; ID: <code style={{ fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>{item.id.slice(0, 10)}</code>
                    {item.predictedStage && ` &middot; Stage: ${item.predictedStage}`}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ textAlign: 'right', minWidth: '60px' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', display: 'block' }}>
                      PEAK RISK
                    </span>
                    <strong
                      style={{
                        fontSize: '13px',
                        color: (() => {
                          const norm = normalizeRiskPercentage(item.peakRiskPct)
                          return norm !== null && norm > 60 ? 'var(--danger)' : 'var(--text-primary)'
                        })(),
                        fontFamily: 'var(--font-sans)',
                        fontWeight: 700,
                        fontVariantNumeric: 'tabular-nums',
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
