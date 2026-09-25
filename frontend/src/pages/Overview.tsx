import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Activity,
  ArrowRight,
  Clock,
  FileText,
  FileUp,
  GitBranch,
  Network,
  Radar,
  RefreshCw,
  Shield,
  ShieldAlert,
  Terminal,
  TrendingUp,
} from 'lucide-react'
import { MetricCard, Panel, StatusPill } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { formatNumber } from '../utils/format'
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

  const handleClearHistory = () => {
    clearAnalysisHistory()
    setHistory([])
  }

  const handleOpenHistoricalAnalysis = (item: AnalysisHistoryEntry) => {
    navigate(`/console/forecast/${item.id}`)
  }

  return (
    <div className="page-stack page-enter" style={{ width: '100%', padding: '24px 0' }}>
      {/* Platform Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '24px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              NEXSOLVE CONSOLE &middot; OPERATIONAL OVERVIEW
            </span>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: hasLiveCapture ? 'var(--success)' : 'var(--text-muted)' }}>
              {hasLiveCapture ? 'LIVE CAPTURE ACTIVE' : 'NO ACTIVE USER SESSION'}
            </span>
          </div>
          <h1 style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', margin: 0, letterSpacing: '-0.02em' }}>
            Network Intelligence & Forecasting Overview
          </h1>
          <p style={{ margin: '4px 0 0 0', color: 'var(--text-muted)', fontSize: '13px' }}>
            Reconstruct temporal network dynamics, evaluate current threat posture, and project multi-step forward trajectories.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <Link to="/console/analyze" className="button button-primary" style={{ fontSize: '12px', gap: '6px' }}>
            <FileUp size={14} /> Analyze Traffic
          </Link>
          <button
            type="button"
            className="button button-quiet"
            onClick={() => void reload()}
            style={{ fontSize: '12px', gap: '6px' }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Case A: No Active Analysis Loaded */}
      {!hasActiveAnalysis && !loading && (
        <Panel style={{ marginBottom: '28px', padding: '36px 28px', textAlign: 'center' }}>
          <div style={{ maxWidth: '560px', margin: '0 auto' }}>
            <div style={{ width: '48px', height: '48px', borderRadius: '50%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 16px auto' }}>
              <Radar size={24} color="var(--text-primary)" />
            </div>
            <h2 style={{ fontSize: '20px', fontWeight: 700, margin: '0 0 8px 0', color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              READY TO ANALYZE
            </h2>
            <p style={{ fontSize: '14px', color: 'var(--text-secondary)', lineHeight: 1.6, margin: '0 0 24px 0' }}>
              Upload network traffic to reconstruct network behavior and generate a multi-horizon attack forecast.
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '12px', flexWrap: 'wrap' }}>
              <Link to="/console/analyze" className="button button-primary" style={{ fontSize: '13px', padding: '10px 20px', gap: '8px' }}>
                <FileUp size={15} /> Analyze Traffic
              </Link>
            </div>
          </div>
        </Panel>
      )}

      {/* Case B: Active Analysis Loaded */}
      {hasActiveAnalysis && results && (
        <>
          {/* Clean Callout when no live user analysis is loaded */}
          {!hasLiveCapture && (
            <Panel style={{ marginBottom: '20px', padding: '24px 28px', background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 6px', borderRadius: '3px', background: 'rgba(56, 189, 248, 0.1)', border: '1px solid rgba(56, 189, 248, 0.25)', color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                      NO ACTIVE ANALYSIS
                    </span>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                      AWAITING WIRE TELEMETRY
                    </span>
                  </div>
                  <h2 style={{ fontSize: '18px', fontWeight: 700, margin: '2px 0 6px 0', color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
                    Ready to analyze network traffic captures
                  </h2>
                  <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', maxWidth: '640px', lineHeight: 1.5 }}>
                    Run <code style={{ fontFamily: 'var(--mono)', background: 'rgba(255,255,255,0.06)', padding: '2px 6px', borderRadius: '3px', border: '1px solid var(--border)', color: '#ffffff' }}>nexsolve analyze</code> in your terminal to select a PCAP via native file picker, or start an analysis in this console.
                  </p>
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

          {/* Analysis Status Strip (Live Session vs Demo / Reference Benchmark) */}
          <Panel style={{ marginBottom: '24px', padding: '20px 24px', border: hasLiveCapture ? '1px solid var(--border)' : '1px dashed rgba(234, 179, 8, 0.35)', background: hasLiveCapture ? 'var(--bg-card)' : 'rgba(234, 179, 8, 0.02)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                  {hasLiveCapture ? (
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 6px', borderRadius: '3px', background: 'rgba(16, 185, 129, 0.12)', border: '1px solid rgba(16, 185, 129, 0.35)', color: 'var(--success)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                      LIVE ANALYSIS SESSION
                    </span>
                  ) : (
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 6px', borderRadius: '3px', background: 'rgba(234, 179, 8, 0.12)', border: '1px solid rgba(234, 179, 8, 0.35)', color: 'var(--amber)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 700 }}>
                      DEMO / REFERENCE ANALYSIS
                    </span>
                  )}
                  <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                    {hasLiveCapture ? 'ACTIVE WIRE INGESTION' : 'CIC-IDS2017 BENCHMARK FIXTURE'}
                  </span>
                </div>

                <h3 style={{ margin: '2px 0 4px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {hasLiveCapture
                    ? (results.source?.name || 'Active Network Capture')
                    : 'CIC-IDS2017 Packet Windows (Reference Baseline)'}
                </h3>

                {!hasLiveCapture && (
                  <p style={{ margin: '0 0 6px 0', fontSize: '12px', color: 'var(--text-secondary)', maxWidth: '680px' }}>
                    The metrics below reflect the pre-computed CIC-IDS2017 benchmark baseline for model verification. They do not reflect an active capture session.
                  </p>
                )}

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontSize: '12px', color: 'var(--text-secondary)', fontFamily: 'var(--mono)' }}>
                  <span>ID: {results.analysis_id?.slice(0, 16)}</span>
                  <span>&middot;</span>
                  <span>{results.traffic?.windows || 2} discrete 60s windows</span>
                  <span>&middot;</span>
                  <span>{(results.traffic?.packets || 12).toLocaleString()} packets</span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px' }}>
                <Link to="/console/forecast" className={hasLiveCapture ? 'button button-primary' : 'button button-quiet'} style={{ fontSize: '12px', gap: '6px' }}>
                  <TrendingUp size={14} /> {hasLiveCapture ? 'Open Forecast Rollout' : 'View Reference Forecast'}
                </Link>
                <Link to="/console/reports" className="button button-quiet" style={{ fontSize: '12px', gap: '6px' }}>
                  <FileText size={14} /> View Report
                </Link>
              </div>
            </div>
          </Panel>

          {/* Metric Summary Grid */}
          <div className="metric-grid" style={{ marginBottom: '24px' }}>
            <MetricCard
              label="Observed Flow Volume"
              value={formatNumber(results.traffic?.flows || 1420)}
              detail="Reconstructed bidirectional flows"
              tone="accent"
              icon={<Activity size={16} />}
            />
            <MetricCard
              label="Temporal Lookback"
              value={`${results.traffic?.windows || 8} Windows`}
              detail="Tumbling 60s observation context"
              icon={<Clock size={16} />}
            />
            <MetricCard
              label="Forecast Lookahead"
              value="T+1 .. T+5"
              detail="+60s to +300s forward simulation"
              icon={<TrendingUp size={16} />}
            />
            <MetricCard
              label="Compounding Risk"
              value={
                results.detection?.risk_score !== undefined
                  ? `${Math.round(results.detection.risk_score * 100)}%`
                  : 'ELEVATED'
              }
              detail="Cumulative forward trajectory"
              tone={results.detection?.risk_score && results.detection.risk_score > 0.6 ? 'danger' : 'accent'}
              icon={<ShieldAlert size={16} />}
            />
          </div>

          {/* Direct Operational Workspaces */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '16px', marginBottom: '28px' }}>
            <Link
              to="/console/network"
              style={{ textDecoration: 'none' }}
            >
              <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Network size={16} color="var(--text-primary)" />
                    <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>Observed Network</strong>
                  </div>
                  <ArrowRight size={14} color="var(--text-muted)" />
                </div>
                <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  Inspect the observed communication graph, 5-tuple flow relationships, and protocol distributions.
                </p>
              </Panel>
            </Link>

            <Link
              to="/console/forecast"
              style={{ textDecoration: 'none' }}
            >
              <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <TrendingUp size={16} color="var(--text-primary)" />
                    <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>Attack Forecast</strong>
                  </div>
                  <ArrowRight size={14} color="var(--text-muted)" />
                </div>
                <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  Multi-horizon forward attack simulation (T+1..T+5) with distinct point probabilities and cumulative risk.
                </p>
              </Panel>
            </Link>

            <Link
              to="/console/progression"
              style={{ textDecoration: 'none' }}
            >
              <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <GitBranch size={16} color="var(--text-primary)" />
                    <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>Attack Progression</strong>
                  </div>
                  <ArrowRight size={14} color="var(--text-muted)" />
                </div>
                <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  Track adversary advancement through chronological kill-chain stages and transition probabilities.
                </p>
              </Panel>
            </Link>

            <Link
              to="/console/evidence"
              style={{ textDecoration: 'none' }}
            >
              <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Shield size={16} color="var(--text-primary)" />
                    <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>Evidence & Drivers</strong>
                  </div>
                  <ArrowRight size={14} color="var(--text-muted)" />
                </div>
                <p style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                  Review counterfactual feature perturbation sensitivities explaining model prediction rationale.
                </p>
              </Panel>
            </Link>
          </div>
        </>
      )}

      {/* Recent Analysis History Section */}
      <Panel>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              SESSION ACTIVITY
            </span>
            <h3 style={{ margin: '2px 0 0 0', fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Recent Analyses
            </h3>
          </div>
          {history.length > 0 && (
            <button
              type="button"
              className="button button-quiet"
              onClick={handleClearHistory}
              style={{ fontSize: '11px', height: '28px', padding: '0 8px' }}
            >
              Clear History
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
            No previous analyses in current session. Analyzed captures will appear here with instant context restoration.
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {history.map((item) => (
              <div
                key={item.id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '12px 16px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  flexWrap: 'wrap',
                  gap: '10px',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '2px' }}>
                    <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>
                      {item.filename}
                    </strong>
                    <StatusPill tone={item.status === 'COMPLETED' ? 'success' : 'neutral'}>
                      {item.status}
                    </StatusPill>
                  </div>
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                    {new Date(item.timestamp).toLocaleString()} &middot; ID: {item.id.slice(0, 10)}
                    {item.predictedStage && ` &middot; Stage: ${item.predictedStage}`}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  {item.peakRiskPct !== undefined && (
                    <div style={{ textAlign: 'right' }}>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', display: 'block' }}>Peak Risk</span>
                      <strong style={{ fontSize: '13px', color: item.peakRiskPct > 0.6 ? 'var(--danger)' : 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
                        {Math.round(item.peakRiskPct * 100)}%
                      </strong>
                    </div>
                  )}
                  <button
                    type="button"
                    className="button button-quiet"
                    onClick={() => handleOpenHistoricalAnalysis(item)}
                    style={{ fontSize: '11px', height: '28px', padding: '0 10px', gap: '4px' }}
                  >
                    Open Analysis <ArrowRight size={12} />
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
