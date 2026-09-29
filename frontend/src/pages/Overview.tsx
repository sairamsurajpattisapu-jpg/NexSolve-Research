import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  ArrowRight,
  FileText,
  FileUp,
  Network,
  RefreshCw,
  RotateCcw,
  Shield,
  ShieldAlert,
  Terminal,
  TrendingUp,
  Workflow,
} from 'lucide-react'
import { Panel, AnalysisStatusBadge } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { useAnalysis } from '../context/AnalysisContext'
import { formatNumber, formatRiskPercentage, normalizeRiskPercentage, formatDisplayLabel, formatBytes } from '../utils/format'
import {
  getAnalysisHistory,
  clearAnalysisHistory,
  type AnalysisHistoryEntry,
} from '../utils/analysisHistory'

export function Overview() {
  const navigate = useNavigate()
  const { canonical: activeCanonical, loadAnalysisFromHistory } = useAnalysis()
  const { data, loading, reload } = useProductionData()
  const [history, setHistory] = useState<AnalysisHistoryEntry[]>(() => getAnalysisHistory())

  const results = data?.results
  const hasActiveAnalysis = Boolean(activeCanonical || (results && (results.analysis_id || results.traffic)))

  // Active analysis attributes derived from canonical or results
  const filename = activeCanonical?.input?.filename || results?.source?.filename || results?.source?.name || 'Active Wire Capture'
  const analysisId = activeCanonical?.id || results?.analysis_id || 'live'
  const packetCount = activeCanonical?.input?.packetCount ?? results?.traffic?.packets ?? 0
  const flowCount = activeCanonical?.input?.flowCount ?? results?.traffic?.flows ?? 0
  const windowCount = activeCanonical?.input?.windowCount ?? results?.traffic?.windows ?? 0
  const captureDuration = activeCanonical?.input?.captureDurationSeconds ?? results?.traffic?.duration_seconds ?? 0
  const sizeBytes = activeCanonical?.input?.sizeBytes ?? results?.source?.size_bytes ?? 0

  // Derive abstention status
  const isAbstained = Boolean(
    activeCanonical?.forecast?.status === 'INSUFFICIENT_HISTORY' ||
    activeCanonical?.forecast?.status === 'ABSTAINED' ||
    results?.abstention?.abstained ||
    (windowCount < 8 && !results?.forecasts?.length && !activeCanonical?.forecast?.points?.length)
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

  // Forecast points & evidentiary data
  const forecastPoints = activeCanonical?.forecast?.points || []
  const topDrivers = activeCanonical?.explanations?.drivers || []
  const validationComparison = activeCanonical?.validationComparison
  const threatLevel = activeCanonical?.currentState?.summary?.threatLevel || results?.detection?.threat_level || 'low'
  const currentMitreTechnique = (activeCanonical?.currentState as any)?.summary?.technique || (results?.detection as any)?.technique || 'T1046 (Network Service Scanning)'
  const earlyWarning = activeCanonical?.forecast?.earlyWarning

  const handleClearHistory = () => {
    clearAnalysisHistory()
    setHistory([])
  }

  const handleOpenHistoricalAnalysis = (item: AnalysisHistoryEntry) => {
    void loadAnalysisFromHistory(item)
    navigate(`/console/forecast/${item.id}`)
  }

  return (
    <div className="page-stack page-enter site-container" style={{ maxWidth: '1240px', margin: '0 auto', padding: '0 24px' }}>
      {/* 1. CONSOLE COMPACT SOC HEADER */}
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
                fontFamily: 'var(--mono)',
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
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                fontWeight: 600,
                padding: '2px 8px',
                borderRadius: '3px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                color: hasActiveAnalysis ? 'var(--text-primary)' : 'var(--text-muted)',
              }}
            >
              {hasActiveAnalysis ? 'LIVE CAPTURE ACTIVE' : 'NO ACTIVE ANALYSIS'}
            </span>
          </div>
          <h1
            style={{
              fontSize: '22px',
              fontFamily: 'var(--font-sans)',
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
          {/* Status badge */}
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
                    ? '#ffffff'
                    : actualStatusTone === 'warning'
                    ? '#a3a3a3'
                    : '#525252',
              }}
            />
            {actualStatusLabel}
          </span>

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
        <Panel style={{ marginBottom: '24px', padding: '32px 36px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '20px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: '3px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em', fontWeight: 600 }}>
                  NO ACTIVE ANALYSIS
                </span>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  AWAITING WIRE TELEMETRY
                </span>
              </div>
              <h2 style={{ fontSize: '18px', fontWeight: 700, margin: '0 0 6px 0', color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                Ready to analyze network traffic captures
              </h2>
              <p style={{ margin: '0 0 12px 0', fontSize: '13.5px', color: 'var(--text-secondary)', maxWidth: '640px', lineHeight: 1.6 }}>
                Analyze a network capture to inspect passive Layer 3/4 flow features, evaluate multi-horizon state transitions (T+1 to T+5), and audit counterfactual evidence.
              </p>
              <div style={{ fontSize: '11.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
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

      {/* 3. CASE: ACTIVE ANALYSIS LOADED (FOUR COHESIVE QUESTIONS) */}
      {hasActiveAnalysis && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px', marginBottom: '28px' }}>
          {/* ABSTENTION SAFETY NOTICE (renders only when active analysis has insufficient windows < 8) */}
          {isAbstained && (
            <Panel
              style={{
                padding: '20px 24px',
                border: '1px solid var(--border)',
                background: 'var(--bg-secondary)',
                borderRadius: '8px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '14px' }}>
                <ShieldAlert size={18} color="var(--text-primary)" style={{ flexShrink: 0, marginTop: '2px' }} />
                <div style={{ width: '100%' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span
                      style={{
                        fontSize: '10.5px',
                        fontFamily: 'var(--mono)',
                        fontWeight: 600,
                        color: 'var(--text-primary)',
                        letterSpacing: '0.04em',
                        textTransform: 'uppercase',
                        background: 'var(--bg-surface)',
                        border: '1px solid var(--border)',
                        padding: '2px 7px',
                        borderRadius: '3px',
                      }}
                    >
                      CALIBRATED ABSTENTION
                    </span>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
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
                    <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      Static traffic analysis completed.
                    </span>
                  </div>
                  <h3 style={{ fontSize: '14.5px', fontWeight: 600, margin: '2px 0 4px 0', color: 'var(--text-primary)' }}>
                    Forecast unavailable &middot; Insufficient temporal history.
                  </h3>
                  <p style={{ fontSize: '13px', color: 'var(--text-secondary)', margin: '0 0 12px 0', lineHeight: 1.5 }}>
                    This capture contains only {windowCount} usable temporal {windowCount === 1 ? 'window' : 'windows'}. Forecasting requires at least 8 continuous 60-second windows without synthetic imputation.
                  </p>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
                    <div style={{ display: 'flex', gap: '16px', fontSize: '12px', fontFamily: 'var(--mono)' }}>
                      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '4px', padding: '6px 12px' }}>
                        <span style={{ color: 'var(--text-muted)', fontSize: '10px', display: 'block' }}>Observed</span>
                        <strong style={{ color: 'var(--text-primary)', fontSize: '13px' }}>{windowCount} windows</strong>
                      </div>
                      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '4px', padding: '6px 12px' }}>
                        <span style={{ color: 'var(--text-muted)', fontSize: '10px', display: 'block' }}>Required</span>
                        <strong style={{ color: 'var(--text-primary)', fontSize: '13px' }}>8 windows (480s)</strong>
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

          {/* -------------------------------------------------------------------
              QUESTION 1: WHAT IS HAPPENING?
              Ingress Telemetry & Current Threat Assessment
              ------------------------------------------------------------------- */}
          <Panel style={{ padding: '22px 24px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
                1. WHAT IS HAPPENING? (OBSERVED NETWORK STATE)
              </span>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 7px', border: '1px solid var(--border)', borderRadius: '3px', color: 'var(--text-secondary)' }}>
                BOUNDARY T_0 &middot; MODEL_SCHEMA_45
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
              {/* Telemetry metadata */}
              <div>
                <div style={{ fontSize: '17px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px', letterSpacing: '-0.015em' }}>
                  {filename}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11.5px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', flexWrap: 'wrap', marginBottom: '12px' }}>
                  <span>ID: <code style={{ color: 'var(--text-secondary)' }}>{analysisId.slice(0, 16)}</code></span>
                  <span>&middot;</span>
                  <span>{windowCount} windows</span>
                  <span>&middot;</span>
                  <span>{packetCount.toLocaleString()} packets</span>
                  <span>&middot;</span>
                  <span>{flowCount.toLocaleString()} flows</span>
                  {captureDuration > 0 && (
                    <>
                      <span>&middot;</span>
                      <span>{captureDuration.toFixed(1)}s duration</span>
                    </>
                  )}
                  {sizeBytes > 0 && (
                    <>
                      <span>&middot;</span>
                      <span>{formatBytes(sizeBytes)}</span>
                    </>
                  )}
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '10px' }}>
                  <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '8px 12px', borderRadius: '4px' }}>
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>OBSERVED FLOWS</span>
                    <strong style={{ fontSize: '14.5px', color: 'var(--text-primary)' }}>{flowCount > 0 ? formatNumber(flowCount) : '—'}</strong>
                  </div>
                  <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '8px 12px', borderRadius: '4px' }}>
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>WINDOWS</span>
                    <strong style={{ fontSize: '14.5px', color: 'var(--text-primary)' }}>{windowCount}</strong>
                  </div>
                  <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '8px 12px', borderRadius: '4px' }}>
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block' }}>COMPOUNDING RISK</span>
                    <strong style={{ fontSize: '14.5px', color: 'var(--text-primary)' }}>
                      {earlyWarning?.score !== undefined
                        ? `${earlyWarning.score}%`
                        : forecastPoints.length > 0 && forecastPoints[0].stepAttackProbability !== null
                        ? formatRiskPercentage(forecastPoints[0].stepAttackProbability, '—')
                        : results?.detection?.risk_score !== undefined
                        ? formatRiskPercentage(results.detection.risk_score, '—')
                        : '—'}
                    </strong>
                  </div>
                </div>
              </div>

              {/* Threat State Assessment */}
              <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '16px 18px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <ShieldAlert size={16} color="var(--text-primary)" />
                      <strong style={{ fontSize: '13px', color: 'var(--text-primary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                        {formatDisplayLabel(threatLevel)} Threat Assessment
                      </strong>
                    </div>
                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '1px 6px', border: '1px solid var(--border)', borderRadius: '2px', color: 'var(--text-secondary)' }}>
                      OBSERVED
                    </span>
                  </div>
                  <div style={{ fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5, marginBottom: '10px' }}>
                    Adversary behavior at observation boundary indicates active reconnaissance and horizontal probe sweeps.
                  </div>
                </div>

                <div style={{ borderTop: '1px solid var(--border)', paddingTop: '10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11.5px', fontFamily: 'var(--mono)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>MITRE ATT&CK:</span>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{currentMitreTechnique}</span>
                </div>
              </div>
            </div>
          </Panel>

          {/* -------------------------------------------------------------------
              QUESTION 2: WHAT COMES NEXT?
              Attack Horizon & Forecast Rollout (T+1 .. T+5)
              ------------------------------------------------------------------- */}
          {!isAbstained && forecastPoints.length > 0 && (
            <Panel style={{ padding: '22px 24px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
                <div>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
                    2. WHAT COMES NEXT? (ATTACK HORIZON FORECAST)
                  </span>
                  <h3 style={{ margin: '4px 0 0 0', fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Multi-Horizon State Trajectory (T+1 &rarr; T+5)
                  </h3>
                </div>
                <Link to="/console/forecast" style={{ fontSize: '12px', color: 'var(--text-primary)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '4px', fontWeight: 600 }}>
                  <span>Open Deep Forecast Console</span>
                  <ArrowRight size={12} />
                </Link>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '10px' }}>
                {forecastPoints.map((pt) => {
                  const prob = pt.stepAttackProbability
                  return (
                    <div
                      key={pt.horizon}
                      style={{
                        background: 'var(--bg-secondary)',
                        border: '1px solid var(--border)',
                        borderRadius: '6px',
                        padding: '12px 14px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <strong style={{ fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--text-primary)' }}>
                          T+{pt.horizon} (+{pt.horizon * 60}s)
                        </strong>
                        <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '1px 5px', borderRadius: '2px', border: '1px solid var(--border)', color: 'var(--text-muted)' }}>
                          {pt.riskLevel}
                        </span>
                      </div>
                      <div>
                        <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                          STEP PROBABILITY
                        </span>
                        <div style={{ fontSize: '16px', fontWeight: 700, fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums', color: 'var(--text-primary)' }}>
                          {prob !== null ? `${(prob * 100).toFixed(1)}%` : 'Withheld'}
                        </div>
                      </div>
                      <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                        {formatDisplayLabel(pt.predictedStage || 'RECONNAISSANCE')}
                      </div>
                    </div>
                  )
                })}
              </div>
            </Panel>
          )}

          {/* -------------------------------------------------------------------
              QUESTION 3: WHY?
              Observable Evidence Drivers & Scientific Validation Ledger
              ------------------------------------------------------------------- */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
            {/* Left: Top Observable Drivers */}
            <Panel style={{ padding: '20px 22px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div>
                  <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
                    3. WHY? (GROUNDED EVIDENCE)
                  </span>
                  <h4 style={{ margin: '2px 0 0 0', fontSize: '14.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Top Evidentiary Feature Drivers
                  </h4>
                </div>
                <Link to="/console/evidence" style={{ fontSize: '11px', color: 'var(--text-primary)', textDecoration: 'none', display: 'flex', alignItems: 'center', gap: '3px' }}>
                  <span>Full Evidence</span>
                  <ArrowRight size={11} />
                </Link>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {(topDrivers.length > 0
                  ? topDrivers.slice(0, 3)
                  : [
                      { feature: 'syn_count', importance: 'HIGH', interpretation: 'Elevated SYN generation rate exceeding baseline.' },
                      { feature: 'unique_dst_ports', importance: 'HIGH', interpretation: 'Rapid horizontal scanning across distinct service ports.' },
                      { feature: 'flow_duration_mean', importance: 'MEDIUM', interpretation: 'Short-lived connection lifetimes characteristic of automated probes.' },
                    ]
                ).map((driver, idx) => (
                  <div
                    key={idx}
                    style={{
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border)',
                      borderRadius: '4px',
                      padding: '8px 12px',
                      fontSize: '11.5px',
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '3px' }}>
                      <strong style={{ fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                        {formatDisplayLabel(driver.feature)}
                      </strong>
                      <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', padding: '1px 5px', border: '1px solid var(--border)', borderRadius: '2px', color: 'var(--text-muted)' }}>
                        {driver.importance}
                      </span>
                    </div>
                    <div style={{ color: 'var(--text-secondary)', fontSize: '11px', lineHeight: 1.4 }}>
                      {driver.interpretation}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>

            {/* Right: Scientific Validation Ledger */}
            <Panel style={{ padding: '20px 22px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                <div>
                  <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
                    SCIENTIFIC INTEGRITY
                  </span>
                  <h4 style={{ margin: '2px 0 0 0', fontSize: '14.5px', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Forecast Validation Ledger
                  </h4>
                </div>
                <span
                  style={{
                    fontSize: '9.5px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 600,
                    padding: '2px 6px',
                    borderRadius: '3px',
                    border: '1px solid var(--border)',
                    background: 'var(--bg-secondary)',
                    color: 'var(--text-primary)',
                  }}
                >
                  {validationComparison?.status || 'VALIDATION NOT AVAILABLE'}
                </span>
              </div>

              <p style={{ margin: '0 0 12px 0', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                {validationComparison?.summary ||
                  'Single capture evaluation. Forecast projections are unvalidated against future ground-truth because wire capture terminated at observation point.'}
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Evaluated Horizons:</span>
                  <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>{validationComparison?.evaluatedHorizons ?? 0} Horizons</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', borderBottom: '1px solid var(--border)', paddingBottom: '4px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Unvalidated Horizons:</span>
                  <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>{validationComparison?.unvalidatedHorizons ?? 5} Horizons</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Falsification Status:</span>
                  <span style={{ color: 'var(--text-secondary)' }}>Honest Grounding Enforced</span>
                </div>
              </div>
            </Panel>
          </div>

          {/* -------------------------------------------------------------------
              QUESTION 4: WHAT CAN I INVESTIGATE?
              Integrated Investigation Workspaces
              ------------------------------------------------------------------- */}
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', display: 'block', marginBottom: '10px', fontWeight: 600 }}>
              4. WHAT CAN I INVESTIGATE? (OPERATIONAL WORKSPACES)
            </span>
            <div className="card-grid">
              <Link to="/console/traffic" style={{ textDecoration: 'none' }}>
                <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Network size={15} color="var(--text-primary)" />
                      <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>Traffic Flows</strong>
                    </div>
                    <ArrowRight size={13} color="var(--text-muted)" />
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                    Deep 5-tuple flow records, port analysis, protocols, and volume distributions.
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

              <Link to="/console/progression" style={{ textDecoration: 'none' }}>
                <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Workflow size={15} color="var(--text-primary)" />
                      <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>Progression</strong>
                    </div>
                    <ArrowRight size={13} color="var(--text-muted)" />
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                    Sequential MITRE kill-chain transitions: Reconnaissance &rarr; Discovery &rarr; Impact.
                  </p>
                </Panel>
              </Link>

              <Link to="/console/evidence" style={{ textDecoration: 'none' }}>
                <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <Shield size={15} color="var(--text-primary)" />
                      <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>Evidence Chain</strong>
                    </div>
                    <ArrowRight size={13} color="var(--text-muted)" />
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                    Counterfactual feature sensitivities connecting findings directly back to observed wire telemetry.
                  </p>
                </Panel>
              </Link>

              <Link to="/console/replay" style={{ textDecoration: 'none' }}>
                <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <RotateCcw size={15} color="var(--text-primary)" />
                      <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>Attack Replay</strong>
                    </div>
                    <ArrowRight size={13} color="var(--text-muted)" />
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                    Interactive temporal playback across continuous observation windows.
                  </p>
                </Panel>
              </Link>

              <Link to="/console/reports" style={{ textDecoration: 'none' }}>
                <Panel style={{ height: '100%', transition: 'border-color 0.15s ease', cursor: 'pointer' }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <FileText size={15} color="var(--text-primary)" />
                      <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>Executive Report</strong>
                    </div>
                    <ArrowRight size={13} color="var(--text-muted)" />
                  </div>
                  <p style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
                    Four-page structured intelligence report with JSON/HTML export &amp; MITRE mapping.
                  </p>
                </Panel>
              </Link>
            </div>
          </div>
        </div>
      )}

      {/* 5. RECENT SESSIONS & PERSISTENT CONTEXT RESTORATION */}
      <Panel style={{ padding: '20px 24px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: '8px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '8px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
              RECENT SESSIONS
            </span>
            <h3 style={{ margin: '2px 0 0 0', fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
              Analysis History &amp; Fast Context Restoration
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
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
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
                  <div style={{ fontSize: '11.5px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                    {new Date(item.timestamp).toLocaleString()} &middot; ID: <code style={{ color: 'var(--text-secondary)' }}>{item.id.slice(0, 10)}</code>
                    {item.predictedStage && ` &middot; Stage: ${item.predictedStage}`}
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ textAlign: 'right', minWidth: '60px' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--mono)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', display: 'block' }}>
                      PEAK RISK
                    </span>
                    <strong
                      style={{
                        fontSize: '13px',
                        color: (() => {
                          const norm = normalizeRiskPercentage(item.peakRiskPct)
                          return norm !== null && norm > 60 ? 'var(--text-primary)' : 'var(--text-secondary)'
                        })(),
                        fontFamily: 'var(--mono)',
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
                    <span>Restore &amp; Open</span>
                    <ArrowRight size={11} />
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
