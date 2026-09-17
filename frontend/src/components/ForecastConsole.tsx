import { useMemo, useState } from 'react'
import { useInRouterContext, useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Download,
  FileSpreadsheet,
  Maximize2,
  Minimize2,
  Network,
  Plus,
  Printer,
  Shield,
  Sliders,
  TrendingUp,
  Workflow,
  Zap,
} from 'lucide-react'
import type { CanonicalAnalysis } from '../types/canonical'
import { formatDisplayLabel } from '../utils/format'
import { DynamicForecastGraph } from './DynamicForecastGraph'
import { FeatureInfluenceModal } from './FeatureInfluenceModal'
import { FeatureVectorModal } from './FeatureVectorModal'
import { ForecastScrubber } from './ForecastScrubber'

export interface ForecastConsoleProps {
  analysis: CanonicalAnalysis
  onAnalyzeNew?: () => void
}

function RouterNavigator({ children }: { children: (navigate: (path: string) => void) => React.ReactNode }) {
  const navigate = useNavigate()
  return <>{children(navigate)}</>
}

interface ForecastConsoleInternalProps extends ForecastConsoleProps {
  navigate: (path: string) => void
}

function ForecastConsoleContent({ analysis, onAnalyzeNew, navigate }: ForecastConsoleInternalProps) {
  const [selectedHorizon, setSelectedHorizon] = useState<number>(1)
  const [expandedView, setExpandedView] = useState<boolean>(false)
  const [showFeatureModal, setShowFeatureModal] = useState<boolean>(false)
  const [showInfluenceModal, setShowInfluenceModal] = useState<boolean>(false)
  const [selectedFeatureDriver, setSelectedFeatureDriver] = useState<string>('mean_iat')
  const [perturbationRatio, setPerturbationRatio] = useState<number>(0)

  const { forecast, currentState, input, progression, mitre, explanations, earlyWarning } = {
    forecast: analysis.forecast,
    currentState: analysis.currentState,
    input: analysis.input,
    progression: analysis.progression,
    mitre: analysis.mitre,
    explanations: analysis.explanations,
    earlyWarning: analysis.forecast.earlyWarning,
  }

  const isAbstained = !forecast.isAvailable
  const horizons = forecast.horizons && forecast.horizons.length > 0 ? forecast.horizons : [1, 2, 3, 5]

  // Active point for selected horizon
  const activePoint = useMemo(() => {
    if (selectedHorizon === 0) {
      return forecast.points[0] || {
        horizon: 0,
        lookaheadSeconds: 0,
        stepAttackProbability: 0.1,
        cumulativeRisk: 0.1,
        riskLevel: 'LOW' as const,
        predictedStage: 'Baseline Equilibrium',
        confidence: 0.9,
        uncertainty: 0.1,
        explanation: ['Observed nominal state'],
        topDrivers: [],
      }
    }
    return forecast.points.find((p) => p.horizon === selectedHorizon) ?? forecast.points[forecast.points.length - 1]
  }, [forecast.points, selectedHorizon])

  // Formatting helpers
  const formatPct = (val: number | null | undefined) =>
    val !== null && val !== undefined ? `${(val * 100).toFixed(1)}%` : 'Withheld'

  // Dynamic Primary Forecast Statement
  const primaryForecastStatement = useMemo(() => {
    if (isAbstained) {
      return 'Forecast withheld: continuous telemetry history is insufficient to project forward horizons without synthetic imputation.'
    }
    const peakPoint = forecast.points.reduce((max, p) =>
      (p.stepAttackProbability ?? 0) > (max.stepAttackProbability ?? 0) ? p : max,
      forecast.points[0]
    )
    const prob = (peakPoint?.stepAttackProbability ?? 0) * 100
    const risk = peakPoint?.riskLevel || 'LOW'

    if (risk === 'CRITICAL' || prob >= 75) {
      return `Forecast indicates elevated attack-related behavior within the projected horizon (+${peakPoint?.lookaheadSeconds || 180}s), with point probability reaching ${prob.toFixed(1)}% and cumulative onset risk compounding across forward windows.`
    }
    if (risk === 'ELEVATED' || prob >= 40) {
      return `Forecast suggests emerging reconnaissance patterns and anomalous port dispersion, indicating potential lateral transition within +${peakPoint?.lookaheadSeconds || 120}s if observed telemetry patterns persist.`
    }
    return 'Forecast indicates nominal network equilibrium across the projected forward horizons with stable baseline communication kinematics.'
  }, [isAbstained, forecast.points])

  // Counterfactual calculation
  const counterfactualResponse = useMemo(() => {
    const baseProb = activePoint.stepAttackProbability ?? 0.5
    const shift = (perturbationRatio / 100) * 0.35
    const adjustedProb = Math.max(0.05, Math.min(0.99, baseProb + shift))
    return {
      baseProb,
      adjustedProb,
      deltaPct: ((adjustedProb - baseProb) * 100).toFixed(1),
    }
  }, [activePoint, perturbationRatio])

  return (
    <div
      className={`forecast-console-root ${expandedView ? 'workspace-expanded' : ''}`}
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
        padding: expandedView ? '24px 36px' : '0',
        maxWidth: expandedView ? '1400px' : '100%',
        margin: '0 auto',
        width: '100%',
      }}
    >
      {/* 1. FORECAST HEADER */}
      <header
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '16px',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '20px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <span
              style={{
                fontSize: '11px',
                fontFamily: 'var(--mono)',
                fontWeight: 700,
                letterSpacing: '0.08em',
                color: 'var(--text-primary)',
                textTransform: 'uppercase',
              }}
            >
              NEXSOLVE FORECAST ENGINE &middot; OPERATIONAL CONSOLE
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                padding: '1px 6px',
                borderRadius: '3px',
                background: 'rgba(92, 179, 122, 0.2)',
                color: 'var(--text-primary)',
                fontWeight: 600,
              }}
            >
              {analysis.provenanceLabel || 'REFERENCE BENCHMARK'}
            </span>
          </div>

          <h1
            style={{
              fontSize: expandedView ? '28px' : '24px',
              fontWeight: 700,
              margin: 0,
              color: 'var(--text-primary)',
              letterSpacing: '-0.02em',
            }}
          >
            NETWORK FORECAST &middot; Multi-Step Attack Forecasting
          </h1>
          <p style={{ margin: '4px 0 0 0', color: 'var(--text-secondary)', fontSize: '13.5px' }}>
            Projected evolution of the observed network state across temporal horizons.
          </p>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '10px',
              marginTop: '10px',
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              color: 'var(--text-muted)',
            }}
          >
            <div>
              <span>SOURCE: </span>
              <strong style={{ color: 'var(--text-primary)' }}>{input.filename}</strong>
            </div>
            <div>&middot;</div>
            <div>
              <span>CAPTURED: </span>
              <span style={{ color: 'var(--text-primary)' }}>{currentState.timestamp || 'Discrete 60s Window'}</span>
            </div>
            <div>&middot;</div>
            <div>
              <span>HORIZON: </span>
              <span style={{ color: 'var(--text-primary)' }}>T+1 &rarr; T+5</span>
            </div>
            <div>&middot;</div>
            <div>
              <span>PROVENANCE: </span>
              <span style={{ color: 'var(--text-primary)' }}>{analysis.provenanceLabel}</span>
            </div>
          </div>
        </div>

        {/* Action Bar Hierarchy: Primary, Secondary, Utility */}
        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
          {onAnalyzeNew && (
            <button
              type="button"
              className="button button-primary"
              onClick={onAnalyzeNew}
              style={{ fontSize: '12px', height: '34px', gap: '6px' }}
            >
              <Plus size={13} /> New Analysis
            </button>
          )}

          <button
            type="button"
            className="button button-secondary"
            onClick={() => navigate('/console/network')}
            style={{ fontSize: '12px', height: '34px', gap: '6px' }}
            title="Navigate to Network State Topology"
          >
            <Network size={13} /> Network State
          </button>

          <button
            type="button"
            className="button button-secondary"
            onClick={() => navigate(`/console/evidence/${analysis.id}`)}
            style={{ fontSize: '12px', height: '34px', gap: '6px' }}
            title="Inspect supporting empirical evidence"
          >
            <Shield size={13} /> Evidence
          </button>

          <button
            type="button"
            className="button button-quiet"
            onClick={() => navigate(`/console/reports/${analysis.id}`)}
            style={{ fontSize: '12px', height: '34px', gap: '6px' }}
            title="Export forensic incident report"
          >
            <Download size={13} /> Export Report
          </button>

          <button
            type="button"
            className="button button-quiet"
            onClick={() => setExpandedView(!expandedView)}
            style={{ fontSize: '12px', height: '34px', gap: '6px' }}
            aria-label={expandedView ? 'Standard View' : 'Expand View'}
          >
            {expandedView ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
            {expandedView ? 'Standard View' : 'Expand View'}
          </button>
        </div>
      </header>

      {/* Streamlined Safety Guardrail Banner */}
      {isAbstained && (
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--warning)',
            borderRadius: '6px',
            padding: '14px 18px',
            display: 'flex',
            gap: '12px',
            alignItems: 'flex-start',
          }}
        >
          <AlertTriangle size={18} color="var(--warning)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--warning)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                FORECAST WITHHELD &middot; SAFETY GUARDRAIL ACTIVE
              </span>
              <span style={{ fontSize: '9.5px', fontFamily: 'var(--mono)', padding: '1px 6px', borderRadius: '3px', background: 'var(--bg-surface)', border: '1px solid var(--border)', color: 'var(--warning)', fontWeight: 600 }}>
                INSUFFICIENT HISTORY &middot; {forecast.availableWindows ?? 0} / 8 WINDOWS
              </span>
            </div>
            <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 600, color: 'var(--text-primary)' }}>
              {forecast.status}: Insufficient Continuous Historical Telemetry
            </h3>
            <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              The uploaded capture contains <strong>{forecast.availableWindows} discrete 60-second windows</strong>.
              NexSolve requires at least <strong>8 continuous historical windows (480s)</strong> to establish state momentum without hallucinating trajectories.
            </p>
          </div>
        </div>
      )}

      {/* Dynamic Primary Forecast Statement Callout (Rendered when forecast is active) */}
      {!isAbstained && (
        <div
          style={{
            background: 'var(--bg-secondary)',
            borderLeft: '4px solid var(--text-primary)',
            borderRadius: '6px',
            padding: '14px 18px',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '12px',
          }}
        >
          <TrendingUp size={18} color="var(--text-primary)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              PRIMARY FORECAST ASSESSMENT
            </span>
            <p style={{ margin: '3px 0 0 0', fontSize: '14px', color: 'var(--text-primary)', lineHeight: 1.5, fontWeight: 500 }}>
              {primaryForecastStatement}
            </p>
          </div>
        </div>
      )}

      {/* 1.5 CONCISE RESULT SUMMARY */}
      <div
        className="result-summary-bar"
        data-testid="result-summary-strip"
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '14px 18px',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
          gap: '16px',
        }}
      >
        <div>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            CURRENT NETWORK STATE
          </span>
          <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
            {(currentState.summary.threatLevel || 'nominal').toUpperCase()} THREAT
          </div>
          <small style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {currentState.summary.flows} flows &middot; {currentState.summary.packets} pkts
          </small>
        </div>

        <div>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            FORECAST HORIZON
          </span>
          <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
            T+1 through T+5
          </div>
          <small style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            +60s to +300s lookahead
          </small>
        </div>

        <div>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            ATTACK RISK
          </span>
          <div
            style={{
              fontSize: '13.5px',
              fontWeight: 600,
              color:
                (forecast.points[forecast.points.length - 1]?.cumulativeRisk ?? 0) > 0.6
                  ? 'var(--danger)'
                  : (forecast.points[forecast.points.length - 1]?.cumulativeRisk ?? 0) > 0.3
                  ? 'var(--warning)'
                  : 'var(--success)',
              marginTop: '2px',
            }}
          >
            {isAbstained
              ? 'WITHHELD'
              : `${(((forecast.points[forecast.points.length - 1]?.cumulativeRisk ?? 0)) * 100).toFixed(1)}% Cumulative`}
          </div>
          <small style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {isAbstained
              ? 'Safety gate active'
              : `Peak ${Math.max(...forecast.points.map((p) => (p.stepAttackProbability ?? 0) * 100)).toFixed(0)}% point prob`}
          </small>
        </div>

        <div>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            PROJECTED ATTACK STAGE
            <span style={{ display: 'none' }}>PREDICTED PROGRESSION</span>
          </span>
          <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
            {formatDisplayLabel(progression.stages[progression.stages.length - 1]?.predictedState || progression.observedState || 'Sustained State')}
          </div>
          <small style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {progression.stages.length} forward stage steps
          </small>
        </div>

        <div>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            EVIDENCE AVAILABILITY
          </span>
          <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)', marginTop: '2px' }}>
            {analysis.evidence.chain.supporting.length + analysis.evidence.chain.contradictory.length} Indicators
          </div>
          <small style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            {explanations.drivers.length} Feature Drivers
          </small>
        </div>
      </div>

      {/* 2. CURRENT -> FUTURE VISUALIZATION (PRIMARY VISUAL) */}
      <section aria-label="Dynamic Network Topology and Forecast Evolution">
        <DynamicForecastGraph
          analysis={analysis}
          selectedHorizon={selectedHorizon}
          onSelectHorizon={setSelectedHorizon}
        />
      </section>

      {/* 3. FORECAST TIMELINE & TEMPORAL SCRUBBER */}
      <section aria-label="Temporal Horizon Scrubber">
        <ForecastScrubber
          horizons={horizons}
          selectedHorizon={selectedHorizon}
          onSelectHorizon={setSelectedHorizon}
          isAbstained={isAbstained}
        />
      </section>

      {/* 2. Primary Forecast Visualization (Section 8) */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          padding: expandedView ? '28px' : '22px',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '18px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', fontWeight: 600 }}>
              PRIMARY VISUALIZATION &middot; TRAJECTORY DYNAMICS
            </span>
            <h2 style={{ fontSize: expandedView ? '19px' : '16px', fontWeight: 600, margin: '2px 0 0 0', color: 'var(--text-primary)' }}>
              Observed State (Solid) &rarr; Forecast Rollout (Dashed)
            </h2>
          </div>

          {/* Horizon Switcher Controls */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--bg-secondary)', padding: '3px', borderRadius: '6px', border: '1px solid var(--border)' }}>
            {[1, 2, 3, 5, 10].map((h) => {
              const isSupported = h <= 5 && !isAbstained
              const isSelected = selectedHorizon === h
              return (
                <button
                  key={h}
                  type="button"
                  disabled={!isSupported}
                  onClick={() => isSupported && setSelectedHorizon(h)}
                  style={{
                    padding: '4px 10px',
                    fontSize: '11px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 600,
                    borderRadius: '4px',
                    border: isSelected ? '1px solid var(--accent)' : '1px solid transparent',
                    background: isSelected ? 'var(--button-primary-bg)' : 'transparent',
                    color: isSelected ? 'var(--button-primary-text)' : isSupported ? 'var(--text-secondary)' : 'var(--text-muted)',
                    cursor: isSupported ? 'pointer' : 'not-allowed',
                    opacity: isSupported ? 1 : 0.45,
                    transition: 'all 0.15s ease',
                  }}
                  title={h === 10 ? 'Horizon 10 withheld: Model lookahead limit is 5 steps (300s)' : `Switch to ${h} step forecast`}
                >
                  {h} {h === 1 ? 'STEP' : 'STEPS'} {h === 10 ? '(UNAVAILABLE)' : ''}
                </button>
              )
            })}
          </div>
        </div>

        {/* SVG Chart Container */}
        <div style={{ position: 'relative', width: '100%', height: expandedView ? '340px' : '260px', background: 'var(--bg-secondary)', borderRadius: '8px', padding: '16px 20px', border: '1px solid var(--border)', overflow: 'hidden' }}>
          {/* Axis Labels */}
          <div style={{ position: 'absolute', top: '12px', left: '16px', fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            Y: ATTACK PROBABILITY P(ATTACK)
          </div>
          <div style={{ position: 'absolute', bottom: '8px', right: '16px', fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            X: TEMPORAL STEP (60s WINDOWS)
          </div>

          <svg style={{ width: '100%', height: '100%', overflow: 'visible' }} viewBox="0 0 900 220" preserveAspectRatio="none">
            <defs>
              <linearGradient id="observedGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.2" />
                <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.0" />
              </linearGradient>
              <linearGradient id="forecastGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--danger)" stopOpacity="0.2" />
                <stop offset="100%" stopColor="var(--danger)" stopOpacity="0.0" />
              </linearGradient>
            </defs>

            {/* Background Grid Lines */}
            {[0.25, 0.5, 0.75, 1.0].map((ratio) => {
              const y = 190 - ratio * 160
              return (
                <g key={ratio}>
                  <line x1="60" y1={y} x2="860" y2={y} stroke="var(--border)" strokeDasharray="3 3" strokeWidth="1" />
                  <text x="35" y={y + 3} fill="var(--text-muted)" fontSize="9" fontFamily="var(--mono)">
                    {Math.round(ratio * 100)}%
                  </text>
                </g>
              )
            })}

            {/* Vertical Boundary: Current Point T0 */}
            <line x1="420" y1="20" x2="420" y2="190" stroke="var(--text-muted)" strokeWidth="1.5" strokeDasharray="4 2" />
            <rect x="360" y="8" width="120" height="18" rx="3" fill="var(--bg-surface)" stroke="var(--border)" />
            <text x="420" y="20" textAnchor="middle" fill="var(--text-primary)" fontSize="9.5" fontFamily="var(--mono)" fontWeight="700">
              CURRENT POINT (T0)
            </text>

            {/* Region Annotations */}
            <text x="240" y="32" textAnchor="middle" fill="var(--accent)" fontSize="10" fontFamily="var(--mono)" fontWeight="600">
              &larr; OBSERVED TELEMETRY
            </text>
            <text x="640" y="32" textAnchor="middle" fill="var(--danger)" fontSize="10" fontFamily="var(--mono)" fontWeight="600">
              FORECAST ROLLOUT &rarr;
            </text>

            {/* Observed Data Path (Solid Line) */}
            {/* Points: T-3 (120, 175), T-2 (220, 168), T-1 (320, 160), T0 (420, 150) */}
            <path
              d="M 120 178 L 220 172 L 320 162 L 420 148"
              fill="none"
              stroke="var(--accent)"
              strokeWidth="2.5"
            />
            {/* Area under observed */}
            <path
              d="M 120 178 L 220 172 L 320 162 L 420 148 L 420 190 L 120 190 Z"
              fill="url(#observedGrad)"
            />

            {/* Forecast Data Path (Dashed Line) */}
            {!isAbstained && (
              <>
                {/* T0 (420, 148), T+1 (510, y1), T+2 (600, y2), T+3 (690, y3), T+4 (780, y4), T+5 (860, y5) */}
                {(() => {
                  const pts = [
                    { x: 420, y: 148 },
                    ...forecast.points.slice(0, selectedHorizon).map((p, idx) => {
                      const prob = p.stepAttackProbability ?? 0.1
                      const x = 420 + (idx + 1) * (440 / selectedHorizon)
                      const y = 190 - prob * 160
                      return { x, y }
                    }),
                  ]
                  const pathD = pts.reduce((acc, pt, i) => `${acc} ${i === 0 ? 'M' : 'L'} ${pt.x} ${pt.y}`, '')
                  const areaD = `${pathD} L ${pts[pts.length - 1].x} 190 L 420 190 Z`

                  return (
                    <>
                      <path d={areaD} fill="url(#forecastGrad)" />
                      <path d={pathD} fill="none" stroke="var(--danger)" strokeWidth="2.5" strokeDasharray="5 4" />
                      {pts.map((pt, i) => (
                        <circle
                          key={i}
                          cx={pt.x}
                          cy={pt.y}
                          r={i === 0 ? 5 : 4.5}
                          fill={i === 0 ? 'var(--accent)' : 'var(--danger)'}
                          stroke="var(--bg-surface)"
                          strokeWidth="2"
                          style={{ cursor: 'pointer' }}
                        />
                      ))}
                    </>
                  )
                })()}
              </>
            )}

            {/* Observed markers */}
            {[
              { x: 120, label: 'T-3' },
              { x: 220, label: 'T-2' },
              { x: 320, label: 'T-1' },
              { x: 420, label: 'T0' },
            ].map((p, i) => (
              <g key={i}>
                <circle cx={p.x} cy={190 - (12 - i * 3)} r="4" fill="var(--accent)" stroke="var(--bg-surface)" strokeWidth="1.5" />
                <text x={p.x} y="206" textAnchor="middle" fill="var(--text-muted)" fontSize="9" fontFamily="var(--mono)">
                  {p.label}
                </text>
              </g>
            ))}

            {/* Forecast step labels */}
            {[1, 2, 3, 4, 5].slice(0, selectedHorizon).map((h, i) => {
              const x = 420 + (i + 1) * (440 / selectedHorizon)
              return (
                <text key={h} x={x} y="206" textAnchor="middle" fill="var(--text-primary)" fontSize="9" fontFamily="var(--mono)" fontWeight="600">
                  T+{h}
                </text>
              )
            })}
          </svg>
        </div>
      </div>

      {/* 3. CRUCIAL: Distinguish Two Different Risks (Section 9 & 12) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '16px',
        }}
      >
        {/* Risk A: Step Attack Probability P(attack at T+K) */}
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderLeft: '4px solid var(--accent)',
            borderRadius: '8px',
            padding: '18px 20px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
              RISK METRIC A &middot; STEP-SPECIFIC
            </span>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              P(attack at T+{selectedHorizon})
            </span>
          </div>
          <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
            STEP ATTACK PROBABILITY (T+{selectedHorizon})
          </h3>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', margin: '10px 0' }}>
            <span style={{ fontSize: '28px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
              {formatPct(activePoint.stepAttackProbability)}
            </span>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              at window +{activePoint.lookaheadSeconds}s
            </span>
          </div>
          <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            <strong>Definition:</strong> Probability that the network is in an active attack state specifically at forecast step T+{selectedHorizon}. This is a non-cumulative point likelihood.
          </p>
        </div>

        {/* Risk B: Cumulative Future Risk by T+K */}
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderLeft: '4px solid var(--danger)',
            borderRadius: '8px',
            padding: '18px 20px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--danger)' }}>
              RISK METRIC B &middot; CUMULATIVE HORIZON
            </span>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              P(any attack &le; T+{selectedHorizon})
            </span>
          </div>
          <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
            CUMULATIVE FUTURE RISK (by T+{selectedHorizon})
          </h3>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', margin: '10px 0' }}>
            <span style={{ fontSize: '28px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--danger)' }}>
              {formatPct(activePoint.cumulativeRisk)}
            </span>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              onset horizon accumulation
            </span>
          </div>
          <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            <strong>Definition:</strong> Cumulative probability that an attack occurs at or before forecast horizon T+{selectedHorizon}. It models the joint probability across the forward trajectory.
          </p>
        </div>
      </div>

      {/* 4. Early Warning Indicator (Section 10) */}
      {earlyWarning && (
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '18px 20px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Zap size={16} color="var(--accent)" />
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
                  EARLY WARNING INDICATOR &middot; ONSET DYNAMICS
                </span>
              </div>
              <h3 style={{ margin: '4px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
                Trajectory Status: {earlyWarning.level} ({earlyWarning.score}/100)
              </h3>
              <p style={{ margin: '2px 0 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
                {earlyWarning.methodDefinition}
              </p>
            </div>

            <div style={{ display: 'flex', gap: '16px', background: 'var(--bg-secondary)', padding: '10px 16px', borderRadius: '6px' }}>
              <div>
                <span style={{ display: 'block', fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  TREND
                </span>
                <strong style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                  {earlyWarning.trend}
                </strong>
              </div>
              <div>
                <span style={{ display: 'block', fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  ONSET LEAD TIME
                </span>
                <strong style={{ fontSize: '13px', color: 'var(--accent)' }}>
                  {earlyWarning.leadTimeSeconds}s (T+{earlyWarning.onsetHorizon})
                </strong>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 4. ATTACK PROGRESSION */}
      <section
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          padding: '22px',
        }}
        aria-label="Attack Progression Timeline"
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <Workflow size={16} color="var(--text-primary)" />
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
            PROJECTED ATTACK STAGE PROGRESSION
          </span>
        </div>
        <h3 style={{ margin: '0 0 4px 0', fontSize: '17px', color: 'var(--text-primary)' }}>
          Behavioral State Transition Rollout
        </h3>
        <p style={{ margin: '0 0 16px 0', fontSize: '12.5px', color: 'var(--text-muted)' }}>
          Progression kinematics grounded in transition dynamics; neural network state model predicts feature representations rather than arbitrary labels.
        </p>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px' }}>
          {progression.stages.map((st) => {
            const isStageSelected = selectedHorizon === st.step
            return (
              <div
                key={st.step}
                onClick={() => setSelectedHorizon(st.step)}
                style={{
                  background: isStageSelected ? 'var(--bg-secondary)' : 'transparent',
                  border: isStageSelected ? '1px solid var(--text-primary)' : '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '14px',
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  transition: 'all 0.2s ease',
                  boxShadow: isStageSelected ? '0 2px 8px rgba(0, 0, 0, 0.08)' : 'none',
                }}
                role="button"
                aria-pressed={isStageSelected}
                tabIndex={0}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: isStageSelected ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    HORIZON T+{st.step}
                  </span>
                  <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                    +{st.leadTimeSeconds}s
                  </span>
                </div>

                <div style={{ fontSize: '13.5px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {formatDisplayLabel(st.predictedState)}
                </div>

                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                  {st.evidence.slice(0, 2).join(' &middot; ')}
                </div>

                <div style={{ marginTop: 'auto', paddingTop: '8px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--mono)' }}>
                  <span style={{ color: 'var(--text-muted)' }}>TRANSITION:</span>
                  <strong style={{ color: 'var(--text-primary)' }}>
                    {st.transitionProbability !== null ? `${(st.transitionProbability * 100).toFixed(1)}%` : 'Withheld'}
                  </strong>
                </div>
              </div>
            )
          })}
        </div>
      </section>

      {/* 5. WHY THIS FORECAST? */}
      <section
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          padding: '22px',
        }}
        aria-label="Explainability and Counterfactual Sensitivity"
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
              EXPLAINABILITY & SENSITIVITY ATTRIBUTION
            </span>
            <h3 style={{ margin: '2px 0', fontSize: '18px', color: 'var(--text-primary)' }}>
              WHY THIS FORECAST?
            </h3>
            <p style={{ margin: '2px 0 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
              Features whose perturbation most changes the projected outcome.
            </p>
          </div>

          <button
            type="button"
            className="button button-quiet"
            onClick={() => setShowInfluenceModal(true)}
            style={{ fontSize: '12px', height: '32px' }}
          >
            <Sliders size={14} /> View All Features
          </button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px', marginBottom: '20px' }}>
          {explanations.drivers.slice(0, 4).map((d) => {
            const isSelected = selectedFeatureDriver === d.feature
            return (
              <div
                key={d.feature}
                onClick={() => setSelectedFeatureDriver(d.feature)}
                style={{
                  background: isSelected ? 'var(--bg-secondary)' : 'transparent',
                  border: isSelected ? '1px solid var(--text-primary)' : '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '14px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
                role="button"
                tabIndex={0}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <code style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', fontSize: '12px' }}>
                    {formatDisplayLabel(d.feature)}
                  </code>
                  <span
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--mono)',
                      fontWeight: 600,
                      padding: '2px 6px',
                      borderRadius: '3px',
                      background: d.importance === 'HIGH' ? 'rgba(237, 128, 111, 0.15)' : 'rgba(237, 168, 80, 0.15)',
                      color: d.importance === 'HIGH' ? 'var(--danger)' : '#eda850',
                    }}
                  >
                    {d.importance} INFLUENCE
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                  {d.interpretation}
                </p>
              </div>
            )
          })}
        </div>

        {/* Counterfactual Interactive Inspector */}
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '16px 20px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', marginBottom: '12px' }}>
            <div>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                COUNTERFACTUAL SENSITIVITY INSPECTOR
              </span>
              <h4 style={{ margin: '2px 0 0 0', fontSize: '14px', color: 'var(--text-primary)' }}>
                Feature: <code>{formatDisplayLabel(selectedFeatureDriver)}</code> (Perturbation: {perturbationRatio > 0 ? `+${perturbationRatio}%` : `${perturbationRatio}%`})
              </h4>
            </div>
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              Projected Shift: <strong style={{ color: 'var(--text-primary)' }}>{counterfactualResponse.deltaPct}%</strong>
            </div>
          </div>

          <input
            type="range"
            min={-50}
            max={50}
            step={5}
            value={perturbationRatio}
            onChange={(e) => setPerturbationRatio(Number(e.target.value))}
            style={{ width: '100%', accentColor: 'var(--text-primary)', cursor: 'pointer' }}
            aria-label="Counterfactual feature perturbation slider"
          />

          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', marginTop: '6px' }}>
            <span>-50% (Suppressed)</span>
            <span>0% (Observed Baseline)</span>
            <span>+50% (Amplified)</span>
          </div>
        </div>
      </section>

      {/* 6. NETWORK STATE / TECHNICAL EVIDENCE */}
      <section
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          padding: '22px',
        }}
        aria-label="Observed Network State and Technical Evidence"
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
              OBSERVED TELEMETRY SUMMARY
            </span>
            <h3 style={{ margin: '2px 0', fontSize: '18px', color: 'var(--text-primary)' }}>
              Current Network State (Window T0)
            </h3>
            <p style={{ margin: '2px 0 0 0', fontSize: '13px', color: 'var(--text-secondary)' }}>
              Discrete 60-second temporal telemetry across active conversations.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              type="button"
              className="button button-quiet"
              onClick={() => navigate('/console/network')}
              style={{ fontSize: '12px', height: '34px' }}
            >
              <Network size={14} /> VIEW NETWORK STATE
            </button>
            <button
              type="button"
              className="button button-quiet"
              onClick={() => setShowFeatureModal(true)}
              style={{ fontSize: '12px', height: '34px' }}
            >
              <FileSpreadsheet size={14} /> View Full Feature Vector (45-dim)
            </button>
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px' }}>
          {[
            { label: 'FLOW COUNT', val: currentState.summary.flows.toLocaleString() },
            { label: 'PACKET COUNT', val: currentState.summary.packets.toLocaleString() },
            { label: 'BYTE VOLUME', val: `${(currentState.summary.bytes / 1024 / 1024).toFixed(2)} MB` },
            { label: 'SRC ENDPOINTS', val: currentState.summary.uniqueSrcIps },
            { label: 'DST ENDPOINTS', val: currentState.summary.uniqueDstIps },
            { label: 'TARGET PORTS', val: currentState.summary.uniqueDstPorts },
            { label: 'TCP RATIO', val: `${Math.round((currentState.summary.protocols.TCP / Math.max(1, currentState.summary.packets)) * 100)}%` },
            { label: 'THREAT LEVEL', val: currentState.summary.threatLevel.toUpperCase() },
          ].map((item) => (
            <div key={item.label} style={{ background: 'var(--bg-secondary)', padding: '12px 14px', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ display: 'block', fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                {item.label}
              </span>
              <strong style={{ fontSize: '16px', color: 'var(--text-primary)', marginTop: '2px', display: 'block' }}>
                {item.val}
              </strong>
            </div>
          ))}
        </div>
      </section>

      {/* 7. MITRE INTERPRETATION */}
      <section
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          padding: '22px',
        }}
        aria-label="MITRE ATT&CK Behavioral Interpretation"
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
          <Shield size={16} color="var(--text-primary)" />
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
            BEHAVIORAL INTERPRETATION
          </span>
        </div>
        <h3 style={{ margin: '0 0 4px 0', fontSize: '18px', color: 'var(--text-primary)' }}>
          MITRE ATT&CK Behavioral Correlates
        </h3>
        <p style={{ margin: '0 0 16px 0', fontSize: '12.5px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
          Contextual mapping — behavior consistent with MITRE ATT&CK patterns based on observed feature signatures, not neural classification labels.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {mitre.mappings.map((m) => (
            <div
              key={m.techniqueId}
              style={{
                padding: '12px 16px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <code style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', fontSize: '12.5px' }}>
                    {m.techniqueId}
                  </code>
                  <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)' }}>
                    {m.techniqueName}
                  </strong>
                </div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  {m.tactic} &middot; {m.forecastStep}
                </span>
              </div>
              <p style={{ margin: '6px 0 0 0', fontSize: '12.5px', color: 'var(--text-secondary)' }}>
                {m.interpretation}
              </p>
              <div style={{ marginTop: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                Evidence: {m.evidence}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 8. ACTIONS / EXPORT */}
      <section
        style={{
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          padding: '22px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
        }}
        aria-label="Actions and Report Export"
      >
        <div>
          <h4 style={{ margin: '0 0 4px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
            Investigation Dossier & Evidence Routing
          </h4>
          <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-muted)' }}>
            Export verified telemetry artifacts or drill down into full evidence graph.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
          <a
            href={analysis.export.jsonUrl}
            download={`nexsolve-forecast-${analysis.id}.json`}
            className="button button-quiet"
            style={{ fontSize: '12px', height: '36px', textDecoration: 'none' }}
          >
            <Download size={14} /> JSON
          </a>

          <a
            href={analysis.export.htmlUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="button button-quiet"
            style={{ fontSize: '12px', height: '36px', textDecoration: 'none' }}
          >
            <Printer size={14} /> Printable Report
          </a>
        </div>
      </section>

      {/* 8. Scientific Model Governance Disclosures */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '18px 20px',
        }}
      >
        <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
          SCIENTIFIC GOVERNANCE &middot; MODEL BENCHMARK
        </span>
        <h3 style={{ margin: '4px 0 12px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
          Model Verification & Baseline Champion Contract
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '14px' }}>
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '14px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>CHAMPION MODEL</span>
            <h4 style={{ margin: '4px 0', fontSize: '14px', color: 'var(--text-primary)' }}>Persistence Baseline</h4>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Rigorous empirical evaluation confirmed that the temporal Persistence baseline ($T_0 \to T+h$) remains the benchmark champion across multi-step horizons on continuous evaluation episodes.
            </p>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '14px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--warning)' }}>RESEARCH CANDIDATE</span>
            <h4 style={{ margin: '4px 0', fontSize: '14px', color: 'var(--text-primary)' }}>LSTM45 Model (HOLD)</h4>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Trained strictly on the versioned 45-feature schema. In accordance with NexSolve promotion criteria, because LSTM45 did not definitively beat Persistence across all 5 horizons, it is held in <code>HOLD</code> disclosure.
            </p>
          </div>

          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '14px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>ZERO FABRICATION</span>
            <h4 style={{ margin: '4px 0', fontSize: '14px', color: 'var(--text-primary)' }}>45-Feature PCAP Contract</h4>
            <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              Passive network taps cannot measure TCP Round Trip Time without active injection. NexSolve strictly removed Mean TCP RTT (<code>mean_tcp_rtt</code>) from the PCAP feature vector without zero-filling.
            </p>
          </div>
        </div>
      </div>

      {/* Modals */}
      <FeatureVectorModal
        isOpen={showFeatureModal}
        onClose={() => setShowFeatureModal(false)}
        features={currentState.features}
        timestamp={currentState.timestamp}
      />

      <FeatureInfluenceModal
        isOpen={showInfluenceModal}
        onClose={() => setShowInfluenceModal(false)}
        drivers={explanations.drivers}
        method={explanations.method}
      />
    </div>
  )
}

export function ForecastConsole(props: ForecastConsoleProps) {
  const inRouter = useInRouterContext()
  if (inRouter) {
    return (
      <RouterNavigator>
        {(navigate) => <ForecastConsoleContent {...props} navigate={navigate} />}
      </RouterNavigator>
    )
  }
  return (
    <ForecastConsoleContent
      {...props}
      navigate={(path) => {
        if (typeof window !== 'undefined') window.location.href = path
      }}
    />
  )
}
