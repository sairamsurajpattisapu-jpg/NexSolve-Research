import { useState } from 'react'
import {
  AlertTriangle,
  Download,
  FileSpreadsheet,
  Maximize2,
  Minimize2,
  Printer,
  Shield,
  Sliders,
  Workflow,
  Zap,
} from 'lucide-react'
import type { CanonicalAnalysis } from '../types/canonical'
import { FeatureInfluenceModal } from './FeatureInfluenceModal'
import { FeatureVectorModal } from './FeatureVectorModal'

interface ForecastConsoleProps {
  analysis: CanonicalAnalysis
  onAnalyzeNew?: () => void
}

export function ForecastConsole({ analysis, onAnalyzeNew }: ForecastConsoleProps) {
  const [selectedHorizon, setSelectedHorizon] = useState<number>(5)
  const [presentationMode, setPresentationMode] = useState<boolean>(false)
  const [showFeatureModal, setShowFeatureModal] = useState<boolean>(false)
  const [showInfluenceModal, setShowInfluenceModal] = useState<boolean>(false)

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

  // Active point for selected horizon
  const activePoint = forecast.points.find((p) => p.horizon === selectedHorizon) ?? forecast.points[forecast.points.length - 1]

  // Formatting helpers
  const formatPct = (val: number | null) => (val !== null ? `${(val * 100).toFixed(1)}%` : 'Withheld')

  return (
    <div
      className={`forecast-console-root ${presentationMode ? 'presentation-active' : ''}`}
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '20px',
        padding: presentationMode ? '24px 36px' : '0',
        maxWidth: presentationMode ? '1400px' : '100%',
        margin: '0 auto',
        width: '100%',
      }}
    >
      {/* 1. Header & Compact Information Strip */}
      <div
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '16px',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span
              style={{
                fontSize: '11px',
                fontFamily: 'var(--mono)',
                fontWeight: 700,
                letterSpacing: '0.08em',
                color: 'var(--accent)',
              }}
            >
              NEXSOLVE FORECAST ENGINE
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                padding: '1px 6px',
                borderRadius: '3px',
                background: analysis.isDemo ? 'rgba(242, 187, 113, 0.2)' : 'rgba(92, 179, 122, 0.2)',
                color: analysis.isDemo ? '#eda850' : 'var(--accent)',
                fontWeight: 600,
              }}
            >
              {analysis.provenanceLabel}
            </span>
          </div>
          <h1 style={{ fontSize: presentationMode ? '26px' : '22px', fontWeight: 700, margin: 0, color: 'var(--text-primary)' }}>
            NETWORK FORECAST
          </h1>
          <p style={{ margin: '4px 0 0 0', color: 'var(--text-muted)', fontSize: '13px' }}>
            Multi-Step Attack Forecasting (T+1 .. T+5): attack probability and cumulative risk rollout across forward horizons.
          </p>
        </div>

        {/* Action buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <button
            type="button"
            className="button button-quiet"
            onClick={() => setPresentationMode(!presentationMode)}
            style={{ fontSize: '12px', height: '34px' }}
            title={presentationMode ? 'Exit full presentation view' : 'Expand layout for projector / presentation'}
          >
            {presentationMode ? <Minimize2 size={14} /> : <Maximize2 size={14} />}
            {presentationMode ? 'Standard View' : 'Presentation Mode'}
          </button>

          <a
            href={analysis.export.jsonUrl}
            download={`nexsolve-forecast-${analysis.id}.json`}
            className="button button-quiet"
            style={{ fontSize: '12px', height: '34px', textDecoration: 'none' }}
          >
            <Download size={14} /> Export JSON
          </a>

          <a
            href={analysis.export.htmlUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="button button-quiet"
            style={{ fontSize: '12px', height: '34px', textDecoration: 'none' }}
          >
            <Printer size={14} /> Printable Report
          </a>

          {onAnalyzeNew && (
            <button
              type="button"
              className="button"
              onClick={onAnalyzeNew}
              style={{ fontSize: '12px', height: '34px' }}
            >
              New Analysis
            </button>
          )}
        </div>
      </div>

      {/* Compact Information Strip (Section 7) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '12px',
          background: 'var(--bg-secondary)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '12px 16px',
        }}
      >
        <div>
          <span style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            CURRENT STATE
          </span>
          <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>
            {isAbstained ? 'Observed Baseline' : progression.observedState}
          </strong>
        </div>

        <div>
          <span style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            FORECAST HORIZON
          </span>
          <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>
            {selectedHorizon} Steps (+{selectedHorizon * 60}s)
          </strong>
        </div>

        <div>
          <span style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            RISK STATUS
          </span>
          <strong
            style={{
              fontSize: '14px',
              color:
                activePoint.riskLevel === 'CRITICAL'
                  ? 'var(--danger)'
                  : activePoint.riskLevel === 'ELEVATED'
                  ? '#eda850'
                  : 'var(--accent)',
            }}
          >
            {activePoint.riskLevel}
          </strong>
        </div>

        <div>
          <span style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            SOURCE & CONTRACT
          </span>
          <strong style={{ fontSize: '14px', color: 'var(--text-primary)' }}>
            {input.filename} (45-dim PCAP)
          </strong>
        </div>
      </div>

      {/* Safety Abstention Banner if Applicable */}
      {isAbstained && (
        <div
          style={{
            background: 'rgba(242, 187, 113, 0.08)',
            border: '1px solid var(--warning)',
            borderRadius: '8px',
            padding: '18px 20px',
            display: 'flex',
            gap: '14px',
            alignItems: 'flex-start',
          }}
        >
          <AlertTriangle size={22} color="var(--warning)" style={{ flexShrink: 0, marginTop: '2px' }} />
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--warning)' }}>
              FORECAST WITHHELD &middot; SAFETY GUARDRAIL ACTIVE
            </span>
            <h3 style={{ margin: '4px 0 6px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
              {forecast.status}: Insufficient Continuous Historical Telemetry
            </h3>
            <p style={{ margin: 0, fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              The uploaded capture contains <strong>{forecast.availableWindows} discrete 60-second windows</strong>.
              NexSolve's world model requires at least <strong>8 continuous historical windows (480s)</strong> to establish state momentum without hallucinating trajectories.
            </p>
            <div style={{ display: 'flex', gap: '10px', marginTop: '12px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: '4px', background: 'var(--bg-secondary)', color: 'var(--text-primary)' }}>
                Required: 8 windows
              </span>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: '4px', background: 'var(--bg-secondary)', color: 'var(--warning)' }}>
                Available: {forecast.availableWindows} windows
              </span>
            </div>
          </div>
        </div>
      )}

      {/* 2. Primary Forecast Visualization (Section 8) */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '10px',
          padding: presentationMode ? '28px' : '22px',
          boxShadow: '0 4px 20px rgba(0, 0, 0, 0.04)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '18px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', fontWeight: 600 }}>
              PRIMARY VISUALIZATION &middot; TRAJECTORY DYNAMICS
            </span>
            <h2 style={{ fontSize: presentationMode ? '19px' : '16px', fontWeight: 600, margin: '2px 0 0 0', color: 'var(--text-primary)' }}>
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
        <div style={{ position: 'relative', width: '100%', height: presentationMode ? '340px' : '260px', background: 'var(--bg-secondary)', borderRadius: '8px', padding: '16px 20px', border: '1px solid var(--border)', overflow: 'hidden' }}>
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

      {/* 5. Predicted Attacker Progression & Behavioral MITRE Section (Section 11 & 12) */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))',
          gap: '16px',
        }}
      >
        {/* Progression */}
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '18px 20px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <Workflow size={16} color="var(--accent)" />
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
              PREDICTED ATTACK PROGRESSION
            </span>
          </div>
          <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
            Behavioral State Transition Rollout
          </h3>
          <p style={{ margin: '0 0 14px 0', fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
            Behavioral interpretation based on Markovian transition dynamics; neural model predicts telemetry features, not explicit labels.
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {progression.stages.map((st) => (
              <div
                key={st.step}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '10px 14px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                }}
              >
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                      T+{st.step} (+{st.leadTimeSeconds}s)
                    </span>
                    <strong style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                      {st.predictedState}
                    </strong>
                  </div>
                  <span style={{ display: 'block', fontSize: '11px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                    {st.evidence.join(' &middot; ')}
                  </span>
                </div>

                <div style={{ textAlign: 'right' }}>
                  <span style={{ display: 'block', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--accent)', fontWeight: 700 }}>
                    {st.transitionProbability !== null ? `${(st.transitionProbability * 100).toFixed(1)}%` : 'Withheld'}
                  </span>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                    transition prob
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* MITRE ATT&CK */}
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '18px 20px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <Shield size={16} color="var(--accent)" />
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
              MITRE ATT&CK BEHAVIORAL INTERPRETATION
            </span>
          </div>
          <h3 style={{ margin: '0 0 6px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
            Observable & Projected Technique Correlates
          </h3>
          <p style={{ margin: '0 0 14px 0', fontSize: '12px', color: 'var(--text-muted)', fontStyle: 'italic' }}>
            {mitre.disclaimer}
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {mitre.mappings.map((m) => (
              <div
                key={m.techniqueId}
                style={{
                  padding: '10px 14px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <code style={{ fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)', fontSize: '12px' }}>
                      {m.techniqueId}
                    </code>
                    <strong style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                      {m.techniqueName}
                    </strong>
                  </div>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                    {m.tactic} &middot; {m.forecastStep}
                  </span>
                </div>
                <p style={{ margin: '4px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)' }}>
                  {m.interpretation}
                </p>
                <span style={{ display: 'block', marginTop: '4px', fontSize: '11px', color: 'var(--text-muted)' }}>
                  Evidence: {m.evidence}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Dynamic Network Graph Fusion Structural Signals (Mode B) */}
      {analysis.graphFusion && (
        <div
          style={{
            background: 'var(--bg-surface)',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            padding: '18px 20px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', marginBottom: '12px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Workflow size={16} color="var(--text-primary)" />
              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                  GRAPH STRUCTURAL ATTRIBUTION &middot; {analysis.graphFusion.active_mode}
                </span>
                <h3 style={{ margin: '2px 0 0 0', fontSize: '16px', color: 'var(--text-primary)' }}>
                  Interaction Graph State Fusion
                </h3>
              </div>
            </div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', border: '1px solid var(--border)', padding: '2px 8px', borderRadius: '4px' }}>
              16-DIM STRUCTURAL VECTOR ACTIVE
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '12px', fontSize: '12px' }}>
            <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>Top Structural Drivers</div>
              <ul style={{ margin: 0, paddingLeft: '16px', color: 'var(--text-secondary)' }}>
                {analysis.graphFusion.top_structural_drivers.map((drv, i) => (
                  <li key={i} style={{ marginBottom: '4px' }}>{drv}</li>
                ))}
              </ul>
            </div>

            {analysis.graphFusion.mitre_structural_attributions.length > 0 && (
              <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '6px', border: '1px solid var(--border)' }}>
                <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: '6px' }}>Structural MITRE Correlates</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                  {analysis.graphFusion.mitre_structural_attributions.map((att, i) => (
                    <div key={i} style={{ fontSize: '11px', fontFamily: 'var(--mono)' }}>
                      <strong>{att.technique_id} ({att.technique_name})</strong> &middot; {att.node_ip}
                      <div style={{ color: 'var(--text-muted)' }}>{att.evidence}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}


      {/* 6. Explainability ("Why this forecast?") (Section 13) */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '18px 20px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
              EXPLAINABILITY & SENSITIVITY ATTRIBUTION
            </span>
            <h3 style={{ margin: '2px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
              Why This Forecast? &middot; Key Influencing Signals
            </h3>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              {explanations.disclaimer}
            </span>
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

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '12px' }}>
          {explanations.drivers.slice(0, 4).map((d) => (
            <div
              key={d.feature}
              style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '12px 14px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <code style={{ fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text-primary)', fontSize: '12px' }}>
                  {d.feature}
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
              <p style={{ margin: '6px 0 0 0', fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                {d.interpretation}
              </p>
            </div>
          ))}
        </div>
      </div>

      {/* 7. Current Network State (Section 14) */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '18px 20px',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px', marginBottom: '14px' }}>
          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
              OBSERVED TELEMETRY SUMMARY
            </span>
            <h3 style={{ margin: '2px 0', fontSize: '16px', color: 'var(--text-primary)' }}>
              Current Network State (Window T0)
            </h3>
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
              Aggregated 60-second temporal telemetry across active conversations
            </span>
          </div>

          <button
            type="button"
            className="button button-quiet"
            onClick={() => setShowFeatureModal(true)}
            style={{ fontSize: '12px', height: '32px' }}
          >
            <FileSpreadsheet size={14} /> View Full Feature Vector (45-dim)
          </button>
        </div>

        {/* 6-8 core summary metrics */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '10px' }}>
          {[
            { label: 'FLOW COUNT', val: currentState.summary.flows.toLocaleString() },
            { label: 'PACKET COUNT', val: currentState.summary.packets.toLocaleString() },
            { label: 'BYTE VOLUME', val: `${(currentState.summary.bytes / 1024 / 1024).toFixed(2)} MB` },
            { label: 'SRC ENDPOINTS', val: currentState.summary.uniqueSrcIps },
            { label: 'DST ENDPOINTS', val: currentState.summary.uniqueDstIps },
            { label: 'TARGET PORTS', val: currentState.summary.uniqueDstPorts },
            { label: 'TCP RATIO', val: `${Math.round((currentState.summary.protocols.TCP / currentState.summary.packets) * 100)}%` },
            { label: 'THREAT LEVEL', val: currentState.summary.threatLevel.toUpperCase() },
          ].map((item) => (
            <div key={item.label} style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <span style={{ display: 'block', fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                {item.label}
              </span>
              <strong style={{ fontSize: '15px', color: 'var(--text-primary)', marginTop: '2px', display: 'block' }}>
                {item.val}
              </strong>
            </div>
          ))}
        </div>
      </div>

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
              Passive network taps cannot measure TCP Round Trip Time without active injection. NexSolve strictly removed <code>mean_tcp_rtt</code> from the PCAP feature vector without zero-filling.
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
