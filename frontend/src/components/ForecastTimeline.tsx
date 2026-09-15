import { useState } from 'react'
import { Clock } from 'lucide-react'
import { Panel } from './Ui'
import { RiskBadge } from './RiskBadge'

export interface TimelinePoint {
  horizon: number
  lookaheadSeconds: number
  attackProbability: number | null
  cumulativeRisk: number | null
  riskLevel: string
  predictedStage: string | null
  timestamp?: string
  confidence?: number | null
  uncertainty?: number | null
}

interface ForecastTimelineProps {
  currentRisk?: number
  forecasts: TimelinePoint[]
  abstained?: boolean
  abstainedReason?: string | null
}

export function ForecastTimeline({
  currentRisk = 0.05,
  forecasts = [],
  abstained = false,
  abstainedReason,
}: ForecastTimelineProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null)

  // Construct continuous trajectory series: T0 + horizons
  const fullSeries = [
    {
      horizon: 0,
      lookaheadSeconds: 0,
      attackProbability: currentRisk,
      cumulativeRisk: currentRisk,
      riskLevel: currentRisk >= 0.75 ? 'CRITICAL' : currentRisk >= 0.5 ? 'HIGH' : currentRisk >= 0.25 ? 'MEDIUM' : 'LOW',
      predictedStage: currentRisk >= 0.5 ? 'ATTACK_OBSERVED' : 'NORMAL',
      label: 'NOW',
    },
    ...forecasts.map((f) => ({
      ...f,
      label: `T+${f.horizon}`,
    })),
  ]

  // Chart dimensions
  const width = 800
  const height = 240
  const padding = { top: 30, right: 30, bottom: 40, left: 50 }
  const innerW = width - padding.left - padding.right
  const innerH = height - padding.top - padding.bottom

  const xStep = innerW / Math.max(1, fullSeries.length - 1)

  const getY = (val: number | null) => {
    if (val === null || val === undefined) return innerH
    return innerH - Math.min(1.0, Math.max(0.0, val)) * innerH
  }

  // Generate SVG path for Attack Probability (Solid Line)
  const probPoints = fullSeries
    .filter((p) => p.attackProbability !== null)
    .map((p, i) => `${padding.left + i * xStep},${padding.top + getY(p.attackProbability)}`)

  const probPath = probPoints.length > 1 ? `M ${probPoints.join(' L ')}` : ''

  // Generate SVG path for Cumulative Risk (Area + Dashed Line)
  const cumPoints = fullSeries
    .filter((p) => p.cumulativeRisk !== null)
    .map((p, i) => `${padding.left + i * xStep},${padding.top + getY(p.cumulativeRisk)}`)

  const cumLine = cumPoints.length > 1 ? `M ${cumPoints.join(' L ')}` : ''
  const cumArea =
    cumPoints.length > 1
      ? `M ${cumPoints[0]} L ${cumPoints.slice(1).join(' L ')} L ${padding.left + (cumPoints.length - 1) * xStep},${padding.top + innerH} L ${padding.left},${padding.top + innerH} Z`
      : ''

  const activeHover = hoveredIndex !== null ? fullSeries[hoveredIndex] : fullSeries[fullSeries.length - 1]

  return (
    <Panel className="forecast-timeline-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              CONTINUOUS MULTI-HORIZON TRAJECTORY (T₀ → T+5)
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                padding: '2px 6px',
                borderRadius: '3px',
                background: 'rgba(104, 225, 216, 0.1)',
                color: 'var(--accent)',
              }}
            >
              MONOTONIC RISK ESCALATION
            </span>
          </div>
          <h3 style={{ fontSize: '18px', fontWeight: 700, margin: '4px 0 2px 0', color: 'var(--text-primary)' }}>
            Network Future Trajectory
          </h3>
          <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-muted)', maxWidth: '640px' }}>
            Simultaneous projection of instantaneous attack likelihood P(Attack at T+H) and cumulative infiltration risk Risk(H) across forward horizons.
          </p>
        </div>

        {/* Legend */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', fontSize: '11.5px', fontFamily: 'var(--mono)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '12px', height: '3px', background: 'var(--accent)', borderRadius: '2px' }} />
            <span style={{ color: 'var(--text-secondary)' }}>Attack Likelihood P(T+H)</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '12px', height: '3px', background: 'var(--danger)', borderRadius: '2px', borderTop: '1px dashed var(--danger)' }} />
            <span style={{ color: 'var(--text-secondary)' }}>Cumulative Infiltration Risk</span>
          </div>
        </div>
      </div>

      {abstained ? (
        <div
          style={{
            padding: '36px',
            textAlign: 'center',
            borderRadius: '6px',
            background: 'rgba(242, 187, 113, 0.05)',
            border: '1px dashed var(--warning)',
          }}
        >
          <Clock size={28} color="var(--warning)" style={{ margin: '0 auto 8px auto' }} />
          <h4 style={{ color: 'var(--text-primary)', margin: 0 }}>Trajectory Withheld by Safety Guardrail</h4>
          <p style={{ color: 'var(--text-secondary)', fontSize: '13px', margin: '6px auto 0 auto', maxWidth: '520px' }}>
            {abstainedReason || 'Input telemetry requires at least 8 continuous historical windows (480s) to establish valid state momentum.'}
          </p>
        </div>
      ) : (
        <div style={{ position: 'relative', width: '100%', overflowX: 'auto' }}>
          <svg
            viewBox={`0 0 ${width} ${height}`}
            style={{ width: '100%', minWidth: '600px', height: 'auto', display: 'block' }}
          >
            <defs>
              <linearGradient id="cum-risk-grad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="var(--danger)" stopOpacity="0.25" />
                <stop offset="100%" stopColor="var(--danger)" stopOpacity="0.0" />
              </linearGradient>
            </defs>

            {/* Grid horizontal lines */}
            {[0.0, 0.25, 0.5, 0.75, 1.0].map((v) => {
              const y = padding.top + getY(v)
              return (
                <g key={v}>
                  <line
                    x1={padding.left}
                    y1={y}
                    x2={width - padding.right}
                    y2={y}
                    stroke="var(--border)"
                    strokeDasharray="3 3"
                    strokeWidth="0.8"
                  />
                  <text
                    x={padding.left - 8}
                    y={y + 3}
                    fill="var(--text-muted)"
                    fontSize="10"
                    fontFamily="var(--mono)"
                    textAnchor="end"
                  >
                    {(v * 100).toFixed(0)}%
                  </text>
                </g>
              )
            })}

            {/* Area fill for cumulative risk */}
            {cumArea && <path d={cumArea} fill="url(#cum-risk-grad)" />}

            {/* Cumulative risk dashed line */}
            {cumLine && (
              <path
                d={cumLine}
                fill="none"
                stroke="var(--danger)"
                strokeWidth="2.2"
                strokeDasharray="4 4"
              />
            )}

            {/* Instantaneous probability solid line */}
            {probPath && (
              <path
                d={probPath}
                fill="none"
                stroke="var(--accent)"
                strokeWidth="2.5"
              />
            )}

            {/* Nodes and vertical tick lines */}
            {fullSeries.map((item, idx) => {
              const x = padding.left + idx * xStep
              const yProb = padding.top + getY(item.attackProbability)
              const yCum = padding.top + getY(item.cumulativeRisk)
              const isSelected = hoveredIndex === idx

              return (
                <g
                  key={item.label}
                  style={{ cursor: 'pointer' }}
                  onMouseEnter={() => setHoveredIndex(idx)}
                  onMouseLeave={() => setHoveredIndex(null)}
                >
                  {/* Vertical Guide Line */}
                  <line
                    x1={x}
                    y1={padding.top}
                    x2={x}
                    y2={padding.top + innerH}
                    stroke={isSelected ? 'var(--accent)' : 'var(--border)'}
                    strokeWidth={isSelected ? 1.5 : 0.8}
                    strokeDasharray={isSelected ? 'none' : '2 2'}
                  />

                  {/* Cumulative Node */}
                  {item.cumulativeRisk !== null && (
                    <circle
                      cx={x}
                      cy={yCum}
                      r={isSelected ? 5.5 : 4}
                      fill="var(--danger)"
                      stroke="var(--bg-surface)"
                      strokeWidth="1.5"
                    />
                  )}

                  {/* Probability Node */}
                  {item.attackProbability !== null && (
                    <circle
                      cx={x}
                      cy={yProb}
                      r={isSelected ? 6 : 4.5}
                      fill="var(--accent)"
                      stroke="var(--bg-surface)"
                      strokeWidth="2"
                    />
                  )}

                  {/* X Axis Label */}
                  <text
                    x={x}
                    y={padding.top + innerH + 16}
                    fill={isSelected ? 'var(--accent)' : 'var(--text-secondary)'}
                    fontSize="11"
                    fontWeight={isSelected ? 'bold' : 'normal'}
                    fontFamily="var(--mono)"
                    textAnchor="middle"
                  >
                    {item.label}
                  </text>
                  <text
                    x={x}
                    y={padding.top + innerH + 28}
                    fill="var(--text-muted)"
                    fontSize="9.5"
                    fontFamily="var(--mono)"
                    textAnchor="middle"
                  >
                    +{item.lookaheadSeconds}s
                  </text>
                </g>
              )
            })}
          </svg>

          {/* Interactive Inspection Card */}
          {activeHover && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '12px',
                padding: '12px 16px',
                borderRadius: '6px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                marginTop: '12px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <span
                  style={{
                    fontFamily: 'var(--mono)',
                    fontSize: '14px',
                    fontWeight: 700,
                    color: 'var(--accent)',
                  }}
                >
                  {activeHover.label} (+{activeHover.lookaheadSeconds}s Lookahead)
                </span>
                <RiskBadge level={activeHover.riskLevel} size="sm" />
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  Stage: <strong style={{ color: 'var(--text-primary)' }}>{activeHover.predictedStage || 'NORMAL'}</strong>
                </span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '20px', fontFamily: 'var(--mono)' }}>
                <div>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)', display: 'block' }}>ATTACK PROBABILITY</span>
                  <strong style={{ fontSize: '14px', color: 'var(--accent)' }}>
                    {activeHover.attackProbability !== null ? `${(activeHover.attackProbability * 100).toFixed(1)}%` : 'Withheld'}
                  </strong>
                </div>
                <div>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)', display: 'block' }}>CUMULATIVE RISK</span>
                  <strong style={{ fontSize: '14px', color: 'var(--danger)' }}>
                    {activeHover.cumulativeRisk !== null ? `${(activeHover.cumulativeRisk * 100).toFixed(1)}%` : 'Withheld'}
                  </strong>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </Panel>
  )
}
