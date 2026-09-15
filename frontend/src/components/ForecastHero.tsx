import { Shield } from 'lucide-react'
import { Panel } from './Ui'
import { RiskBadge } from './RiskBadge'

interface ForecastHeroProps {
  currentProbability: number | null
  earlyWarningScore: number | null
  earlyWarningLevel?: string
  t1Risk: number | null
  t3Risk: number | null
  t5Risk: number | null
  currentStage: string
  forecastConfidence?: number | null
  modelStatus?: string
  lookbackWindows?: number
}

export function ForecastHero({
  currentProbability,
  earlyWarningScore,
  earlyWarningLevel = 'NORMAL',
  t1Risk,
  t3Risk,
  t5Risk,
  currentStage,
  forecastConfidence,
  lookbackWindows = 8,
}: ForecastHeroProps) {
  const isHighRisk = (currentProbability ?? 0) >= 0.5 || (earlyWarningScore ?? 0) >= 50
  const isCritical = (currentProbability ?? 0) >= 0.75 || (earlyWarningScore ?? 0) >= 75

  return (
    <div
      style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(12, 1fr)',
        gap: '14px',
      }}
    >
      {/* 1. Primary AI Risk Core (Spans 5 cols) */}
      <Panel
        style={{
          gridColumn: 'span 5',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          background: isCritical
            ? 'radial-gradient(circle at top left, rgba(237, 128, 111, 0.15), var(--bg-surface) 70%)'
            : isHighRisk
            ? 'radial-gradient(circle at top left, rgba(242, 187, 113, 0.15), var(--bg-surface) 70%)'
            : 'radial-gradient(circle at top left, rgba(104, 225, 216, 0.12), var(--bg-surface) 70%)',
          border: `1px solid ${isCritical ? 'rgba(237, 128, 111, 0.4)' : isHighRisk ? 'rgba(242, 187, 113, 0.4)' : 'rgba(104, 225, 216, 0.3)'}`,
        }}
      >
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              AI THREAT RADAR · ACTIVE STATE
            </span>
            <RiskBadge level={earlyWarningLevel} size="sm" />
          </div>

          <div style={{ display: 'flex', alignItems: 'baseline', gap: '14px', marginTop: '14px' }}>
            <div style={{ fontSize: '38px', fontWeight: 800, fontFamily: 'var(--mono)', letterSpacing: '-0.03em', color: isCritical ? 'var(--danger)' : isHighRisk ? 'var(--warning)' : 'var(--accent)' }}>
              {earlyWarningScore !== null ? earlyWarningScore : '—'}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                Early Warning Score
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                Scale 0-100 &middot; Composite Risk Momentum
              </span>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '16px', borderTop: '1px solid var(--border)', marginTop: '16px', fontSize: '12px', fontFamily: 'var(--mono)' }}>
          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>CURRENT STAGE</span>
            <strong style={{ color: 'var(--text-primary)', fontSize: '13px' }}>
              {currentStage.replace(/_/g, ' ')}
            </strong>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>IMMEDIATE PROBABILITY</span>
            <strong style={{ color: isHighRisk ? 'var(--danger)' : 'var(--accent)', fontSize: '13px' }}>
              {currentProbability !== null ? `${(currentProbability * 100).toFixed(1)}%` : 'Withheld'}
            </strong>
          </div>
        </div>
      </Panel>

      {/* 2. Forward Horizon Projections Grid (Spans 4 cols) */}
      <Panel
        style={{
          gridColumn: 'span 4',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <span className="eyebrow" style={{ color: 'var(--text-muted)' }}>
            FORWARD ROLLOUT HORIZONS
          </span>
          <h4 style={{ margin: '4px 0 12px 0', fontSize: '14px', color: 'var(--text-primary)' }}>
            Cumulative Infiltration Risk
          </h4>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {/* T+1 */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>T+1 (+60s)</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <strong style={{ fontFamily: 'var(--mono)', color: 'var(--text-primary)' }}>
                  {t1Risk !== null ? `${(t1Risk * 100).toFixed(1)}%` : '—'}
                </strong>
                <span
                  style={{
                    width: '40px',
                    height: '4px',
                    borderRadius: '2px',
                    background: 'var(--bg-secondary)',
                    overflow: 'hidden',
                  }}
                >
                  <span
                    style={{
                      display: 'block',
                      height: '100%',
                      width: `${(t1Risk ?? 0) * 100}%`,
                      background: (t1Risk ?? 0) >= 0.5 ? 'var(--danger)' : 'var(--accent)',
                    }}
                  />
                </span>
              </div>
            </div>

            {/* T+3 */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>T+3 (+180s)</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <strong style={{ fontFamily: 'var(--mono)', color: (t3Risk ?? 0) >= 0.5 ? 'var(--warning)' : 'var(--text-primary)' }}>
                  {t3Risk !== null ? `${(t3Risk * 100).toFixed(1)}%` : '—'}
                </strong>
                <span
                  style={{
                    width: '40px',
                    height: '4px',
                    borderRadius: '2px',
                    background: 'var(--bg-secondary)',
                    overflow: 'hidden',
                  }}
                >
                  <span
                    style={{
                      display: 'block',
                      height: '100%',
                      width: `${(t3Risk ?? 0) * 100}%`,
                      background: (t3Risk ?? 0) >= 0.5 ? 'var(--warning)' : 'var(--accent)',
                    }}
                  />
                </span>
              </div>
            </div>

            {/* T+5 */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '12px' }}>
              <span style={{ fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>T+5 (+300s)</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <strong style={{ fontFamily: 'var(--mono)', color: (t5Risk ?? 0) >= 0.5 ? 'var(--danger)' : 'var(--text-primary)' }}>
                  {t5Risk !== null ? `${(t5Risk * 100).toFixed(1)}%` : '—'}
                </strong>
                <span
                  style={{
                    width: '40px',
                    height: '4px',
                    borderRadius: '2px',
                    background: 'var(--bg-secondary)',
                    overflow: 'hidden',
                  }}
                >
                  <span
                    style={{
                      display: 'block',
                      height: '100%',
                      width: `${(t5Risk ?? 0) * 100}%`,
                      background: (t5Risk ?? 0) >= 0.5 ? 'var(--danger)' : 'var(--accent)',
                    }}
                  />
                </span>
              </div>
            </div>
          </div>
        </div>

        <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', paddingTop: '10px', borderTop: '1px solid var(--border)' }}>
          Risk(H) = 1 - ∏(1 - p_h) &middot; Monotonic
        </div>
      </Panel>

      {/* 3. Model Governance & Telemetry Health (Spans 3 cols) */}
      <Panel
        style={{
          gridColumn: 'span 3',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
        }}
      >
        <div>
          <span className="eyebrow" style={{ color: 'var(--text-muted)' }}>
            GOVERNANCE & INTEGRITY
          </span>
          <h4 style={{ margin: '4px 0 12px 0', fontSize: '14px', color: 'var(--text-primary)' }}>
            Telemetry Telemetry
          </h4>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '11.5px', fontFamily: 'var(--mono)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Model Schema:</span>
              <strong style={{ color: 'var(--accent)' }}>45 Passive</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>TCP RTT:</span>
              <strong style={{ color: 'var(--text-secondary)' }}>Omitted (No fake)</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Lookback:</span>
              <strong style={{ color: 'var(--text-primary)' }}>{lookbackWindows} / 8 windows</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Confidence:</span>
              <strong style={{ color: 'var(--text-primary)' }}>
                {forecastConfidence !== null && forecastConfidence !== undefined ? `${(forecastConfidence * 100).toFixed(0)}%` : 'Uncalibrated'}
              </strong>
            </div>
          </div>
        </div>

        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '10.5px',
            fontFamily: 'var(--mono)',
            color: 'var(--success)',
            background: 'rgba(16, 185, 129, 0.08)',
            padding: '4px 8px',
            borderRadius: '4px',
          }}
        >
          <Shield size={12} />
          <span>ZERO FABRICATION CONTRACT</span>
        </div>
      </Panel>
    </div>
  )
}
