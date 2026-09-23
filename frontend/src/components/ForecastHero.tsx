import { Shield } from 'lucide-react'
import { Panel } from './Ui'
import { RiskBadge } from './RiskBadge'
import { formatDisplayLabel } from '../utils/format'

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
      {/* 1. Primary Risk Core (Spans 5 cols) */}
      <Panel
        style={{
          gridColumn: 'span 5',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
        }}
      >
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="eyebrow" style={{ color: 'var(--text-primary)', margin: 0 }}>
              THREAT ASSESSMENT
            </span>
            <RiskBadge level={earlyWarningLevel} size="sm" />
          </div>

          <div style={{ display: 'flex', alignItems: 'baseline', gap: '14px', marginTop: '14px' }}>
            <div style={{ fontSize: '38px', fontWeight: 800, fontFamily: 'var(--mono)', letterSpacing: '-0.03em', color: isCritical ? 'var(--danger)' : isHighRisk ? 'var(--warning)' : 'var(--accent)' }}>
              {earlyWarningScore !== null ? earlyWarningScore : '—'}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)' }}>
                Early Warning
              </span>
              <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                Scale 0-100 &middot; Risk Momentum
              </span>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: '16px', borderTop: '1px solid var(--border)', marginTop: '16px', fontSize: '12px', fontFamily: 'var(--mono)' }}>
          <div>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>CURRENT STAGE</span>
            <strong style={{ color: 'var(--text-primary)', fontSize: '13px' }}>
              {formatDisplayLabel(currentStage)}
            </strong>
          </div>
          <div style={{ textAlign: 'right' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>CURRENT RISK</span>
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
            FORECAST HORIZONS
          </span>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', marginTop: '14px' }}>
            {/* T+1 */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '12px' }}>
                <span style={{ color: 'var(--text-muted)' }}>T+1 (+60s)</span>
                <strong style={{ fontFamily: 'var(--mono)', color: (t1Risk ?? 0) >= 0.5 ? 'var(--danger)' : 'var(--text-primary)' }}>
                  {t1Risk !== null ? `${(t1Risk * 100).toFixed(1)}%` : 'Withheld'}
                </strong>
              </div>
              <div
                style={{
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
              </div>
            </div>

            {/* T+3 */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '12px' }}>
                <span style={{ color: 'var(--text-muted)' }}>T+3 (+180s)</span>
                <strong style={{ fontFamily: 'var(--mono)', color: (t3Risk ?? 0) >= 0.5 ? 'var(--danger)' : 'var(--text-primary)' }}>
                  {t3Risk !== null ? `${(t3Risk * 100).toFixed(1)}%` : 'Withheld'}
                </strong>
              </div>
              <div
                style={{
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
                    background: (t3Risk ?? 0) >= 0.5 ? 'var(--danger)' : 'var(--accent)',
                  }}
                />
              </div>
            </div>

            {/* T+5 */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px', fontSize: '12px' }}>
                <span style={{ color: 'var(--text-muted)' }}>T+5 (+300s)</span>
                <strong style={{ fontFamily: 'var(--mono)', color: (t5Risk ?? 0) >= 0.5 ? 'var(--danger)' : 'var(--text-primary)' }}>
                  {t5Risk !== null ? `${(t5Risk * 100).toFixed(1)}%` : 'Withheld'}
                </strong>
              </div>
              <div
                style={{
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
            DATA &amp; MODEL INTEGRITY
          </span>
          <h4 style={{ margin: '4px 0 12px 0', fontSize: '14px', color: 'var(--text-primary)' }}>
            Network Telemetry
          </h4>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '11.5px', fontFamily: 'var(--mono)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Feature Schema:</span>
              <strong style={{ color: 'var(--accent)' }}>45 passive features</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>TCP RTT:</span>
              <strong style={{ color: 'var(--text-secondary)' }}>Not observed from passive capture</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>History:</span>
              <strong style={{ color: 'var(--text-primary)' }}>{lookbackWindows} / 8 required windows</strong>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--text-muted)' }}>Assessment Confidence:</span>
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
          <span>Data Integrity Verified</span>
        </div>
      </Panel>
    </div>
  )
}
