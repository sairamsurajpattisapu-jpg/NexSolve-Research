import { AlertTriangle, CheckCircle, Clock, HelpCircle, Shield, ShieldAlert, Sliders } from 'lucide-react'
import { useState } from 'react'
import { attackHorizonFixtures } from '../fixtures/attackHorizonFixtures'
import type { AttackHorizonPayload, AttackHorizonStateType } from '../types/api'
import { Panel, SectionHeading, StatusPill } from './Ui'

interface AttackHorizonCardProps {
  initialPayload?: AttackHorizonPayload
  allowStateSwitching?: boolean
}

const STATE_CONFIG: Record<
  AttackHorizonStateType,
  { label: string; tone: 'success' | 'warning' | 'danger' | 'neutral'; icon: typeof Shield }
> = {
  NO_ATTACK_FORECAST: {
    label: 'No Attack Forecast',
    tone: 'success',
    icon: CheckCircle,
  },
  EARLY_SIGNAL: {
    label: 'Early Signal',
    tone: 'warning',
    icon: AlertTriangle,
  },
  SUSTAINED_ATTACK_FORECAST: {
    label: 'Sustained Attack Forecast',
    tone: 'danger',
    icon: ShieldAlert,
  },
  UNCERTAIN_FORECAST: {
    label: 'Uncertain Forecast',
    tone: 'neutral',
    icon: HelpCircle,
  },
  ABSTAINED: {
    label: 'Abstained',
    tone: 'warning',
    icon: Clock,
  },
}

export function AttackHorizonCard({
  initialPayload,
  allowStateSwitching = true,
}: AttackHorizonCardProps) {
  const [selectedFixtureKey, setSelectedFixtureKey] = useState<string>('sustainedAttack')
  const payload: AttackHorizonPayload = initialPayload ?? attackHorizonFixtures[selectedFixtureKey] ?? attackHorizonFixtures.sustainedAttack

  const config = STATE_CONFIG[payload.state] ?? STATE_CONFIG.NO_ATTACK_FORECAST
  const StateIcon = config.icon

  return (
    <Panel className="attack-horizon-panel">
      <SectionHeading
        eyebrow="Forecasting (T+1 → T+5) / Rollout Engine"
        title="Attack Horizon & Lead Time"
        description="What is likely to happen next: dynamic forward rollout determining how far into future temporal windows traffic evidence supports an attack."
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <StatusPill tone={config.tone}>{config.label}</StatusPill>
            {allowStateSwitching && !initialPayload && (
              <div className="horizon-fixture-switcher" style={{ display: 'flex', gap: '4px', marginLeft: '8px' }}>
                {(
                  [
                    ['sustainedAttack', 'Sustained'],
                    ['earlySignal', 'Early'],
                    ['noAttack', 'Baseline'],
                    ['uncertain', 'Uncertain'],
                    ['abstained', 'Abstained'],
                  ] as const
                ).map(([key, label]) => (
                  <button
                    key={key}
                    type="button"
                    className={`button button-quiet ${selectedFixtureKey === key ? 'active' : ''}`}
                    style={{
                      padding: '4px 10px',
                      fontSize: '11px',
                      fontFamily: 'var(--font-sans)',
                      fontWeight: 500,
                      borderRadius: '6px',
                      borderColor: selectedFixtureKey === key ? 'rgba(255, 255, 255, 0.2)' : 'var(--border)',
                      color: selectedFixtureKey === key ? 'var(--text-primary)' : 'var(--text-muted)',
                      background: selectedFixtureKey === key ? 'rgba(255, 255, 255, 0.08)' : 'transparent',
                    }}
                    onClick={() => setSelectedFixtureKey(key)}
                  >
                    {label}
                  </button>
                ))}
              </div>
            )}
          </div>
        }
      />

      <div
        className="horizon-metrics-grid"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '12px',
          marginTop: '16px',
          marginBottom: '16px',
        }}
      >
        <div className="metric-card" style={{ padding: '16px', minHeight: 'auto', background: 'rgba(255, 255, 255, 0.015)', border: '1px solid var(--border)', borderRadius: '10px' }}>
          <div className="metric-top" style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)' }}>
            <span>Attack Horizon</span>
            <Clock size={13} />
          </div>
          <strong style={{ fontSize: '20px', fontWeight: 600, marginTop: '8px', color: 'var(--text-primary)', fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>
            {payload.horizon_windows > 0 ? `${payload.horizon_windows} windows` : '0 windows'}
          </strong>
          <small style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)', marginTop: '2px' }}>{payload.horizon_seconds > 0 ? `${payload.horizon_seconds} seconds continuous` : 'No attack span'}</small>
        </div>

        <div className="metric-card" style={{ padding: '16px', minHeight: 'auto', background: 'rgba(255, 255, 255, 0.015)', border: '1px solid var(--border)', borderRadius: '10px' }}>
          <div className="metric-top" style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)' }}>
            <span>Onset Lead Time</span>
            <StateIcon size={13} />
          </div>
          <strong style={{ fontSize: '20px', fontWeight: 600, marginTop: '8px', color: 'var(--text-primary)', fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>
            {payload.lead_time_seconds !== null ? `${payload.lead_time_seconds}s` : 'N/A'}
          </strong>
          <small style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)', marginTop: '2px' }}>{payload.onset_horizon !== null ? `Begins at window T+${payload.onset_horizon}` : 'No onset detected'}</small>
        </div>

        <div className="metric-card" style={{ padding: '16px', minHeight: 'auto', background: 'rgba(255, 255, 255, 0.015)', border: '1px solid var(--border)', borderRadius: '10px' }}>
          <div className="metric-top" style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)' }}>
            <span>Temporal Consistency</span>
            <Sliders size={13} />
          </div>
          <strong style={{ fontSize: '20px', fontWeight: 600, marginTop: '8px', color: 'var(--text-primary)', fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>
            {(payload.temporal_consistency * 100).toFixed(0)}%
          </strong>
          <small style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)', marginTop: '2px' }}>{payload.decay_observed ? 'Monotonic decay observed' : 'Contiguous sequence'}</small>
        </div>

        <div className="metric-card" style={{ padding: '16px', minHeight: 'auto', background: 'rgba(255, 255, 255, 0.015)', border: '1px solid var(--border)', borderRadius: '10px' }}>
          <div className="metric-top" style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)' }}>
            <span>Calibration Status</span>
            <Shield size={13} />
          </div>
          <strong style={{ fontSize: '15px', fontWeight: 600, marginTop: '10px', fontFamily: 'var(--font-sans)', color: 'var(--text-secondary)' }}>
            {payload.confidence_summary.calibration_status}
          </strong>
          <small style={{ color: 'var(--text-muted)', fontSize: '11px', fontFamily: 'var(--font-sans)', marginTop: '2px' }}>Raw model scores; uncalibrated</small>
        </div>
      </div>

      <div
        className="horizon-summary-banner"
        style={{
          padding: '12px 14px',
          background: 'var(--bg-secondary)',
          borderLeft: `2px solid ${config.tone === 'danger' ? 'var(--danger)' : config.tone === 'warning' ? 'var(--warning)' : 'var(--border-strong)'}`,
          borderRadius: '4px',
          marginBottom: '16px',
        }}
      >
        <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.5 }}>
          {payload.summary}
        </p>
        {payload.current_stage && (
          <div style={{ marginTop: '6px', fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
            Observed Stage @ T0: <strong style={{ color: 'var(--text-primary)' }}>{payload.current_stage}</strong>
            {payload.escalation_horizon && (
              <> &middot; Impending Escalation: <strong style={{ color: 'var(--danger)' }}>T+{payload.escalation_horizon} ({payload.lead_time_to_escalation_seconds}s lead time)</strong></>
            )}
          </div>
        )}
        {payload.abstention_reason && (
          <small style={{ display: 'block', marginTop: '6px', color: 'var(--warning)', fontFamily: 'var(--font-sans)', fontSize: '11px' }}>
            Abstention reason: {payload.abstention_reason}
          </small>
        )}
      </div>

      <div className="horizon-evidence-chain">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
          <span className="eyebrow" style={{ margin: 0, fontSize: '11px', color: 'var(--text-secondary)' }}>
            Sequential Horizon Rollout (T0 Observed &rarr; T+1 to T+5 Forward Windows)
          </span>
          <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
            Status: UNCALIBRATED FORECAST MARGIN
          </span>
        </div>

        <div
          className="horizon-timeline-instrument"
          style={{
            border: '1px solid var(--border)',
            borderRadius: '10px',
            background: 'rgba(255, 255, 255, 0.012)',
            overflow: 'hidden',
          }}
        >
          {/* Timeline Rule Bar */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              padding: '8px 14px',
              borderBottom: '1px solid var(--border)',
              background: 'rgba(255, 255, 255, 0.02)',
              fontSize: '11px',
              color: 'var(--text-muted)',
            }}
          >
            <span>Decision Baseline: &theta;={payload.decision_threshold.toFixed(2)}</span>
            <span>60s Temporal Resolution &middot; Continuous Forward Projection</span>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(6, 1fr)',
            }}
          >
            {/* T0: Current State Anchor */}
            <div
              style={{
                borderRight: '1px solid var(--border)',
                background: 'rgba(255, 255, 255, 0.02)',
                padding: '14px 12px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                minHeight: '140px',
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '10px', fontFamily: 'var(--font-sans)', marginBottom: '8px' }}>
                  <strong style={{ color: 'var(--text-primary)', fontSize: '11px' }}>t0 (Now)</strong>
                  <span>Observed</span>
                </div>
                <div style={{ margin: '8px 0' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, fontFamily: 'var(--font-sans)', color: 'var(--text-primary)', display: 'block' }}>
                    CURRENT
                  </span>
                  <small style={{ display: 'block', color: 'var(--text-muted)', fontSize: '10px', marginTop: '3px', fontFamily: 'var(--font-sans)' }}>
                    Ground Truth
                  </small>
                </div>
              </div>
              <div style={{ fontSize: '10.5px', color: 'var(--text-muted)', marginTop: '8px' }}>
                Active Window
              </div>
            </div>

            {/* T+1 through T+5 Forward Forecast Horizons */}
            {payload.evidence_chain.map((point, idx) => {
              const isAbstained = point.abstained || point.attack_probability === null
              const isAttack = !isAbstained && point.above_threshold
              const isWithinHorizon =
                payload.onset_horizon !== null &&
                payload.end_horizon !== null &&
                point.horizon >= payload.onset_horizon &&
                point.horizon <= payload.end_horizon
              const isLast = idx === payload.evidence_chain.length - 1

              return (
                <div
                  key={point.horizon}
                  style={{
                    borderRight: isLast ? 'none' : '1px solid var(--border)',
                    background: isWithinHorizon
                      ? 'rgba(244, 63, 94, 0.04)'
                      : 'transparent',
                    padding: '14px 12px',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    minHeight: '140px',
                    position: 'relative',
                  }}
                >
                  <div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: 'var(--text-muted)', fontSize: '10px', fontFamily: 'var(--font-sans)', marginBottom: '8px' }}>
                      <strong style={{ color: isWithinHorizon ? 'var(--text-primary)' : 'var(--text-secondary)', fontSize: '11px' }}>
                        T+{point.horizon}
                      </strong>
                      <span style={{ fontVariantNumeric: 'tabular-nums' }}>+{point.horizon_seconds}s</span>
                    </div>

                    <div style={{ margin: '6px 0' }}>
                      {isAbstained ? (
                        <span style={{ color: 'var(--warning)', fontSize: '12px', fontWeight: 500, fontFamily: 'var(--font-sans)' }}>Withheld</span>
                      ) : (
                        <div style={{ display: 'flex', flexDirection: 'column' }}>
                          <span
                            style={{
                              fontSize: '18px',
                              fontWeight: 600,
                              fontFamily: 'var(--font-sans)',
                              fontVariantNumeric: 'tabular-nums',
                              color: isAttack ? 'var(--text-primary)' : 'var(--text-secondary)',
                            }}
                          >
                            {point.attack_probability?.toFixed(2)}
                          </span>
                          <small style={{ color: 'var(--text-muted)', fontSize: '9.5px', marginTop: '2px', fontVariantNumeric: 'tabular-nums' }}>
                            vs &theta;={payload.decision_threshold.toFixed(2)}
                          </small>
                        </div>
                      )}
                    </div>

                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {point.predicted_stage ?? (isAttack ? 'Suspicious' : 'Baseline')}
                    </div>
                  </div>

                  <div style={{ marginTop: '8px', paddingTop: '8px', borderTop: '1px solid rgba(255, 255, 255, 0.04)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ fontSize: '10px', fontFamily: 'var(--font-sans)' }}>
                      {isWithinHorizon ? (
                        <span style={{ color: 'var(--danger)', fontWeight: 600, display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                          <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: 'var(--danger)', display: 'inline-block' }} />
                          In Horizon
                        </span>
                      ) : isAbstained ? (
                        <span style={{ color: 'var(--text-muted)' }}>Abstained</span>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>Beyond Span</span>
                      )}
                    </div>
                    <span
                      style={{
                        fontSize: '8px',
                        fontFamily: 'var(--font-sans)',
                        letterSpacing: '0.04em',
                        color: 'var(--text-very-muted)',
                      }}
                    >
                      UNCALIBRATED
                    </span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </Panel>
  )
}
