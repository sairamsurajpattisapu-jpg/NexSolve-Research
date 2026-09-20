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
                      padding: '4px 8px',
                      fontSize: '9px',
                      fontFamily: 'var(--mono)',
                      borderColor: selectedFixtureKey === key ? 'var(--accent)' : 'var(--border)',
                      color: selectedFixtureKey === key ? 'var(--accent)' : 'var(--text-secondary)',
                      background: selectedFixtureKey === key ? 'var(--accent-muted)' : 'var(--button-secondary-bg)',
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
          marginTop: '12px',
          marginBottom: '16px',
        }}
      >
        <div className="metric-card metric-accent" style={{ padding: '14px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Attack Horizon</span>
            <Clock size={14} />
          </div>
          <strong style={{ fontSize: '20px', marginTop: '8px' }}>
            {payload.horizon_windows > 0 ? `${payload.horizon_windows} windows` : '0 windows'}
          </strong>
          <small>{payload.horizon_seconds > 0 ? `${payload.horizon_seconds} seconds continuous` : 'No attack span'}</small>
        </div>

        <div className="metric-card" style={{ padding: '14px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Onset Lead Time</span>
            <StateIcon size={14} />
          </div>
          <strong style={{ fontSize: '20px', marginTop: '8px' }}>
            {payload.lead_time_seconds !== null ? `${payload.lead_time_seconds}s` : 'N/A'}
          </strong>
          <small>{payload.onset_horizon !== null ? `Begins at window T+${payload.onset_horizon}` : 'No onset detected'}</small>
        </div>

        <div className="metric-card" style={{ padding: '14px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Temporal Consistency</span>
            <Sliders size={14} />
          </div>
          <strong style={{ fontSize: '20px', marginTop: '8px' }}>
            {(payload.temporal_consistency * 100).toFixed(0)}%
          </strong>
          <small>{payload.decay_observed ? 'Monotonic decay observed' : 'Contiguous sequence'}</small>
        </div>

        <div className="metric-card" style={{ padding: '14px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Calibration Status</span>
            <Shield size={14} />
          </div>
          <strong style={{ fontSize: '16px', marginTop: '10px', color: 'var(--amber)' }}>
            {payload.confidence_summary.calibration_status}
          </strong>
          <small>Raw model scores; uncalibrated</small>
        </div>
      </div>

      <div
        className="horizon-summary-banner"
        style={{
          padding: '12px 14px',
          background: 'rgba(255, 255, 255, 0.03)',
          borderLeft: `3px solid ${config.tone === 'danger' ? 'var(--red)' : config.tone === 'warning' ? 'var(--amber)' : config.tone === 'success' ? 'var(--teal)' : 'var(--muted)'}`,
          borderRadius: '4px',
          marginBottom: '16px',
        }}
      >
        <p style={{ fontSize: '11px', color: 'var(--subtle)', margin: 0, lineHeight: 1.5 }}>
          {payload.summary}
        </p>
        {payload.current_stage && (
          <div style={{ marginTop: '6px', fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
            Observed Stage @ T0: <strong style={{ color: 'var(--teal)' }}>{payload.current_stage}</strong>
            {payload.escalation_horizon && (
              <> &middot; Impending Escalation: <strong style={{ color: 'var(--red)' }}>T+{payload.escalation_horizon} ({payload.lead_time_to_escalation_seconds}s lead time)</strong></>
            )}
          </div>
        )}
        {payload.abstention_reason && (
          <small style={{ display: 'block', marginTop: '6px', color: 'var(--amber)', fontFamily: 'var(--mono)', fontSize: '10px' }}>
            Abstention reason: {payload.abstention_reason}
          </small>
        )}
      </div>

      <div className="horizon-evidence-chain">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <span className="eyebrow" style={{ margin: 0 }}>
            Predictive Forecast Timeline (t0 Observed &rarr; T+1 to T+5 Forward Rollout)
          </span>
          <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--amber)' }}>
            Status: UNCALIBRATED FORECAST MARGIN
          </span>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(6, 1fr)',
            gap: '8px',
          }}
        >
          {/* T0: Current State Anchor */}
          <div
            style={{
              border: '1px solid rgba(104, 225, 216, 0.4)',
              background: 'rgba(104, 225, 216, 0.06)',
              borderRadius: '5px',
              padding: '10px 8px',
              textAlign: 'center',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--teal)', fontSize: '9px', fontFamily: 'var(--mono)', marginBottom: '6px' }}>
              <strong>t0 (Now)</strong>
              <span>Observed</span>
            </div>
            <div style={{ margin: '8px 0' }}>
              <span style={{ fontSize: '13px', fontWeight: 700, fontFamily: 'var(--mono)', color: 'var(--white)' }}>
                CURRENT
              </span>
              <small style={{ display: 'block', color: 'var(--teal)', fontSize: '8px', marginTop: '2px', fontFamily: 'var(--mono)' }}>
                Ground Truth
              </small>
            </div>
            <div style={{ fontSize: '9px', color: 'var(--subtle)', marginTop: '4px' }}>
              Active Window
            </div>
          </div>

          {/* T+1 through T+5 Forward Forecast Horizons */}
          {payload.evidence_chain.map((point) => {
            const isAbstained = point.abstained || point.attack_probability === null
            const isAttack = !isAbstained && point.above_threshold
            const isWithinHorizon =
              payload.onset_horizon !== null &&
              payload.end_horizon !== null &&
              point.horizon >= payload.onset_horizon &&
              point.horizon <= payload.end_horizon

            return (
              <div
                key={point.horizon}
                style={{
                  border: `1px solid ${isWithinHorizon ? 'rgba(237, 128, 111, 0.6)' : isAttack ? 'rgba(237, 128, 111, 0.3)' : 'var(--border)'}`,
                  background: isWithinHorizon
                    ? 'rgba(237, 128, 111, 0.12)'
                    : isAttack
                    ? 'rgba(237, 128, 111, 0.05)'
                    : 'var(--bg-secondary)',
                  borderRadius: '5px',
                  padding: '10px 8px',
                  textAlign: 'center',
                  position: 'relative',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--muted)', fontSize: '9px', fontFamily: 'var(--mono)', marginBottom: '6px' }}>
                  <strong>T+{point.horizon}</strong>
                  <span>+{point.horizon_seconds}s</span>
                </div>

                <div style={{ margin: '6px 0' }}>
                  {isAbstained ? (
                    <span style={{ color: 'var(--amber)', fontSize: '11px', fontFamily: 'var(--mono)' }}>Withheld</span>
                  ) : (
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                      <span
                        style={{
                          fontSize: '15px',
                          fontWeight: 700,
                          fontFamily: 'var(--mono)',
                          color: isAttack ? 'var(--red)' : 'var(--teal)',
                        }}
                      >
                        {point.attack_probability?.toFixed(2)}
                      </span>
                      <small style={{ color: 'var(--muted)', fontSize: '8px' }}>
                        vs &theta;={payload.decision_threshold.toFixed(2)}
                      </small>
                    </div>
                  )}
                </div>

                <div style={{ fontSize: '9px', color: 'var(--subtle)', marginTop: '4px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                  {point.predicted_stage ?? (isAttack ? 'Suspicious' : 'Baseline')}
                </div>

                <div style={{ marginTop: '6px', fontSize: '8px', fontFamily: 'var(--mono)' }}>
                  {isWithinHorizon ? (
                    <span style={{ color: 'var(--red)', fontWeight: 700 }}>In Horizon</span>
                  ) : isAbstained ? (
                    <span style={{ color: 'var(--muted)' }}>Abstained</span>
                  ) : (
                    <span style={{ color: 'var(--muted)' }}>Beyond Span</span>
                  )}
                </div>

                <div style={{ marginTop: '3px' }}>
                  <span
                    style={{
                      fontSize: '7px',
                      fontFamily: 'var(--mono)',
                      color: 'var(--amber)',
                      background: 'rgba(245, 158, 11, 0.1)',
                      padding: '1px 3px',
                      borderRadius: '2px',
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
    </Panel>
  )
}
