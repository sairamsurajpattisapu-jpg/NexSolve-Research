import { Activity, Clock } from 'lucide-react'
import type { AttackProgressionForecast, StageForecastPoint } from '../types/api'
import { Panel, SectionHeading, StatusPill } from './Ui'

interface AttackProgressionCardProps {
  progression: AttackProgressionForecast
}

export function AttackProgressionCard({ progression }: AttackProgressionCardProps) {
  const isAbstained = progression.verdict === 'ABSTAINED'
  const observedState = progression.observed_state
  const observedTechniques = progression.observed_techniques

  return (
    <Panel className="attack-progression-panel">
      <SectionHeading
        eyebrow="EMPIRICAL MARKOVIAN PROGRESSION (T+1 .. T+5)"
        title="Attack-Stage Progression Forecaster"
        description="Temporal stage forecasting strictly grounded in authentic transition kinematics. Disentangles active state persistence from downstream multi-stage progression without arbitrary confidence multipliers."
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <StatusPill tone={isAbstained ? 'warning' : 'success'}>
              {isAbstained ? 'Progression Abstained' : progression.verdict.replace(/_/g, ' ')}
            </StatusPill>
          </div>
        }
      />

      {/* Observed Telemetry vs Forecast Rollout Anchor */}
      <div
        className="observed-telemetry-anchor"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
          gap: '12px',
          marginTop: '12px',
          marginBottom: '16px',
        }}
      >
        <div
          style={{
            background: 'rgba(104, 225, 216, 0.05)',
            border: '1px solid rgba(104, 225, 216, 0.3)',
            borderRadius: '6px',
            padding: '14px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--teal)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Observed State (Ground Truth @ T0)
            </span>
            <Activity size={14} color="var(--teal)" />
          </div>
          <strong style={{ fontSize: '18px', color: 'var(--white)', display: 'block', marginBottom: '4px' }}>
            {observedState.replace(/_/g, ' ')}
          </strong>
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '6px' }}>
            {observedTechniques.length > 0 ? (
              observedTechniques.map((tech) => (
                <span
                  key={tech}
                  style={{
                    fontSize: '9px',
                    fontFamily: 'var(--mono)',
                    padding: '2px 6px',
                    borderRadius: '3px',
                    background: 'rgba(104, 225, 216, 0.15)',
                    color: 'var(--teal)',
                  }}
                >
                  {tech}
                </span>
              ))
            ) : (
              <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>No attack techniques active</span>
            )}
          </div>
        </div>

        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            padding: '14px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Scientific Semantic Guardrail
            </span>
            <Clock size={14} color="var(--text-muted)" />
          </div>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            {progression.summary}
          </p>
          <div style={{ marginTop: '8px', fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--amber)' }}>
            Supported: T+1m, T+3m, T+5m &middot; Withheld: T+10m, T+15m
          </div>
        </div>
      </div>

      {/* Multi-Horizon Progression Rollout Grid */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <span className="eyebrow" style={{ margin: 0 }}>
          Forward Progression Trajectory (T+1 .. T+15)
        </span>
        <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
          Strictly Past-Conditioned: P(S_T+K | S_T)
        </span>
      </div>

      <div
        className="progression-points-grid"
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '10px',
        }}
      >
        {progression.forecast_points.map((pt: StageForecastPoint) => {
          const isPtAbstained = pt.abstained || pt.prediction_type === 'ABSTAINED'
          const isPersistence = pt.prediction_type === 'STATE_PERSISTENCE'
          const isProgression = pt.prediction_type === 'DOWNSTREAM_PROGRESSION'
          const probPercent = pt.transition_probability !== null ? (pt.transition_probability * 100).toFixed(1) : null

          return (
            <div
              key={pt.horizon_minutes}
              style={{
                border: `1px solid ${
                  isPtAbstained
                    ? 'var(--border)'
                    : isProgression
                    ? 'rgba(237, 128, 111, 0.4)'
                    : 'rgba(104, 225, 216, 0.3)'
                }`,
                background: isPtAbstained
                  ? 'rgba(255, 255, 255, 0.01)'
                  : isProgression
                  ? 'rgba(237, 128, 111, 0.05)'
                  : 'rgba(104, 225, 216, 0.03)',
                borderRadius: '6px',
                padding: '12px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <strong style={{ fontFamily: 'var(--mono)', fontSize: '12px', color: 'var(--text-primary)' }}>
                    T+{pt.horizon_minutes}m
                  </strong>
                  <span style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: 'var(--text-muted)' }}>
                    +{pt.lead_time_seconds}s
                  </span>
                </div>

                {/* Prediction Type Badge */}
                <div style={{ marginBottom: '8px' }}>
                  {isPtAbstained ? (
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'var(--mono)',
                        padding: '2px 5px',
                        borderRadius: '3px',
                        background: 'rgba(245, 158, 11, 0.1)',
                        color: 'var(--amber)',
                      }}
                    >
                      ABSTAINED
                    </span>
                  ) : isPersistence ? (
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'var(--mono)',
                        padding: '2px 5px',
                        borderRadius: '3px',
                        background: 'rgba(104, 225, 216, 0.15)',
                        color: 'var(--teal)',
                      }}
                    >
                      STATE PERSISTENCE
                    </span>
                  ) : (
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'var(--mono)',
                        padding: '2px 5px',
                        borderRadius: '3px',
                        background: 'rgba(237, 128, 111, 0.15)',
                        color: 'var(--red)',
                      }}
                    >
                      DOWNSTREAM PROGRESSION
                    </span>
                  )}
                </div>

                {/* State Label */}
                <div style={{ marginBottom: '8px' }}>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)', display: 'block' }}>
                    {isPersistence ? 'Active Ongoing Stage:' : isProgression ? 'Predicted Next Stage:' : 'Status:'}
                  </span>
                  <strong
                    style={{
                      fontSize: '13px',
                      color: isPtAbstained ? 'var(--text-muted)' : isProgression ? 'var(--red)' : 'var(--white)',
                    }}
                  >
                    {isPtAbstained ? 'Withheld' : pt.predicted_state.replace(/_/g, ' ')}
                  </strong>
                </div>

                {/* Probability readout */}
                {!isPtAbstained && probPercent !== null && (
                  <div style={{ marginBottom: '8px' }}>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {isPersistence ? 'Empirical persistence probability:' : 'Empirical transition probability:'}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'baseline', gap: '6px', marginTop: '2px' }}>
                      <span
                        style={{
                          fontSize: '16px',
                          fontWeight: 700,
                          fontFamily: 'var(--mono)',
                          color: isProgression ? 'var(--red)' : 'var(--teal)',
                        }}
                      >
                        {probPercent}%
                      </span>
                      <span style={{ fontSize: '9px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                        at T+{pt.horizon_minutes} min
                      </span>
                    </div>
                  </div>
                )}

                {/* Forecast techniques (Strictly empty for persistence) */}
                {isProgression && pt.forecast_techniques.length > 0 && (
                  <div style={{ marginTop: '6px' }}>
                    <span style={{ fontSize: '9px', color: 'var(--text-muted)' }}>Predicted Techniques:</span>
                    <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '2px' }}>
                      {pt.forecast_techniques.map((tech) => (
                        <span
                          key={tech}
                          style={{
                            fontSize: '8px',
                            fontFamily: 'var(--mono)',
                            padding: '1px 4px',
                            borderRadius: '2px',
                            background: 'rgba(237, 128, 111, 0.2)',
                            color: 'var(--red)',
                          }}
                        >
                          {tech}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Abstention Reason if applicable */}
                {isPtAbstained && pt.abstention_reason && (
                  <div
                    style={{
                      fontSize: '10px',
                      color: 'var(--amber)',
                      lineHeight: 1.4,
                      background: 'rgba(245, 158, 11, 0.05)',
                      padding: '6px 8px',
                      borderRadius: '4px',
                      borderLeft: '2px solid var(--amber)',
                    }}
                  >
                    {pt.abstention_reason}
                  </div>
                )}
              </div>

              {/* Supporting evidence snippet */}
              {pt.supporting_evidence.length > 0 && (
                <div style={{ marginTop: '8px', paddingTop: '6px', borderTop: '1px solid var(--border)' }}>
                  <small style={{ fontSize: '9px', color: 'var(--text-muted)', display: 'block', lineHeight: 1.3 }}>
                    {pt.supporting_evidence[0]}
                  </small>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </Panel>
  )
}
