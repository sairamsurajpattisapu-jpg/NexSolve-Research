import { useState } from 'react'
import { Activity, ChevronDown, ChevronUp, Clock } from 'lucide-react'
import type { AttackProgressionForecast, StageForecastPoint } from '../types/api'
import { Panel, SectionHeading, StatusPill } from './Ui'

interface AttackProgressionCardProps {
  progression: AttackProgressionForecast
}

export function AttackProgressionCard({ progression }: AttackProgressionCardProps) {
  const [selectedTimelineIdx, setSelectedTimelineIdx] = useState<number | null>(null)
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
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            padding: '14px',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Observed State (Ground Truth @ T0)
            </span>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              {progression.classification && (
                <span
                  style={{
                    fontSize: '9px',
                    fontFamily: 'var(--font-sans)',
                    fontWeight: 600,
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: 'var(--bg-elevated)',
                    color: progression.classification === 'OBSERVED' ? 'var(--text-primary)' : 'var(--text-secondary)',
                    border: '1px solid var(--border)',
                  }}
                >
                  {progression.classification}
                </span>
              )}
              <Activity size={14} color="var(--text-muted)" />
            </div>
          </div>
          <strong style={{ fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)', display: 'block', marginBottom: '4px', letterSpacing: '-0.01em' }}>
            {observedState.replace(/_/g, ' ')}
          </strong>
          {progression.stage_confidence !== undefined && progression.stage_confidence > 0 && (
            <div style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-secondary)', marginBottom: '4px', fontVariantNumeric: 'tabular-nums' }}>
              Stage Confidence: {(progression.stage_confidence * 100).toFixed(0)}%
              {progression.technique_confidence !== undefined && progression.technique_confidence > 0 && (
                <span style={{ marginLeft: '8px', color: 'var(--text-muted)' }}>
                  · Sensor Match: {(progression.technique_confidence * 100).toFixed(0)}%
                </span>
              )}
            </div>
          )}
          <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap', marginTop: '6px' }}>
            {observedTechniques.length > 0 ? (
              observedTechniques.map((tech) => (
                <span
                  key={tech}
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                    padding: '2px 6px',
                    borderRadius: '4px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {tech}
                </span>
              ))
            ) : (
              <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>No attack techniques active</span>
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
            <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
              Scientific Semantic Guardrail
            </span>
            <Clock size={14} color="var(--text-muted)" />
          </div>
          <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
            {progression.summary}
          </p>
          <div style={{ marginTop: '8px', fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
            Supported: <span style={{ color: 'var(--text-secondary)' }}>{progression.supported_horizons.map(h => `T+${h}m`).join(', ') || 'None'}</span> {progression.unsupported_horizons.length > 0 && <span>· Withheld: <span style={{ color: 'var(--text-secondary)' }}>{progression.unsupported_horizons.map(h => `T+${h}m`).join(', ')}</span></span>}
          </div>
        </div>
      </div>

      {/* Multi-Horizon Progression Rollout Grid */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
        <span className="eyebrow" style={{ margin: 0 }}>
          Continuous Temporal Progression Trajectory (T+1 .. T+5)
        </span>
        <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
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
                border: isPtAbstained
                  ? '1px solid var(--border)'
                  : isProgression
                  ? '1px solid rgba(244, 63, 94, 0.28)'
                  : '1px solid var(--border)',
                background: isPtAbstained
                  ? 'rgba(255, 255, 255, 0.01)'
                  : isProgression
                  ? 'rgba(244, 63, 94, 0.03)'
                  : 'var(--bg-secondary)',
                borderRadius: '6px',
                padding: '12px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <strong style={{ fontFamily: 'var(--font-sans)', fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)', fontVariantNumeric: 'tabular-nums' }}>
                    T+{pt.horizon_minutes}m
                  </strong>
                  <span style={{ fontFamily: 'var(--font-sans)', fontSize: '10px', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
                    +{pt.lead_time_seconds}s
                  </span>
                </div>

                {/* Prediction Type Badge */}
                <div style={{ marginBottom: '8px' }}>
                  {isPtAbstained ? (
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'var(--font-sans)',
                        fontWeight: 600,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'rgba(245, 158, 11, 0.08)',
                        color: 'var(--amber)',
                        border: '1px solid rgba(245, 158, 11, 0.25)',
                      }}
                    >
                      ABSTAINED
                    </span>
                  ) : isPersistence ? (
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'var(--font-sans)',
                        fontWeight: 600,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'var(--bg-elevated)',
                        color: 'var(--text-primary)',
                        border: '1px solid var(--border)',
                      }}
                    >
                      STATE PERSISTENCE
                    </span>
                  ) : (
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'var(--font-sans)',
                        fontWeight: 600,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'rgba(244, 63, 94, 0.1)',
                        color: 'var(--red)',
                        border: '1px solid rgba(244, 63, 94, 0.3)',
                      }}
                    >
                      DOWNSTREAM PROGRESSION
                    </span>
                  )}
                </div>

                {/* State Label */}
                <div style={{ marginBottom: '8px' }}>
                  <span style={{ fontSize: '10px', color: 'var(--text-muted)', display: 'block', marginBottom: '2px' }}>
                    {isPersistence ? 'Active Ongoing Stage:' : isProgression ? 'Predicted Next Stage:' : 'Status:'}
                  </span>
                  <strong
                    style={{
                      fontSize: '13px',
                      fontWeight: 600,
                      color: isPtAbstained ? 'var(--text-muted)' : isProgression ? 'var(--text-primary)' : 'var(--text-primary)',
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
                          fontWeight: 600,
                          fontFamily: 'var(--font-sans)',
                          fontVariantNumeric: 'tabular-nums',
                          color: isProgression ? 'var(--red)' : 'var(--text-primary)',
                        }}
                      >
                        {probPercent}%
                      </span>
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)', fontVariantNumeric: 'tabular-nums' }}>
                        at T+{pt.horizon_minutes} min
                      </span>
                    </div>
                  </div>
                )}

                {/* Forecast techniques (Strictly empty for persistence) */}
                {isProgression && pt.forecast_techniques.length > 0 && (
                  <div style={{ marginTop: '6px' }}>
                    <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>Predicted Techniques:</span>
                    <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap', marginTop: '3px' }}>
                      {pt.forecast_techniques.map((tech) => (
                        <span
                          key={tech}
                          style={{
                            fontSize: '9px',
                            fontFamily: 'var(--mono)',
                            padding: '1px 5px',
                            borderRadius: '3px',
                            background: 'rgba(244, 63, 94, 0.1)',
                            border: '1px solid rgba(244, 63, 94, 0.25)',
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
                      background: 'rgba(245, 158, 11, 0.04)',
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
                  <small style={{ fontSize: '10px', color: 'var(--text-muted)', display: 'block', lineHeight: 1.4 }}>
                    {pt.supporting_evidence[0]}
                  </small>
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Canonical Progression Timeline (Observed, Inferred, Forecast) */}
      {progression.timeline && progression.timeline.length > 0 && (
        <div style={{ marginTop: '20px', borderTop: '1px dashed var(--border)', paddingTop: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span className="eyebrow" style={{ margin: 0 }}>
              Attack Progression Timeline (Observed &rarr; Forecast)
            </span>
            <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
              {progression.timeline.length} Temporal Checkpoints
            </span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {progression.timeline.map((ev, idx) => {
              const clsTone =
                ev.classification === 'OBSERVED'
                  ? 'var(--text-primary)'
                  : ev.classification === 'FORECAST'
                  ? 'var(--text-secondary)'
                  : 'var(--amber)'
              const clsBg =
                ev.classification === 'OBSERVED'
                  ? 'var(--bg-elevated)'
                  : ev.classification === 'FORECAST'
                  ? 'rgba(255, 255, 255, 0.04)'
                  : 'rgba(245, 158, 11, 0.08)'
              const timeLabel =
                ev.horizon_label || (ev.classification === 'FORECAST' ? `+${ev.lead_time_seconds ?? 0}s` : 'T0')
              const isSelected = selectedTimelineIdx === idx
              return (
                <div
                  key={idx}
                  onClick={() => setSelectedTimelineIdx(isSelected ? null : idx)}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    borderRadius: '4px',
                    background: isSelected ? 'var(--bg-elevated)' : 'var(--bg-secondary)',
                    border: isSelected ? '1px solid var(--border-strong)' : '1px solid var(--border)',
                    fontSize: '12px',
                    cursor: 'pointer',
                    transition: 'all 0.15s ease',
                  }}
                  title="Click to view corroborating evidence and telemetry rationale"
                >
                  <div
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '8px 12px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{ fontFamily: 'var(--font-sans)', fontSize: '11px', color: 'var(--text-muted)', minWidth: '40px', fontVariantNumeric: 'tabular-nums' }}>
                        {timeLabel}
                      </span>
                      <strong style={{ fontFamily: 'var(--font-sans)', fontWeight: 500, color: 'var(--text-primary)' }}>
                        {ev.stage.replace(/_/g, ' ')}
                      </strong>
                      <span
                        style={{
                          fontSize: '9px',
                          fontFamily: 'var(--font-sans)',
                          padding: '1px 6px',
                          borderRadius: '3px',
                          fontWeight: 600,
                          background: clsBg,
                          color: clsTone,
                          border: '1px solid var(--border)',
                        }}
                      >
                        {ev.classification}
                      </span>
                      {ev.primary_techniques && ev.primary_techniques.length > 0 && (
                        <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                          [{ev.primary_techniques.join(', ')}]
                        </span>
                      )}
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', fontFamily: 'var(--font-sans)', fontSize: '11px', fontVariantNumeric: 'tabular-nums' }}>
                      <span style={{ color: 'var(--text-secondary)' }}>
                        Conf: {(ev.confidence * 100).toFixed(0)}%
                      </span>
                      <span style={{ color: 'var(--text-muted)', fontSize: '10px' }}>
                        {ev.supporting_evidence_count ?? 0} evidence
                      </span>
                      {isSelected ? <ChevronUp size={14} color="var(--text-muted)" /> : <ChevronDown size={14} color="var(--text-muted)" />}
                    </div>
                  </div>

                  {/* Expanded Evidence Exposure Drawer */}
                  {isSelected && (
                    <div
                      style={{
                        padding: '10px 14px',
                        borderTop: '1px dashed var(--border)',
                        background: 'rgba(0, 0, 0, 0.2)',
                        fontSize: '11px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '6px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', color: 'var(--text-muted)' }}>
                        <span>Temporal Status: <strong style={{ color: clsTone }}>{ev.classification}</strong></span>
                        <span>Stage Confidence: <strong>{(ev.stage_confidence * 100).toFixed(1)}%</strong> | Technique Certainty: <strong>{(ev.technique_confidence * 100).toFixed(1)}%</strong></span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>MITRE ATT&CK Mapping: </span>
                        <span style={{ color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
                          {ev.primary_techniques && ev.primary_techniques.length > 0 ? ev.primary_techniques.join(', ') : 'Zero specific malicious techniques mapped (Nominal baseline)'}
                        </span>
                      </div>
                      <div style={{ color: 'var(--text-secondary)', lineHeight: 1.4 }}>
                        <span style={{ color: 'var(--text-muted)' }}>Evidentiary Telemetry: </span>
                        {ev.supporting_evidence_count && ev.supporting_evidence_count > 0
                          ? `Grounded in ${ev.supporting_evidence_count} corroborating telemetry observations across layer-3/4 packet features.`
                          : 'No anomalous feature deviation from baseline detected for this checkpoint.'}
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Evaluated Transitions & Timeline Validation Audit */}
      {progression.transitions && progression.transitions.length > 0 && (
        <div style={{ marginTop: '20px', borderTop: '1px dashed var(--border)', paddingTop: '16px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
            <span className="eyebrow" style={{ margin: 0 }}>
              Evaluated State Transition Kinematics & Evidence Rules
            </span>
            {progression.validation && (
              <span
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--font-sans)',
                  padding: '2px 8px',
                  borderRadius: '4px',
                  fontWeight: 600,
                  background: progression.validation.valid ? 'rgba(74, 222, 128, 0.08)' : 'rgba(239, 68, 68, 0.08)',
                  color: progression.validation.valid ? 'var(--green, #4ade80)' : 'var(--danger)',
                  border: '1px solid currentColor',
                }}
              >
                AUDIT: {progression.validation.valid ? 'PASSED (VALID)' : 'ISSUES DETECTED'}
              </span>
            )}
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {progression.transitions.map((tr, idx) => {
              const isValid = tr.status === 'VALID' || tr.status === 'VALID_BUT_UNUSUAL'
              const isUnusual = tr.status === 'VALID_BUT_UNUSUAL'
              return (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '8px 12px',
                    borderRadius: '4px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                    fontSize: '12px',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <strong style={{ fontFamily: 'var(--font-sans)', fontWeight: 500, color: 'var(--text-primary)' }}>
                      {tr.from_stage} &rarr; {tr.to_stage}
                    </strong>
                    <span
                      style={{
                        fontSize: '9px',
                        fontFamily: 'var(--font-sans)',
                        padding: '1px 5px',
                        borderRadius: '3px',
                        fontWeight: 600,
                        background: isValid
                          ? isUnusual
                            ? 'rgba(245, 158, 11, 0.1)'
                            : 'rgba(74, 222, 128, 0.1)'
                          : 'rgba(239, 68, 68, 0.1)',
                        color: isValid
                          ? isUnusual
                            ? 'var(--amber)'
                            : 'var(--green, #4ade80)'
                          : 'var(--danger)',
                      }}
                    >
                      {tr.status}
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                      {tr.reason}
                    </span>
                  </div>
                  <span style={{ fontFamily: 'var(--font-sans)', fontSize: '11px', color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
                    Conf: {(tr.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </Panel>
  )
}
