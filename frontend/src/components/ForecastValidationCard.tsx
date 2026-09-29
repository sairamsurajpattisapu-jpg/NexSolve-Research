import { CheckCircle2, AlertCircle, HelpCircle, ShieldCheck } from 'lucide-react'
import type { ForecastValidation } from '../types/canonical'
import { Panel } from './Ui'

interface ForecastValidationCardProps {
  validation?: ForecastValidation
  isAbstained?: boolean
  abstentionReason?: string | null
}

export function ForecastValidationCard({
  validation,
  isAbstained = false,
  abstentionReason,
}: ForecastValidationCardProps) {
  const status = validation?.status ?? (isAbstained ? 'VALIDATION NOT AVAILABLE' : 'VALIDATION NOT AVAILABLE')
  const summary = validation?.summary ?? (
    isAbstained
      ? `Validation not available: forecasting withheld (${abstentionReason || 'Insufficient historical sequence'}).`
      : 'Validation not available: capture terminates at T0 without subsequent recorded observation windows.'
  )
  const points = validation?.points ?? []

  const isFullyValidated = status === 'VALIDATED'
  const isPartiallyValidated = status === 'PARTIALLY_VALIDATED'

  const statusBadgeBg = isFullyValidated
    ? 'rgba(255, 255, 255, 0.08)'
    : isPartiallyValidated
    ? 'rgba(255, 255, 255, 0.05)'
    : 'rgba(255, 255, 255, 0.02)'

  return (
    <Panel
      className="forecast-validation-card"
      style={{
        background: 'var(--bg-surface)',
        border: '1px solid var(--border)',
        borderRadius: '10px',
        padding: '22px',
        marginTop: '20px',
      }}
      aria-label="Forecast Validation Audit"
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                fontSize: '11px',
                fontFamily: 'var(--font-sans)',
                fontWeight: 600,
                letterSpacing: '0.04em',
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
              }}
            >
              FORECAST VALIDATION AUDIT
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--font-sans)',
                fontWeight: 700,
                padding: '2px 8px',
                borderRadius: '4px',
                background: statusBadgeBg,
                color: 'var(--text-primary)',
                border: '1px solid var(--border)',
                letterSpacing: '0.04em',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
              }}
            >
              {isFullyValidated ? <CheckCircle2 size={11} /> : isPartiallyValidated ? <ShieldCheck size={11} /> : <AlertCircle size={11} />}
              {status}
            </span>
          </div>

          <h3 style={{ margin: '4px 0 2px 0', fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
            Observed State (T0) &rarr; Forecast Rollout &rarr; Actual Telemetry
          </h3>
          <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', maxWidth: '780px' }}>
            {summary}
          </p>
        </div>

        <div style={{ textAlign: 'right', display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
            Empirical Coverage
          </span>
          <span style={{ fontSize: '14px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
            {validation ? `${validation.evaluatedHorizons} / 5` : '0 / 5'} Horizons
          </span>
        </div>
      </div>

      {/* Validation Comparison Table */}
      <div
        style={{
          border: '1px solid var(--border)',
          borderRadius: '8px',
          overflowX: 'auto',
          background: 'rgba(255, 255, 255, 0.01)',
        }}
      >
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
          <thead>
            <tr style={{ background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)' }}>
              <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600, width: '100px' }}>HORIZON</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600, width: '120px' }}>OBSERVED (T0)</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600, width: '160px' }}>PROJECTED (T+k)</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600, width: '170px' }}>ACTUAL SUBSEQUENT</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600, width: '130px' }}>RELATIONSHIP</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600, width: '130px' }}>STATUS</th>
              <th style={{ padding: '10px 12px', color: 'var(--text-muted)', fontWeight: 600 }}>TELEMETRY RATIONALE</th>
            </tr>
          </thead>
          <tbody>
            {points.length === 0 ? (
              <tr>
                <td colSpan={7} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  <HelpCircle size={16} style={{ display: 'inline', marginRight: '6px', verticalAlign: 'text-bottom' }} />
                  VALIDATION NOT AVAILABLE — No forward forecast points evaluated.
                </td>
              </tr>
            ) : (
              points.map((pt) => {
                const isPointValid = pt.validationStatus === 'VALIDATED'
                const isConsistent = pt.relationship === 'CONSISTENT'

                return (
                  <tr
                    key={pt.horizon}
                    style={{
                      borderBottom: '1px solid var(--border)',
                      background: 'transparent',
                    }}
                  >
                    <td style={{ padding: '10px 12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                      T+{pt.horizon} <span style={{ color: 'var(--text-muted)', fontWeight: 400, fontSize: '11px' }}>({pt.lookaheadSeconds}s)</span>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span
                        style={{
                          fontSize: '11px',
                          padding: '2px 6px',
                          borderRadius: '3px',
                          background: 'var(--bg-secondary)',
                          border: '1px solid var(--border)',
                          color: 'var(--text-primary)',
                        }}
                      >
                        {pt.observedStateAtT0}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      {pt.predictedStage ? (
                        <div>
                          <strong style={{ color: 'var(--text-primary)', display: 'block' }}>{pt.predictedStage}</strong>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                            P(Atk): {pt.predictedProbability !== null ? `${(pt.predictedProbability * 100).toFixed(1)}%` : 'Withheld'}
                          </span>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>Withheld</span>
                      )}
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      {pt.actualSubsequentState ? (
                        <div>
                          <strong style={{ color: 'var(--text-primary)', display: 'block' }}>{pt.actualSubsequentState}</strong>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
                            Score: {pt.actualThreatScore?.toFixed(1) ?? '—'}
                            {pt.actualPacketCount != null ? ` · ${pt.actualPacketCount} pkts` : ''}
                          </span>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-sans)', fontSize: '11px' }}>
                          NOT AVAILABLE
                        </span>
                      )}
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span
                        style={{
                          fontSize: '10.5px',
                          fontFamily: 'var(--font-sans)',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: '3px',
                          background: isConsistent
                            ? 'rgba(255, 255, 255, 0.08)'
                            : pt.relationship === 'DIVERGENT'
                            ? 'rgba(255, 255, 255, 0.04)'
                            : 'transparent',
                          border: '1px solid var(--border)',
                          color: 'var(--text-primary)',
                        }}
                      >
                        {pt.relationship}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px' }}>
                      <span
                        style={{
                          fontSize: '10.5px',
                          fontFamily: 'var(--font-sans)',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: '3px',
                          background: isPointValid ? 'rgba(255, 255, 255, 0.08)' : 'rgba(255, 255, 255, 0.02)',
                          border: '1px solid var(--border)',
                          color: 'var(--text-primary)',
                        }}
                      >
                        {pt.validationStatus}
                      </span>
                    </td>
                    <td style={{ padding: '10px 12px', color: 'var(--text-secondary)', fontSize: '11.5px', lineHeight: 1.4 }}>
                      {pt.explanation}
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <div style={{ marginTop: '12px', fontSize: '11.5px', color: 'var(--text-muted)', lineHeight: 1.45 }}>
        <strong>Forensic Validation Standard:</strong> NexSolve compares autoregressive multi-horizon rollouts strictly against empirical packets observed in subsequent capture time windows when present. When captures conclude at T0 or provide insufficient sequence length, validation status is explicitly withheld without imputation.
      </div>
    </Panel>
  )
}
