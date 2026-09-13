import { CheckCircle2, Info, ShieldOff } from 'lucide-react'
import type { ForecastAbstentionPayload } from '../types/api'
import { Panel, SectionHeading, StatusPill } from './Ui'

interface ForecastStatusProps {
  abstention: ForecastAbstentionPayload
}

export function ForecastStatus({ abstention }: ForecastStatusProps) {
  const isAbstained = abstention.abstained || abstention.status === 'FORECAST_UNAVAILABLE'
  const isAvailable = abstention.status === 'FORECAST_AVAILABLE'
  const isUncalibrated = abstention.status === 'FORECAST_AVAILABLE_BUT_UNCALIBRATED'

  return (
    <Panel className="forecast-status-panel">
      <SectionHeading
        eyebrow="Epistemic Safety Gate / Decision Integrity"
        title="Forecast Availability Status"
        description="NexSolve forecasts future network states when sufficient evidence exists, and explicitly abstains rather than hallucinating when observation history is insufficient."
        action={
          <StatusPill tone={isAvailable ? 'success' : isUncalibrated ? 'neutral' : 'warning'}>
            {isAbstained ? 'FORECAST WITHHELD' : abstention.status.replaceAll('_', ' ')}
          </StatusPill>
        }
      />

      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: '12px',
          padding: '14px 16px',
          background: isAbstained ? 'rgba(242, 187, 113, 0.1)' : 'var(--bg-secondary)',
          borderLeft: `3px solid ${isAvailable ? 'var(--accent)' : isUncalibrated ? 'var(--text-secondary)' : 'var(--warning)'}`,
          borderRadius: '4px',
        }}
      >
        <div style={{ marginTop: '2px' }}>
          {isAbstained ? (
            <ShieldOff size={18} color="var(--warning)" />
          ) : isUncalibrated ? (
            <Info size={18} color="var(--text-secondary)" />
          ) : (
            <CheckCircle2 size={18} color="var(--accent)" />
          )}
        </div>
        <div style={{ flex: 1 }}>
          <strong style={{ display: 'block', fontSize: '13px', color: isAbstained ? 'var(--warning)' : 'var(--text-primary)', marginBottom: '4px' }}>
            {isAbstained
              ? `Forecast Abstained: ${abstention.reason} (Deliberate Safety Decision)`
              : isUncalibrated
              ? 'Forecast Available (Uncalibrated Baseline)'
              : 'Forecast Fully Available'}
          </strong>
          <p style={{ fontSize: '12px', color: 'var(--text-primary)', margin: 0, lineHeight: 1.5 }}>
            {isAbstained
              ? 'FORECAST WITHHELD: NexSolve does not have enough reliable evidence to forecast the next network state.'
              : abstention.explanation}
          </p>
          {isAbstained && (
            <p style={{ fontSize: '11px', color: 'var(--subtle)', margin: '4px 0 0 0', lineHeight: 1.4 }}>
              {abstention.explanation}
            </p>
          )}

          {/* Structured Abstention Criteria Cards */}
          {isAbstained && (
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                gap: '8px',
                marginTop: '12px',
              }}
            >
              <div
                style={{
                  padding: '8px 10px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                }}
              >
                <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--warning)', textTransform: 'uppercase', display: 'block' }}>
                  Abstention Reason
                </span>
                <strong style={{ fontSize: '11px', color: 'var(--text-primary)' }}>
                  {abstention.reason === 'INSUFFICIENT_HISTORY'
                    ? 'Insufficient Temporal History'
                    : abstention.reason === 'GAPPED_HISTORY'
                    ? 'Telemetry Contains Temporal Gaps'
                    : (abstention.reason ?? 'INSUFFICIENT_EVIDENCE')}
                </strong>
              </div>

              <div
                style={{
                  padding: '8px 10px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                }}
              >
                <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--accent)', textTransform: 'uppercase', display: 'block' }}>
                  Observed Windows
                </span>
                <strong style={{ fontSize: '11px', color: 'var(--text-primary)' }}>
                  {abstention.observed_windows != null
                    ? `${abstention.observed_windows} window${abstention.observed_windows === 1 ? '' : 's'}${abstention.capture_duration_seconds ? ` (${Math.round(abstention.capture_duration_seconds)}s)` : ''}`
                    : '1 window (60s)'}
                </strong>
              </div>

              <div
                style={{
                  padding: '8px 10px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                }}
              >
                <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', display: 'block' }}>
                  {abstention.gap_seconds ? 'Gap Detected' : 'Required Minimum'}
                </span>
                <strong style={{ fontSize: '11px', color: 'var(--text-primary)' }}>
                  {abstention.gap_seconds
                    ? `${abstention.gap_seconds}s non-contiguous gap`
                    : `${abstention.required_windows ?? 8} contiguous windows (480s)`}
                </strong>
              </div>

              <div
                style={{
                  padding: '8px 10px',
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '4px',
                }}
              >
                <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--accent)', textTransform: 'uppercase', display: 'block' }}>
                  Recommended Action
                </span>
                <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  {abstention.reason === 'INSUFFICIENT_HISTORY'
                    ? 'Upload a longer capture containing continuous traffic history (at least 8 min).'
                    : abstention.reason === 'GAPPED_HISTORY'
                    ? 'Ensure capture has continuous traffic without idle minutes.'
                    : abstention.reason?.includes('QUALITY')
                    ? 'Re-capture traffic with non-degraded capture interface.'
                    : 'Observe network for at least 8 contiguous windows (480s).'}
                </span>
              </div>
            </div>
          )}

          {abstention.missing_requirements.length > 0 && (
            <div style={{ marginTop: '10px' }}>
              <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', color: 'var(--amber)', textTransform: 'uppercase', display: 'block', marginBottom: '4px' }}>
                Missing Prerequisites ({abstention.missing_requirements.length}):
              </span>
              <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--muted)' }}>
                {abstention.missing_requirements.map((req) => (
                  <li key={req}>{req}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    </Panel>
  )
}
