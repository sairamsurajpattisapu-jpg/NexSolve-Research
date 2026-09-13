import { AlertCircle, Gauge, Info, ShieldCheck } from 'lucide-react'
import type { ForecastConfidencePayload } from '../types/api'
import { Panel, SectionHeading, StatusPill } from './Ui'

interface ForecastConfidenceProps {
  confidence: ForecastConfidencePayload
}

export function ForecastConfidence({ confidence }: ForecastConfidenceProps) {
  const isCalibrated = confidence.calibration_status === 'CALIBRATED'
  const isHighUncertainty = confidence.uncertainty_level === 'HIGH'

  return (
    <Panel className="forecast-confidence-panel">
      <SectionHeading
        eyebrow="Trust Layer / Uncertainty Breakdown"
        title="Confidence & Calibration"
        description="Separation of raw model output from calibrated posterior support and statistical uncertainty."
        action={
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--muted)' }}>
              Calibration:
            </span>
            <StatusPill tone={isCalibrated ? 'success' : 'warning'}>
              {confidence.calibration_status}
            </StatusPill>
          </div>
        }
      />

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))',
          gap: '12px',
          marginBottom: '14px',
        }}
      >
        <div className="metric-card" style={{ padding: '12px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Raw Forecast Score</span>
            <Gauge size={14} />
          </div>
          <strong style={{ fontSize: '20px', marginTop: '6px' }}>
            {confidence.forecast_score !== null ? confidence.forecast_score.toFixed(2) : 'N/A'}
          </strong>
          <small>Raw model head output margin</small>
        </div>

        <div className="metric-card" style={{ padding: '12px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Calibrated Confidence</span>
            {isCalibrated ? <ShieldCheck size={14} color="var(--teal)" /> : <Info size={14} color="var(--amber)" />}
          </div>
          <strong
            style={{
              fontSize: '18px',
              marginTop: '8px',
              color: isCalibrated ? 'var(--teal)' : 'var(--amber)',
            }}
          >
            {isCalibrated && confidence.confidence_value !== null
              ? (confidence.confidence_value * 100).toFixed(1) + '%'
              : 'Uncalibrated'}
          </strong>
          <small>{isCalibrated ? 'Statistically validated' : 'Withheld (Unsupported)'}</small>
        </div>

        <div className="metric-card" style={{ padding: '12px', minHeight: 'auto' }}>
          <div className="metric-top">
            <span>Uncertainty Level</span>
            <AlertCircle size={14} color={isHighUncertainty ? 'var(--red)' : 'var(--muted)'} />
          </div>
          <strong
            style={{
              fontSize: '18px',
              marginTop: '8px',
              color: isHighUncertainty ? 'var(--danger)' : 'var(--text-primary)',
            }}
          >
            {confidence.uncertainty_level}
          </strong>
          <small>Epistemic & boundary uncertainty</small>
        </div>
      </div>

      <div
        style={{
          padding: '10px 12px',
          background: 'var(--bg-secondary)',
          borderLeft: '2px solid var(--border)',
          borderRadius: '4px',
          fontSize: '11px',
          color: 'var(--text-secondary)',
          lineHeight: 1.5,
        }}
      >
        {confidence.explanation}
      </div>
    </Panel>
  )
}
