import { AlertCircle, AlertTriangle, CheckCircle2, Clock, Cpu, HardDrive } from 'lucide-react'
import type { JobStageType, JobStatusResponse } from '../types/api'
import { Panel } from './Ui'

interface JobProgressProps {
  job: JobStatusResponse
  onCancel?: () => void
}

const STAGE_LABELS: Record<JobStageType, string> = {
  INGESTION: 'Uploading & Ingesting Capture',
  PARSING: 'Parsing Frames & Packets',
  FLOW_RECONSTRUCTION: 'Reconstructing Transport Flows',
  WINDOWING: 'Building 60s Temporal Windows',
  NETWORK_STATE: 'Computing Canonical Network State',
  FORECAST: 'Evaluating Attack Forecasting Models',
  EVIDENCE: 'Corroborating Observable Evidence Chain',
  REPORT: 'Compiling Forensic & Predictive Report',
  COMPLETE: 'Processing Complete',
}

const STAGES_ORDER: JobStageType[] = [
  'INGESTION',
  'PARSING',
  'FLOW_RECONSTRUCTION',
  'WINDOWING',
  'NETWORK_STATE',
  'FORECAST',
  'EVIDENCE',
  'REPORT',
  'COMPLETE',
]

export function JobProgress({ job }: JobProgressProps) {
  const isFailed = job.status === 'FAILED'
  const isLimitExceeded = job.status === 'RESOURCE_LIMIT_EXCEEDED'
  const isComplete = job.status === 'COMPLETED'
  const percent = Math.min(100, Math.max(0, Math.round(job.progress * 100)))

  return (
    <Panel className="job-progress-panel">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', width: '100%' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <span className="eyebrow" style={{ color: 'var(--teal)' }}>Asynchronous PCAP Engine</span>
            <h4 style={{ margin: '2px 0 0 0', fontSize: '15px', color: 'var(--white)' }}>
              {isLimitExceeded
                ? 'Resource Limit Exceeded'
                : isFailed
                ? 'Processing Halted'
                : isComplete
                ? 'Network Analysis Complete'
                : STAGE_LABELS[job.stage] || 'Processing Capture'}
            </h4>
          </div>
          <div style={{ textAlign: 'right', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--muted)' }}>
            <div>JOB ID: {job.job_id}</div>
            <div style={{ color: isLimitExceeded ? '#f59e0b' : isFailed ? 'var(--red)' : isComplete ? '#10b981' : 'var(--teal)' }}>
              {job.status}
            </div>
          </div>
        </div>

        {/* Deterministic Progress Bar */}
        <div style={{ width: '100%', background: 'rgba(255, 255, 255, 0.06)', borderRadius: '4px', height: '8px', overflow: 'hidden' }}>
          <div
            style={{
              height: '100%',
              width: `${percent}%`,
              background: isLimitExceeded
                ? 'linear-gradient(90deg, #f59e0b, #d97706)'
                : isFailed
                ? 'linear-gradient(90deg, #e11d48, #be123c)'
                : isComplete
                ? 'linear-gradient(90deg, #10b981, #059669)'
                : 'linear-gradient(90deg, #0d9488, #0ea5e9)',
              transition: 'width 0.4s ease-in-out',
            }}
          />
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--muted)' }}>
          <span>Stage: {job.stage}</span>
          <span>{percent}% Deterministic Progress</span>
        </div>

        {/* Stage Timeline Badges */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px', marginTop: '4px' }}>
          {STAGES_ORDER.map((stageName, idx) => {
            const currentIdx = STAGES_ORDER.indexOf(job.stage)
            const isPast = idx < currentIdx || isComplete
            const isCurrent = idx === currentIdx && !isComplete && !isFailed && !isLimitExceeded
            return (
              <span
                key={stageName}
                style={{
                  fontSize: '9px',
                  fontFamily: 'var(--mono)',
                  padding: '2px 6px',
                  borderRadius: '3px',
                  background: isCurrent
                    ? 'rgba(13, 148, 136, 0.25)'
                    : isPast
                    ? 'rgba(16, 185, 129, 0.12)'
                    : 'rgba(255, 255, 255, 0.03)',
                  color: isCurrent
                    ? 'var(--teal)'
                    : isPast
                    ? '#34d399'
                    : 'var(--muted)',
                  border: isCurrent
                    ? '1px solid var(--teal)'
                    : isPast
                    ? '1px solid rgba(52, 211, 153, 0.3)'
                    : '1px solid rgba(255, 255, 255, 0.05)',
                }}
              >
                {stageName}
              </span>
            )
          })}
        </div>

        {/* Resource Limit Banner */}
        {isLimitExceeded && job.error && (
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '8px',
              background: 'rgba(245, 158, 11, 0.1)',
              border: '1px solid rgba(245, 158, 11, 0.3)',
              borderRadius: '4px',
              padding: '10px 12px',
              fontSize: '12px',
              color: '#fde68a',
            }}
          >
            <AlertTriangle size={16} color="#f59e0b" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong>Safety Boundary Enforced ({job.error.resource}):</strong> {job.error.explanation}
              {job.error.observed !== undefined && job.error.limit !== undefined && (
                <div style={{ marginTop: '4px', fontSize: '11px', fontFamily: 'var(--mono)' }}>
                  Observed: {job.error.observed} &middot; Limit: {job.error.limit}
                </div>
              )}
            </div>
          </div>
        )}

        {/* General Failure Banner */}
        {isFailed && job.error && (
          <div
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '8px',
              background: 'rgba(225, 29, 72, 0.1)',
              border: '1px solid rgba(225, 29, 72, 0.3)',
              borderRadius: '4px',
              padding: '10px 12px',
              fontSize: '12px',
              color: '#fecdd3',
            }}
          >
            <AlertCircle size={16} color="#e11d48" style={{ flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong>Processing Failed:</strong> {job.error.message || 'An unexpected parsing error occurred.'}
            </div>
          </div>
        )}

        {/* Execution Statistics */}
        {job.processing_statistics && Object.keys(job.processing_statistics).length > 0 && (
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))',
              gap: '8px',
              marginTop: '6px',
              background: 'rgba(15, 23, 42, 0.4)',
              border: '1px solid var(--line)',
              borderRadius: '4px',
              padding: '8px 12px',
            }}
          >
            {job.processing_statistics.packets_processed !== undefined && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                <Cpu size={12} color="var(--teal)" />
                <span>{job.processing_statistics.packets_processed.toLocaleString()} pkts</span>
              </div>
            )}
            {job.processing_statistics.windows_processed !== undefined && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                <HardDrive size={12} color="var(--teal)" />
                <span>{job.processing_statistics.windows_processed} windows</span>
              </div>
            )}
            {job.processing_statistics.processing_seconds !== undefined && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px' }}>
                <Clock size={12} color="var(--teal)" />
                <span>{job.processing_statistics.processing_seconds}s runtime</span>
              </div>
            )}
            {isComplete && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: '#34d399' }}>
                <CheckCircle2 size={12} color="#34d399" />
                <span>Verified</span>
              </div>
            )}
          </div>
        )}
      </div>
    </Panel>
  )
}
