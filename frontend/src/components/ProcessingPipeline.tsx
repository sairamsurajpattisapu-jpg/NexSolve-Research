import { CheckCircle2 } from 'lucide-react'
import { Panel } from './Ui'
import type { JobStageType, JobStatusResponse } from '../types/api'

interface ProcessingPipelineProps {
  job: JobStatusResponse
  onCancel?: () => void
}

const ORDERED_STAGES: Array<{ key: JobStageType; label: string; detail: string }> = [
  { key: 'INGESTION', label: 'Uploading PCAP', detail: 'Ingesting binary capture stream' },
  { key: 'PARSING', label: 'Extracting Packets', detail: 'Parsing frame headers & timestamps' },
  { key: 'FLOW_RECONSTRUCTION', label: 'Reconstructing Flows', detail: 'Assembling 5-tuple sessions' },
  { key: 'WINDOWING', label: 'Temporal Windowing', detail: 'Partitioning 60s observation windows' },
  { key: 'NETWORK_STATE', label: 'State Construction', detail: 'Extracting 45-feature state vectors' },
  { key: 'FORECAST', label: 'Running Forecast', detail: 'LSTM rollout & cumulative risk calculation' },
  { key: 'EVIDENCE', label: 'Attack Progression', detail: 'MITRE mapping & feature driver attribution' },
  { key: 'COMPLETE', label: 'Complete', detail: 'Results verified and ready' },
]

export function ProcessingPipeline({ job, onCancel }: ProcessingPipelineProps) {
  const isFailed = job.status === 'FAILED'
  const isLimitExceeded = job.status === 'RESOURCE_LIMIT_EXCEEDED'
  const isComplete = job.status === 'COMPLETED'
  const percent = Math.min(100, Math.max(0, Math.round(job.progress * 100)))

  // Current stage index
  const currentIndex = ORDERED_STAGES.findIndex((s) => s.key === job.stage)

  return (
    <Panel className="processing-pipeline-panel">
      <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <span className="eyebrow" style={{ color: 'var(--accent)' }}>
              REAL-TIME PROCESSING PIPELINE
            </span>
            <h3 style={{ margin: '2px 0 0 0', fontSize: '17px', color: 'var(--text-primary)' }}>
              {isComplete
                ? 'Analysis & Forecast Complete'
                : isFailed
                ? 'Processing Halted with Error'
                : isLimitExceeded
                ? 'Resource Limit Reached'
                : 'Processing Network Telemetry...'}
            </h3>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <span
              style={{
                fontFamily: 'var(--mono)',
                fontSize: '11px',
                padding: '2px 8px',
                borderRadius: '4px',
                background: isComplete
                  ? 'rgba(16, 185, 129, 0.12)'
                  : isFailed || isLimitExceeded
                  ? 'rgba(237, 128, 111, 0.12)'
                  : 'rgba(104, 225, 216, 0.12)',
                color: isComplete
                  ? 'var(--success)'
                  : isFailed || isLimitExceeded
                  ? 'var(--danger)'
                  : 'var(--accent)',
              }}
            >
              JOB: {job.job_id} &middot; {job.status}
            </span>

            {onCancel && !isComplete && (
              <button
                type="button"
                className="button button-quiet"
                onClick={onCancel}
                style={{ fontSize: '11px', padding: '3px 8px' }}
              >
                Cancel
              </button>
            )}
          </div>
        </div>

        {/* Progress Bar */}
        <div
          style={{
            width: '100%',
            height: '6px',
            borderRadius: '3px',
            background: 'var(--bg-secondary)',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              height: '100%',
              width: `${percent}%`,
              background: isComplete
                ? 'var(--success)'
                : isFailed || isLimitExceeded
                ? 'var(--danger)'
                : 'linear-gradient(90deg, var(--accent), #38bdf8)',
              transition: 'width 0.3s ease-in-out',
            }}
          />
        </div>

        {/* Stages Stepper */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: `repeat(${ORDERED_STAGES.length}, 1fr)`,
            gap: '8px',
            overflowX: 'auto',
            paddingBottom: '4px',
          }}
        >
          {ORDERED_STAGES.map((stage, idx) => {
            const isDone = isComplete || (currentIndex >= 0 && idx < currentIndex)
            const isCurrent = !isComplete && idx === currentIndex

            return (
              <div
                key={stage.key}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                  padding: '8px 10px',
                  borderRadius: '4px',
                  background: isCurrent
                    ? 'rgba(104, 225, 216, 0.08)'
                    : isDone
                    ? 'rgba(16, 185, 129, 0.05)'
                    : 'var(--bg-secondary)',
                  border: isCurrent
                    ? '1px solid var(--accent)'
                    : isDone
                    ? '1px solid rgba(16, 185, 129, 0.3)'
                    : '1px solid var(--border)',
                  minWidth: '100px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {isDone ? (
                    <CheckCircle2 size={12} color="var(--success)" />
                  ) : isCurrent ? (
                    <span
                      style={{
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        background: 'var(--accent)',
                        boxShadow: '0 0 6px var(--accent)',
                      }}
                    />
                  ) : (
                    <span
                      style={{
                        width: '6px',
                        height: '6px',
                        borderRadius: '50%',
                        background: 'var(--text-muted)',
                        opacity: 0.4,
                      }}
                    />
                  )}
                  <span
                    style={{
                      fontFamily: 'var(--mono)',
                      fontSize: '10px',
                      fontWeight: 700,
                      color: isCurrent
                        ? 'var(--accent)'
                        : isDone
                        ? 'var(--success)'
                        : 'var(--text-muted)',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {stage.label}
                  </span>
                </div>
                <span
                  style={{
                    fontSize: '9.5px',
                    color: 'var(--text-muted)',
                    lineHeight: 1.2,
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden',
                  }}
                >
                  {stage.detail}
                </span>
              </div>
            )
          })}
        </div>

        {/* Live Statistics when available */}
        {job.processing_statistics && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '10px 14px',
              borderRadius: '4px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              fontFamily: 'var(--mono)',
              fontSize: '11px',
              color: 'var(--text-secondary)',
            }}
          >
            <span>Packets: {job.processing_statistics.packets_processed?.toLocaleString() ?? 0}</span>
            <span>Flows: {job.processing_statistics.flows_processed?.toLocaleString() ?? 0}</span>
            <span>Windows: {job.processing_statistics.windows_processed?.toLocaleString() ?? 0}</span>
            <span>Duration: {job.processing_statistics.processing_seconds?.toFixed(2) ?? 0}s</span>
          </div>
        )}
      </div>
    </Panel>
  )
}
