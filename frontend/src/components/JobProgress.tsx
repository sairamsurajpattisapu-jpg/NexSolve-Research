import { useEffect, useState } from 'react'
import { AlertCircle, AlertTriangle, CheckCircle2, Clock, Cpu, HardDrive, Timer } from 'lucide-react'
import type { JobStageType, JobStatusResponse } from '../types/api'
import { calculateEta } from '../utils/etaEstimator'
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
  REPORT: 'Compiling Predictive Assessment Report',
  COMPLETE: 'Processing Complete',
}

export const CIRCUIT_8_STAGES = [
  { id: 'UPLOAD', num: '01', label: 'UPLOAD', sublabel: 'Wire stream' },
  { id: 'VALIDATE', num: '02', label: 'VALIDATE', sublabel: 'Format check' },
  { id: 'PARSE', num: '03', label: 'PARSE', sublabel: 'Header decode' },
  { id: 'FLOWS', num: '04', label: 'FLOWS', sublabel: 'Conversations' },
  { id: 'FEATURES', num: '05', label: 'FEATURES', sublabel: '45-dim schema' },
  { id: 'DETECT', num: '06', label: 'DETECT', sublabel: 'Threat vectors' },
  { id: 'FORECAST', num: '07', label: 'FORECAST', sublabel: 'T+1..T+5 horizons' },
  { id: 'REPORT', num: '08', label: 'REPORT', sublabel: 'Evidence chain' },
]

function getCircuit8Index(stage: JobStageType | string, isComplete: boolean): number {
  if (isComplete) return 7
  const s = String(stage || '').toUpperCase()
  if (s === 'UPLOAD' || s === 'UPLOADING') return 0
  if (s === 'VALIDATE' || s === 'VALIDATING') return 1
  if (s === 'INGESTION' || s === 'INGEST' || s === 'PARSING' || s === 'NORMALIZE') return 2
  if (s === 'FLOW_RECONSTRUCTION' || s === 'FLOWS' || s === 'WINDOWING' || s === 'WINDOWS') return 3
  if (s === 'NETWORK_STATE' || s === 'FEATURES') return 4
  if (s === 'THREAT_ANALYSIS' || s === 'THREATS' || s === 'DETECT' || s === 'BEHAVIOR') return 5
  if (s === 'FORECAST' || s === 'FORECASTING') return 6
  if (s === 'EVIDENCE' || s === 'REPORT' || s === 'COMPLETE' || s === 'COMPLETED') return 7
  return 2
}

export function JobProgress({ job, onCancel }: JobProgressProps) {
  const [elapsedSeconds, setElapsedSeconds] = useState(0)
  const isFailed = job.status === 'FAILED'
  const isLimitExceeded = job.status === 'RESOURCE_LIMIT_EXCEEDED'
  const isComplete = job.status === 'COMPLETED'
  const percent = Math.min(100, Math.max(0, Math.round(job.progress * 100)))

  const isStalled = job.last_progress_timestamp && (Date.now() / 1000 - job.last_progress_timestamp > 15)

  const formatBytes = (b?: number) => {
    if (b == null) return ''
    return (b / (1024 * 1024)).toFixed(1) + ' MB'
  }

  useEffect(() => {
    if (isComplete || isFailed || isLimitExceeded) return
    const timer = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1)
    }, 1000)
    return () => clearInterval(timer)
  }, [isComplete, isFailed, isLimitExceeded])

  const { formattedEta, isCalculating } = calculateEta({
    elapsedSeconds,
    progress: job.progress,
    stage: job.stage,
    status: job.status,
    backendEtaSeconds: job.estimated_remaining_seconds,
    bytesProcessed: job.bytes_processed,
    totalBytes: job.bytes_total,
    packetsProcessed: job.packets_processed,
  })

  const activeIndex = getCircuit8Index(job.stage, isComplete)

  return (
    <Panel className="job-progress-panel" style={{ padding: '20px 24px', position: 'relative', overflow: 'hidden' }}>
      {/* Subtle Top Ambient Activity Line */}
      {!isComplete && !isFailed && (
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            width: '100%',
            height: '2px',
            background: 'linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.85) 50%, transparent 100%)',
            animation: 'cinematicScan 2.4s ease-in-out infinite',
            opacity: 0.75,
            pointerEvents: 'none',
          }}
        />
      )}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', width: '100%' }}>
        {/* 1. Header with Overall Status & Filename */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: isLimitExceeded
                  ? 'var(--warning)'
                  : isFailed
                  ? 'var(--danger)'
                  : isComplete
                  ? 'var(--text-primary)'
                  : 'var(--text-primary)',
                boxShadow: isComplete || isFailed ? 'none' : '0 0 10px rgba(255, 255, 255, 0.8)',
                animation: isComplete || isFailed ? 'none' : 'subtleSignalPulse 1.8s ease-in-out infinite',
              }}
            />
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
                  {isLimitExceeded ? 'Safety Boundary' : isComplete ? 'ANALYSIS COMPLETE' : isFailed ? 'ANALYSIS FAILED' : 'ANALYZING CAPTURE'}
                </span>
                <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  STAGE: <strong style={{ color: 'var(--text-primary)' }}>{CIRCUIT_8_STAGES[activeIndex]?.label}</strong>
                </span>
              </div>
              <h4 style={{ margin: '2px 0 0 0', fontSize: '14px', color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
                {isLimitExceeded
                  ? 'Resource Limit Exceeded'
                  : isFailed
                  ? 'Processing Halted'
                  : STAGE_LABELS[job.stage] || (job.filename ? `CAPTURE · ${job.filename}` : 'Processing Capture')}
              </h4>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', fontFamily: 'var(--mono)', fontSize: '11px' }}>
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', letterSpacing: '0.06em' }}>PROGRESS</div>
              <div style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)' }}>{percent}%</div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', letterSpacing: '0.06em' }}>Elapsed:</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--text-secondary)' }}>
                <Clock size={11} color="var(--text-muted)" />
                <span>{elapsedSeconds}s</span>
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', letterSpacing: '0.06em' }}>Remaining:</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: isCalculating ? 'var(--text-muted)' : 'var(--text-primary)' }}>
                <Timer size={11} color="var(--text-muted)" />
                <span>{formattedEta}</span>
              </div>
            </div>

            {onCancel && !isComplete && !isFailed && (
              <button
                type="button"
                className="button button-quiet"
                onClick={onCancel}
                style={{ padding: '4px 10px', fontSize: '11px', height: '28px' }}
                aria-label="Cancel job"
              >
                Cancel
              </button>
            )}
          </div>
        </div>

        {/* 2. REAL 8-STAGE EXECUTION CIRCUIT FLOW */}
        <div style={{ position: 'relative', width: '100%', margin: '4px 0 6px 0' }}>
          {/* Continuous Circuit Bus Trace Wire */}
          <div
            style={{
              position: 'absolute',
              top: '22px',
              left: '4%',
              right: '4%',
              height: '1.5px',
              background: 'rgba(255, 255, 255, 0.12)',
              zIndex: 1,
            }}
          >
            {/* Subtle traveling signal bead showing live execution */}
            {!isComplete && !isFailed && (
              <div
                style={{
                  position: 'absolute',
                  top: '-3px',
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  background: 'var(--text-primary)',
                  boxShadow: '0 0 8px rgba(255, 255, 255, 0.9)',
                  animation: 'signalTravel 2.2s cubic-bezier(0.4, 0, 0.2, 1) infinite',
                }}
              />
            )}
          </div>

          <div
            className="circuit-flow-nodes"
            style={{
              display: 'grid',
              gridTemplateColumns: `repeat(${CIRCUIT_8_STAGES.length}, minmax(0, 1fr))`,
              gap: '6px',
              position: 'relative',
              zIndex: 2,
            }}
          >
            {CIRCUIT_8_STAGES.map((st, idx) => {
              const isPassed = isComplete || idx < activeIndex
              const isCurrent = !isComplete && idx === activeIndex
              const isCurrentFailed = isCurrent && isFailed
              const isCurrentActive = isCurrent && !isFailed
              const isUpcoming = !isComplete && idx > activeIndex

              return (
                <div
                  key={st.id}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    textAlign: 'center',
                    opacity: isUpcoming ? 0.35 : 1,
                    transition: 'all 0.25s ease',
                  }}
                >
                  <div
                    style={{
                      width: '20px',
                      height: '20px',
                      borderRadius: '50%',
                      background: isPassed
                        ? 'var(--text-primary)'
                        : isCurrentFailed
                        ? 'var(--danger)'
                        : isCurrentActive
                        ? 'var(--bg-primary)'
                        : 'var(--bg-secondary)',
                      border: isCurrentActive
                        ? '2px solid var(--text-primary)'
                        : isPassed
                        ? '1px solid var(--text-primary)'
                        : '1px solid rgba(255, 255, 255, 0.18)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '9px',
                      fontFamily: 'var(--mono)',
                      fontWeight: 700,
                      color: isPassed ? 'var(--bg-primary)' : 'var(--text-primary)',
                      boxShadow: isCurrentActive
                        ? '0 0 10px rgba(255, 255, 255, 0.4)'
                        : 'none',
                      marginBottom: '6px',
                    }}
                  >
                    {isPassed ? '✓' : isCurrentFailed ? '×' : isCurrentActive ? '●' : st.num}
                  </div>

                  <div
                    style={{
                      fontSize: '9.5px',
                      fontFamily: 'var(--mono)',
                      fontWeight: isCurrent ? 700 : 500,
                      color: isCurrentActive
                        ? 'var(--text-primary)'
                        : isPassed
                        ? 'var(--text-secondary)'
                        : 'var(--text-muted)',
                      letterSpacing: '0.04em',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      width: '100%',
                    }}
                  >
                    {st.label}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* 3. Progress Bar */}
        <div style={{ width: '100%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '4px', height: '6px', overflow: 'hidden' }}>
          <div
            style={{
              height: '100%',
              width: `${percent}%`,
              background: isLimitExceeded
                ? 'var(--warning)'
                : isFailed
                ? 'var(--danger)'
                : 'var(--text-primary)',
              transition: 'width 0.3s ease',
            }}
          />
        </div>

        {/* 4. Compact Telemetry Info */}
        <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', gap: '16px' }}>
            <span>Stage: <strong style={{ color: 'var(--text-secondary)' }}>{job.stage}</strong></span>
            {job.bytes_total && job.bytes_processed != null && (
              <span style={{ color: 'var(--text-secondary)' }}>{formatBytes(job.bytes_processed)} / {formatBytes(job.bytes_total)}</span>
            )}
            {job.throughput_mbps != null && job.throughput_mbps > 0 && (
              <span style={{ color: 'var(--text-secondary)' }}>{job.throughput_mbps} MB/s</span>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            {isStalled && !isComplete && !isFailed && !isLimitExceeded && (
              <span style={{ color: 'var(--warning)' }}>Processing continues - no progress reported</span>
            )}
            <span>{percent}% Deterministic Progress</span>
          </div>
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
              marginTop: '4px',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: '4px',
              padding: '8px 12px',
            }}
          >
            {job.processing_statistics.packets_processed !== undefined && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                <Cpu size={12} color="var(--accent)" />
                <span>{job.processing_statistics.packets_processed.toLocaleString()} pkts</span>
              </div>
            )}
            {job.processing_statistics.windows_processed !== undefined && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                <HardDrive size={12} color="var(--accent)" />
                <span>{job.processing_statistics.windows_processed} windows</span>
              </div>
            )}
            {job.processing_statistics.processing_seconds !== undefined && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-secondary)' }}>
                <Clock size={12} color="var(--accent)" />
                <span>{job.processing_statistics.processing_seconds}s runtime</span>
              </div>
            )}
            {isComplete && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-primary)' }}>
                <CheckCircle2 size={12} color="var(--text-primary)" />
                <span>Verified</span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Embedded CSS Animations for Subtle Cinematic Activity */}
      <style>{`
        @keyframes subtleSignalPulse {
          0%, 100% { transform: scale(1); opacity: 1; }
          50% { transform: scale(1.25); opacity: 0.75; }
        }
        @keyframes signalTravel {
          0% { left: 0%; opacity: 0; }
          15% { opacity: 1; }
          85% { opacity: 1; }
          100% { left: 100%; opacity: 0; }
        }
        @keyframes cinematicScan {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(100%); }
        }
      `}</style>
    </Panel>
  )
}
