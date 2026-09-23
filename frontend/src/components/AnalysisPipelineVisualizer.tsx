import { useEffect, useMemo, useState } from 'react'
import {
  ArrowRight,
  CheckCircle,
  Clock,
  LoaderCircle,
  RefreshCw,
  Timer,
  X,
} from 'lucide-react'
import type { JobStageType, JobStatusResponse } from '../types/api'
import { calculateEta, formatElapsedDuration } from '../utils/etaEstimator'

export interface AnalysisPipelineVisualizerProps {
  jobId: string
  stage?: JobStageType | string
  progress?: number
  job?: JobStatusResponse | null
  file?: File | null
  isReconnecting?: boolean
  reconnectAttempt?: number
  isComplete?: boolean
  error?: string | null
  errorCode?: string | null
  onCancel?: () => void
  onReady?: () => void
  onRetry?: () => void
}

export interface PipelineStageDef {
  num: string
  id: string
  label: string
  activeTitle: string
  detail: string
}

export const PIPELINE_STAGES: PipelineStageDef[] = [
  {
    num: '01',
    id: 'UPLOAD',
    label: 'UPLOAD',
    activeTitle: 'UPLOADING CAPTURE',
    detail: 'Transmitting network capture to passive wire processing engine.',
  },
  {
    num: '02',
    id: 'VALIDATE',
    label: 'VALIDATE',
    activeTitle: 'VALIDATING CAPTURE',
    detail: 'Validating PCAP/PCAPNG boundaries, magic bytes, and headers.',
  },
  {
    num: '03',
    id: 'INGEST',
    label: 'INGEST',
    activeTitle: 'INGESTING CAPTURE',
    detail: 'Reading passive network frames from the capture.',
  },
  {
    num: '04',
    id: 'NORMALIZE',
    label: 'NORMALIZE',
    activeTitle: 'NORMALIZING FRAMES',
    detail: 'Decoding packet headers and protocol metadata.',
  },
  {
    num: '05',
    id: 'RECONSTRUCT',
    label: 'RECONSTRUCT',
    activeTitle: 'RECONSTRUCTING FLOWS',
    detail: 'Grouping bidirectional traffic into communication flows.',
  },
  {
    num: '06',
    id: 'WINDOWS',
    label: 'WINDOWS',
    activeTitle: 'BUILDING TEMPORAL WINDOWS',
    detail: 'Segmenting observed traffic into sequential analysis windows.',
  },
  {
    num: '07',
    id: 'FEATURES',
    label: 'FEATURES',
    activeTitle: 'EXTRACTING CANONICAL FEATURES',
    detail: 'Extracting 45-dimensional canonical network features.',
  },
  {
    num: '08',
    id: 'NETWORK_STATE',
    label: 'NETWORK STATE',
    activeTitle: 'RECONSTRUCTING NETWORK STATE',
    detail: 'Assembling canonical network-state representation and topology.',
  },
  {
    num: '09',
    id: 'THREAT_ANALYSIS',
    label: 'THREAT ANALYSIS',
    activeTitle: 'EVALUATING THREAT BEHAVIORS',
    detail: 'Evaluating behavioral heuristics, MITRE correlates, and entity profiles.',
  },
  {
    num: '10',
    id: 'FORECAST',
    label: 'FORECAST',
    activeTitle: 'GENERATING FORECAST',
    detail: 'Projecting future network-state evolution across configured horizons.',
  },
  {
    num: '11',
    id: 'EVIDENCE',
    label: 'EVIDENCE',
    activeTitle: 'COMPILING EVIDENCE CHAIN',
    detail: 'Corroborating observable evidence chain and counterfactual drivers.',
  },
  {
    num: '12',
    id: 'COMPLETE',
    label: 'COMPLETE',
    activeTitle: 'ANALYSIS COMPLETE',
    detail: 'Forensic and predictive record compiled. Ready for forecast view.',
  },
]

export const STAGE_INDEX_MAP: Record<string, number> = {
  UPLOAD: 0,
  UPLOADING: 0,
  VALIDATE: 1,
  VALIDATING: 1,
  INGESTION: 2,
  INGEST: 2,
  PARSING: 3,
  NORMALIZE: 3,
  NORMALIZING: 3,
  FLOW_RECONSTRUCTION: 4,
  FLOWS: 4,
  RECONSTRUCT: 4,
  RECONSTRUCTING: 4,
  WINDOWING: 5,
  WINDOWS: 5,
  TEMPORAL_WINDOWING: 5,
  FEATURES: 6,
  REPRESENT: 6,
  CANONICAL_FEATURES: 6,
  NETWORK_STATE: 7,
  ANALYZE: 7,
  THREAT_ANALYSIS: 8,
  THREATS: 8,
  BEHAVIOR: 8,
  SIMULATE: 8,
  SIMULATION: 8,
  FORECAST: 9,
  FORECASTING: 9,
  EVIDENCE: 10,
  EXPLAIN: 10,
  REPORT: 10,
  COMPLETE: 11,
  COMPLETED: 11,
}

export function AnalysisPipelineVisualizer({
  jobId,
  stage = 'INGEST',
  progress = 0,
  job = null,
  file = null,
  isReconnecting = false,
  reconnectAttempt = 0,
  isComplete = false,
  error = null,
  errorCode = null,
  onCancel,
  onReady,
  onRetry,
}: AnalysisPipelineVisualizerProps) {
  const [mountTime] = useState(() => Date.now())
  const [now, setNow] = useState(mountTime)

  // Authoritative status evaluation strictly distinguishing Transport Timeout from Real Job Failure
  const jobStatus = job?.status
  const isTerminalFailed = jobStatus === 'FAILED' || jobStatus === 'ABORTED'
  const isLimitExceeded = jobStatus === 'RESOURCE_LIMIT_EXCEEDED'
  const isJobTimedOut =
    errorCode === 'ANALYSIS_TIMED_OUT' ||
    (isLimitExceeded && (job?.error as any)?.resource === 'processing_duration')

  const isFailed =
    !isReconnecting &&
    (isTerminalFailed ||
      isLimitExceeded ||
      isJobTimedOut ||
      (!!error && !job && !jobId))

  const isSuccess = isComplete || jobStatus === 'COMPLETED' || String(stage).toUpperCase() === 'COMPLETE'
  const isUploading = String(stage).toUpperCase() === 'UPLOAD' || (!job && !isSuccess && !isFailed && !jobId)

  // Timer loop
  useEffect(() => {
    if (isSuccess || isFailed) return
    const timer = setInterval(() => {
      setNow(Date.now())
    }, 1000)
    return () => clearInterval(timer)
  }, [isSuccess, isFailed])

  // Preserved elapsed duration from backend started_at if available
  const elapsedSeconds = useMemo(() => {
    if (job?.started_at) {
      const startTime = new Date(job.started_at).getTime()
      if (!Number.isNaN(startTime)) {
        if (job.completed_at) {
          const endTime = new Date(job.completed_at).getTime()
          if (!Number.isNaN(endTime)) {
            return Math.max(0, Math.floor((endTime - startTime) / 1000))
          }
        }
        return Math.max(0, Math.floor((now - startTime) / 1000))
      }
    }
    return Math.max(0, Math.floor((now - mountTime) / 1000))
  }, [job?.started_at, job?.completed_at, now, mountTime])

  // Map active stage
  const stageKey = String(stage || '').toUpperCase()
  const effectiveIdx = isSuccess ? 11 : (STAGE_INDEX_MAP[stageKey] ?? 2)
  const activeStageDef = PIPELINE_STAGES[Math.min(effectiveIdx, PIPELINE_STAGES.length - 1)] || PIPELINE_STAGES[0]

  // File metadata
  const filename = job?.filename || file?.name || 'capture.pcap'
  const isPcapng = filename.toLowerCase().endsWith('.pcapng')
  const isCsv = filename.toLowerCase().endsWith('.csv')
  const formatLabel = isPcapng ? 'PCAPNG' : isCsv ? 'CSV' : 'PCAP'

  const fileSizeStr = useMemo(() => {
    if (file?.size) {
      return `${(file.size / (1024 * 1024)).toFixed(2)} MB`
    }
    const bytes = (job as any)?.upload?.size_bytes || (job as any)?.source?.size_bytes
    if (bytes) {
      return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
    }
    return null
  }, [file?.size, job])

  const stats = job?.processing_statistics
  const packetsCount = stats?.packets_processed
  const totalPackets = (stats as any)?.total_packets
  const flowsCount = (stats as any)?.flows_processed ?? (job as any)?.traffic?.flow_count
  const windowsCount = stats?.windows_processed
  const totalWindows = (stats as any)?.total_windows

  // Deterministic progress calculation from real telemetry
  const hasRealProgress = isSuccess || (job?.progress !== undefined && job.progress > 0) || (progress !== undefined && progress > 0)
  const effectiveProgressFraction = isSuccess
    ? 1.0
    : job?.progress !== undefined && job.progress > 0
    ? job.progress
    : progress > 0
    ? (progress > 1 ? progress / 100 : progress)
    : 0

  const progressPercent = Math.min(100, Math.max(0, Math.round(effectiveProgressFraction * 100)))

  // ETA Calculation strictly from real telemetry
  const { formattedEta, isCalculating: isEtaCalculating } = calculateEta({
    elapsedSeconds,
    progress: effectiveProgressFraction,
    stage: activeStageDef.id,
    status: isSuccess ? 'COMPLETED' : isFailed ? 'FAILED' : isJobTimedOut ? 'TIMED_OUT' : jobStatus,
    backendEtaSeconds: (job as any)?.estimated_remaining_seconds ?? (job as any)?.eta_seconds ?? null,
    packetsProcessed: packetsCount,
    totalPackets,
    windowsProcessed: windowsCount,
    totalWindows,
  })

  // Authoritative status banner string
  const authoritativeStatus = isJobTimedOut
    ? 'ANALYSIS TIMED OUT'
    : isFailed
    ? 'ANALYSIS FAILED'
    : isSuccess
    ? 'COMPLETED'
    : isReconnecting
    ? 'PROCESSING CONTINUES'
    : isUploading
    ? 'UPLOADING'
    : 'PROCESSING'

  const currentStepTitle = isJobTimedOut
    ? 'ANALYSIS TIMED OUT'
    : isFailed
    ? effectiveIdx === 0
      ? 'UPLOAD FAILED'
      : effectiveIdx === 1
      ? 'CAPTURE VALIDATION FAILED'
      : 'ANALYSIS FAILED'
    : isSuccess
    ? 'ANALYSIS COMPLETE'
    : activeStageDef.activeTitle

  return (
    <div
      className="page-stack page-enter analysis-pipeline-root"
      style={{
        maxWidth: '1040px',
        margin: '24px auto 48px auto',
        width: '100%',
        padding: '0 16px',
      }}
      role="region"
      aria-label="Network Attack Analysis Pipeline"
    >
      {/* PROCESSING CONTINUES banner when HTTP request times out while background analysis continues */}
      {isReconnecting && !isFailed && !isSuccess && (
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-strong)',
            borderRadius: '6px',
            padding: '12px 18px',
            marginBottom: '16px',
            display: 'flex',
            flexDirection: 'column',
            gap: '6px',
            fontSize: '12px',
            fontFamily: 'var(--mono)',
            color: 'var(--text-primary)',
          }}
          role="status"
          aria-live="polite"
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, color: 'var(--text-primary)' }}>
              <RefreshCw size={14} className="spin-slow" />
              <span>PROCESSING CONTINUES</span>
            </div>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Attempt {reconnectAttempt}/10
            </span>
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '12.5px', fontFamily: 'var(--font-sans)' }}>
            The request exceeded the response window, but the analysis job is still running.
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            <strong>CURRENT STEP:</strong> {activeStageDef.activeTitle}
          </div>
        </div>
      )}

      {/* Main Analysis Container */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '24px 28px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
        }}
      >
        {/* 1. HERO SECTION */}
        <div
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '20px',
            paddingBottom: '20px',
            borderBottom: '1px solid var(--border)',
          }}
        >
          <div style={{ flex: 1, minWidth: '280px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px', flexWrap: 'wrap' }}>
              <span
                style={{
                  fontFamily: 'var(--mono)',
                  fontSize: '10px',
                  fontWeight: 700,
                  letterSpacing: '0.12em',
                  padding: '3px 8px',
                  borderRadius: '4px',
                  background: isSuccess
                    ? 'rgba(255, 255, 255, 0.12)'
                    : isFailed
                    ? 'rgba(255, 255, 255, 0.08)'
                    : 'var(--bg-elevated)',
                  color: isFailed ? 'var(--danger)' : 'var(--text-primary)',
                  border: '1px solid var(--border)',
                  textTransform: 'uppercase',
                }}
              >
                {isSuccess ? 'COMPLETED' : isFailed ? 'ANALYSIS FAILED' : 'ANALYZING'}
              </span>

              {formatLabel && (
                <span
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                    color: 'var(--text-muted)',
                    padding: '2px 6px',
                    borderRadius: '3px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                  }}
                >
                  {formatLabel}
                </span>
              )}

              {fileSizeStr && (
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  {fileSizeStr}
                </span>
              )}

              {jobId && (
                <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  · {jobId.slice(0, 14)}
                </span>
              )}
            </div>

            <h1
              style={{
                fontSize: '22px',
                fontWeight: 700,
                color: isFailed ? 'var(--danger)' : 'var(--text-primary)',
                margin: '0 0 4px 0',
                letterSpacing: '-0.02em',
                fontFamily: 'var(--font-sans)',
              }}
              title={filename}
            >
              {filename}
            </h1>

            <div style={{ fontSize: '13px', color: isFailed ? 'var(--danger)' : 'var(--text-secondary)' }}>
              {isFailed ? 'Analysis could not be completed.' : 'Processing network traffic'}
            </div>

            <div style={{ marginTop: '10px', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                STAGE:
              </span>
              <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--text-primary)' }}>
                {currentStepTitle}
              </span>
            </div>

            {/* Failure state recovery & diagnostics */}
            {isFailed && (
              <div style={{ marginTop: '14px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  {onRetry && (
                    <button
                      type="button"
                      className="button button-primary"
                      onClick={onRetry}
                      style={{ fontSize: '11px', height: '32px', padding: '0 14px' }}
                    >
                      {isUploading ? 'Retry Upload' : 'Retry Analysis'}
                    </button>
                  )}
                  {onCancel && (
                    <>
                      <button
                        type="button"
                        className="button button-quiet"
                        onClick={onCancel}
                        style={{ fontSize: '11px', height: '32px', padding: '0 14px' }}
                      >
                        Choose Another File
                      </button>
                      <button
                        type="button"
                        className="button button-quiet"
                        onClick={onCancel}
                        style={{ fontSize: '11px', height: '32px', padding: '0 14px' }}
                      >
                        Return to Console
                      </button>
                    </>
                  )}
                </div>

                <details
                  style={{
                    marginTop: '14px',
                    maxWidth: '620px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                    borderRadius: '4px',
                    padding: '8px 12px',
                    fontSize: '11px',
                    fontFamily: 'var(--mono)',
                  }}
                >
                  <summary style={{ cursor: 'pointer', color: 'var(--text-muted)', fontWeight: 600 }}>
                    Technical Diagnostics
                  </summary>
                  <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-secondary)' }}>
                    <div><strong>Job ID:</strong> {jobId || 'N/A'}</div>
                    <div><strong>Failed Stage:</strong> {activeStageDef.label}</div>
                    <div><strong>Status:</strong> {authoritativeStatus}</div>
                    <div><strong>Error Details:</strong> {error || (job?.error as any)?.explanation || (job?.error as any)?.message || 'Unspecified execution error.'}</div>
                  </div>
                </details>
              </div>
            )}
          </div>

          {/* Progress & Live Time Telemetry */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '22px', flexWrap: 'wrap' }}>
            <div style={{ textAlign: 'right' }}>
              <div
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--mono)',
                  color: 'var(--text-muted)',
                  marginBottom: '3px',
                  letterSpacing: '0.06em',
                }}
              >
                PROGRESS
              </div>
              <div
                style={{
                  fontSize: '22px',
                  fontFamily: 'var(--mono)',
                  fontWeight: 700,
                  color: 'var(--text-primary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  justifyContent: 'flex-end',
                }}
              >
                {hasRealProgress ? (
                  `${progressPercent}%`
                ) : (
                  <span style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <LoaderCircle size={13} className="spin-slow" /> PROCESSING
                  </span>
                )}
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--mono)',
                  color: 'var(--text-muted)',
                  marginBottom: '3px',
                  letterSpacing: '0.06em',
                }}
              >
                ELAPSED TIME
              </div>
              <div
                style={{
                  fontSize: '18px',
                  fontFamily: 'var(--mono)',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  justifyContent: 'flex-end',
                }}
              >
                <Clock size={14} color="var(--text-muted)" />
                {formatElapsedDuration(elapsedSeconds)}
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--mono)',
                  color: 'var(--text-muted)',
                  marginBottom: '3px',
                  letterSpacing: '0.06em',
                }}
              >
                ESTIMATED REMAINING
              </div>
              <div
                style={{
                  fontSize: '18px',
                  fontFamily: 'var(--mono)',
                  fontWeight: 600,
                  color: isEtaCalculating ? 'var(--text-muted)' : 'var(--text-primary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  justifyContent: 'flex-end',
                }}
              >
                <Timer size={14} color="var(--text-muted)" />
                {formattedEta}
              </div>
            </div>

            {onCancel && !isSuccess && !isFailed && (
              <button
                type="button"
                className="button button-quiet"
                onClick={onCancel}
                style={{ height: '32px', padding: '0 10px', fontSize: '11px', gap: '4px' }}
                title="Cancel processing job"
              >
                <X size={13} /> Cancel
              </button>
            )}
          </div>
        </div>

        {/* Subtle Progress Bar */}
        <div
          style={{
            width: '100%',
            height: '2px',
            background: 'var(--bg-elevated)',
            margin: '16px 0',
            overflow: 'hidden',
          }}
        >
          <div
            style={{
              height: '100%',
              width: `${progressPercent}%`,
              background: 'var(--text-primary)',
              transition: 'width 0.3s ease',
            }}
          />
        </div>

        {/* 2. ANALYSIS PROGRESS PIPELINE (Circuit-Board Execution Path) */}
        <div style={{ marginTop: '16px', marginBottom: '20px' }}>
          {/* Milestone Overview Track */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '8px',
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              color: 'var(--text-muted)',
              overflowX: 'auto',
              paddingBottom: '8px',
              marginBottom: '14px',
            }}
          >
            {[
              { id: 'upload', label: '1. UPLOAD' },
              { id: 'parse', label: '2. PARSE' },
              { id: 'flows', label: '3. FLOWS' },
              { id: 'features', label: '4. FEATURES' },
              { id: 'detect', label: '5. DETECT' },
              { id: 'forecast', label: '6. FORECAST' },
              { id: 'report', label: '7. REPORT' },
            ].map((step, stepIdx) => {
              const isStepActive =
                (stepIdx === 0 && effectiveIdx <= 1) ||
                (stepIdx === 1 && (effectiveIdx === 2 || effectiveIdx === 3)) ||
                (stepIdx === 2 && (effectiveIdx === 4 || effectiveIdx === 5)) ||
                (stepIdx === 3 && (effectiveIdx === 6 || effectiveIdx === 7)) ||
                (stepIdx === 4 && effectiveIdx === 8) ||
                (stepIdx === 5 && effectiveIdx === 9) ||
                (stepIdx === 6 && effectiveIdx >= 10)

              const isStepCompleted =
                isSuccess ||
                (stepIdx === 0 && effectiveIdx > 1) ||
                (stepIdx === 1 && effectiveIdx > 3) ||
                (stepIdx === 2 && effectiveIdx > 5) ||
                (stepIdx === 3 && effectiveIdx > 7) ||
                (stepIdx === 4 && effectiveIdx > 8) ||
                (stepIdx === 5 && effectiveIdx > 9)

              return (
                <div key={step.id} style={{ display: 'flex', alignItems: 'center', gap: '8px', whiteSpace: 'nowrap' }}>
                  <span
                    style={{
                      fontWeight: isStepActive ? 700 : 500,
                      color: isStepActive
                        ? 'var(--text-primary)'
                        : isStepCompleted
                        ? 'var(--text-secondary)'
                        : 'var(--text-muted)',
                      letterSpacing: '0.04em',
                    }}
                  >
                    {step.label}
                  </span>
                  {stepIdx < 6 && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '2px', opacity: 0.4 }}>
                      <span style={{ width: '3px', height: '3px', borderRadius: '50%', background: isStepCompleted ? 'var(--text-primary)' : 'var(--border)' }} />
                      <span style={{ width: '12px', height: '1px', background: isStepCompleted ? 'var(--text-secondary)' : 'var(--border)' }} />
                      <span style={{ width: '3px', height: '3px', borderRadius: '50%', background: isStepCompleted ? 'var(--text-primary)' : 'var(--border)' }} />
                    </div>
                  )}
                </div>
              )
            })}
          </div>

          {/* 12-stage Canonical Execution Segment Bar (PCB Circuit Metaphor) */}
          <div style={{ position: 'relative', width: '100%' }}>
            {/* Underlying PCB Bus Trace Wire */}
            <svg
              style={{
                position: 'absolute',
                top: '50%',
                left: 0,
                width: '100%',
                height: '10px',
                transform: 'translateY(-50%)',
                zIndex: 0,
                pointerEvents: 'none',
              }}
              preserveAspectRatio="none"
            >
              <line x1="2%" y1="5" x2="98%" y2="5" stroke="rgba(255, 255, 255, 0.12)" strokeWidth="1" strokeDasharray="3 3" />
            </svg>

            <div
              className="pipeline-stages-bar"
              role="list"
              aria-label="Pipeline execution stages"
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(72px, 1fr))',
                gap: '8px',
                position: 'relative',
                zIndex: 1,
              }}
            >
              {PIPELINE_STAGES.map((st, idx) => {
                const isPassed = isSuccess || idx < effectiveIdx
                const isCurrent = !isSuccess && idx === effectiveIdx
                const isCurrentFailed = isCurrent && isFailed
                const isCurrentActive = isCurrent && !isFailed
                const isPending = !isSuccess && idx > effectiveIdx

                return (
                  <div
                    key={st.id}
                    role="listitem"
                    aria-current={isCurrentActive ? 'step' : undefined}
                    aria-label={`Stage ${st.num}: ${st.label}, ${
                      isPassed
                        ? 'completed'
                        : isCurrentFailed
                        ? 'failed'
                        : isCurrentActive
                        ? 'currently processing'
                        : 'pending'
                    }`}
                    style={{
                      position: 'relative',
                      padding: '10px 4px 8px 4px',
                      borderRadius: '4px',
                      border: isCurrentActive
                        ? '1.5px solid rgba(255, 255, 255, 0.9)'
                        : isCurrentFailed
                        ? '1px solid var(--danger)'
                        : isPassed
                        ? '1px solid rgba(255, 255, 255, 0.2)'
                        : '1px solid rgba(255, 255, 255, 0.08)',
                      background: isCurrentActive
                        ? 'rgba(255, 255, 255, 0.08)'
                        : isPassed
                        ? 'rgba(255, 255, 255, 0.03)'
                        : 'rgba(0, 0, 0, 0.3)',
                      opacity: isPending ? 0.32 : 1,
                      textAlign: 'center',
                      boxShadow: isCurrentActive ? '0 0 12px rgba(255,255,255,0.2)' : 'none',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    <div style={{ fontSize: '8.5px', fontFamily: 'var(--mono)', color: isCurrentActive ? 'var(--text-primary)' : 'var(--text-muted)', marginBottom: '2px' }}>
                      {st.num}
                    </div>
                    <div
                      style={{
                        fontSize: '10px',
                        fontFamily: 'var(--mono)',
                        fontWeight: isCurrent ? 700 : 500,
                        color: isCurrentActive ? 'var(--text-primary)' : isPassed ? 'var(--text-secondary)' : 'var(--text-muted)',
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                      }}
                      title={st.label}
                    >
                      {st.label}
                    </div>

                    {/* Solder Terminal Pad */}
                    <div
                      style={{
                        marginTop: '4px',
                        display: 'inline-flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        width: '14px',
                        height: '14px',
                        borderRadius: '50%',
                        background: isPassed
                          ? 'var(--text-primary)'
                          : isCurrentFailed
                          ? 'var(--danger)'
                          : isCurrentActive
                          ? 'transparent'
                          : 'rgba(255, 255, 255, 0.04)',
                        border: isCurrentActive
                          ? '1.5px solid var(--text-primary)'
                          : '1px solid rgba(255, 255, 255, 0.18)',
                        color: isPassed ? 'var(--bg-primary)' : 'var(--text-primary)',
                        fontSize: '8.5px',
                        fontFamily: 'var(--mono)',
                        fontWeight: 700,
                        marginInline: 'auto',
                      }}
                    >
                      {isPassed ? '✓' : isCurrentFailed ? '×' : isCurrentActive ? '●' : '○'}
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        {/* 3. CENTRAL VISUAL: TRAFFIC -> STATE -> FORECAST */}
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            padding: '24px 20px',
            margin: '20px 0',
            position: 'relative',
            overflow: 'hidden',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
            <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', letterSpacing: '0.12em', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              NETWORK STATE SYNTHESIS & ATTACK PROJECTION
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              <span>SIGNAL:</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>SYNCHRONIZED</span>
            </div>
          </div>

          <svg
            viewBox="0 0 760 110"
            style={{ width: '100%', height: 'auto', display: 'block' }}
            aria-hidden="true"
          >
            {/* Grid hairline guides */}
            <line x1="40" y1="55" x2="720" y2="55" stroke="var(--border)" strokeWidth="1" strokeDasharray="4 4" />

            {/* Signal Waveform 1: Traffic to State */}
            <path
              d="M 160 55 C 210 20, 260 90, 310 55 C 330 40, 350 70, 380 55"
              fill="none"
              stroke={effectiveIdx >= 4 ? 'var(--text-primary)' : 'var(--border-strong)'}
              strokeWidth={effectiveIdx >= 0 ? 1.5 : 1}
              strokeOpacity={effectiveIdx >= 4 ? 0.9 : 0.4}
            />

            {/* Signal Waveform 2: State to Forecast */}
            <path
              d="M 420 55 C 470 25, 520 85, 570 55 C 600 40, 620 65, 640 55"
              fill="none"
              stroke={effectiveIdx >= 9 ? 'var(--text-primary)' : 'var(--border-strong)'}
              strokeWidth={effectiveIdx >= 4 ? 1.5 : 1}
              strokeOpacity={effectiveIdx >= 9 ? 0.9 : 0.3}
            />

            {/* Node 1: TRAFFIC */}
            <g transform="translate(120, 55)">
              <circle r="22" fill="var(--bg-surface)" stroke={effectiveIdx < 4 ? 'var(--text-primary)' : 'var(--border)'} strokeWidth="1.5" />
              <circle r="6" fill={effectiveIdx < 4 ? 'var(--text-primary)' : 'var(--text-muted)'} />
              <text y="38" textAnchor="middle" fill="var(--text-primary)" fontSize="10.5" fontFamily="var(--mono)" fontWeight="700" letterSpacing="0.06em">
                TRAFFIC
              </text>
              <text y="50" textAnchor="middle" fill="var(--text-muted)" fontSize="8.5" fontFamily="var(--mono)">
                FRAMES / WIRE
              </text>
            </g>

            {/* Node 2: STATE */}
            <g transform="translate(400, 55)">
              <circle r="22" fill="var(--bg-surface)" stroke={effectiveIdx >= 4 && effectiveIdx < 9 ? 'var(--text-primary)' : 'var(--border)'} strokeWidth="1.5" />
              <circle r="6" fill={effectiveIdx >= 4 && effectiveIdx < 9 ? 'var(--text-primary)' : effectiveIdx >= 9 ? 'var(--text-secondary)' : 'var(--text-muted)'} />
              <text y="38" textAnchor="middle" fill="var(--text-primary)" fontSize="10.5" fontFamily="var(--mono)" fontWeight="700" letterSpacing="0.06em">
                STATE
              </text>
              <text y="50" textAnchor="middle" fill="var(--text-muted)" fontSize="8.5" fontFamily="var(--mono)">
                CANONICAL TOPOLOGY
              </text>
            </g>

            {/* Node 3: ATTACK HORIZONS */}
            <g transform="translate(660, 55)">
              <circle r="22" fill="var(--bg-surface)" stroke={effectiveIdx >= 9 ? 'var(--text-primary)' : 'var(--border)'} strokeWidth="1.5" />
              <circle r="6" fill={effectiveIdx >= 9 ? 'var(--text-primary)' : 'var(--text-muted)'} />
              <text y="38" textAnchor="middle" fill="var(--text-primary)" fontSize="10.5" fontFamily="var(--mono)" fontWeight="700" letterSpacing="0.06em">
                HORIZONS
              </text>
              <text y="50" textAnchor="middle" fill="var(--text-muted)" fontSize="8.5" fontFamily="var(--mono)">
                ATTACK TRAJECTORY
              </text>
            </g>
          </svg>
        </div>

        {/* 4. LIVE METRICS GRID */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '12px',
            margin: '20px 0',
          }}
        >
          {/* Card 1: PACKETS */}
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '14px 16px' }}>
            <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '6px' }}>
              PACKETS
            </div>
            <div style={{ fontSize: '20px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
              {packetsCount !== undefined && packetsCount > 0
                ? totalPackets !== undefined && totalPackets > packetsCount
                  ? `${packetsCount.toLocaleString()} / ${totalPackets.toLocaleString()}`
                  : packetsCount.toLocaleString()
                : '—'}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Raw capture frames
            </div>
          </div>

          {/* Card 2: FLOWS */}
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '14px 16px' }}>
            <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '6px' }}>
              FLOWS
            </div>
            <div style={{ fontSize: '20px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
              {flowsCount !== undefined && flowsCount > 0 ? flowsCount.toLocaleString() : '—'}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              Reconstructed sessions
            </div>
          </div>

          {/* Card 3: WINDOWS */}
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '14px 16px' }}>
            <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '6px' }}>
              WINDOWS
            </div>
            <div style={{ fontSize: '20px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
              {windowsCount !== undefined && windowsCount > 0
                ? totalWindows !== undefined && totalWindows > windowsCount
                  ? `${windowsCount} / ${totalWindows} Windows`
                  : `${windowsCount} Windows`
                : 'Calculating...'}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              60s discrete slices
            </div>
          </div>

          {/* Card 4: STATUS */}
          <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px', padding: '14px 16px' }}>
            <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '6px' }}>
              STATUS
            </div>
            <div
              style={{
                fontSize: '18px',
                fontFamily: 'var(--mono)',
                fontWeight: 700,
                color: isSuccess
                  ? 'var(--text-primary)'
                  : isFailed
                  ? 'var(--danger)'
                  : isReconnecting
                  ? '#eda850'
                  : 'var(--text-primary)',
                whiteSpace: 'nowrap',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
              }}
            >
              {authoritativeStatus}
            </div>
            <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '4px' }}>
              {activeStageDef.label}
            </div>
          </div>
        </div>

        {/* 5. FORECAST SECTION & 6. EVIDENCE SUBTLE NOTE */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '16px',
            padding: '14px 18px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            marginTop: '12px',
          }}
        >
          {/* Forecast Progression */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', fontWeight: 600 }}>
              FORECAST HORIZON:
            </span>
            <div style={{ display: 'flex', gap: '6px' }}>
              {['T+1', 'T+2', 'T+3', 'T+4', 'T+5'].map((horizon) => (
                <span
                  key={horizon}
                  style={{
                    fontFamily: 'var(--mono)',
                    fontSize: '11px',
                    fontWeight: 600,
                    padding: '3px 8px',
                    borderRadius: '4px',
                    border: '1px solid var(--border)',
                    background: effectiveIdx >= 9 ? 'var(--bg-elevated)' : 'transparent',
                    color: effectiveIdx >= 9 ? 'var(--text-primary)' : 'var(--text-muted)',
                  }}
                >
                  {horizon}
                </span>
              ))}
            </div>
          </div>

          {/* Evidence note */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
            <span
              style={{
                display: 'inline-block',
                width: '6px',
                height: '6px',
                borderRadius: '50%',
                background: effectiveIdx >= 10 ? 'var(--text-primary)' : 'var(--text-muted)',
              }}
            />
            <span>Building evidence chain</span>
          </div>
        </div>

        {/* 7. COMPLETION STATE */}
        {isSuccess && (
          <div
            style={{
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-strong)',
              borderRadius: '6px',
              padding: '18px 24px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '16px',
              marginTop: '20px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <CheckCircle size={20} color="var(--text-primary)" />
              <div>
                <div style={{ fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
                  ANALYSIS COMPLETE &rarr; FORECAST READY
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '2px' }}>
                  Forensic temporal record and multi-horizon attack trajectory compiled.
                </div>
              </div>
            </div>
            {onReady && (
              <button
                type="button"
                className="button button-primary"
                onClick={onReady}
                style={{ fontSize: '12px', height: '36px', padding: '0 18px', gap: '8px' }}
              >
                Open Forecast <ArrowRight size={14} />
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
