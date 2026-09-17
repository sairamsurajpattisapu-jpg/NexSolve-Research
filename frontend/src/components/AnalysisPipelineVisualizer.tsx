import { useEffect, useMemo, useState } from 'react'
import {
  ArrowRight,
  CheckCircle,
  Circle,
  Clock,
  LoaderCircle,
  RefreshCw,
  Timer,
  X,
  XCircle,
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

  // When isReconnecting is true (HTTP transport timeout while job continues), it is NEVER classified as failed!
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

  const currentStepDescription = isJobTimedOut
    ? 'The capture exceeded the configured processing window before analysis completed.'
    : isFailed
    ? error || (job?.error as any)?.explanation || (job?.error as any)?.message || 'The analysis could not be completed.'
    : isSuccess
    ? 'Forensic and predictive record compiled. Ready for forecast view.'
    : activeStageDef.detail

  return (
    <div
      className="page-stack page-enter analysis-pipeline-root"
      style={{
        maxWidth: '1080px',
        margin: '28px auto 48px auto',
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
            border: '1px solid var(--accent)',
            borderRadius: '4px',
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, color: 'var(--accent)' }}>
              <RefreshCw size={14} className="spin-slow" />
              <span>PROCESSING CONTINUES</span>
            </div>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
              Attempt {reconnectAttempt}/10
            </span>
          </div>
          <div style={{ color: 'var(--text-secondary)', fontSize: '12.5px', fontFamily: 'var(--sans)' }}>
            The request exceeded the response window, but the analysis job is still running.
          </div>
          <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
            <strong>CURRENT STEP:</strong> {activeStageDef.activeTitle}
          </div>
        </div>
      )}

      {/* Main Analysis Pipeline Container */}
      <div
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '6px',
          boxShadow: '0 1px 3px rgba(0,0,0,0.06)',
          overflow: 'hidden',
        }}
      >
        {/* Compact Technical Metadata Bar */}
        <div
          style={{
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-secondary)',
            padding: '10px 20px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
            gap: '12px',
            fontSize: '11px',
            fontFamily: 'var(--mono)',
          }}
        >
          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              INPUT
            </span>
            <span style={{ fontWeight: 600, color: 'var(--text-primary)' }} title={filename}>
              {filename.length > 20 ? `${filename.slice(0, 18)}...` : filename}
            </span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              FORMAT
            </span>
            <span style={{ color: 'var(--text-primary)' }}>{formatLabel}</span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              STATUS
            </span>
            <span
              style={{
                fontWeight: 700,
                color: isSuccess
                  ? 'var(--success)'
                  : isFailed
                  ? 'var(--danger)'
                  : isReconnecting
                  ? '#eda850'
                  : 'var(--text-primary)',
              }}
            >
              {authoritativeStatus}
            </span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              DISCRETIZATION
            </span>
            <span style={{ color: 'var(--text-primary)' }}>60s discrete</span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              FEATURE SCHEMA
            </span>
            <span style={{ color: 'var(--text-primary)' }}>45-feature canonical</span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              CONTEXT
            </span>
            <span style={{ color: 'var(--text-primary)' }}>
              {windowsCount !== undefined && windowsCount > 0
                ? totalWindows !== undefined && totalWindows > windowsCount
                  ? `${windowsCount} / ${totalWindows} Windows`
                  : `${windowsCount} Windows`
                : 'Calculating...'}
            </span>
          </div>

          {fileSizeStr && (
            <div>
              <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
                FILE SIZE
              </span>
              <span style={{ color: 'var(--text-primary)' }}>{fileSizeStr}</span>
            </div>
          )}

          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              PACKETS
            </span>
            <span style={{ color: 'var(--text-primary)' }}>
              {packetsCount !== undefined && packetsCount > 0
                ? totalPackets !== undefined && totalPackets > packetsCount
                  ? `${packetsCount.toLocaleString()} / ${totalPackets.toLocaleString()}`
                  : packetsCount.toLocaleString()
                : '—'}
            </span>
          </div>
        </div>

        {/* Header Section with Current Step & Timing Metrics */}
        <div
          style={{
            padding: '24px 28px 20px 28px',
            borderBottom: '1px solid var(--border)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            flexWrap: 'wrap',
            gap: '16px',
          }}
        >
          <div style={{ flex: 1, minWidth: '260px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px', flexWrap: 'wrap' }}>
              <span
                style={{
                  fontSize: '10px',
                  fontFamily: 'var(--mono)',
                  letterSpacing: '0.1em',
                  fontWeight: 700,
                  color: 'var(--text-muted)',
                  textTransform: 'uppercase',
                }}
              >
                EXECUTION PIPELINE
              </span>
              <span
                style={{
                  fontSize: '9.5px',
                  fontFamily: 'var(--mono)',
                  padding: '2px 7px',
                  borderRadius: '3px',
                  fontWeight: 600,
                  background: isSuccess
                    ? 'rgba(16, 185, 129, 0.12)'
                    : isFailed
                    ? 'rgba(225, 29, 72, 0.1)'
                    : 'var(--bg-secondary)',
                  color: isSuccess
                    ? 'var(--success)'
                    : isFailed
                    ? 'var(--danger)'
                    : 'var(--text-primary)',
                  border: isSuccess
                    ? '1px solid rgba(16, 185, 129, 0.3)'
                    : isFailed
                    ? '1px solid rgba(225, 29, 72, 0.3)'
                    : '1px solid var(--border)',
                }}
              >
                {authoritativeStatus}
              </span>
              {jobId && (
                <span
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                    padding: '1px 6px',
                    borderRadius: '3px',
                    border: '1px solid var(--border)',
                    background: 'var(--bg-secondary)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  ID: {jobId.slice(0, 16)}
                </span>
              )}
            </div>

            <h1
              style={{
                fontSize: '21px',
                fontWeight: 700,
                margin: '2px 0 0 0',
                color: isFailed ? 'var(--danger)' : 'var(--text-primary)',
                letterSpacing: '-0.02em',
              }}
            >
              {currentStepTitle}
            </h1>
            <p
              style={{
                margin: '4px 0 0 0',
                fontSize: '13px',
                color: isFailed ? 'var(--text-muted)' : 'var(--text-secondary)',
                lineHeight: 1.45,
                maxWidth: '620px',
              }}
            >
              {currentStepDescription}
            </p>

            {/* Failure state recovery & diagnostics */}
            {isFailed && (
              <>
                <div style={{ marginTop: '6px', fontSize: '12px', color: 'var(--text-muted)' }}>
                  Analysis could not be completed.
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '14px', flexWrap: 'wrap' }}>
                  {onRetry && (
                    <button
                      type="button"
                      className="button button-primary"
                      onClick={onRetry}
                      style={{ fontSize: '12px', height: '32px', padding: '0 14px' }}
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
                        style={{ fontSize: '12px', height: '32px', padding: '0 14px' }}
                      >
                        Choose Another File
                      </button>
                      <button
                        type="button"
                        className="button button-quiet"
                        onClick={onCancel}
                        style={{ fontSize: '12px', height: '32px', padding: '0 14px' }}
                      >
                        Return to Console
                      </button>
                    </>
                  )}
                </div>

                <details
                  style={{
                    marginTop: '16px',
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
              </>
            )}
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '20px', flexWrap: 'wrap' }}>
            <div style={{ textAlign: 'right' }}>
              <div
                style={{
                  fontSize: '10.5px',
                  fontFamily: 'var(--mono)',
                  color: 'var(--text-muted)',
                  marginBottom: '2px',
                }}
              >
                PROGRESS
              </div>
              <div
                style={{
                  fontSize: '18px',
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
                  <span style={{ fontSize: '14px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <LoaderCircle size={14} className="spin-slow" /> PROCESSING
                  </span>
                )}
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div
                style={{
                  fontSize: '10.5px',
                  fontFamily: 'var(--mono)',
                  color: 'var(--text-muted)',
                  marginBottom: '2px',
                }}
              >
                ELAPSED TIME
              </div>
              <div
                style={{
                  fontSize: '18px',
                  fontFamily: 'var(--mono)',
                  fontWeight: 700,
                  color: 'var(--text-primary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  justifyContent: 'flex-end',
                }}
              >
                <Clock size={15} color="var(--text-muted)" />
                {formatElapsedDuration(elapsedSeconds)}
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div
                style={{
                  fontSize: '10.5px',
                  fontFamily: 'var(--mono)',
                  color: 'var(--text-muted)',
                  marginBottom: '2px',
                }}
              >
                ESTIMATED REMAINING
              </div>
              <div
                style={{
                  fontSize: '18px',
                  fontFamily: 'var(--mono)',
                  fontWeight: 700,
                  color: isEtaCalculating ? 'var(--text-muted)' : 'var(--text-primary)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  justifyContent: 'flex-end',
                }}
              >
                <Timer size={15} color="var(--text-muted)" />
                {formattedEta}
              </div>
            </div>

            {onCancel && !isSuccess && !isFailed && (
              <button
                type="button"
                className="button button-quiet"
                onClick={onCancel}
                style={{ height: '32px', padding: '0 10px', fontSize: '12px', gap: '4px' }}
                title="Cancel processing job"
              >
                <X size={14} /> Cancel
              </button>
            )}
          </div>
        </div>

        {/* Completion Transition Overlay */}
        {isSuccess && (
          <div
            style={{
              background: 'rgba(16, 185, 129, 0.08)',
              borderBottom: '1px solid rgba(16, 185, 129, 0.25)',
              padding: '14px 28px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
              fontSize: '12.5px',
              animation: 'fadeIn 0.3s ease',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <CheckCircle size={18} color="var(--success)" />
              <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>
                ANALYSIS COMPLETE &rarr; FORECAST READY
              </span>
            </div>
            {onReady && (
              <button
                type="button"
                className="button button-primary"
                onClick={onReady}
                style={{ fontSize: '12px', height: '30px', padding: '0 14px', gap: '6px' }}
              >
                Open Forecast <ArrowRight size={14} />
              </button>
            )}
          </div>
        )}

        {/* 12-Stage Editorial Timeline */}
        <div
          style={{
            padding: '28px 28px 20px 28px',
          }}
        >
          <div
            className="editorial-timeline"
            role="list"
            aria-label="Pipeline execution stages"
            style={{
              display: 'flex',
              flexDirection: 'column',
              gap: '0',
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
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '18px',
                    position: 'relative',
                    paddingBottom: idx === PIPELINE_STAGES.length - 1 ? '0' : '20px',
                    opacity: isPending ? 0.45 : 1,
                    transition: 'opacity 0.25s ease',
                  }}
                >
                  {/* Vertical connecting line */}
                  {idx < PIPELINE_STAGES.length - 1 && (
                    <div
                      style={{
                        position: 'absolute',
                        left: '15px',
                        top: '30px',
                        bottom: '0',
                        width: '1px',
                        background: isPassed ? 'var(--text-primary)' : 'var(--border)',
                        transition: 'background 0.3s ease',
                      }}
                    />
                  )}

                  {/* Stage Marker Indicator */}
                  <div
                    style={{
                      width: '32px',
                      height: '32px',
                      borderRadius: '50%',
                      background: isPassed
                        ? 'var(--bg-surface)'
                        : isCurrentActive
                        ? 'var(--bg-surface)'
                        : isCurrentFailed
                        ? 'rgba(225, 29, 72, 0.1)'
                        : 'var(--bg-secondary)',
                      color: isPassed
                        ? 'var(--success)'
                        : isCurrentFailed
                        ? 'var(--danger)'
                        : isCurrentActive
                        ? 'var(--accent)'
                        : 'var(--text-muted)',
                      border: isCurrentFailed
                        ? '2px solid var(--danger)'
                        : isCurrentActive
                        ? '2px solid var(--accent)'
                        : isPassed
                        ? '1px solid rgba(16, 185, 129, 0.3)'
                        : '1px solid var(--border)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                      position: 'relative',
                      zIndex: 2,
                      fontSize: '11px',
                      fontFamily: 'var(--mono)',
                      fontWeight: 700,
                      boxShadow: isCurrentActive ? '0 0 0 3px var(--border)' : 'none',
                      transition: 'all 0.25s ease',
                    }}
                  >
                    {isPassed ? (
                      <CheckCircle size={16} color="var(--success)" />
                    ) : isCurrentFailed ? (
                      <XCircle size={16} color="var(--danger)" />
                    ) : isCurrentActive ? (
                      <LoaderCircle size={16} className="spin-slow" color="var(--accent)" />
                    ) : (
                      <Circle size={14} color="var(--text-muted)" />
                    )}
                  </div>

                  {/* Stage Content */}
                  <div
                    style={{
                      flex: 1,
                      display: 'flex',
                      alignItems: 'baseline',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: '8px',
                      paddingTop: '5px',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span
                          style={{
                            fontSize: '11px',
                            fontFamily: 'var(--mono)',
                            color: 'var(--text-muted)',
                            fontWeight: 600,
                          }}
                        >
                          {st.num}
                        </span>
                        <span
                          style={{
                            fontSize: '13px',
                            fontWeight: isCurrent ? 700 : 600,
                            fontFamily: 'var(--mono)',
                            letterSpacing: '0.04em',
                            color: isCurrentFailed
                              ? 'var(--danger)'
                              : isCurrentActive
                              ? 'var(--text-primary)'
                              : isPassed
                              ? 'var(--text-primary)'
                              : 'var(--text-muted)',
                          }}
                        >
                          {st.label}
                        </span>
                      </div>
                      <div
                        style={{
                          fontSize: '12px',
                          color: isCurrentFailed
                            ? 'var(--danger)'
                            : isCurrentActive
                            ? 'var(--text-secondary)'
                            : 'var(--text-muted)',
                          marginTop: '2px',
                        }}
                      >
                        {isCurrentFailed
                          ? error || (job?.error as any)?.explanation || (job?.error as any)?.message || st.detail
                          : st.detail}
                      </div>
                    </div>

                    {/* Stage Status Marker */}
                    <div style={{ textAlign: 'right' }}>
                      <span
                        style={{
                          fontSize: '10px',
                          fontFamily: 'var(--mono)',
                          padding: '2px 8px',
                          borderRadius: '3px',
                          fontWeight: 600,
                          background: isPassed
                            ? 'rgba(16, 185, 129, 0.08)'
                            : isCurrentFailed
                            ? 'rgba(225, 29, 72, 0.1)'
                            : isCurrentActive
                            ? 'var(--button-primary-bg)'
                            : 'transparent',
                          color: isPassed
                            ? 'var(--success)'
                            : isCurrentFailed
                            ? 'var(--danger)'
                            : isCurrentActive
                            ? 'var(--button-primary-text)'
                            : 'var(--text-muted)',
                          border: isPassed
                            ? '1px solid rgba(16, 185, 129, 0.25)'
                            : isCurrentFailed
                            ? '1px solid rgba(225, 29, 72, 0.3)'
                            : isCurrentActive
                            ? '1px solid var(--border)'
                            : '1px solid transparent',
                        }}
                      >
                        {isPassed
                          ? '✓ COMPLETE'
                          : isCurrentFailed
                          ? '× FAILED'
                          : isCurrentActive
                          ? '● ACTIVE'
                          : '○ PENDING'}
                      </span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
