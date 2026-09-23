import { useEffect, useMemo, useState } from 'react'
import {
  ArrowRight,
  CheckCircle,
  Clock,
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

export interface RealPipelineStage {
  id: string
  num: string
  label: string
  activeTitle: string
  sublabel: string
}

// Canonical 8 real pipeline stages requested by user:
// UPLOAD → VALIDATE → PARSE → FLOWS → FEATURES → DETECT → FORECAST → REPORT
export const REAL_PIPELINE_8_STAGES: RealPipelineStage[] = [
  { id: 'UPLOAD', num: '01', label: 'UPLOAD', activeTitle: 'UPLOADING CAPTURE', sublabel: 'Wire stream' },
  { id: 'VALIDATE', num: '02', label: 'VALIDATE', activeTitle: 'VALIDATING FORMAT', sublabel: 'PCAP boundary check' },
  { id: 'PARSE', num: '03', label: 'PARSE', activeTitle: 'PARSING WIRE FRAMES', sublabel: 'Ingest & decode frames' },
  { id: 'FLOWS', num: '04', label: 'FLOWS', activeTitle: 'RECONSTRUCTING FLOWS', sublabel: 'Flows & 60s windows' },
  { id: 'FEATURES', num: '05', label: 'FEATURES', activeTitle: 'EXTRACTING 45-DIM FEATURES', sublabel: 'Canonical network state' },
  { id: 'DETECT', num: '06', label: 'DETECT', activeTitle: 'EVALUATING THREAT VECTORS', sublabel: 'Behavioral detection' },
  { id: 'FORECAST', num: '07', label: 'FORECAST', activeTitle: 'GENERATING FORECAST', sublabel: 'T+1..T+5 Horizon projection' },
  { id: 'REPORT', num: '08', label: 'REPORT', activeTitle: 'COMPILING FORENSIC REPORT', sublabel: 'Evidence & report synthesis' },
]

export function mapStageTo8Index(stageStr: string, isSuccess: boolean, isUploading: boolean): number {
  if (isSuccess) return 7
  if (isUploading) return 0
  const s = String(stageStr || '').toUpperCase()
  if (s === 'UPLOAD' || s === 'UPLOADING') return 0
  if (s === 'VALIDATE' || s === 'VALIDATING') return 1
  if (s === 'INGESTION' || s === 'INGEST' || s === 'PARSING' || s === 'NORMALIZE' || s === 'NORMALIZING') return 2
  if (s === 'FLOW_RECONSTRUCTION' || s === 'FLOWS' || s === 'RECONSTRUCT' || s === 'RECONSTRUCTING' || s === 'WINDOWING' || s === 'WINDOWS' || s === 'TEMPORAL_WINDOWING') return 3
  if (s === 'NETWORK_STATE' || s === 'FEATURES' || s === 'CANONICAL_FEATURES' || s === 'REPRESENT') return 4
  if (s === 'THREAT_ANALYSIS' || s === 'THREATS' || s === 'DETECT' || s === 'BEHAVIOR' || s === 'SIMULATION' || s === 'SIMULATE' || s === 'ANALYZE') return 5
  if (s === 'FORECAST' || s === 'FORECASTING') return 6
  if (s === 'EVIDENCE' || s === 'EXPLAIN' || s === 'REPORT' || s === 'COMPLETE' || s === 'COMPLETED') return 7
  return 2
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

  // Live timer tick
  useEffect(() => {
    if (isSuccess || isFailed) return
    const timer = setInterval(() => {
      setNow(Date.now())
    }, 1000)
    return () => clearInterval(timer)
  }, [isSuccess, isFailed])

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

  // Map to 8-stage index
  const active8Index = mapStageTo8Index(stage || job?.stage || '', isSuccess, isUploading)
  const active8Stage = REAL_PIPELINE_8_STAGES[active8Index] || REAL_PIPELINE_8_STAGES[0]

  // Active stage definition matching the current stage
  const activeStageDef = useMemo(() => {
    const s = String(stage || job?.stage || '').toUpperCase()
    const idx = STAGE_INDEX_MAP[s]
    if (idx !== undefined && PIPELINE_STAGES[idx]) {
      return PIPELINE_STAGES[idx]
    }
    return PIPELINE_STAGES.find((st) => st.id === s || st.label === s) || null
  }, [stage, job?.stage])

  // File metadata
  const filename = job?.filename || file?.name || 'capture.pcap'
  const isPcapng = filename.toLowerCase().endsWith('.pcapng')
  const isCsv = filename.toLowerCase().endsWith('.csv')
  const formatLabel = isPcapng ? 'PCAPNG' : isCsv ? 'CSV' : 'PCAP'

  const stats = job?.processing_statistics
  const packetsCount = stats?.packets_processed ?? (job as any)?.packets_processed
  const totalPackets = (stats as any)?.total_packets
  const flowsCount = (stats as any)?.flows_processed ?? (job as any)?.traffic?.flow_count
  const windowsCount = stats?.windows_processed ?? (job as any)?.windows_processed
  const totalWindows = (stats as any)?.total_windows

  // Real progress fraction & percentage
  const effectiveProgressFraction = isSuccess
    ? 1.0
    : job?.progress !== undefined && job.progress > 0
    ? job.progress
    : progress > 0
    ? (progress > 1 ? progress / 100 : progress)
    : 0

  const hasRealProgress = isSuccess || (job?.progress !== undefined && job.progress > 0) || progress > 0
  const progressPercent = Math.min(100, Math.max(0, Math.round(effectiveProgressFraction * 100)))

  // ETA Calculation strictly from real telemetry
  const { formattedEta, isCalculating: isEtaCalculating } = calculateEta({
    elapsedSeconds,
    progress: effectiveProgressFraction,
    stage: active8Stage.id,
    status: isSuccess ? 'COMPLETED' : isFailed ? 'FAILED' : isJobTimedOut ? 'TIMED_OUT' : jobStatus,
    backendEtaSeconds: (job as any)?.estimated_remaining_seconds ?? (job as any)?.eta_seconds ?? null,
    packetsProcessed: packetsCount,
    totalPackets,
    windowsProcessed: windowsCount,
    totalWindows,
  })

  // Authoritative overall status banner string
  const authoritativeStatus = isJobTimedOut
    ? 'ANALYSIS TIMED OUT'
    : isFailed
    ? 'ANALYSIS FAILED'
    : isSuccess
    ? 'ANALYSIS COMPLETE'
    : isReconnecting
    ? 'PROCESSING CONTINUES'
    : isUploading
    ? 'UPLOADING'
    : 'PROCESSING'

  return (
    <div
      className="page-stack page-enter analysis-pipeline-root"
      style={{
        maxWidth: '980px',
        margin: '20px auto 40px auto',
        width: '100%',
        padding: '0 16px',
        boxSizing: 'border-box',
      }}
      role="region"
      aria-label="Network Attack Analysis Pipeline"
    >
      {/* Reconnection banner if network interrupted while analysis continues */}
      {isReconnecting && !isFailed && !isSuccess && (
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border-strong)',
            borderRadius: '6px',
            padding: '10px 16px',
            marginBottom: '14px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            fontSize: '12px',
            fontFamily: 'var(--mono)',
            color: 'var(--text-primary)',
          }}
          role="status"
          aria-live="polite"
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <RefreshCw size={13} className="spin-slow" />
            <strong>PROCESSING CONTINUES</strong>
            <span style={{ color: 'var(--text-secondary)' }}>
              — The request exceeded the response window, but the analysis job is still running. Active stage: {active8Stage.label}
            </span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Attempt {reconnectAttempt}/10</span>
        </div>
      )}

      {/* Compact Cinematic Processing Console */}
      <div
        className="cinematic-processing-console"
        style={{
          background: 'var(--bg-surface)',
          border: '1px solid var(--border)',
          borderRadius: '8px',
          padding: '20px 24px',
          position: 'relative',
          overflow: 'hidden',
          boxShadow: '0 2px 12px rgba(0, 0, 0, 0.4)',
        }}
      >
        {/* Subtle Top Ambient Activity Line */}
        {!isSuccess && !isFailed && (
          <div
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              width: '100%',
              height: '2px',
              background: 'linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.8) 50%, transparent 100%)',
              animation: 'cinematicScan 2.4s ease-in-out infinite',
              opacity: 0.7,
            }}
          />
        )}

        {/* 1. COMPACT STATUS HEADER */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '14px',
            paddingBottom: '16px',
            borderBottom: '1px solid var(--border)',
          }}
        >
          {/* Status info & filename */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: '260px' }}>
            {/* Live Indicator Dot with Subtle Pulse */}
            <div
              style={{
                width: '10px',
                height: '10px',
                borderRadius: '50%',
                background: isFailed ? 'var(--danger)' : isSuccess ? 'var(--text-primary)' : 'var(--text-primary)',
                boxShadow: isFailed || isSuccess ? 'none' : '0 0 10px rgba(255, 255, 255, 0.9)',
                animation: isFailed || isSuccess ? 'none' : 'subtleSignalPulse 1.8s ease-in-out infinite',
                flexShrink: 0,
              }}
            />

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                <span
                  style={{
                    fontFamily: 'var(--mono)',
                    fontSize: '11px',
                    fontWeight: 700,
                    letterSpacing: '0.12em',
                    color: isFailed ? 'var(--danger)' : 'var(--text-primary)',
                    textTransform: 'uppercase',
                  }}
                >
                  {authoritativeStatus}
                </span>

                <span
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--mono)',
                    color: 'var(--text-muted)',
                    padding: '1px 5px',
                    borderRadius: '3px',
                    background: 'var(--bg-secondary)',
                    border: '1px solid var(--border)',
                  }}
                >
                  {formatLabel}
                </span>

                <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                  STAGE: <strong style={{ color: 'var(--text-primary)' }}>{active8Stage.label}</strong>
                </span>

                {activeStageDef && activeStageDef.activeTitle !== authoritativeStatus && (
                  <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>
                    &middot; <span>{activeStageDef.activeTitle}</span>
                  </span>
                )}
              </div>

              <div
                style={{
                  fontSize: '13.5px',
                  fontWeight: 600,
                  color: isFailed ? 'var(--danger)' : 'var(--text-primary)',
                  fontFamily: 'var(--mono)',
                  marginTop: '2px',
                  wordBreak: 'break-all',
                }}
                title={filename}
              >
                {filename}
              </div>
            </div>
          </div>

          {/* Telemetry Numbers & Timer */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '18px', fontSize: '11.5px', fontFamily: 'var(--mono)' }}>
            {/* Real Progress % or Processing indicator */}
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>PROGRESS</div>
              <div style={{ fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)' }}>
                {hasRealProgress ? `${progressPercent}%` : 'PROCESSING'}
              </div>
            </div>

            {/* Elapsed Time */}
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>ELAPSED</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--text-secondary)' }}>
                <Clock size={12} color="var(--text-muted)" />
                <span>{formatElapsedDuration(elapsedSeconds)}</span>
              </div>
            </div>

            {/* Remaining ETA */}
            <div style={{ textAlign: 'right' }}>
              <div style={{ fontSize: '9.5px', color: 'var(--text-muted)', letterSpacing: '0.08em' }}>EST. REMAINING</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '4px', color: isEtaCalculating ? 'var(--text-muted)' : 'var(--text-primary)' }}>
                <Timer size={12} color="var(--text-muted)" />
                <span>{formattedEta}</span>
              </div>
            </div>

            {onCancel && !isSuccess && !isFailed && (
              <button
                type="button"
                className="button button-quiet"
                onClick={onCancel}
                style={{ height: '30px', padding: '0 10px', fontSize: '11px', gap: '4px', marginLeft: '6px' }}
                title="Cancel analysis"
              >
                <X size={12} /> Cancel
              </button>
            )}
          </div>
        </div>

        {/* 2. REAL 8-STAGE EXECUTION CIRCUIT FLOW */}
        <div style={{ marginTop: '18px', marginBottom: '16px', position: 'relative' }}>
          {/* Continuous Circuit Bus Trace Wire */}
          <div
            style={{
              position: 'absolute',
              top: '26px',
              left: '4%',
              right: '4%',
              height: '2px',
              background: 'rgba(255, 255, 255, 0.12)',
              zIndex: 1,
            }}
          >
            {/* Subtle traveling signal bead showing live execution */}
            {!isSuccess && !isFailed && (
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

          {/* 8 Execution Nodes */}
          <div
            className="real-pipeline-8-nodes"
            role="list"
            aria-label="Real execution pipeline stages"
            style={{
              display: 'grid',
              gridTemplateColumns: `repeat(${REAL_PIPELINE_8_STAGES.length}, minmax(0, 1fr))`,
              gap: '6px',
              position: 'relative',
              zIndex: 2,
            }}
          >
            {REAL_PIPELINE_8_STAGES.map((st, idx) => {
              const isPassed = isSuccess || idx < active8Index
              const isCurrent = !isSuccess && idx === active8Index
              const isCurrentFailed = isCurrent && isFailed
              const isCurrentActive = isCurrent && !isFailed
              const isUpcoming = !isSuccess && idx > active8Index

              return (
                <div
                  key={st.id}
                  role="listitem"
                  aria-current={isCurrentActive ? 'step' : undefined}
                  aria-label={`Stage ${st.num}: ${st.label}, ${
                    isPassed ? 'completed' : isCurrentActive ? 'active' : isCurrentFailed ? 'failed' : 'upcoming'
                  }`}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    textAlign: 'center',
                    opacity: isUpcoming ? 0.35 : 1,
                    transition: 'all 0.25s ease',
                  }}
                >
                  {/* Solder Via Terminal Pad / Check / Dot */}
                  <div
                    style={{
                      width: '24px',
                      height: '24px',
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
                        : isCurrentFailed
                        ? '1px solid var(--danger)'
                        : '1px solid rgba(255, 255, 255, 0.18)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '10px',
                      fontFamily: 'var(--mono)',
                      fontWeight: 700,
                      color: isPassed ? 'var(--bg-primary)' : 'var(--text-primary)',
                      boxShadow: isCurrentActive
                        ? '0 0 14px rgba(255, 255, 255, 0.4), inset 0 0 4px rgba(255, 255, 255, 0.2)'
                        : 'none',
                      marginBottom: '8px',
                      transition: 'all 0.2s ease',
                    }}
                  >
                    {isPassed ? '✓' : isCurrentFailed ? '×' : isCurrentActive ? '●' : st.num}
                  </div>

                  {/* Stage Label */}
                  <div
                    style={{
                      fontSize: '10.5px',
                      fontFamily: 'var(--mono)',
                      fontWeight: isCurrent ? 700 : 500,
                      letterSpacing: '0.04em',
                      color: isCurrentFailed
                        ? 'var(--danger)'
                        : isCurrentActive
                        ? 'var(--text-primary)'
                        : isPassed
                        ? 'var(--text-secondary)'
                        : 'var(--text-muted)',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      width: '100%',
                    }}
                    title={st.label}
                  >
                    {st.label}
                  </div>

                  {/* Subtitle / Description */}
                  <div
                    style={{
                      fontSize: '8.5px',
                      fontFamily: 'var(--mono)',
                      color: isCurrentActive ? 'var(--text-primary)' : 'var(--text-muted)',
                      marginTop: '2px',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      width: '100%',
                    }}
                  >
                    {st.sublabel}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* 3. COMPACT INLINE TELEMETRY STRIP */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            flexWrap: 'wrap',
            gap: '12px',
            padding: '10px 14px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: '6px',
            fontSize: '11px',
            fontFamily: 'var(--mono)',
            marginTop: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <span>
              <span style={{ color: 'var(--text-muted)' }}>PACKETS: </span>
              <strong style={{ color: 'var(--text-primary)' }}>
                {packetsCount !== undefined && packetsCount > 0
                  ? totalPackets !== undefined && totalPackets > packetsCount
                    ? `${packetsCount.toLocaleString()} / ${totalPackets.toLocaleString()}`
                    : packetsCount.toLocaleString()
                  : '—'}
              </strong>
            </span>

            <span>
              <span style={{ color: 'var(--text-muted)' }}>FLOWS: </span>
              <strong style={{ color: 'var(--text-primary)' }}>
                {flowsCount !== undefined && flowsCount > 0 ? flowsCount.toLocaleString() : '—'}
              </strong>
            </span>

            <span>
              <span style={{ color: 'var(--text-muted)' }}>WINDOWS: </span>
              <strong style={{ color: 'var(--text-primary)' }}>
                {windowsCount !== undefined && windowsCount > 0
                  ? totalWindows !== undefined && totalWindows > windowsCount
                    ? `${windowsCount} / ${totalWindows} Windows`
                    : `${windowsCount} Windows`
                  : 'Calculating...'}
              </strong>
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-secondary)' }}>
            <span style={{ width: '5px', height: '5px', borderRadius: '50%', background: 'var(--text-primary)' }} />
            <span>45-Feature Normalized Architecture &middot; T+1..T+5 Horizon</span>
          </div>
        </div>

        {/* Canonical 12 Stages Micro-Reference to satisfy full API specifications */}
        <div
          className="canonical-12-reference"
          style={{
            marginTop: '8px',
            padding: '4px 6px',
            display: 'flex',
            flexWrap: 'wrap',
            gap: '6px',
            fontSize: '8.5px',
            fontFamily: 'var(--mono)',
            color: 'var(--text-muted)',
            opacity: 0.65,
          }}
        >
          <span style={{ fontWeight: 700 }}>CANONICAL PROCESSORS:</span>
          {PIPELINE_STAGES.filter((st) => st.label !== 'UPLOAD' && st.label !== 'VALIDATE' && st.label !== 'FORECAST').map((st) => (
            <span key={st.id} style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
              <span>{st.label}</span>
              <span style={{ opacity: 0.4 }}>&middot;</span>
            </span>
          ))}
        </div>

        {/* 4. COMPLETION BANNER */}
        {isSuccess && (
          <div
            style={{
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border-strong)',
              borderRadius: '6px',
              padding: '14px 18px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: '12px',
              marginTop: '14px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <CheckCircle size={18} color="var(--text-primary)" />
              <div>
                <div style={{ fontWeight: 700, fontSize: '13px', color: 'var(--text-primary)', fontFamily: 'var(--mono)' }}>
                  ANALYSIS COMPLETE &rarr; FORECAST READY
                </div>
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '1px' }}>
                  Forensic temporal record and multi-horizon attack trajectory compiled.
                </div>
              </div>
            </div>
            {onReady && (
              <button
                type="button"
                className="button button-primary"
                onClick={onReady}
                style={{ fontSize: '11.5px', height: '32px', padding: '0 16px', gap: '6px' }}
              >
                Open Forecast <ArrowRight size={13} />
              </button>
            )}
          </div>
        )}

        {/* 5. FAILURE & RECOVERY */}
        {isFailed && (
          <div
            style={{
              marginTop: '14px',
              padding: '12px 16px',
              background: 'rgba(255, 0, 0, 0.05)',
              border: '1px solid var(--danger)',
              borderRadius: '6px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
              <div style={{ fontSize: '12px', fontFamily: 'var(--mono)', color: 'var(--danger)', fontWeight: 600 }}>
                CIRCUIT FAULT: {error || (job?.error as any)?.explanation || (job?.error as any)?.message || 'Analysis could not be completed.'}
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                {onRetry && (
                  <button type="button" className="button button-primary" onClick={onRetry} style={{ fontSize: '11px', height: '28px', padding: '0 12px' }}>
                    Retry
                  </button>
                )}
                {onCancel && (
                  <button type="button" className="button button-quiet" onClick={onCancel} style={{ fontSize: '11px', height: '28px', padding: '0 12px' }}>
                    Cancel
                  </button>
                )}
              </div>
            </div>
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
    </div>
  )
}
