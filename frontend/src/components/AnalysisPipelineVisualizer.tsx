import { useEffect, useState } from 'react'
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Clock,
  Cpu,
  Layers,
  Network,
  Radio,
  RefreshCw,
  ShieldAlert,
  Sparkles,
  Workflow,
  X,
} from 'lucide-react'
import type { JobStageType, JobStatusResponse } from '../types/api'

interface AnalysisPipelineVisualizerProps {
  jobId: string
  stage: JobStageType | string
  progress: number
  job: JobStatusResponse | null
  isReconnecting?: boolean
  reconnectAttempt?: number
  isComplete?: boolean
  onCancel?: () => void
  onReady?: () => void
}

export interface PipelineStageDef {
  num: string
  id: string
  label: string
  detail: string
  icon: typeof Network
}

export const PIPELINE_STAGES: PipelineStageDef[] = [
  { num: '01', id: 'INGEST', label: 'INGEST', detail: 'Reading passive wire frames and validating capture boundaries.', icon: Radio },
  { num: '02', id: 'NORMALIZE', label: 'NORMALIZE', detail: 'Decoding packet headers and standardizing timing intervals.', icon: Layers },
  { num: '03', id: 'RECONSTRUCT', label: 'RECONSTRUCT', detail: 'Reconstructing bidirectional flows and session conversations.', icon: Network },
  { num: '04', id: 'REPRESENT', label: 'REPRESENT', detail: 'Segmenting telemetry into 45-dimensional canonical vectors.', icon: Activity },
  { num: '05', id: 'ANALYZE', label: 'ANALYZE', detail: 'Evaluating graph topology, centrality, and baseline state.', icon: Cpu },
  { num: '06', id: 'SIMULATE', label: 'SIMULATE', detail: 'Simulating forward temporal state dynamics with network state model.', icon: Sparkles },
  { num: '07', id: 'FORECAST', label: 'FORECAST', detail: 'Multi-horizon attack probability and trajectory projection.', icon: ShieldAlert },
  { num: '08', id: 'EXPLAIN', label: 'EXPLAIN', detail: 'Attributing feature influence and MITRE behavioral correlates.', icon: Workflow },
]

const STAGE_INDEX_MAP: Record<string, number> = {
  INGESTION: 0,
  INGEST: 0,
  PARSING: 1,
  NORMALIZE: 1,
  FLOW_RECONSTRUCTION: 2,
  FLOWS: 2,
  RECONSTRUCT: 2,
  WINDOWING: 3,
  TEMPORAL_WINDOWING: 3,
  REPRESENT: 3,
  NETWORK_STATE: 4,
  ANALYZE: 4,
  WORLD_MODEL: 5,
  SIMULATION: 5,
  SIMULATE: 5,
  FORECAST: 6,
  FORECASTING: 6,
  EVIDENCE: 7,
  EXPLAIN: 7,
  REPORT: 7,
  COMPLETE: 8,
}

export function AnalysisPipelineVisualizer({
  jobId,
  stage,
  progress,
  job,
  isReconnecting = false,
  reconnectAttempt = 0,
  isComplete = false,
  onCancel,
  onReady,
}: AnalysisPipelineVisualizerProps) {
  const [elapsedSeconds, setElapsedSeconds] = useState(0)

  useEffect(() => {
    const timer = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1)
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  const stageKey = String(stage || '').toUpperCase()
  const currentIdx = isComplete ? 8 : (STAGE_INDEX_MAP[stageKey] ?? 0)
  const effectiveIdx = currentIdx
  const activeStageDef = PIPELINE_STAGES[Math.min(currentIdx, PIPELINE_STAGES.length - 1)] || PIPELINE_STAGES[0]

  const stats = job?.processing_statistics
  const hasStats =
    stats &&
    (stats.packets_processed !== undefined ||
      stats.flows_processed !== undefined ||
      stats.windows_processed !== undefined)

  const filename = (job as any)?.filename || 'capture.pcap'
  const isPcapng = filename.toLowerCase().endsWith('.pcapng')
  const formatLabel = isPcapng ? 'PCAPNG (Passive Wire)' : 'PCAP (Passive Wire)'
  const progressPercent = isComplete
    ? 100
    : job?.progress !== undefined && job.progress > 0
    ? Math.max(0, Math.min(100, Math.round(job.progress * 100)))
    : progress > 0
    ? Math.max(0, Math.min(100, Math.round(progress * 100)))
    : Math.max(5, Math.min(95, Math.round(((effectiveIdx + 0.5) / 8) * 100)))

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
      {/* Reconnecting banner if communication is temporarily interrupted */}
      {isReconnecting && (
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--accent)',
            borderRadius: '4px',
            padding: '8px 16px',
            marginBottom: '16px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: '12px',
            fontFamily: 'var(--mono)',
            color: 'var(--text-primary)',
          }}
          role="status"
          aria-live="polite"
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <RefreshCw size={13} className="spin-slow" />
            <span>
              <strong>RECONNECTING</strong> &middot; Temporary communication interruption. Retrying analysis state... (Attempt {reconnectAttempt}/10)
            </span>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Background process active</span>
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
        {/* Compact Technical Metadata Bar (Part 12) */}
        <div
          style={{
            borderBottom: '1px solid var(--border)',
            background: 'var(--bg-secondary)',
            padding: '10px 20px',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))',
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
                color: isComplete
                  ? 'var(--accent)'
                  : isReconnecting
                  ? '#eda850'
                  : 'var(--text-primary)',
              }}
            >
              {isComplete ? 'RESULT READY' : isReconnecting ? 'RECONNECTING' : 'ANALYZING'}
            </span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              WINDOW
            </span>
            <span style={{ color: 'var(--text-primary)' }}>60s Discrete</span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              CONTEXT
            </span>
            <span style={{ color: 'var(--text-primary)' }}>8 Windows (480s)</span>
          </div>

          <div>
            <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
              FEATURES
            </span>
            <span style={{ color: 'var(--text-primary)' }}>45-Dim Canonical</span>
          </div>
        </div>

        {/* Header Section with Stage Title & Elapsed Counter */}
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
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
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
            </div>

            <h1
              style={{
                fontSize: '22px',
                fontWeight: 700,
                margin: 0,
                color: 'var(--text-primary)',
                letterSpacing: '-0.02em',
              }}
            >
              {isComplete ? 'Analysis Complete &middot; Preparing Forecast' : activeStageDef.label}
            </h1>
            <p
              style={{
                margin: '4px 0 0 0',
                fontSize: '13px',
                color: 'var(--text-secondary)',
                lineHeight: 1.4,
              }}
            >
              {isComplete ? 'Compiling multi-horizon trajectory curves and counterfactual evidence.' : activeStageDef.detail}
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '20px' }}>
            <div style={{ textAlign: 'right' }}>
              <div
                style={{
                  fontSize: '11px',
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
                }}
              >
                {progressPercent}%
              </div>
            </div>

            <div style={{ textAlign: 'right' }}>
              <div
                style={{
                  fontSize: '11px',
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
                {elapsedSeconds}s
              </div>
            </div>

            {onCancel && !isComplete && (
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

        {/* Completion Transition Overlay / Indicator (Part 15) */}
        {isComplete && (
          <div
            style={{
              background: 'var(--bg-secondary)',
              borderBottom: '1px solid var(--border)',
              padding: '14px 28px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              fontSize: '12.5px',
              color: 'var(--text-primary)',
              animation: 'fadeIn 0.3s ease',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <CheckCircle2 size={18} color="var(--accent)" />
              <span style={{ fontWeight: 600 }}>
                ANALYSIS COMPLETE &rarr; FORECAST READY
              </span>
            </div>
            {onReady && (
              <button
                type="button"
                className="button button-primary"
                onClick={onReady}
                style={{ fontSize: '11.5px', height: '28px', padding: '0 12px', gap: '4px' }}
              >
                Open Forecast <ArrowRight size={13} />
              </button>
            )}
          </div>
        )}

        {/* Editorial Pipeline Timeline (Parts 6, 7, 8, 9, 10, 24) */}
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
              const isPassed = idx < effectiveIdx
              const isCurrent = idx === effectiveIdx && !isComplete
              const isPending = idx > effectiveIdx

              const IconComp = st.icon

              return (
                <div
                  key={st.id}
                  role="listitem"
                  aria-current={isCurrent ? 'step' : undefined}
                  aria-label={`Stage ${st.num}: ${st.label}, ${isPassed ? 'completed' : isCurrent ? 'currently processing' : 'pending'}`}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '18px',
                    position: 'relative',
                    paddingBottom: idx === PIPELINE_STAGES.length - 1 ? '0' : '22px',
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
                        ? 'var(--text-primary)'
                        : isCurrent
                        ? 'var(--bg-surface)'
                        : 'var(--bg-secondary)',
                      color: isPassed
                        ? 'var(--bg-primary)'
                        : isCurrent
                        ? 'var(--text-primary)'
                        : 'var(--text-muted)',
                      border: isCurrent
                        ? '2px solid var(--text-primary)'
                        : isPassed
                        ? '2px solid var(--text-primary)'
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
                      boxShadow: isCurrent ? '0 0 0 4px var(--border)' : 'none',
                      transition: 'all 0.25s ease',
                    }}
                  >
                    {isPassed ? (
                      <CheckCircle2 size={16} />
                    ) : isCurrent ? (
                      <span className="pulse-dot" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                        <IconComp size={14} />
                      </span>
                    ) : (
                      <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>{st.num}</span>
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
                      paddingTop: '4px',
                    }}
                  >
                    <div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span
                          style={{
                            fontSize: '11px',
                            fontFamily: 'var(--mono)',
                            color: isCurrent || isPassed ? 'var(--text-muted)' : 'var(--text-muted)',
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
                            color: isCurrent
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
                          color: isCurrent ? 'var(--text-secondary)' : 'var(--text-muted)',
                          marginTop: '2px',
                        }}
                      >
                        {st.detail}
                      </div>
                    </div>

                    {/* Stage Status Marker / Progress Track */}
                    <div style={{ textAlign: 'right' }}>
                      <span
                        style={{
                          fontSize: '10px',
                          fontFamily: 'var(--mono)',
                          padding: '2px 8px',
                          borderRadius: '3px',
                          fontWeight: 600,
                          background: isPassed
                            ? 'var(--bg-secondary)'
                            : isCurrent
                            ? 'var(--button-primary-bg)'
                            : 'transparent',
                          color: isPassed
                            ? 'var(--text-primary)'
                            : isCurrent
                            ? 'var(--button-primary-text)'
                            : 'var(--text-muted)',
                          border: isPassed || isCurrent ? '1px solid var(--border)' : '1px solid transparent',
                        }}
                      >
                        {isPassed ? '● COMPLETE' : isCurrent ? '◐ PROCESSING' : '○ PENDING'}
                      </span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Live Processing Telemetry Strip (Part 13: Only Show Real Values) */}
        {hasStats && (
          <div
            style={{
              borderTop: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
              padding: '14px 28px',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: '16px',
              fontSize: '11px',
              fontFamily: 'var(--mono)',
            }}
          >
            {stats.packets_processed !== undefined && (
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
                  PACKETS PROCESSED
                </span>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {stats.packets_processed.toLocaleString()}
                </span>
              </div>
            )}

            {stats.flows_processed !== undefined && (
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
                  FLOWS RECONSTRUCTED
                </span>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {stats.flows_processed.toLocaleString()}
                </span>
              </div>
            )}

            {stats.windows_processed !== undefined && (
              <div>
                <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
                  TEMPORAL WINDOWS
                </span>
                <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                  {stats.windows_processed}
                </span>
              </div>
            )}

            <div>
              <span style={{ color: 'var(--text-muted)', fontSize: '9.5px', textTransform: 'uppercase', display: 'block' }}>
                CURRENT STAGE
              </span>
              <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                {activeStageDef.label}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

