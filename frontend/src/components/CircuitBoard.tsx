export interface CircuitStageNode {
  id: string
  num: string
  label: string
  sublabel?: string
}

export const COMPACT_CIRCUIT_STAGES: CircuitStageNode[] = [
  { id: 'UPLOAD', num: '01', label: 'PACKET PARSING', sublabel: 'Wire stream ingest' },
  { id: 'FLOWS', num: '02', label: 'FLOW RECONSTRUCTION', sublabel: 'Bidirectional sessions' },
  { id: 'FEATURES', num: '03', label: 'FEATURE EXTRACTION', sublabel: '45-dim state schema' },
  { id: 'DETECT', num: '04', label: 'DETECTION', sublabel: 'Behavior analysis' },
  { id: 'FORECAST', num: '05', label: 'FORECASTING', sublabel: 'T+1..T+5 horizons' },
  { id: 'REPORT', num: '06', label: 'EVIDENCE GENERATION', sublabel: 'Attribution chain' },
]

export interface CircuitBoardProps {
  stages?: CircuitStageNode[]
  activeStageIndex: number
  isComplete?: boolean
  isFailed?: boolean
  error?: string | null
  statusText?: string
  progressPercent?: number
  compact?: boolean
  filename?: string
  className?: string
}

export function CircuitBoard({
  stages = COMPACT_CIRCUIT_STAGES,
  activeStageIndex,
  isComplete = false,
  isFailed = false,
  error = null,
  statusText,
  progressPercent,
  compact = false,
  filename,
  className = '',
}: CircuitBoardProps) {
  const effectiveIndex = isComplete ? stages.length - 1 : Math.max(0, Math.min(activeStageIndex, stages.length - 1))

  return (
    <div
      className={`nexsolve-pipeline-flow ${compact ? 'pipeline-compact' : 'pipeline-full'} ${className}`}
      role="region"
      aria-label="Processing Pipeline Stages"
      style={{
        width: '100%',
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderRadius: '4px',
        padding: compact ? '12px 14px' : '16px 18px',
        boxSizing: 'border-box',
      }}
    >
      {/* Header Info */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '10px',
          marginBottom: '14px',
          paddingBottom: '8px',
          borderBottom: '1px solid var(--border)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: isFailed ? 'var(--danger)' : 'var(--text-primary)',
            }}
          />
          <div>
            <div
              style={{
                fontFamily: 'var(--font-sans)',
                fontSize: '10.5px',
                fontWeight: 600,
                letterSpacing: '0.06em',
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
              }}
            >
              PIPELINE EXECUTION &middot; {isComplete ? 'COMPLETE' : isFailed ? 'REJECTED / FAILED' : activeStageIndex > 0 ? 'PROCESSING' : 'READY'}
            </div>
            {filename && (
              <div
                style={{
                  fontSize: '12px',
                  fontWeight: 600,
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--mono)',
                  marginTop: '1px',
                  wordBreak: 'break-all',
                }}
              >
                {compact ? `CAPTURE · ${filename}` : filename}
              </div>
            )}
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11px', fontFamily: 'var(--font-sans)' }}>
          {statusText && (
            <span
              style={{
                fontWeight: 600,
                color: isFailed ? 'var(--danger)' : 'var(--text-secondary)',
              }}
            >
              {statusText}
            </span>
          )}
          {progressPercent !== undefined && (
            <span
              style={{
                padding: '2px 6px',
                borderRadius: '3px',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border)',
                fontWeight: 600,
                fontFamily: 'var(--mono)',
                fontSize: '10.5px',
                color: 'var(--text-primary)',
              }}
            >
              {progressPercent}%
            </span>
          )}
        </div>
      </div>

      {/* Pipeline Stage Nodes */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: `repeat(${stages.length}, minmax(0, 1fr))`,
          gap: '8px',
        }}
      >
        {stages.map((st, idx) => {
          const isPassed = isComplete || idx < effectiveIndex
          const isCurrent = !isComplete && idx === effectiveIndex
          const isCurrentFailed = isCurrent && isFailed
          const isCurrentActive = isCurrent && !isFailed
          const isPending = !isComplete && idx > effectiveIndex

          return (
            <div
              key={st.id}
              style={{
                background: isCurrentActive
                  ? 'var(--button-secondary-bg)'
                  : isPassed
                  ? 'var(--bg-primary)'
                  : 'transparent',
                border: isCurrentFailed
                  ? '1px solid var(--danger)'
                  : isCurrentActive
                  ? '1px solid var(--text-primary)'
                  : isPassed
                  ? '1px solid var(--border-strong)'
                  : '1px dashed var(--border)',
                borderRadius: '4px',
                padding: compact ? '8px 6px' : '10px 8px',
                opacity: isPending ? 0.4 : 1,
                textAlign: 'left',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  marginBottom: '4px',
                }}
              >
                <span
                  style={{
                    fontSize: '9px',
                    fontFamily: 'var(--mono)',
                    color: isCurrentActive ? 'var(--text-primary)' : 'var(--text-muted)',
                  }}
                >
                  {st.num}
                </span>
                <span
                  style={{
                    fontSize: '9px',
                    fontFamily: 'var(--mono)',
                    fontWeight: 700,
                    color: isPassed
                      ? 'var(--text-primary)'
                      : isCurrentFailed
                      ? 'var(--danger)'
                      : isCurrentActive
                      ? 'var(--text-primary)'
                      : 'var(--text-muted)',
                  }}
                >
                  {isPassed ? '✓' : isCurrentFailed ? '×' : isCurrentActive ? '●' : '○'}
                </span>
              </div>

              <div
                style={{
                  fontSize: compact ? '10px' : '11px',
                  fontFamily: 'var(--font-sans)',
                  fontWeight: isCurrent ? 700 : 500,
                  color: isCurrentFailed
                    ? 'var(--danger)'
                    : isCurrentActive
                    ? 'var(--text-primary)'
                    : isPassed
                    ? 'var(--text-primary)'
                    : 'var(--text-muted)',
                  letterSpacing: '0.02em',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
                title={st.label}
              >
                {st.label}
              </div>

              {!compact && st.sublabel && (
                <div
                  style={{
                    fontSize: '9px',
                    fontFamily: 'var(--font-sans)',
                    color: 'var(--text-muted)',
                    marginTop: '2px',
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                  }}
                >
                  {st.sublabel}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {/* Error Message */}
      {isFailed && error && (
        <div
          style={{
            marginTop: '12px',
            padding: '8px 12px',
            background: 'var(--danger-muted)',
            border: '1px solid var(--danger)',
            borderRadius: '4px',
            fontSize: '11px',
            fontFamily: 'var(--mono)',
            color: 'var(--danger)',
          }}
        >
          ANALYSIS REJECTED: {error}
        </div>
      )}
    </div>
  )
}

export default CircuitBoard
