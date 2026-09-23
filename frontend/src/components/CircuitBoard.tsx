export interface CircuitStageNode {
  id: string
  num: string
  label: string
  sublabel?: string
}

export const COMPACT_CIRCUIT_STAGES: CircuitStageNode[] = [
  { id: 'UPLOAD', num: '01', label: 'UPLOAD', sublabel: 'Wire stream' },
  { id: 'VALIDATE', num: '02', label: 'VALIDATE', sublabel: 'Format check' },
  { id: 'PARSE', num: '03', label: 'PARSE', sublabel: 'Header decode' },
  { id: 'FLOWS', num: '04', label: 'FLOWS', sublabel: 'Conversations' },
  { id: 'FEATURES', num: '05', label: 'FEATURES', sublabel: '45-dim schema' },
  { id: 'DETECT', num: '06', label: 'DETECT', sublabel: 'Threat vectors' },
  { id: 'FORECAST', num: '07', label: 'FORECAST', sublabel: 'T+1..T+5 horizons' },
  { id: 'REPORT', num: '08', label: 'REPORT', sublabel: 'Evidence chain' },
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
      className={`nexsolve-circuit-execution-path ${compact ? 'circuit-compact' : 'circuit-full'} ${className}`}
      role="region"
      aria-label="Circuit Board Execution Flow"
      style={{
        width: '100%',
        background: 'transparent',
        border: 'none',
        padding: compact ? '4px 0 14px 0' : '12px 0 20px 0',
        position: 'relative',
        boxSizing: 'border-box',
      }}
    >
      {/* Subtle Technical Meta Bar (Frameless, integrated into background) */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '10px',
          marginBottom: '12px',
          paddingBottom: '8px',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div
            style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: isFailed
                ? 'var(--danger)'
                : isComplete
                ? 'var(--text-primary)'
                : 'var(--text-primary)',
              boxShadow: isComplete || isFailed ? 'none' : '0 0 8px rgba(255,255,255,0.7)',
            }}
          />
          <div>
            <div
              style={{
                fontFamily: 'var(--mono)',
                fontSize: '10px',
                fontWeight: 700,
                letterSpacing: '0.12em',
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
              }}
            >
              NETWORK CAPTURE &middot; {isComplete ? 'SYNCHRONIZED' : isFailed ? 'CIRCUIT FAULT' : activeStageIndex > 0 ? 'PROCESSING' : 'READY FOR INGESTION'}
            </div>
            {filename && (
              <div
                style={{
                  fontSize: '12.5px',
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

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11px', fontFamily: 'var(--mono)' }}>
          {statusText && (
            <span
              style={{
                fontWeight: 600,
                color: isFailed ? 'var(--danger)' : isComplete ? 'var(--text-primary)' : 'var(--text-secondary)',
              }}
            >
              {statusText}
            </span>
          )}
          {progressPercent !== undefined && (
            <span
              style={{
                padding: '1px 6px',
                borderRadius: '3px',
                background: 'rgba(255, 255, 255, 0.06)',
                border: '1px solid rgba(255, 255, 255, 0.12)',
                fontWeight: 700,
                fontSize: '10.5px',
                color: 'var(--text-primary)',
              }}
            >
              {progressPercent}%
            </span>
          )}
        </div>
      </div>

      {/* Execution Path Track Running Directly On Top Of Circuit Environment */}
      <div className="circuit-board-track" style={{ position: 'relative', width: '100%' }}>
        {/* Underlying Continuous Circuit Bus Trace Connecting Nodes */}
        <svg
          style={{
            position: 'absolute',
            top: '38px',
            left: 0,
            width: '100%',
            height: '14px',
            zIndex: 1,
            pointerEvents: 'none',
          }}
          preserveAspectRatio="none"
        >
          {/* Subtle background circuit bus line */}
          <line x1="3%" y1="7" x2="97%" y2="7" stroke="rgba(255, 255, 255, 0.12)" strokeWidth="1" strokeDasharray="3 3" />
        </svg>

        {/* Real Stages Execution Path */}
        <div
          className="circuit-nodes-flow"
          style={{
            display: 'grid',
            gridTemplateColumns: `repeat(${stages.length}, minmax(0, 1fr))`,
            gap: compact ? '6px' : '8px',
            position: 'relative',
            zIndex: 2,
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
                className={`circuit-node ${isCurrentActive ? 'node-active' : ''} ${isPassed ? 'node-completed' : ''} ${isPending ? 'node-waiting' : ''}`}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  position: 'relative',
                  opacity: isPending ? 0.32 : 1,
                  transition: 'opacity 0.25s ease',
                  textAlign: 'center',
                }}
              >
                {/* Circuit Node Capsule */}
                <div
                  style={{
                    background: isCurrentActive
                      ? 'rgba(255, 255, 255, 0.08)'
                      : isPassed
                      ? 'rgba(255, 255, 255, 0.03)'
                      : 'rgba(0, 0, 0, 0.3)',
                    border: isCurrentFailed
                      ? '1px solid var(--danger)'
                      : isCurrentActive
                      ? '1.5px solid rgba(255, 255, 255, 0.9)'
                      : isPassed
                      ? '1px solid rgba(255, 255, 255, 0.2)'
                      : '1px solid rgba(255, 255, 255, 0.08)',
                    borderRadius: '4px',
                    padding: compact ? '6px 4px' : '8px 6px',
                    position: 'relative',
                    boxShadow: isCurrentActive
                      ? '0 0 12px rgba(255, 255, 255, 0.2), inset 0 0 6px rgba(255, 255, 255, 0.05)'
                      : 'none',
                    transition: 'all 0.2s ease',
                  }}
                >
                  {/* Step Number */}
                  <div
                    style={{
                      fontSize: '8.5px',
                      fontFamily: 'var(--mono)',
                      color: isCurrentActive ? 'var(--text-primary)' : 'var(--text-muted)',
                      marginBottom: '1px',
                    }}
                  >
                    {st.num}
                  </div>

                  {/* Stage Label */}
                  <div
                    style={{
                      fontSize: compact ? '9.5px' : '10.5px',
                      fontFamily: 'var(--mono)',
                      fontWeight: isCurrent ? 700 : 500,
                      color: isCurrentFailed
                        ? 'var(--danger)'
                        : isCurrentActive
                        ? 'var(--text-primary)'
                        : isPassed
                        ? 'var(--text-secondary)'
                        : 'var(--text-muted)',
                      letterSpacing: '0.04em',
                      whiteSpace: 'nowrap',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                    title={st.label}
                  >
                    {st.label}
                  </div>

                  {/* Solder Via Terminal Pad */}
                  <div
                    style={{
                      marginTop: '3px',
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

                {/* Subtitle if available and not compact */}
                {!compact && st.sublabel && (
                  <div
                    style={{
                      fontSize: '8.5px',
                      fontFamily: 'var(--mono)',
                      color: 'var(--text-muted)',
                      marginTop: '4px',
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
      </div>

      {/* Error banner if failed */}
      {isFailed && error && (
        <div
          style={{
            marginTop: '10px',
            padding: '6px 10px',
            background: 'rgba(255, 0, 0, 0.06)',
            border: '1px solid var(--danger)',
            borderRadius: '4px',
            fontSize: '11px',
            fontFamily: 'var(--mono)',
            color: 'var(--danger)',
          }}
        >
          CIRCUIT FAULT: {error}
        </div>
      )}
    </div>
  )
}
