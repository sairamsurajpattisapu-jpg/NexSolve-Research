import { useCallback } from 'react'
import { Clock } from 'lucide-react'

export interface ForecastScrubberProps {
  horizons: number[] // e.g. [1, 2, 3, 5]
  selectedHorizon: number // 0 = OBSERVED, 1 = T+1, etc.
  onSelectHorizon: (h: number) => void
  isAbstained?: boolean
}

export function ForecastScrubber({
  horizons,
  selectedHorizon,
  onSelectHorizon,
  isAbstained = false,
}: ForecastScrubberProps) {
  // All discrete temporal ticks: 0 for OBSERVED, then actual horizons from backend data
  const allTicks = [0, ...horizons]

  const currentIndex = allTicks.indexOf(selectedHorizon) >= 0 ? allTicks.indexOf(selectedHorizon) : 0

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'ArrowRight' || e.key === 'ArrowUp') {
        e.preventDefault()
        const nextIdx = Math.min(currentIndex + 1, allTicks.length - 1)
        if (!isAbstained || allTicks[nextIdx] === 0) {
          onSelectHorizon(allTicks[nextIdx])
        }
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowDown') {
        e.preventDefault()
        const prevIdx = Math.max(currentIndex - 1, 0)
        onSelectHorizon(allTicks[prevIdx])
      } else if (e.key === 'Home') {
        e.preventDefault()
        onSelectHorizon(allTicks[0])
      } else if (e.key === 'End') {
        e.preventDefault()
        if (!isAbstained) {
          onSelectHorizon(allTicks[allTicks.length - 1])
        }
      }
    },
    [currentIndex, allTicks, isAbstained, onSelectHorizon]
  )

  return (
    <div
      className="forecast-temporal-scrubber"
      style={{
        background: 'var(--bg-secondary)',
        border: '1px solid var(--border)',
        borderRadius: '8px',
        padding: '16px 20px',
        display: 'flex',
        flexDirection: 'column',
        gap: '12px',
      }}
      role="region"
      aria-label="Temporal Horizon Scrubber"
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Clock size={16} color="var(--text-primary)" />
          <span
            style={{
              fontSize: '11.5px',
              fontFamily: 'var(--mono)',
              fontWeight: 700,
              letterSpacing: '0.08em',
              color: 'var(--text-primary)',
              textTransform: 'uppercase',
            }}
          >
            TEMPORAL SCRUBBER &middot; TIME-STEP INTERACTION
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              color: 'var(--text-muted)',
            }}
          >
            SELECTED HORIZON:
          </span>
          <span
            style={{
              fontSize: '12px',
              fontFamily: 'var(--mono)',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: '4px',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              color: selectedHorizon === 0 ? 'var(--accent)' : 'var(--danger)',
            }}
          >
            {selectedHorizon === 0 ? 'OBSERVED (T0)' : `HORIZON T+${selectedHorizon} (+${selectedHorizon * 60}s)`}
          </span>
        </div>
      </div>

      {/* Interactive Track & Ticks */}
      <div
        style={{
          position: 'relative',
          padding: '12px 10px',
        }}
      >
        {/* Slider Input for accessibility and range dragging */}
        <input
          type="range"
          min={0}
          max={allTicks.length - 1}
          step={1}
          value={currentIndex}
          onChange={(e) => {
            const idx = Number(e.target.value)
            const targetHorizon = allTicks[idx]
            if (!isAbstained || targetHorizon === 0) {
              onSelectHorizon(targetHorizon)
            }
          }}
          onKeyDown={handleKeyDown}
          aria-label="Temporal forecast scrubber slider"
          aria-valuemin={0}
          aria-valuemax={allTicks.length - 1}
          aria-valuenow={currentIndex}
          aria-valuetext={
            selectedHorizon === 0
              ? 'Observed current network state, selected'
              : `T+${selectedHorizon} forecast horizon, selected`
          }
          style={{
            width: '100%',
            height: '6px',
            accentColor: selectedHorizon === 0 ? 'var(--accent)' : 'var(--text-primary)',
            cursor: 'pointer',
            margin: 0,
          }}
        />

        {/* Tick Labels Row */}
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'flex-start',
            marginTop: '10px',
          }}
        >
          {allTicks.map((h) => {
            const isSelected = selectedHorizon === h
            const isFuture = h > 0
            const isDisabled = isFuture && isAbstained

            return (
              <button
                key={h}
                type="button"
                disabled={isDisabled}
                onClick={() => !isDisabled && onSelectHorizon(h)}
                style={{
                  background: isSelected
                    ? 'var(--text-primary)'
                    : 'var(--bg-surface)',
                  color: isSelected
                    ? 'var(--bg-primary)'
                    : isDisabled
                    ? 'var(--text-muted)'
                    : 'var(--text-primary)',
                  border: isSelected
                    ? '1px solid var(--text-primary)'
                    : '1px solid var(--border)',
                  padding: '6px 12px',
                  borderRadius: '5px',
                  fontSize: '11px',
                  fontFamily: 'var(--mono)',
                  fontWeight: isSelected ? 700 : 500,
                  cursor: isDisabled ? 'not-allowed' : 'pointer',
                  opacity: isDisabled ? 0.35 : 1,
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '2px',
                  minWidth: '70px',
                  transition: 'all 0.15s ease',
                }}
                aria-pressed={isSelected}
                aria-label={h === 0 ? 'Observed Current State' : `T+${h} Forecast Horizon`}
              >
                <span>{h === 0 ? 'OBSERVED' : `T+${h}`}</span>
                <span
                  style={{
                    fontSize: '9px',
                    opacity: 0.75,
                    fontWeight: 400,
                  }}
                >
                  {h === 0 ? 'Now (T0)' : `+${h * 60} sec`}
                </span>
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}
