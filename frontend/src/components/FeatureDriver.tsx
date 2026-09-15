import { ArrowDownRight, ArrowRight, ArrowUpRight } from 'lucide-react'

export interface DriverItem {
  feature: string
  current_value?: number
  predicted_value?: number
  direction: 'increasing' | 'decreasing' | 'stable' | string
  relative_change: number
  importance: 'HIGH' | 'MEDIUM' | 'LOW' | string
  interpretation: string
}

interface FeatureDriverProps {
  driver: DriverItem
  rank?: number
}

const IMPORTANCE_TONES: Record<string, { badge: string; color: string; bg: string }> = {
  HIGH: {
    badge: 'CRITICAL SHIFT',
    color: 'var(--danger, #ed806f)',
    bg: 'rgba(237, 128, 111, 0.1)',
  },
  MEDIUM: {
    badge: 'ELEVATED DELTA',
    color: 'var(--warning, #f2bb71)',
    bg: 'rgba(242, 187, 113, 0.1)',
  },
  LOW: {
    badge: 'NOMINAL DRIFT',
    color: 'var(--accent, #68e1d8)',
    bg: 'rgba(104, 225, 216, 0.08)',
  },
}

export function FeatureDriver({ driver, rank }: FeatureDriverProps) {
  const normImp = (driver.importance || 'LOW').toUpperCase()
  const styling = IMPORTANCE_TONES[normImp] ?? IMPORTANCE_TONES.LOW

  const isUp = driver.direction === 'increasing' || driver.relative_change > 0
  const isDown = driver.direction === 'decreasing' || driver.relative_change < 0
  const pct = Math.abs(driver.relative_change * 100).toFixed(1)

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        padding: '12px 14px',
        borderRadius: '6px',
        background: 'var(--bg-secondary, #0e1719)',
        border: '1px solid var(--border, rgba(255, 255, 255, 0.12))',
        borderLeft: `3px solid ${styling.color}`,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          {rank !== undefined && (
            <span
              style={{
                fontFamily: 'var(--mono)',
                fontSize: '11px',
                color: 'var(--text-muted)',
                fontWeight: 700,
              }}
            >
              #{rank}
            </span>
          )}
          <span
            style={{
              fontFamily: 'var(--mono)',
              fontSize: '12.5px',
              fontWeight: 700,
              color: 'var(--text-primary)',
            }}
          >
            {driver.feature}
          </span>
          <span
            style={{
              fontSize: '9.5px',
              fontFamily: 'var(--mono)',
              fontWeight: 700,
              padding: '1px 5px',
              borderRadius: '3px',
              background: styling.bg,
              color: styling.color,
            }}
          >
            {styling.badge}
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <span
            style={{
              fontFamily: 'var(--mono)',
              fontSize: '12px',
              fontWeight: 700,
              color: isUp ? 'var(--danger)' : isDown ? 'var(--success)' : 'var(--text-secondary)',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '3px',
            }}
          >
            {isUp ? <ArrowUpRight size={13} /> : isDown ? <ArrowDownRight size={13} /> : <ArrowRight size={13} />}
            {isUp ? `+${pct}%` : isDown ? `-${pct}%` : `${pct}%`}
          </span>
        </div>
      </div>

      <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.45 }}>
        {driver.interpretation}
      </p>

      {driver.current_value !== undefined && driver.predicted_value !== undefined && (
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            fontFamily: 'var(--mono)',
            fontSize: '10.5px',
            color: 'var(--text-muted)',
            marginTop: '2px',
          }}
        >
          <span>Now: <strong style={{ color: 'var(--text-primary)' }}>{driver.current_value}</strong></span>
          <span>→</span>
          <span>Forecast: <strong style={{ color: styling.color }}>{driver.predicted_value}</strong></span>
        </div>
      )}
    </div>
  )
}
