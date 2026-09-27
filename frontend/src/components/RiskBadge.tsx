import type { CSSProperties } from 'react'

export type RiskSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'NORMAL' | 'ELEVATED' | 'UNCALIBRATED' | 'ABSTAINED'

interface RiskBadgeProps {
  level: RiskSeverity | string
  score?: number | null
  showScore?: boolean
  size?: 'sm' | 'md' | 'lg'
  style?: CSSProperties
  className?: string
}

const LEVEL_STYLES: Record<string, { bg: string; text: string; border: string }> = {
  CRITICAL: {
    bg: 'rgba(244, 63, 94, 0.1)',
    text: 'var(--danger, #f43f5e)',
    border: 'rgba(244, 63, 94, 0.25)',
  },
  HIGH: {
    bg: 'rgba(245, 158, 11, 0.1)',
    text: 'var(--warning, #f59e0b)',
    border: 'rgba(245, 158, 11, 0.25)',
  },
  ELEVATED: {
    bg: 'rgba(245, 158, 11, 0.08)',
    text: 'var(--warning, #f59e0b)',
    border: 'rgba(245, 158, 11, 0.2)',
  },
  MEDIUM: {
    bg: 'var(--bg-elevated)',
    text: 'var(--text-secondary, #94a3b8)',
    border: 'var(--border, rgba(255, 255, 255, 0.08))',
  },
  LOW: {
    bg: 'rgba(74, 222, 128, 0.08)',
    text: 'var(--success, #4ade80)',
    border: 'rgba(74, 222, 128, 0.2)',
  },
  NORMAL: {
    bg: 'rgba(74, 222, 128, 0.08)',
    text: 'var(--success, #4ade80)',
    border: 'rgba(74, 222, 128, 0.2)',
  },
  ABSTAINED: {
    bg: 'var(--bg-secondary)',
    text: 'var(--text-muted, #64748b)',
    border: 'var(--border)',
  },
  UNCALIBRATED: {
    bg: 'var(--bg-elevated)',
    text: 'var(--text-secondary)',
    border: 'var(--border)',
  },
}

export function RiskBadge({
  level,
  score,
  showScore = false,
  size = 'md',
  style,
  className = '',
}: RiskBadgeProps) {
  const normKey = (level || 'LOW').toUpperCase()
  const styling = LEVEL_STYLES[normKey] ?? LEVEL_STYLES.LOW

  const sizeStyles: Record<'sm' | 'md' | 'lg', CSSProperties> = {
    sm: { fontSize: '10px', padding: '1px 6px', borderRadius: '3px' },
    md: { fontSize: '11px', padding: '2px 8px', borderRadius: '4px' },
    lg: { fontSize: '12px', padding: '4px 12px', borderRadius: '6px' },
  }

  return (
    <span
      className={`risk-badge ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '5px',
        fontFamily: 'var(--font-sans)',
        fontWeight: 600,
        letterSpacing: '0.02em',
        background: styling.bg,
        color: styling.text,
        border: `1px solid ${styling.border}`,
        textTransform: 'uppercase',
        ...sizeStyles[size],
        ...style,
      }}
    >
      <span
        style={{
          width: size === 'lg' ? '6px' : '5px',
          height: size === 'lg' ? '6px' : '5px',
          borderRadius: '50%',
          background: styling.text,
        }}
      />
      <span>{normKey}</span>
      {showScore && score !== undefined && score !== null && (
        <span style={{ opacity: 0.85, fontWeight: 500, fontVariantNumeric: 'tabular-nums' }}>
          ({typeof score === 'number' ? (score <= 1.0 ? `${Math.round(score * 100)}%` : `${score}/100`) : score})
        </span>
      )}
    </span>
  )
}
