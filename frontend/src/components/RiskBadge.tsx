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
    bg: 'rgba(237, 128, 111, 0.15)',
    text: 'var(--danger, #ed806f)',
    border: 'rgba(237, 128, 111, 0.4)',
  },
  HIGH: {
    bg: 'rgba(242, 187, 113, 0.15)',
    text: 'var(--warning, #f2bb71)',
    border: 'rgba(242, 187, 113, 0.4)',
  },
  ELEVATED: {
    bg: 'rgba(242, 187, 113, 0.12)',
    text: 'var(--warning, #f2bb71)',
    border: 'rgba(242, 187, 113, 0.3)',
  },
  MEDIUM: {
    bg: 'rgba(104, 225, 216, 0.12)',
    text: 'var(--accent, #68e1d8)',
    border: 'rgba(104, 225, 216, 0.3)',
  },
  LOW: {
    bg: 'rgba(16, 185, 129, 0.12)',
    text: 'var(--success, #10b981)',
    border: 'rgba(16, 185, 129, 0.3)',
  },
  NORMAL: {
    bg: 'rgba(16, 185, 129, 0.12)',
    text: 'var(--success, #10b981)',
    border: 'rgba(16, 185, 129, 0.3)',
  },
  ABSTAINED: {
    bg: 'rgba(133, 158, 156, 0.12)',
    text: 'var(--text-muted, #859e9c)',
    border: 'rgba(133, 158, 156, 0.3)',
  },
  UNCALIBRATED: {
    bg: 'rgba(104, 225, 216, 0.08)',
    text: 'var(--text-secondary, #ccdcda)',
    border: 'rgba(104, 225, 216, 0.2)',
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
        fontFamily: 'var(--mono)',
        fontWeight: 700,
        letterSpacing: '0.04em',
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
        <span style={{ opacity: 0.85, fontWeight: 500 }}>
          ({typeof score === 'number' ? (score <= 1.0 ? `${Math.round(score * 100)}%` : `${score}/100`) : score})
        </span>
      )}
    </span>
  )
}
