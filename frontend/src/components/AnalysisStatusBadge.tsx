import type { ReactNode } from 'react'

export interface AnalysisStatusBadgeProps {
  status: 'COMPLETED' | 'PROCESSING' | 'FAILED' | 'QUEUED' | string
  className?: string
  children?: ReactNode
}

/**
 * Semantic status indicator badge for analysis history and execution tracking.
 * Features a small 5.5px indicator dot with semantic color encoding:
 * - COMPLETED: static muted green dot
 * - PROCESSING: muted blue/neutral dot with subtle pulse (respects prefers-reduced-motion)
 * - FAILED: static muted red dot
 * - QUEUED: static muted amber dot
 * Label remains neutral/light to prevent saturated color dominance.
 */
export function AnalysisStatusBadge({ status, className = '', children }: AnalysisStatusBadgeProps) {
  const normStatus = (status || 'UNKNOWN').toUpperCase()
  const statusKey = normStatus.toLowerCase()

  return (
    <span className={`analysis-status-badge status-${statusKey} ${className}`}>
      <span className={`analysis-status-dot dot-${statusKey}`} aria-hidden="true" />
      <span className="analysis-status-label">{children ?? normStatus}</span>
    </span>
  )
}

export default AnalysisStatusBadge
