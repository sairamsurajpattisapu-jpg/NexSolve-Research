import { useEffect, useState, type CSSProperties, type DragEvent, type ReactNode } from 'react'
import type { Severity } from '../types/api'

export function Panel({
  children,
  className = '',
  as = 'section',
  style,
  onDragOver,
  onDragLeave,
  onDrop,
}: {
  children: ReactNode
  className?: string
  as?: 'section' | 'div'
  style?: CSSProperties
  onDragOver?: (e: DragEvent<HTMLElement>) => void
  onDragLeave?: (e: DragEvent<HTMLElement>) => void
  onDrop?: (e: DragEvent<HTMLElement>) => void
}) {
  const Tag = as
  return (
    <Tag
      className={`panel ${className}`}
      style={style}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
    >
      {children}
    </Tag>
  )
}

export function MetricCard({ label, value, detail, tone = 'neutral', icon }: { label: string; value: string | number; detail?: string; tone?: 'neutral' | 'accent' | 'warning' | 'danger'; icon?: ReactNode }) {
  return <div className={`metric-card metric-${tone}`}>
    <div className="metric-top"><span>{label}</span>{icon && <span className="metric-icon">{icon}</span>}</div>
    <strong>{value}</strong>
    {detail && <small>{detail}</small>}
  </div>
}

export function SeverityPill({ severity }: { severity: Severity | string }) {
  return <span className={`severity severity-${severity}`}>{severity}</span>
}

export function StatusPill({ children, tone = 'success' }: { children: ReactNode; tone?: 'success' | 'warning' | 'danger' | 'neutral' }) {
  return <span className={`status status-${tone}`}><span className="status-dot" />{children}</span>
}

export function SectionHeading({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: ReactNode }) {
  return <div className="section-heading">
    <div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2>{title}</h2>{description && <p>{description}</p>}</div>
    {action}
  </div>
}

export function LoadingState({ message = 'Loading production analysis' }: { message?: string }) {
  const [slow, setSlow] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => setSlow(true), 4000)
    return () => clearTimeout(timer)
  }, [])

  return (
    <div className="state-card">
      <span className="spinner" aria-hidden="true" />
      <strong>{message}</strong>
      <span>
        {slow
          ? 'Connecting to backend service... (Cold starts on hosted platforms may take up to 30 seconds)'
          : 'Reading verified backend data...'}
      </span>
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return <div className="state-card state-error"><span className="state-symbol">!</span><strong>Backend unavailable</strong><span>{message}</span>{onRetry && <button className="button button-quiet" onClick={onRetry}>Retry connection</button>}</div>
}

export function EmptyState({ title, message }: { title: string; message: string }) {
  return <div className="empty-state"><span className="empty-mark" /><strong>{title}</strong><span>{message}</span></div>
}
