export function formatNumber(value: number) {
  return Number.isFinite(value) ? new Intl.NumberFormat('en-US').format(value) : 'Unavailable'
}

export function formatPercent(value: number) {
  return Number.isFinite(value) ? `${(value * 100).toFixed(1)}%` : 'Unavailable'
}

export function formatTimestamp(value: string | number) {
  const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
  return Number.isNaN(date.getTime()) ? 'Unknown time' : date.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export function formatBytes(bytes: number) {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`
}
