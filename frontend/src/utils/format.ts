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
