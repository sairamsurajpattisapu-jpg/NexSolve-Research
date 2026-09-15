import { useState } from 'react'
import { Panel } from './Ui'

export interface StateTrajectoryPoint {
  window: number
  label: string
  isForecast: boolean
  values: Record<string, number>
}

interface NetworkStateChartProps {
  trajectories?: StateTrajectoryPoint[]
}

const METRICS_OPTIONS: Array<{ key: string; label: string; unit: string; tone: string }> = [
  { key: 'flow_count', label: 'Flow Count', unit: 'flows', tone: 'var(--accent, #68e1d8)' },
  { key: 'total_packets', label: 'Packet Count', unit: 'pkts', tone: 'var(--warning, #f2bb71)' },
  { key: 'total_bytes', label: 'Total Bytes', unit: 'bytes', tone: '#38bdf8' },
  { key: 'unique_dst_ports', label: 'Unique Dst Ports', unit: 'ports', tone: 'var(--danger, #ed806f)' },
  { key: 'mean_iat', label: 'Inter-Arrival Time (IAT)', unit: 'ms', tone: '#a78bfa' },
  { key: 'mean_tcp_window', label: 'Mean TCP Window', unit: 'bytes', tone: '#34d399' },
  { key: 'mean_ttl', label: 'Mean TTL', unit: 'hops', tone: '#f472b6' },
  { key: 'delta_total_packets', label: 'Temporal Packet Delta', unit: 'Δpkts', tone: '#fb923c' },
]

export function NetworkStateChart({ trajectories }: NetworkStateChartProps) {
  const [selectedMetric, setSelectedMetric] = useState<string>('unique_dst_ports')

  // Generate synthetic high-fidelity 8 actual windows + 5 forecast windows if none supplied
  const points: StateTrajectoryPoint[] = trajectories ?? [
    { window: -7, label: 'W-7', isForecast: false, values: { flow_count: 24, total_packets: 180, total_bytes: 45000, unique_dst_ports: 4, mean_iat: 42, mean_tcp_window: 14600, mean_ttl: 64, delta_total_packets: 2 } },
    { window: -6, label: 'W-6', isForecast: false, values: { flow_count: 26, total_packets: 195, total_bytes: 48000, unique_dst_ports: 4, mean_iat: 41, mean_tcp_window: 14600, mean_ttl: 64, delta_total_packets: 15 } },
    { window: -5, label: 'W-5', isForecast: false, values: { flow_count: 25, total_packets: 190, total_bytes: 46000, unique_dst_ports: 5, mean_iat: 43, mean_tcp_window: 14600, mean_ttl: 64, delta_total_packets: -5 } },
    { window: -4, label: 'W-4', isForecast: false, values: { flow_count: 28, total_packets: 210, total_bytes: 52000, unique_dst_ports: 5, mean_iat: 40, mean_tcp_window: 14600, mean_ttl: 64, delta_total_packets: 20 } },
    { window: -3, label: 'W-3', isForecast: false, values: { flow_count: 31, total_packets: 230, total_bytes: 56000, unique_dst_ports: 6, mean_iat: 38, mean_tcp_window: 14600, mean_ttl: 64, delta_total_packets: 20 } },
    { window: -2, label: 'W-2', isForecast: false, values: { flow_count: 35, total_packets: 260, total_bytes: 62000, unique_dst_ports: 8, mean_iat: 34, mean_tcp_window: 14600, mean_ttl: 63, delta_total_packets: 30 } },
    { window: -1, label: 'W-1', isForecast: false, values: { flow_count: 42, total_packets: 320, total_bytes: 75000, unique_dst_ports: 12, mean_iat: 28, mean_tcp_window: 14400, mean_ttl: 62, delta_total_packets: 60 } },
    { window: 0, label: 'T₀ (Now)', isForecast: false, values: { flow_count: 58, total_packets: 440, total_bytes: 98000, unique_dst_ports: 19, mean_iat: 21, mean_tcp_window: 14200, mean_ttl: 60, delta_total_packets: 120 } },
    { window: 1, label: 'T+1', isForecast: true, values: { flow_count: 78, total_packets: 610, total_bytes: 135000, unique_dst_ports: 28, mean_iat: 15, mean_tcp_window: 13800, mean_ttl: 58, delta_total_packets: 170 } },
    { window: 2, label: 'T+2', isForecast: true, values: { flow_count: 104, total_packets: 840, total_bytes: 184000, unique_dst_ports: 39, mean_iat: 11, mean_tcp_window: 13200, mean_ttl: 57, delta_total_packets: 230 } },
    { window: 3, label: 'T+3', isForecast: true, values: { flow_count: 135, total_packets: 1120, total_bytes: 245000, unique_dst_ports: 52, mean_iat: 8, mean_tcp_window: 12400, mean_ttl: 56, delta_total_packets: 280 } },
    { window: 4, label: 'T+4', isForecast: true, values: { flow_count: 168, total_packets: 1410, total_bytes: 310000, unique_dst_ports: 64, mean_iat: 6, mean_tcp_window: 11800, mean_ttl: 55, delta_total_packets: 290 } },
    { window: 5, label: 'T+5', isForecast: true, values: { flow_count: 202, total_packets: 1720, total_bytes: 380000, unique_dst_ports: 76, mean_iat: 5, mean_tcp_window: 11200, mean_ttl: 55, delta_total_packets: 310 } },
  ]

  const metricMeta = METRICS_OPTIONS.find((m) => m.key === selectedMetric) ?? METRICS_OPTIONS[0]

  // Chart setup
  const width = 800
  const height = 220
  const padding = { top: 25, right: 30, bottom: 35, left: 60 }
  const innerW = width - padding.left - padding.right
  const innerH = height - padding.top - padding.bottom

  const vals = points.map((p) => p.values[selectedMetric] ?? 0)
  const minVal = Math.min(...vals)
  const maxVal = Math.max(...vals, 1)
  const valRange = Math.max(maxVal - minVal, 1)

  const xStep = innerW / Math.max(1, points.length - 1)

  const getY = (val: number) => {
    const norm = (val - minVal) / valRange
    return innerH - norm * innerH
  }

  // Split into Actual (solid) and Forecast (dashed) path segments
  const actualPoints = points.filter((p) => !p.isForecast || p.window === 0)
  const forecastPoints = points.filter((p) => p.isForecast || p.window === 0)

  const actualPath = actualPoints
    .map((p, i) => `${padding.left + i * xStep},${padding.top + getY(p.values[selectedMetric] ?? 0)}`)
    .join(' L ')

  const forecastOffset = actualPoints.length - 1
  const forecastPath = forecastPoints
    .map((p, i) => `${padding.left + (forecastOffset + i) * xStep},${padding.top + getY(p.values[selectedMetric] ?? 0)}`)
    .join(' L ')

  return (
    <Panel className="network-state-chart-panel">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '16px', marginBottom: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              CONTINUOUS 45-DIMENSIONAL RECONSTRUCTION
            </span>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                padding: '2px 6px',
                borderRadius: '3px',
                background: 'rgba(104, 225, 216, 0.1)',
                color: 'var(--accent)',
              }}
            >
              PHYSICAL NETWORK STATE
            </span>
          </div>
          <h3 style={{ fontSize: '18px', fontWeight: 700, margin: '4px 0 2px 0', color: 'var(--text-primary)' }}>
            Network State Trajectory
          </h3>
          <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-muted)', maxWidth: '640px' }}>
            Comparing measured lookback telemetry (solid line) against LSTM recursive continuous predictions (dashed line).
          </p>
        </div>

        {/* Feature Selector Dropdown */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>FEATURE:</span>
          <select
            value={selectedMetric}
            onChange={(e) => setSelectedMetric(e.target.value)}
            style={{
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              borderRadius: '4px',
              padding: '6px 10px',
              fontSize: '12px',
              fontFamily: 'var(--mono)',
              color: 'var(--text-primary)',
              cursor: 'pointer',
            }}
          >
            {METRICS_OPTIONS.map((opt) => (
              <option key={opt.key} value={opt.key}>
                {opt.label} ({opt.unit})
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* SVG Chart */}
      <div style={{ position: 'relative', width: '100%', overflowX: 'auto' }}>
        <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', minWidth: '600px', height: 'auto', display: 'block' }}>
          {/* Horizontal Grid lines */}
          {[0, 0.25, 0.5, 0.75, 1.0].map((step) => {
            const val = minVal + step * valRange
            const y = padding.top + innerH - step * innerH
            return (
              <g key={step}>
                <line
                  x1={padding.left}
                  y1={y}
                  x2={width - padding.right}
                  y2={y}
                  stroke="var(--border)"
                  strokeDasharray="2 2"
                  strokeWidth="0.8"
                />
                <text
                  x={padding.left - 8}
                  y={y + 3}
                  fill="var(--text-muted)"
                  fontSize="10"
                  fontFamily="var(--mono)"
                  textAnchor="end"
                >
                  {val >= 1000 ? `${(val / 1000).toFixed(1)}k` : Math.round(val)}
                </text>
              </g>
            )
          })}

          {/* Dividing Vertical Line between Actual and Forecast */}
          <line
            x1={padding.left + forecastOffset * xStep}
            y1={padding.top}
            x2={padding.left + forecastOffset * xStep}
            y2={padding.top + innerH}
            stroke="var(--accent)"
            strokeWidth="1.2"
            strokeDasharray="4 2"
          />
          <text
            x={padding.left + forecastOffset * xStep}
            y={padding.top - 8}
            fill="var(--accent)"
            fontSize="10"
            fontFamily="var(--mono)"
            fontWeight="bold"
            textAnchor="middle"
          >
            NOW (T₀)
          </text>

          {/* Actual Solid Line */}
          {actualPath && (
            <path
              d={`M ${actualPath}`}
              fill="none"
              stroke={metricMeta.tone}
              strokeWidth="2.4"
            />
          )}

          {/* Forecast Dashed Line */}
          {forecastPath && (
            <path
              d={`M ${forecastPath}`}
              fill="none"
              stroke={metricMeta.tone}
              strokeWidth="2.4"
              strokeDasharray="5 4"
            />
          )}

          {/* Nodes */}
          {points.map((p, idx) => {
            const x = padding.left + idx * xStep
            const y = padding.top + getY(p.values[selectedMetric] ?? 0)

            return (
              <g key={p.label}>
                <circle
                  cx={x}
                  cy={y}
                  r={p.window === 0 ? 5 : 3.5}
                  fill={p.isForecast ? 'var(--bg-surface)' : metricMeta.tone}
                  stroke={metricMeta.tone}
                  strokeWidth="2"
                />
                <text
                  x={x}
                  y={padding.top + innerH + 16}
                  fill={p.window === 0 ? 'var(--accent)' : 'var(--text-muted)'}
                  fontSize="10"
                  fontWeight={p.window === 0 ? 'bold' : 'normal'}
                  fontFamily="var(--mono)"
                  textAnchor="middle"
                >
                  {p.label}
                </text>
              </g>
            )
          })}
        </svg>

        {/* Legend Footnote */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
          <div style={{ display: 'flex', gap: '16px' }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ width: '12px', height: '2px', background: metricMeta.tone }} /> Actual Observed Windows
            </span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ width: '12px', height: '2px', borderTop: `2px dashed ${metricMeta.tone}` }} /> LSTM Forward Projections
            </span>
          </div>
          <span>Lookback: 8 windows (480s) &middot; Projection: 5 steps (300s)</span>
        </div>
      </div>
    </Panel>
  )
}
