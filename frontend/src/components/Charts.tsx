import type { WindowRow } from '../types/api'
import { formatNumber, formatPercent } from '../utils/format'

export function ActivityChart({ windows }: { windows: WindowRow[] }) {
  const sample = windows.length > 48 ? windows.filter((_, index) => index % Math.ceil(windows.length / 48) === 0) : windows
  const max = Math.max(...sample.map((window) => window.packet_count), 1)
  const points = sample.map((window, index) => `${(index / Math.max(sample.length - 1, 1)) * 100},${92 - (window.packet_count / max) * 82}`).join(' ')
  return <div className="chart-wrap">
    <svg className="activity-chart" viewBox="0 0 100 100" preserveAspectRatio="none" role="img" aria-label="Packets per analysis window">
      <defs><linearGradient id="activity-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0" stopColor="#4ed8d0" stopOpacity=".3" /><stop offset="1" stopColor="#4ed8d0" stopOpacity="0" /></linearGradient></defs>
      <polygon points={`0,100 ${points} 100,100`} fill="url(#activity-fill)" />
      <polyline points={points} fill="none" stroke="#68e1d8" strokeWidth=".9" vectorEffect="non-scaling-stroke" />
    </svg>
    <div className="chart-axis"><span>{sample[0] ? formatNumber(sample[0].packet_count) : '0'} packets</span><span>{sample.at(-1) ? formatNumber(sample.at(-1)!.packet_count) : '0'} packets</span></div>
  </div>
}

export function ProtocolBars({ protocols }: { protocols: Record<string, number> }) {
  const entries = Object.entries(protocols).sort(([, a], [, b]) => b - a).slice(0, 5)
  const max = Math.max(...entries.map(([, value]) => value), 1)
  return <div className="protocol-list">{entries.map(([name, value]) => <div className="protocol-row" key={name}><div><span>{name}</span><strong>{formatNumber(value)}</strong></div><div className="bar-track"><span style={{ width: `${(value / max) * 100}%` }} /></div></div>)}</div>
}

export function RiskDistribution({ windows }: { windows: WindowRow[] }) {
  const bands = [
    { label: 'Elevated', count: windows.filter((item) => item.port_scan_score >= .5).length, color: 'high' },
    { label: 'Watch', count: windows.filter((item) => item.tcp_retransmission_rate >= .05 && item.port_scan_score < .5).length, color: 'medium' },
    { label: 'Baseline', count: windows.filter((item) => item.port_scan_score < .5 && item.tcp_retransmission_rate < .05).length, color: 'low' },
  ]
  return <div className="distribution">{bands.map((band) => <div className="distribution-row" key={band.label}><span className={`distribution-dot ${band.color}`} /><span>{band.label}</span><strong>{band.count}</strong><small>{formatPercent(band.count / Math.max(windows.length, 1))}</small></div>)}</div>
}
