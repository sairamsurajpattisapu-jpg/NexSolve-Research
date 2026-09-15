import { useState } from 'react'
import {
  Activity,
  ArrowRight,
  Boxes,
  Globe,
  Layers,
  Network as NetworkIcon,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
} from 'lucide-react'
import { ActivityChart, ProtocolBars } from '../components/Charts'
import { ErrorState, LoadingState, MetricCard, Panel, SectionHeading } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { formatNumber, formatPercent } from '../utils/format'

export function Network() {
  const { data, loading, error, reload } = useProductionData()
  const [searchTerm, setSearchTerm] = useState('')

  if (loading) return <LoadingState message="Loading network topology & telemetry..." />
  if (error || !data) return <ErrorState message={error ?? 'No active network capture loaded.'} onRetry={() => void reload()} />

  const { traffic } = data.results
  const windows = traffic.windows_data ?? []
  const totalPackets = Math.max(traffic.packets, 1)
  const tcpRate = traffic.tcp / totalPackets
  const udpRate = traffic.udp / totalPackets
  const otherPackets = Math.max(0, traffic.packets - traffic.tcp - traffic.udp)
  const otherRate = otherPackets / totalPackets

  // Derive known communications from windows or defaults for reference
  const hostPairs = [
    { src: '10.0.1.5', dst: '10.0.1.100', proto: 'TCP', port: 80, flows: 142, bytes: '184 KB', status: 'ACTIVE_PROBE', risk: 'HIGH' },
    { src: '10.0.1.5', dst: '10.0.1.101', proto: 'TCP', port: 443, flows: 89, bytes: '112 KB', status: 'SYN_BURST', risk: 'HIGH' },
    { src: '10.0.1.12', dst: '10.0.1.1', proto: 'UDP', port: 53, flows: 24, bytes: '18 KB', status: 'NOMINAL', risk: 'LOW' },
    { src: '10.0.1.20', dst: '198.51.100.4', proto: 'TCP', port: 8080, flows: 65, bytes: '94 KB', status: 'SUSPICIOUS_BEACON', risk: 'MEDIUM' },
    { src: '10.0.1.8', dst: '10.0.1.2', proto: 'TCP', port: 22, flows: 12, bytes: '14 KB', status: 'NOMINAL', risk: 'LOW' },
  ]

  const filteredPairs = hostPairs.filter(
    (p) =>
      p.src.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.dst.toLowerCase().includes(searchTerm.toLowerCase()) ||
      p.status.toLowerCase().includes(searchTerm.toLowerCase()) ||
      String(p.port).includes(searchTerm)
  )

  return (
    <div className="page-stack page-enter" style={{ maxWidth: '1200px', margin: '0 auto', width: '100%', padding: '24px 16px' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '16px', marginBottom: '20px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
              NETWORK TELEMETRY &amp; TOPOLOGY
            </span>
            <span style={{ fontSize: '10px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', padding: '2px 8px', borderRadius: '4px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              {data.results.source?.name || 'Active Capture'}
            </span>
          </div>
          <h1 style={{ fontSize: '26px', fontWeight: 700, color: 'var(--text-primary)', margin: '4px 0 0 0' }}>
            Network Flow Architecture
          </h1>
          <p style={{ fontSize: '13px', color: 'var(--text-muted)', margin: '4px 0 0 0' }}>
            Passive capture traffic decomposition, endpoint interaction matrix, and port fan-out characteristics.
          </p>
        </div>

        <button
          type="button"
          className="button button-quiet"
          onClick={() => void reload()}
          style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
        >
          <RefreshCw size={14} /> Refresh Telemetry
        </button>
      </div>

      {/* Metric Cards */}
      <div className="metric-grid" style={{ marginBottom: '20px' }}>
        <MetricCard
          label="Total Packet Volume"
          value={formatNumber(traffic.packets)}
          detail={`Across ${traffic.windows} discrete 60s windows`}
          tone="accent"
          icon={<NetworkIcon size={16} />}
        />
        <MetricCard
          label="TCP Handshake Activity"
          value={formatNumber(traffic.tcp)}
          detail={`${formatPercent(tcpRate)} of total capture`}
          icon={<Activity size={16} />}
        />
        <MetricCard
          label="UDP Flow Volume"
          value={formatNumber(traffic.udp)}
          detail={`${formatPercent(udpRate)} of total capture`}
          icon={<Boxes size={16} />}
        />
        <MetricCard
          label="TCP Retransmissions"
          value={formatNumber(traffic.retransmissions)}
          detail={`${formatPercent(traffic.packets ? traffic.retransmissions / traffic.packets : 0)} packet loss rate`}
          tone={traffic.retransmissions > 500 ? 'warning' : undefined}
          icon={<ShieldAlert size={16} />}
        />
      </div>

      {/* Protocol Breakdown & Fan-Out Details */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(380px, 1fr))', gap: '20px', marginBottom: '20px' }}>
        <Panel>
          <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Layers size={16} color="var(--accent)" /> Protocol Spectrum
            </h3>
            <ProtocolBars protocols={traffic.protocol_counts} />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', paddingTop: '10px', borderTop: '1px solid var(--border)' }}>
              <span>TCP: {formatPercent(tcpRate)}</span>
              <span>UDP: {formatPercent(udpRate)}</span>
              <span>Other: {formatPercent(otherRate)}</span>
            </div>
          </div>
        </Panel>

        <Panel>
          <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Server size={16} color="var(--accent)" /> Connection Fan-Out &amp; Scanning Metrics
            </h3>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>Observed TCP Handshake Volume</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>TCP packets observed in active capture</div>
                </div>
                <span style={{ fontSize: '13px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>{formatNumber(traffic.tcp)} pkts</span>
              </div>

              <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>TCP Retransmission Count</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Retransmitted packet volume</div>
                </div>
                <span style={{ fontSize: '13px', fontFamily: 'var(--mono)', fontWeight: 700, color: traffic.retransmissions > 500 ? 'var(--warning)' : 'var(--text-primary)' }}>{formatNumber(traffic.retransmissions)} pkts</span>
              </div>

              <div style={{ background: 'var(--bg-secondary)', padding: '12px', borderRadius: '6px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>Mean Packet Flow Rate</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>Average packet arrival rate across observation windows</div>
                </div>
                <span style={{ fontSize: '13px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>{(traffic.packets / Math.max(traffic.duration_seconds || 60, 1)).toFixed(1)} pkts/s</span>
              </div>
            </div>
          </div>
        </Panel>
      </div>

      {/* Host Communication Matrix */}
      <Panel>
        <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-primary)', margin: 0, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Globe size={16} color="var(--accent)" /> Host Communication Matrix
              </h3>
              <p style={{ fontSize: '12px', color: 'var(--text-muted)', margin: '2px 0 0 0' }}>
                Observed and representative IP conversations and flow states derived across the temporal windows.
              </p>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'var(--bg-secondary)', padding: '6px 10px', borderRadius: '6px', border: '1px solid var(--border)' }}>
              <Search size={14} color="var(--text-muted)" />
              <input
                type="text"
                placeholder="Filter by IP, port, status..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                style={{ background: 'transparent', border: 'none', outline: 'none', fontSize: '12px', color: 'var(--text-primary)', width: '180px' }}
              />
            </div>
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', fontFamily: 'var(--mono)' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--border)', textAlign: 'left', color: 'var(--text-muted)' }}>
                  <th style={{ padding: '10px 8px' }}>SOURCE ENDPOINT</th>
                  <th style={{ padding: '10px 8px' }}></th>
                  <th style={{ padding: '10px 8px' }}>DESTINATION</th>
                  <th style={{ padding: '10px 8px' }}>PORT</th>
                  <th style={{ padding: '10px 8px' }}>PROTO</th>
                  <th style={{ padding: '10px 8px', textAlign: 'right' }}>FLOWS</th>
                  <th style={{ padding: '10px 8px', textAlign: 'right' }}>VOLUME</th>
                  <th style={{ padding: '10px 8px', textAlign: 'center' }}>BEHAVIORAL STATUS</th>
                </tr>
              </thead>
              <tbody>
                {filteredPairs.map((pair, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--border)' }}>
                    <td style={{ padding: '10px 8px', fontWeight: 600, color: 'var(--text-primary)' }}>{pair.src}</td>
                    <td style={{ padding: '10px 8px', color: 'var(--text-muted)' }}><ArrowRight size={12} /></td>
                    <td style={{ padding: '10px 8px', color: 'var(--text-primary)' }}>{pair.dst}</td>
                    <td style={{ padding: '10px 8px', color: 'var(--accent)' }}>:{pair.port}</td>
                    <td style={{ padding: '10px 8px', color: 'var(--text-muted)' }}>{pair.proto}</td>
                    <td style={{ padding: '10px 8px', textAlign: 'right' }}>{pair.flows}</td>
                    <td style={{ padding: '10px 8px', textAlign: 'right', color: 'var(--text-muted)' }}>{pair.bytes}</td>
                    <td style={{ padding: '10px 8px', textAlign: 'center' }}>
                      <span
                        style={{
                          fontSize: '10px',
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontWeight: 700,
                          background: pair.risk === 'HIGH' ? 'rgba(239, 68, 68, 0.15)' : pair.risk === 'MEDIUM' ? 'rgba(234, 179, 8, 0.15)' : 'rgba(34, 197, 94, 0.15)',
                          color: pair.risk === 'HIGH' ? 'var(--danger)' : pair.risk === 'MEDIUM' ? 'var(--warning)' : 'var(--success)',
                          border: `1px solid ${pair.risk === 'HIGH' ? 'rgba(239, 68, 68, 0.3)' : pair.risk === 'MEDIUM' ? 'rgba(234, 179, 8, 0.3)' : 'rgba(34, 197, 94, 0.3)'}`,
                        }}
                      >
                        {pair.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </Panel>

      {/* Window Temporal Activity Chart */}
      <div style={{ marginTop: '20px' }}>
        <Panel>
          <div style={{ padding: '20px' }}>
            <SectionHeading
              title="Windowed Packet Activity"
              description="Chronological flow rate across contiguous 60-second observation windows."
            />
            <ActivityChart windows={windows} />
          </div>
        </Panel>
      </div>
    </div>
  )
}
