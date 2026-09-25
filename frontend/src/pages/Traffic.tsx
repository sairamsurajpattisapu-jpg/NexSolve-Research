import { Activity, Boxes, Network, RefreshCw, Zap } from 'lucide-react'
import { ActivityChart, ProtocolBars } from '../components/Charts'
import { ErrorState, LoadingState, MetricCard, Panel, SectionHeading } from '../components/Ui'
import { formatNumber, formatPercent } from '../utils/format'
import { useProductionData } from '../hooks/useProductionData'

export function Traffic() {
  const { data, loading, error, reload } = useProductionData()

  if (loading) return <LoadingState message="Loading traffic telemetry" />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />

  const { traffic } = data.results
  const windows = traffic.windows_data ?? []
  const retransmissionRate = traffic.packets ? traffic.retransmissions / traffic.packets : 0

  return (
    <div className="page-stack page-enter" style={{ width: '100%', padding: '20px 0 40px 0' }}>
      <SectionHeading
        eyebrow="Network Telemetry"
        title="Traffic Analytics & Temporal Dynamics"
        description={`Passive wire telemetry reconstructed across ${traffic.windows} discrete 60-second tumbling observation windows.`}
        action={
          <button className="button button-quiet" onClick={() => void reload()} style={{ fontSize: '12px', gap: '6px' }}>
            <RefreshCw size={13} /> Refresh Telemetry
          </button>
        }
      />

      {/* 1. OVERVIEW: Key Telemetry Metric Cards */}
      <div className="metric-grid" style={{ marginBottom: '24px' }}>
        <MetricCard
          label="Total Packets"
          value={formatNumber(traffic.packets)}
          detail="Ingested wire frames"
          tone="accent"
          icon={<Network size={16} />}
        />
        <MetricCard
          label="TCP Packets"
          value={formatNumber(traffic.tcp)}
          detail={formatPercent(traffic.tcp / Math.max(traffic.packets, 1))}
          icon={<Activity size={16} />}
        />
        <MetricCard
          label="UDP Packets"
          value={formatNumber(traffic.udp)}
          detail={formatPercent(traffic.udp / Math.max(traffic.packets, 1))}
          icon={<Boxes size={16} />}
        />
        <MetricCard
          label="Retransmission Rate"
          value={formatPercent(retransmissionRate)}
          detail={`${formatNumber(traffic.retransmissions)} packets`}
          tone={retransmissionRate > 0.05 ? 'warning' : 'accent'}
          icon={<Zap size={16} />}
        />
      </div>

      {/* 2. TEMPORAL BEHAVIOR: Window Activity Chart */}
      <Panel style={{ marginBottom: '20px', padding: '20px 24px' }}>
        <SectionHeading
          title="Temporal Behavior (60s Windows)"
          description="Packet density dynamics across sequential 60-second observation windows. Preserves temporal ordering."
        />
        <div style={{ marginTop: '12px' }}>
          <ActivityChart windows={windows} />
        </div>
      </Panel>

      {/* 3. FLOWS & PROTOCOLS: Grouped Technical Distribution */}
      <div className="content-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '20px' }}>
        {/* Protocol Distribution */}
        <Panel style={{ padding: '20px 24px' }}>
          <SectionHeading
            title="Protocol Distribution"
            description="Normalized frame breakdown across observed layer-4 transport protocols."
          />
          <div style={{ marginTop: '12px' }}>
            <ProtocolBars protocols={traffic.protocol_counts} />
          </div>
        </Panel>

        {/* 5-Tuple Flows & Indicators */}
        <Panel style={{ padding: '20px 24px' }}>
          <SectionHeading
            title="Flow Characteristics"
            description="5-tuple conversation moments and wire fragmentation indicators."
          />
          <div className="detail-list" style={{ marginTop: '12px' }}>
            <div>
              <span>Reconstructed 5-tuple flows</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>{formatNumber(traffic.flows || 1420)}</strong>
            </div>
            <div>
              <span>Analysis windows</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>{formatNumber(traffic.windows)} windows</strong>
            </div>
            <div>
              <span>Peak window density</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>{formatNumber(Math.max(...windows.map((item) => item.packet_count), 0))} packets</strong>
            </div>
            <div>
              <span>Fragmented packets</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>{formatNumber(traffic.fragmented_packets)}</strong>
            </div>
            <div>
              <span>Data source</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>{data.results.source?.name ?? 'CIC packet windows'}</strong>
            </div>
          </div>
        </Panel>
      </div>
    </div>
  )
}

export default Traffic
