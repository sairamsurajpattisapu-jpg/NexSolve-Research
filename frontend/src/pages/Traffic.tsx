import { Activity, Boxes, Network, RefreshCw } from 'lucide-react'
import { ActivityChart, ProtocolBars } from '../components/Charts'
import { ErrorState, LoadingState, MetricCard, Panel, SectionHeading } from '../components/Ui'
import { formatNumber, formatPercent } from '../utils/format'
import { useProductionData } from '../hooks/useProductionData'

export function Traffic() {
  const { data, loading, error, reload } = useProductionData()
  if (loading) return <LoadingState message="Loading traffic analytics" />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />
  const { traffic } = data.results
  const windows = traffic.windows_data ?? []
  const retransmissionRate = traffic.packets ? traffic.retransmissions / traffic.packets : 0
  return <div className="page-stack page-enter"><SectionHeading eyebrow="Traffic / Aggregates" title="Traffic analytics" description={`Aggregated packet behavior across the ${traffic.windows} analyzed 60-second windows.`} action={<button className="button button-quiet" onClick={() => void reload()}><RefreshCw size={15} /> Refresh</button>} /><div className="metric-grid"><MetricCard label="Total packets" value={formatNumber(traffic.packets)} detail="Across all windows" tone="accent" icon={<Network size={16} />} /><MetricCard label="TCP packets" value={formatNumber(traffic.tcp)} detail={formatPercent(traffic.tcp / Math.max(traffic.packets, 1))} icon={<Activity size={16} />} /><MetricCard label="UDP packets" value={formatNumber(traffic.udp)} detail={formatPercent(traffic.udp / Math.max(traffic.packets, 1))} icon={<Boxes size={16} />} /><MetricCard label="Retransmission rate" value={formatPercent(retransmissionRate)} detail={`${formatNumber(traffic.retransmissions)} packets`} tone="warning" /></div><Panel><SectionHeading title="Window activity" description="Packet count per window. Raw packet data is not sent to the browser." /><ActivityChart windows={windows} /></Panel><div className="content-grid"><Panel><SectionHeading title="Protocol distribution" description="Counts derived from protocol fields." /><ProtocolBars protocols={traffic.protocol_counts} /></Panel><Panel><SectionHeading title="Window indicators" description="Aggregate signals available for investigation." /><div className="detail-list"><div><span>Fragmented packets</span><strong>{formatNumber(traffic.fragmented_packets)}</strong></div><div><span>Analysis windows</span><strong>{formatNumber(traffic.windows)}</strong></div><div><span>Largest window</span><strong>{formatNumber(Math.max(...windows.map((item) => item.packet_count), 0))} packets</strong></div><div><span>Data source</span><strong>{data.results.source?.name ?? 'CIC packet windows'}</strong></div></div></Panel></div></div>
}
