import { CheckCircle2, Database, FileCheck2, RefreshCw } from 'lucide-react'
import { ErrorState, LoadingState, MetricCard, Panel, SectionHeading, StatusPill } from '../components/Ui'
import { formatNumber } from '../utils/format'
import { useProductionData } from '../hooks/useProductionData'

export function Analysis() {
  const { data, loading, error, reload } = useProductionData()
  if (loading) return <LoadingState message="Loading analysis status" />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />
  const { results, status } = data
  const validation = results.validation
  const isComplete = status.status === 'completed'
  const parsingQuality = Object.values(validation.null_counts).every((value) => value === 0) ? 'Clean' : 'Review'
  return <div className="page-stack page-enter">
    <SectionHeading eyebrow="Analysis / Current source" title="Analysis workspace" description={isComplete ? 'The current packet analysis is complete and available for review.' : 'No completed analysis is available.'} action={<button className="button button-quiet" onClick={() => void reload()}><RefreshCw size={15} /> Refresh</button>} />
    <Panel className="analysis-banner"><div className="analysis-status-icon"><CheckCircle2 size={27} /></div><div><StatusPill tone={isComplete ? 'success' : 'warning'}>{status.status}</StatusPill><h3>{results.analysis_id}</h3><p>Source: {results.source?.name ?? data.report.metadata.name} &middot; {validation.window.seconds}-second UTC windows</p></div><div className="banner-side"><span>Detection mode</span><strong>Traffic heuristics</strong><small>Risk scores are not probabilities or model confidence.</small></div></Panel>
    <div className="metric-grid"><MetricCard label="Packets processed" value={formatNumber(results.traffic.packets)} detail="Parsed packet windows" tone="accent" /><MetricCard label="Windows" value={formatNumber(validation.rows)} detail="Chronologically ordered" /><MetricCard label="Feature columns" value={formatNumber(validation.columns.length)} detail="Validated schema" /><MetricCard label="Parsing quality" value={parsingQuality} detail="Null fields" tone="accent" /></div>
    <div className="content-grid"><Panel><SectionHeading title="Data quality" description="Integrity checks performed on the production artifact." /><div className="detail-list"><div><span><Database size={15} /> Dataset status</span><StatusPill tone={validation.status === 'VALID' ? 'success' : 'warning'}>{validation.status}</StatusPill></div><div><span><FileCheck2 size={15} /> Missing columns</span><strong>{validation.missing_columns.length}</strong></div><div><span><CheckCircle2 size={15} /> Ordered windows</span><strong>{validation.window.ordered ? 'Yes' : 'Review'}</strong></div><div><span><Database size={15} /> Model compatibility</span><strong>{validation.model_compatibility.forecast_model_ready ? 'Ready' : 'Packet-only'}</strong></div></div></Panel><Panel><SectionHeading title="Available indicators" description="Fields exposed by the verified extraction." /><div className="indicator-grid"><div><span>Retransmission</span><strong>Available</strong></div><div><span>Port scan</span><strong>Available</strong></div><div><span>Protocol mix</span><strong>{Object.keys(results.traffic.protocol_counts).length} types</strong></div><div><span>Labels</span><strong>Not present</strong></div></div></Panel></div>
  </div>
}
