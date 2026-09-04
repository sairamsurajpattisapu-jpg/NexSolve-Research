import { Download, FileText, ShieldCheck } from 'lucide-react'
import { ErrorState, LoadingState, Panel, SectionHeading, SeverityPill } from '../components/Ui'
import { formatNumber } from '../utils/format'
import { useProductionData } from '../hooks/useProductionData'

export function Reports() {
  const { data, loading, error, reload } = useProductionData()
  if (loading) return <LoadingState message="Loading report data" />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />
  const { report } = data
  const riskScore = Number.isFinite(report.detection.risk_score) ? report.detection.risk_score.toFixed(1) : 'Unavailable'
  const severityCounts = report.detection.findings.reduce((counts, finding) => ({ ...counts, [finding.severity]: counts[finding.severity] + 1 }), { high: 0, medium: 0, low: 0 })
  return <div className="page-stack page-enter">
    <SectionHeading eyebrow="Reports / Evidence package" title="Analysis report" description="A structured view of the production analysis and its evidence boundaries." action={<button className="button button-quiet" disabled title="PDF export is not implemented"><Download size={15} /> Export unavailable</button>} />
    <Panel className="report-header"><div className="report-icon"><FileText size={25} /></div><div><span className="eyebrow">Report ID</span><h3>{report.report_id}</h3><p>{report.metadata.name} &middot; {report.status} analysis</p>{report.metadata.kind === 'uploaded_pcap' && <small>Source: Uploaded PCAP &middot; Filename: {report.metadata.filename ?? report.metadata.name}</small>}</div><div className="report-status"><ShieldCheck size={16} /> {report.metadata.kind === 'uploaded_pcap' ? 'Temporary upload' : 'Read-only source'}</div></Panel>
    <div className="content-grid"><Panel><SectionHeading title="Executive summary" /><div className="report-summary"><div><span>Heuristic risk</span><strong>{riskScore}</strong></div><div><span>Detected indicators</span><strong>{formatNumber(report.detection.detected_events)}</strong></div><div><span>Packets analyzed</span><strong>{formatNumber(report.traffic.packets)}</strong></div><div><span>Windows</span><strong>{formatNumber(report.validation.rows)}</strong></div><div><span>High severity</span><strong>{severityCounts.high}</strong></div><div><span>Medium severity</span><strong>{severityCounts.medium}</strong></div><div><span>Low severity</span><strong>{severityCounts.low}</strong></div></div></Panel><Panel><SectionHeading title="Methodology" /><p className="body-copy">This report presents traffic heuristics derived from measured packet-window features. It does not claim supervised attack classification, calibrated confidence, or LSTM predictions.</p><div className="method-code">{report.detection.risk_method}</div></Panel></div>
    <Panel><SectionHeading title="Finding register" description="The most recent evidence-based events in this analysis." />{report.detection.findings.length === 0 ? <p className="body-copy">No detections were returned for this analysis.</p> : <div className="report-table"><div className="table-row table-head"><span>Finding</span><span>Category</span><span>Severity</span><span>Risk</span></div>{report.detection.findings.slice(0, 12).map((finding) => <div className="table-row" key={finding.finding_id}><span>{finding.finding_id}</span><span>{finding.attack_category.replaceAll('_', ' ')}</span><span><SeverityPill severity={finding.severity} /></span><strong>{Number.isFinite(finding.risk_score) ? finding.risk_score.toFixed(1) : 'Unavailable'}</strong></div>)}</div>}</Panel>
  </div>
}
