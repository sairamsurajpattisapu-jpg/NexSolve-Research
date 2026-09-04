import { ArrowUpRight, FileUp, Gauge, Radio, ShieldAlert, TimerReset } from 'lucide-react'
import { useState } from 'react'
import { ActivityChart, ProtocolBars, RiskDistribution } from '../components/Charts'
import { EmptyState, ErrorState, LoadingState, MetricCard, Panel, SectionHeading, SeverityPill } from '../components/Ui'
import { formatNumber, formatTimestamp } from '../utils/format'
import { useProductionData } from '../hooks/useProductionData'

export function Dashboard() {
  const { data, loading, error, reload, analyzePcap, clearUploadedAnalysis, analysisSource, uploadError } = useProductionData()
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [selectionError, setSelectionError] = useState<string | null>(null)
  if (loading && !data) return <LoadingState />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />
  const { traffic, detection } = data.results
  const windows = traffic.windows_data ?? []
  const submitCapture = async () => {
    if (!file) return
    setUploading(true)
    await analyzePcap(file)
    setUploading(false)
    setFile(null)
  }
  return <div className="page-stack page-enter">
    <SectionHeading eyebrow="Overview / Traffic heuristics" title="Network security posture" description={analysisSource === 'uploaded' ? `Live read of uploaded capture: ${data.results.source?.name ?? 'temporary analysis'}.` : 'A live read of the verified CIC-IDS2017 packet-window analysis.'} action={<div className="heading-actions">{analysisSource === 'uploaded' && <button className="button button-quiet" onClick={() => void clearUploadedAnalysis()}>Return to production</button>}<button className="button button-quiet" onClick={() => void reload()}><TimerReset size={15} /> Refresh data</button></div>} />
    <Panel className="capture-upload"><div><span className="eyebrow">Network capture audit</span><h3>Analyze a PCAP or PCAPNG capture</h3><p>Upload an authorized capture to build temporary packet windows and run the active traffic heuristics.</p><small>Supported: .pcap, .pcapng · Maximum size: 64 MB</small></div><div className="capture-actions"><label className="button button-quiet"><FileUp size={15} /> {file ? file.name : 'Choose capture'}<input aria-label="Choose PCAP capture" type="file" accept=".pcap,.pcapng" onChange={(event) => { const selected = event.target.files?.[0] ?? null; const supported = selected && ['.pcap', '.pcapng'].includes(selected.name.slice(selected.name.lastIndexOf('.')).toLowerCase()); setSelectionError(selected && !supported ? 'Choose a .pcap or .pcapng capture.' : null); setFile(supported ? selected : null) }} /></label><button className="button" disabled={!file || uploading} onClick={() => void submitCapture()}>{uploading ? 'Processing capture...' : 'Analyze capture'}</button></div>{(uploadError || selectionError) && <p className="upload-error">{uploadError ?? selectionError}</p>}{uploading && <p className="upload-status" role="status">Uploading capture, building packet windows, and running detection rules...</p>}</Panel>
    {analysisSource === 'uploaded' && <Panel className="capture-result"><div><span className="eyebrow">Uploaded capture result</span><strong>{data.results.source?.name}</strong><small>{data.results.upload?.size_bytes.toLocaleString()} bytes · {data.results.upload?.format.toUpperCase()}</small></div><div><span>Duration</span><strong>{Math.max(0, (windows.at(-1)?.window_end ?? 0) - (windows[0]?.window_start ?? 0))} seconds</strong></div><div><span>Protocols</span><strong>{Object.keys(traffic.protocol_counts).join(', ') || 'None parsed'}</strong></div></Panel>}
    <div className="metric-grid"><MetricCard label="Heuristic risk" value={Number.isFinite(detection.risk_score) ? detection.risk_score.toFixed(1) : 'Unavailable'} detail={`${detection.threat_level} indicator level`} tone="danger" icon={<Gauge size={16} />} /><MetricCard label="Packets analyzed" value={formatNumber(traffic.packets)} detail={`${formatNumber(traffic.windows)} sixty-second windows`} tone="accent" icon={<Radio size={16} />} /><MetricCard label="Detected indicators" value={formatNumber(detection.detected_events)} detail="Evidence-based heuristics" tone="warning" icon={<ShieldAlert size={16} />} /><MetricCard label="Retransmissions" value={formatNumber(traffic.retransmissions)} detail="Observed TCP activity" icon={<ArrowUpRight size={16} />} /></div>
    <div className="content-grid content-grid-wide"><Panel><SectionHeading title="Packet activity" description="Packets aggregated by verified analysis window." /><ActivityChart windows={windows} /></Panel><Panel><SectionHeading title="Protocol mix" description="Observed protocol counts." /><ProtocolBars protocols={traffic.protocol_counts} /></Panel></div>
    <div className="content-grid"><Panel><SectionHeading title="Signal distribution" description="Window-level indicators used by the transparent risk method." /><RiskDistribution windows={windows} /></Panel><Panel><SectionHeading title="Recent findings" action={<a className="text-link" href="/threats">View all <ArrowUpRight size={14} /></a>} />{detection.findings.length === 0 ? <EmptyState title="No threats detected" message="The completed analysis returned no evidence-based findings." /> : <div className="finding-list">{detection.findings.slice(0, 4).map((finding) => <div className="finding-row" key={finding.finding_id}><div><SeverityPill severity={finding.severity} /><strong>{finding.attack_category.replaceAll('_', ' ')}</strong><small>{formatTimestamp(finding.timestamp)}</small></div><b>{finding.risk_score.toFixed(1)}</b></div>)}</div>}</Panel></div>
  </div>
}
