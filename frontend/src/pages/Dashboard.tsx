import { useEffect, useState, type DragEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowUpRight,
  CheckCircle2,
  FileUp,
  Gauge,
  Radio,
  ShieldAlert,
  Sparkles,
  TimerReset,
  X,
} from 'lucide-react'
import { ActivityChart, ProtocolBars } from '../components/Charts'
import { CsvRequirementsModal } from '../components/CsvRequirementsModal'
import { JobProgress } from '../components/JobProgress'
import { JobResult } from '../components/JobResult'
import { ErrorState, LoadingState, MetricCard, Panel, SectionHeading } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { api } from '../services/api'
import type { JobStatusResponse, UploadedAnalysisResponse } from '../types/api'
import { formatNumber } from '../utils/format'
import {
  getAnalysisHistory,
  recordAnalysisHistory,
  clearAnalysisHistory,
  type AnalysisHistoryEntry,
} from '../utils/analysisHistory'

export function Dashboard() {
  const navigate = useNavigate()
  const { data, loading, error, reload, analyzePcap, clearUploadedAnalysis, analysisSource, uploadError } = useProductionData()
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState<boolean>(false)
  const [selectionError, setSelectionError] = useState<string | null>(null)
  const [activeJob, setActiveJob] = useState<JobStatusResponse | null>(null)
  const [jobResult, setJobResult] = useState<UploadedAnalysisResponse | null>(null)
  const [isDragging, setIsDragging] = useState<boolean>(false)
  const [showCsvModal, setShowCsvModal] = useState<boolean>(false)
  const [history, setHistory] = useState<AnalysisHistoryEntry[]>(() => getAnalysisHistory())

  if (loading && !data) return <LoadingState message="Preparing analysis..." />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />

  const { traffic, detection } = data.results
  const windows = traffic.windows_data ?? []
  const effectiveResult = jobResult ?? (analysisSource === 'uploaded' ? (data.results as unknown as UploadedAnalysisResponse) : null)

  const handleFileSelect = (selected: File | null) => {
    if (!selected) {
      setFile(null)
      return
    }
    const name = selected.name.toLowerCase()
    const isPcap = name.endsWith('.pcap') || name.endsWith('.pcapng')
    const isCsv = name.endsWith('.csv')

    if (!isPcap && !isCsv) {
      setSelectionError('Choose a .pcap or .pcapng capture.')
      setFile(null)
    } else if (selected.size === 0) {
      setSelectionError('The selected capture file is empty (0 bytes).')
      setFile(null)
    } else if (selected.size > 250 * 1024 * 1024) {
      setSelectionError('Capture file exceeds maximum size limit (250 MB).')
      setFile(null)
    } else {
      setSelectionError(null)
      setFile(selected)
    }
  }

  // Sync history when effectiveResult is available
  useEffect(() => {
    if (effectiveResult) {
      recordAnalysisHistory({
        id: effectiveResult.analysis_id,
        filename: effectiveResult.source?.name || effectiveResult.source?.filename || 'Uploaded Capture',
        timestamp:
          (effectiveResult as any).timestamp ||
          effectiveResult.detection?.findings?.[0]?.timestamp ||
          new Date().toISOString(),
        status: 'COMPLETED',
        provenance: effectiveResult.is_demo ? 'demo' : 'uploaded',
        peakRiskPct: effectiveResult.detection?.risk_score,
        predictedStage: (effectiveResult as any).attack_progression?.current_stage,
      })
      setHistory(getAnalysisHistory())
    }
  }, [effectiveResult])

  const submitCapture = async () => {
    if (!file || uploading) return
    setUploading(true)
    setSelectionError(null)

    try {
      // Initiate asynchronous processing job
      const job = await api.createJob(file)
      setActiveJob(job)
      recordAnalysisHistory({
        id: job.job_id,
        filename: file.name,
        filesize: `${(file.size / (1024 * 1024)).toFixed(2)} MB`,
        timestamp: new Date().toISOString(),
        status: 'PROCESSING',
        provenance: 'uploaded',
      })
      setHistory(getAnalysisHistory())
      setFile(null)
      // Navigate to dedicated forecast rollout route with the created job ID
      navigate(`/console/forecast/${job.job_id}`)
    } catch {
      // Fallback to synchronous analysis if job manager is bypassed
      try {
        await analyzePcap(file)
        setFile(null)
        navigate('/console/forecast')
      } catch (err: unknown) {
        if (err instanceof Error) {
          const msg = err.message
          if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('ECONNREFUSED')) {
            setSelectionError('The analysis service is temporarily unreachable. Please retry when ready.')
          } else if (msg.includes('500') || msg.includes('Internal Server Error')) {
            setSelectionError('The capture could not be processed. Please ensure the file contains valid packet frames.')
          } else {
            setSelectionError(msg)
          }
        } else {
          setSelectionError('Unable to start analysis. The analysis service is currently unavailable. Please retry when ready.')
        }
      }
    } finally {
      setUploading(false)
    }
  }

  const resetJobView = () => {
    setActiveJob(null)
    setJobResult(null)
    void clearUploadedAnalysis()
  }

  const isCsv = file?.name.toLowerCase().endsWith('.csv')

  return (
    <div className="page-stack page-enter" style={{ maxWidth: '1080px', margin: '0 auto', width: '100%' }}>
      {!effectiveResult && (
        <SectionHeading
          eyebrow="NETWORK ATTACK FORECASTING"
          title="Analyze network traffic"
          description="Upload network telemetry to reconstruct the current network state and forecast future attack progression."
          action={
            <div className="heading-actions">
              <button
                type="button"
                className="button button-quiet"
                onClick={() => navigate('/console/demo')}
                style={{ fontSize: '12px', gap: '6px' }}
              >
                <Sparkles size={14} color="var(--accent)" /> Try Demo
                <span
                  style={{
                    fontSize: '9px',
                    fontFamily: 'var(--mono)',
                    padding: '1px 5px',
                    borderRadius: '3px',
                    background: 'rgba(242, 187, 113, 0.2)',
                    color: '#eda850',
                    fontWeight: 700,
                  }}
                >
                  DEMO DATA
                </span>
              </button>
              <button
                type="button"
                className="button button-quiet"
                onClick={() => void reload()}
                aria-label="Refresh data"
              >
                <TimerReset size={14} /> Refresh
              </button>
            </div>
          }
        />
      )}

      {/* 1. PCAP / PCAPNG / CSV Upload Hero Box */}
      {!effectiveResult && !activeJob && (
        <Panel
          className={`capture-upload ${isDragging ? 'drag-over' : ''}`}
          style={{
            border: isDragging ? '1px dashed var(--accent)' : '1px solid var(--border)',
            background: isDragging ? 'var(--accent-muted)' : 'var(--bg-surface)',
            padding: '36px 28px',
            borderRadius: '8px',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '16px',
            transition: 'all 0.15s ease',
          }}
          onDragOver={(e: DragEvent<HTMLElement>) => {
            e.preventDefault()
            setIsDragging(true)
          }}
          onDragLeave={() => setIsDragging(false)}
          onDrop={(e: DragEvent<HTMLElement>) => {
            e.preventDefault()
            setIsDragging(false)
            const droppedFile = e.dataTransfer.files?.[0] ?? null
            handleFileSelect(droppedFile)
          }}
        >
          {!file ? (
            /* Dropzone Empty State */
            <div style={{ maxWidth: '560px' }}>
              <div
                style={{
                  display: 'inline-flex',
                  padding: '12px',
                  borderRadius: '50%',
                  background: 'var(--button-secondary-bg)',
                  marginBottom: '10px',
                }}
              >
                <FileUp size={26} color="var(--accent)" />
              </div>
              <h3 style={{ fontSize: '19px', fontWeight: 600, margin: '4px 0 6px 0', color: 'var(--text-primary)' }}>
                Analyze a PCAP or PCAPNG capture
              </h3>
              <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '13.5px', lineHeight: 1.5 }}>
                Upload network telemetry to reconstruct the current network state and forecast future attack progression.
              </p>
              <small style={{ display: 'block', marginTop: '10px', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
                Supported: .pcap, .pcapng &middot; Maximum size: 250 MB
              </small>

              <div className="capture-actions" style={{ display: 'flex', gap: '10px', alignItems: 'center', justifyContent: 'center', marginTop: '16px', flexWrap: 'wrap' }}>
                <label className="button button-primary" style={{ cursor: 'pointer', gap: '6px' }}>
                  <FileUp size={14} /> Upload PCAP
                  <input
                    aria-label="Choose PCAP capture"
                    type="file"
                    accept=".pcap,.pcapng"
                    style={{ display: 'none' }}
                    onChange={(event) => {
                      const selected = event.target.files?.[0] ?? null
                      handleFileSelect(selected)
                    }}
                  />
                </label>
              </div>
            </div>
          ) : (
            /* Analysis Confirmation Card (Before Processing) */
            <div style={{ width: '100%', maxWidth: '600px', textAlign: 'left' }}>
              <div style={{ marginBottom: '14px', textAlign: 'center' }}>
                <span className="eyebrow" style={{ color: 'var(--accent)' }}>
                  ANALYSIS CONFIRMATION
                </span>
                <h3 style={{ fontSize: '18px', fontWeight: 700, margin: '4px 0', color: 'var(--text-primary)' }}>
                  Ready to Start Analysis
                </h3>
                <p style={{ margin: 0, fontSize: '12.5px', color: 'var(--text-muted)' }}>
                  Review capture configuration before initiating multi-horizon network simulation.
                </p>
              </div>

              <div
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '16px 20px',
                  display: 'grid',
                  gridTemplateColumns: 'repeat(2, 1fr)',
                  gap: '12px',
                  fontSize: '12px',
                  marginBottom: '16px',
                }}
              >
                <div>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--mono)', fontSize: '10.5px' }}>FILE</span>
                  <strong style={{ display: 'block', color: 'var(--text-primary)', fontSize: '13px', marginTop: '2px', wordBreak: 'break-all' }}>
                    {file.name}
                  </strong>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--mono)', fontSize: '10.5px' }}>SIZE</span>
                  <strong style={{ display: 'block', color: 'var(--text-primary)', fontSize: '13px', marginTop: '2px' }}>
                    {(file.size / (1024 * 1024)).toFixed(2)} MB
                  </strong>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--mono)', fontSize: '10.5px' }}>FORMAT</span>
                  <strong style={{ display: 'block', color: 'var(--text-primary)', fontSize: '13px', marginTop: '2px' }}>
                    {file.name.toLowerCase().endsWith('.pcapng')
                      ? 'PCAPNG (Next Generation)'
                      : isCsv
                      ? 'CSV (Temporal Telemetry)'
                      : 'Standard PCAP (libpcap)'}
                  </strong>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--mono)', fontSize: '10.5px' }}>FORECAST HORIZONS</span>
                  <strong style={{ display: 'block', color: 'var(--text-primary)', fontSize: '13px', marginTop: '2px' }}>
                    Multi-Horizon (T+1..T+5)
                  </strong>
                </div>
                <div style={{ gridColumn: 'span 2', paddingTop: '6px', borderTop: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <CheckCircle2 size={14} color="var(--success)" />
                  <span style={{ color: 'var(--success)', fontFamily: 'var(--mono)', fontSize: '11px', fontWeight: 600 }}>
                    Format validated &middot; Ready for ingestion
                  </span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '10px', alignItems: 'center', justifyContent: 'center', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="button button-primary"
                  disabled={uploading}
                  onClick={() => void submitCapture()}
                  style={{ gap: '6px' }}
                >
                  <Sparkles size={14} /> {uploading ? 'Processing...' : 'Start Analysis'}
                </button>
                <button
                  type="button"
                  className="button button-quiet"
                  onClick={() => {
                    setFile(null)
                    setSelectionError(null)
                  }}
                  style={{ gap: '6px' }}
                >
                  <X size={14} /> Choose Another File
                </button>
              </div>
            </div>
          )}

          {(uploadError || selectionError) && (
            <p className="upload-error" style={{ color: 'var(--danger)', margin: '6px 0 0 0', fontSize: '12px' }}>
              {uploadError ?? selectionError}
            </p>
          )}
          {uploading && !activeJob && (
            <p className="upload-status" role="status" style={{ color: 'var(--accent)', margin: '6px 0 0 0', fontSize: '12px' }}>
              Uploading capture, computing windows, and forecasting...
            </p>
          )}
        </Panel>
      )}

      {/* 2. Active Job Progress */}
      {activeJob && !jobResult && (
        <JobProgress job={activeJob} onCancel={resetJobView} />
      )}

      {/* 3. Completed Job Full Result View */}
      {effectiveResult && !effectiveResult.is_demo && (
        <div className="provenance-banner live-mode" data-testid="provenance-banner-live">
          <div className="provenance-badge-group">
            <span className="provenance-pill live-pill">LIVE PCAP ANALYSIS</span>
            <span className="provenance-pill dataset-pill">{effectiveResult.source?.name || 'Uploaded Capture'}</span>
            <span className="provenance-pill status-pill">ID: {effectiveResult.analysis_id}</span>
          </div>
          <div className="provenance-details">
            <p>
              Active forensic inspection of uploaded capture: <strong>{effectiveResult.source?.name || 'Uploaded Capture'}</strong>.
              All extracted features, packet windows, and predictive assessments are derived directly from this capture.
            </p>
          </div>
        </div>
      )}

      {effectiveResult && effectiveResult.is_demo && (
        <div className="provenance-banner demo-mode" data-testid="provenance-banner-demo">
          <div className="provenance-badge-group">
            <span className="provenance-pill demo-pill">DEMO DATA</span>
            <span className="provenance-pill reference-pill">VERIFIED REFERENCE DATASET</span>
            <span className="provenance-pill dataset-pill">{effectiveResult.demo_scenario_name || 'Evaluation Scenario'}</span>
          </div>
          <div className="provenance-details">
            <p>
              Deterministic evaluation sandbox: <strong>{effectiveResult.demo_scenario_name}</strong>. Validating forward horizon trajectories without live capture dependency.
            </p>
          </div>
        </div>
      )}

      {effectiveResult && (
        <JobResult result={effectiveResult} onReset={resetJobView} />
      )}

      {/* 4. Production Reference Benchmark Panels when no live PCAP is active */}
      {!effectiveResult && (
        <div style={{ marginTop: '24px', paddingTop: '20px', borderTop: '1px solid var(--border)' }}>
          <div className="provenance-banner reference-mode" data-testid="provenance-banner-reference" style={{ marginBottom: '16px' }}>
            <div className="provenance-badge-group">
              <span className="provenance-pill reference-pill">VERIFIED REFERENCE DATASET</span>
              <span className="provenance-pill dataset-pill">CIC-IDS2017</span>
              <span className="provenance-pill status-pill">No PCAP analyzed yet</span>
            </div>
            <div className="provenance-details">
              <p>
                The metrics and telemetry below reflect the verified <strong>CIC-IDS2017</strong> benchmark reference dataset for baseline exploration. <strong>No PCAP has been analyzed yet.</strong>
              </p>
            </div>
          </div>

          <div className="reference-section-header" style={{ marginBottom: '12px' }}>
            <span className="eyebrow" style={{ color: 'var(--amber)' }}>
              CIC-IDS2017 REFERENCE BENCHMARK METRICS (FOR COMPARISON ONLY)
            </span>
          </div>

          <div className="metric-grid" style={{ marginBottom: '16px' }}>
            <MetricCard
              label="Heuristic risk"
              value={Number.isFinite(detection.risk_score) ? detection.risk_score.toFixed(1) : 'Unavailable'}
              detail="CIC-IDS2017 reference benchmark"
              tone="danger"
              icon={<Gauge size={16} />}
            />
            <MetricCard
              label="Packets analyzed"
              value={formatNumber(traffic.packets)}
              detail={`${formatNumber(traffic.windows)} reference windows`}
              tone="accent"
              icon={<Radio size={16} />}
            />
            <MetricCard
              label="Detected indicators"
              value={formatNumber(detection.detected_events)}
              detail="Reference heuristics"
              tone="warning"
              icon={<ShieldAlert size={16} />}
            />
            <MetricCard
              label="Retransmissions"
              value={formatNumber(traffic.retransmissions)}
              detail="Reference TCP activity"
              icon={<ArrowUpRight size={16} />}
            />
          </div>

          <div className="content-grid content-grid-wide">
            <Panel>
              <SectionHeading
                eyebrow="REFERENCE TELEMETRY"
                title="Packet activity"
                description="Aggregated 60s windows from the CIC-IDS2017 reference baseline."
              />
              <ActivityChart windows={windows} />
            </Panel>
            <Panel>
              <SectionHeading
                eyebrow="REFERENCE TELEMETRY"
                title="Protocol mix"
                description="Observed protocols from the reference baseline."
              />
              <ProtocolBars protocols={traffic.protocol_counts} />
            </Panel>
          </div>
        </div>
      )}

      {/* 5. Analysis History Architecture Panel */}
      <div style={{ marginTop: '28px', paddingTop: '20px', borderTop: '1px solid var(--border)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <div>
            <span className="eyebrow" style={{ color: 'var(--text-muted)' }}>
              ANALYSIS HISTORY &middot; SESSION CAPTURES
            </span>
            <h3 style={{ margin: '2px 0 0 0', fontSize: '16px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Recent Analyses
            </h3>
          </div>
          {history.length > 0 && (
            <button
              type="button"
              className="button button-quiet"
              onClick={() => {
                clearAnalysisHistory()
                setHistory([])
              }}
              style={{ fontSize: '11px', height: '26px' }}
            >
              Clear History
            </button>
          )}
        </div>

        {history.length === 0 ? (
          <Panel style={{ padding: '20px', textAlign: 'center', background: 'var(--bg-surface)' }}>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-muted)' }}>
              No previous analyses in current session. Analyzed captures will appear here with instant context restoration.
            </p>
          </Panel>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            {history.map((item) => (
              <Panel
                key={item.id}
                style={{
                  padding: '12px 18px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '12px',
                  background: 'var(--bg-surface)',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                  <div
                    style={{
                      width: '8px',
                      height: '8px',
                      borderRadius: '50%',
                      background:
                        item.status === 'COMPLETED'
                          ? 'var(--success)'
                          : item.status === 'PROCESSING'
                          ? 'var(--accent)'
                          : 'var(--danger)',
                    }}
                  />
                  <div>
                    <strong style={{ fontSize: '13.5px', color: 'var(--text-primary)', display: 'block' }}>
                      {item.filename}
                    </strong>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                      ID: {item.id.slice(0, 16)} &middot; {item.filesize || 'Capture'} &middot; {new Date(item.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  {item.peakRiskPct !== undefined && (
                    <span
                      style={{
                        fontSize: '12px',
                        fontFamily: 'var(--mono)',
                        color: item.peakRiskPct > 50 ? 'var(--danger)' : 'var(--success)',
                      }}
                    >
                      Risk: {Number(item.peakRiskPct).toFixed(1)}%
                    </span>
                  )}
                  <span
                    style={{
                      fontSize: '10px',
                      fontFamily: 'var(--mono)',
                      padding: '2px 6px',
                      borderRadius: '3px',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border)',
                    }}
                  >
                    {item.status}
                  </span>
                  <button
                    type="button"
                    className="button button-quiet"
                    onClick={() => navigate(`/console/forecast/${item.id}`)}
                    style={{ fontSize: '11px', height: '28px' }}
                  >
                    Open Forecast
                  </button>
                </div>
              </Panel>
            ))}
          </div>
        )}
      </div>

      <CsvRequirementsModal
        isOpen={showCsvModal}
        onClose={() => setShowCsvModal(false)}
      />
    </div>
  )
}
