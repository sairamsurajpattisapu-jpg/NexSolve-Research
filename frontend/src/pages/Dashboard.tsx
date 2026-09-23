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
import { CircuitBoard } from '../components/CircuitBoard'
import { CsvRequirementsModal } from '../components/CsvRequirementsModal'
import { JobProgress } from '../components/JobProgress'
import { JobResult } from '../components/JobResult'
import { ErrorState, LoadingState, MetricCard, Panel, SectionHeading } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { api, ApiError } from '../services/api'
import type { JobStatusResponse, UploadedAnalysisResponse } from '../types/api'
import { formatNumber } from '../utils/format'
import {
  MAX_PCAP_UPLOAD_BYTES,
  MAX_PCAP_UPLOAD_LABEL,
  MAX_PCAP_UPLOAD_DESCRIPTION,
  validatePcapFile,
} from '../config/constants'
import {
  getAnalysisHistory,
  recordAnalysisHistory,
  clearAnalysisHistory,
  type AnalysisHistoryEntry,
} from '../utils/analysisHistory'

export function Dashboard() {
  const navigate = useNavigate()
  const { data, loading, error, reload, analyzePcap, clearUploadedAnalysis, clearUploadError, analysisSource, uploadError } = useProductionData()
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState<boolean>(false)
  const [uploadProgress, setUploadProgress] = useState<{ loaded: number; total: number; percentage: number } | null>(null)
  const [selectionError, setSelectionError] = useState<string | null>(null)
  const [activeJob, setActiveJob] = useState<JobStatusResponse | null>(null)
  const [jobResult, setJobResult] = useState<UploadedAnalysisResponse | null>(null)
  const [isDragging, setIsDragging] = useState<boolean>(false)
  const [showCsvModal, setShowCsvModal] = useState<boolean>(false)
  const [history, setHistory] = useState<AnalysisHistoryEntry[]>(() => getAnalysisHistory())

  const effectiveResult = jobResult ?? (analysisSource === 'uploaded' ? (data?.results as unknown as UploadedAnalysisResponse) : null)

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
        provenance: 'uploaded',
        peakRiskPct: effectiveResult.detection?.risk_score,
        predictedStage: (effectiveResult as any).attack_progression?.current_stage,
      })
      setHistory(getAnalysisHistory())
    }
  }, [effectiveResult])

  if (loading && !data) return <LoadingState message="Preparing analysis..." />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />

  const { traffic, detection } = data.results
  const windows = traffic.windows_data ?? []

  const handleFileSelect = (selected: File | null) => {
    clearUploadError?.()
    setUploadProgress(null)
    if (!selected) {
      setFile(null)
      return
    }
    if (selected.size > MAX_PCAP_UPLOAD_BYTES) {
      setSelectionError(`Capture exceeds the maximum allowed upload size of ${MAX_PCAP_UPLOAD_LABEL}.`)
      setFile(null)
      return
    }
    const validation = validatePcapFile(selected, MAX_PCAP_UPLOAD_BYTES)
    if (!validation.valid) {
      setSelectionError(validation.error ?? `Capture exceeds the maximum allowed upload size of ${MAX_PCAP_UPLOAD_LABEL}.`)
      setFile(null)
    } else {
      setSelectionError(null)
      setFile(selected)
    }
  }

  const submitCapture = async () => {
    if (!file || uploading) return
    if (file.size > MAX_PCAP_UPLOAD_BYTES) {
      setSelectionError(`Capture exceeds the maximum allowed upload size of ${MAX_PCAP_UPLOAD_LABEL}.`)
      return
    }
    setUploading(true)
    setSelectionError(null)
    setUploadProgress({ loaded: 0, total: file.size, percentage: 0 })
    clearUploadError?.()

    try {
      // Initiate asynchronous processing job with chunked progress callback
      const job = await api.createJob(file, (progress) => {
        setUploadProgress(progress)
      })
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
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 404) {
        // Fallback to synchronous analysis ONLY if async jobs endpoint is 404
        try {
          await analyzePcap(file)
          setFile(null)
          navigate('/console/forecast')
          return
        } catch {
          // Handled below
        }
      }

      if (err instanceof ApiError) {
        if (err.status === 408) {
          setSelectionError('Upload request timed out. The file could not be transmitted in time. Please check your network connection and retry.')
        } else if (err.status === 413) {
          setSelectionError(
            err.message && err.message.toLowerCase().includes('exceeds')
              ? err.message
              : `Capture exceeds the maximum allowed upload size of ${MAX_PCAP_UPLOAD_LABEL}.`
          )
        } else if (err.status === 415) {
          setSelectionError('Only .pcap and .pcapng captures are supported.')
        } else if (err.status === 422) {
          setSelectionError('The file could not be parsed as a supported PCAP/PCAPNG capture.')
        } else {
          setSelectionError(err.message || 'Unable to start analysis job. Please retry when ready.')
        }
      } else if (err instanceof Error) {
        const msg = err.message
        if (msg.includes('Failed to fetch') || msg.includes('NetworkError') || msg.includes('ECONNREFUSED')) {
          setSelectionError('The analysis service is temporarily unreachable. Please retry when ready.')
        } else {
          setSelectionError(msg)
        }
      } else {
        setSelectionError('Unable to start analysis. The analysis service is currently unavailable. Please retry when ready.')
      }
    } finally {
      setUploading(false)
    }
  }


  const handleCancelJob = async () => {
    if (activeJob) {
      try {
        await api.cancelJob(activeJob.job_id)
      } catch (err) {
        console.error('Failed to cancel job:', err)
      }
    }
    resetJobView()
  }

  const resetJobView = () => {
    setActiveJob(null)
    setJobResult(null)
    void clearUploadedAnalysis()
  }

  const isCsv = file?.name.toLowerCase().endsWith('.csv')

  return (
    <div className="page-stack page-enter">
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
                Supported: .pcap, .pcapng &middot; Maximum size: {MAX_PCAP_UPLOAD_DESCRIPTION}
              </small>

              <div className="capture-actions" style={{ display: 'flex', gap: '10px', alignItems: 'center', justifyContent: 'center', marginTop: '16px', flexWrap: 'wrap' }}>
                <label
                  htmlFor="pcap-upload-input"
                  className="button button-primary"
                  style={{ cursor: 'pointer', gap: '6px' }}
                >
                  <FileUp size={14} /> Upload PCAP
                </label>
                <input
                  id="pcap-upload-input"
                  aria-label="Choose PCAP capture"
                  type="file"
                  accept=".pcap,.pcapng"
                  style={{
                    position: 'absolute',
                    width: '1px',
                    height: '1px',
                    padding: 0,
                    margin: '-1px',
                    overflow: 'hidden',
                    clip: 'rect(0, 0, 0, 0)',
                    whiteSpace: 'nowrap',
                    border: 0,
                  }}
                  onClick={(event) => {
                    // Reset input value so selecting the same capture file repeatedly always triggers onChange
                    (event.target as HTMLInputElement).value = ''
                  }}
                  onChange={(event) => {
                    const selected = event.target.files?.[0] ?? null
                    handleFileSelect(selected)
                  }}
                />
              </div>
            </div>
          ) : (
            /* Analysis Confirmation Card (Before Processing) */
            <div style={{ maxWidth: '640px', width: '100%', margin: '0 auto' }}>
              <div style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: '4px' }}>
                ANALYSIS CONFIRMATION
              </div>
              <h3 style={{ fontSize: '18px', fontWeight: 600, margin: '0 0 14px 0', color: 'var(--text-primary)' }}>
                Ready to Start Analysis
              </h3>

              {/* Compact Execution Circuit View */}
              <div style={{ marginBottom: '16px' }}>
                <CircuitBoard
                  compact
                  filename={file.name}
                  activeStageIndex={uploading ? (uploadProgress && uploadProgress.percentage >= 100 ? 1 : 0) : 1}
                  statusText={uploading ? (uploadProgress && uploadProgress.percentage >= 100 ? 'INGESTING CAPTURE' : 'UPLOADING') : 'FORMAT VALIDATED · READY'}
                  progressPercent={uploadProgress?.percentage}
                />
              </div>

              <div
                style={{
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  padding: '14px 18px',
                  textAlign: 'left',
                  display: 'grid',
                  gridTemplateColumns: '1fr 1fr',
                  gap: '12px',
                  marginBottom: '16px',
                }}
              >
                <div>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--mono)', fontSize: '10.5px' }}>FILENAME</span>
                  <strong style={{ display: 'block', color: 'var(--text-primary)', fontSize: '13px', marginTop: '2px', wordBreak: 'break-all' }}>
                    {file.name}
                  </strong>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--mono)', fontSize: '10.5px' }}>FILE SIZE</span>
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

          {!uploading && (selectionError || uploadError) && (
            <p className="upload-error" style={{ color: 'var(--danger)', margin: '8px 0 0 0', fontSize: '12px' }}>
              {selectionError ?? uploadError}
            </p>
          )}
          {uploading && !activeJob && (
            <div
              className="upload-status-card"
              role="status"
              aria-live="polite"
              style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '14px 18px',
                marginTop: '12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '10px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '12px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className="pulse-dot" style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--accent)', display: 'inline-block' }} />
                  <div>
                    <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', textTransform: 'uppercase' }}>
                      {uploadProgress && uploadProgress.percentage >= 100 ? 'UPLOADED · INGESTING' : 'UPLOADING CAPTURE ·'}
                    </span>{' '}
                    <span style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
                      {uploadProgress && uploadProgress.percentage >= 100
                        ? 'Transfer complete. Initializing passive wire pipeline...'
                        : `Transmitting ${file?.name || 'capture'} to passive wire processing engine...`}
                    </span>
                  </div>
                </div>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 600, color: 'var(--accent)' }}>
                  {uploadProgress ? `${uploadProgress.percentage}%` : '0%'}
                </span>
              </div>

              {/* Visual progress bar */}
              <div style={{ width: '100%', height: '6px', background: 'var(--border)', borderRadius: '3px', overflow: 'hidden' }}>
                <div
                  style={{
                    height: '100%',
                    width: `${uploadProgress?.percentage ?? 0}%`,
                    background: 'var(--accent)',
                    transition: 'width 0.2s ease',
                  }}
                />
              </div>

              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                <span>
                  {uploadProgress
                    ? `${(uploadProgress.loaded / (1024 * 1024)).toFixed(2)} MB of ${(uploadProgress.total / (1024 * 1024)).toFixed(2)} MB`
                    : file ? `${(file.size / (1024 * 1024)).toFixed(2)} MB` : ''}
                </span>
                <span>Chunked Resumable Stream</span>
              </div>
            </div>
          )}
        </Panel>
      )}

      {/* 2. Active Job Progress */}
      {activeJob && !jobResult && (
        <JobProgress job={activeJob} onCancel={handleCancelJob} />
      )}

      {/* 3. Completed Job Full Result View */}
      {effectiveResult && (
        <div className="provenance-banner live-mode" data-testid="provenance-banner-live">
          <div className="provenance-badge-group">
            <span className="provenance-pill live-pill">LIVE PCAP ANALYSIS</span>
            <span className="provenance-pill dataset-pill">{effectiveResult.source?.name || 'Uploaded Capture'}</span>
            <span className="provenance-pill status-pill">ID: {effectiveResult.analysis_id}</span>
          </div>
          <div className="provenance-details">
            <p>
              Source: <strong>{effectiveResult.source?.name || 'Uploaded Capture'}</strong> &middot; Verified wire telemetry under 45-feature canonical contract.
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
