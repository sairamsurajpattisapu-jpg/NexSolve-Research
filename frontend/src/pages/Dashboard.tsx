import { useState, type DragEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ArrowUpRight,
  FileUp,
  Gauge,
  Radio,
  ShieldAlert,
  Sparkles,
  TimerReset,
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

  if (loading && !data) return <LoadingState message="Loading production analysis" />
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
    } else {
      setSelectionError(null)
      setFile(selected)
    }
  }

  const submitCapture = async () => {
    if (!file) return
    setUploading(true)
    setSelectionError(null)

    try {
      // Initiate asynchronous processing job
      const job = await api.createJob(file)
      setActiveJob(job)
      setFile(null)
      // Navigate to dedicated forecast rollout route with the created job ID
      navigate(`/console/forecast/${job.job_id}`)
    } catch {
      // Fallback to synchronous analysis if job manager is bypassed
      try {
        await analyzePcap(file)
        setFile(null)
      } catch (err: unknown) {
        setSelectionError(
          err instanceof Error
            ? err.message
            : 'Unable to start analysis. The analysis service is currently unavailable. Please retry when ready.'
        )
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
          description="Upload a PCAP and NexSolve will reconstruct the traffic, assess the current state, and forecast what may happen next."
          action={
            <div className="heading-actions">
              <button
                type="button"
                className="button button-quiet"
                onClick={() => navigate('/console/demo')}
                style={{ fontSize: '12px' }}
              >
                <Sparkles size={14} color="var(--accent)" /> Launch SIH Demo
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
            gap: '14px',
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
          <div style={{ maxWidth: '540px' }}>
            <div
              style={{
                display: 'inline-flex',
                padding: '10px',
                borderRadius: '50%',
                background: 'var(--button-secondary-bg)',
                marginBottom: '8px',
              }}
            >
              <FileUp size={24} color="var(--accent)" />
            </div>
            <h3 style={{ fontSize: '18px', fontWeight: 600, margin: '4px 0 6px 0', color: 'var(--text-primary)' }}>
              {file ? file.name : 'Analyze a PCAP or PCAPNG capture'}
            </h3>
            <p style={{ margin: 0, color: 'var(--text-muted)', fontSize: '13px', lineHeight: 1.5 }}>
              Reconstructs 5-tuple flows, computes 60s temporal windows, and rolls out attack horizon projections.
            </p>
            <small style={{ display: 'block', marginTop: '8px', fontFamily: 'var(--mono)', fontSize: '11px', color: 'var(--text-muted)' }}>
              Supported: .pcap, .pcapng, .csv &middot; Maximum size: 64 MB
            </small>
          </div>

          {/* Selected File Details */}
          {file && (
            <div
              style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '12px 18px',
                display: 'flex',
                alignItems: 'center',
                gap: '16px',
              }}
            >
              <div style={{ textAlign: 'left' }}>
                <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>INPUT PREVIEW</span>
                <strong style={{ display: 'block', fontSize: '13.5px', color: 'var(--text-primary)' }}>{file.name}</strong>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--accent)' }}>
                  {isCsv ? 'CSV Telemetry' : 'PCAP Network Capture'} &middot; {(file.size / 1024 / 1024).toFixed(2)} MB
                </span>
              </div>
              {isCsv && (
                <button
                  type="button"
                  className="button button-quiet"
                  onClick={() => setShowCsvModal(true)}
                  style={{ fontSize: '11px', height: '26px' }}
                >
                  CSV Specs
                </button>
              )}
            </div>
          )}

          <div className="capture-actions" style={{ display: 'flex', gap: '10px', alignItems: 'center', marginTop: '4px' }}>
            <label className="button button-quiet" style={{ cursor: 'pointer' }}>
              <FileUp size={14} /> {file ? 'Change capture' : 'Choose capture'}
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
            <button
              className="button"
              disabled={!file || uploading}
              onClick={() => void submitCapture()}
            >
              {uploading ? 'Processing...' : 'Analyze PCAP'}
            </button>
          </div>

          {(uploadError || selectionError) && (
            <p className="upload-error" style={{ color: 'var(--danger)', margin: '4px 0 0 0', fontSize: '12px' }}>
              {uploadError ?? selectionError}
            </p>
          )}
          {uploading && !activeJob && (
            <p className="upload-status" role="status" style={{ color: 'var(--accent)', margin: '4px 0 0 0', fontSize: '12px' }}>
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

      <CsvRequirementsModal
        isOpen={showCsvModal}
        onClose={() => setShowCsvModal(false)}
      />
    </div>
  )
}
