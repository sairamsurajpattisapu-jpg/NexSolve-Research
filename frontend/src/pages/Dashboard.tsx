import { useState, type DragEvent } from 'react'
import { Link } from 'react-router-dom'
import {
  ArrowUpRight,
  FileCheck,
  FileUp,
  Gauge,
  GitCommit,
  Radio,
  ShieldAlert,
  Sparkles,
  TimerReset,
  TrendingUp,
} from 'lucide-react'
import { ActivityChart, ProtocolBars, RiskDistribution } from '../components/Charts'
import { DemoModeSelector } from '../components/DemoModeSelector'
import { JobProgress } from '../components/JobProgress'
import { JobResult } from '../components/JobResult'
import { EmptyState, ErrorState, LoadingState, MetricCard, Panel, SectionHeading, SeverityPill } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { api } from '../services/api'
import type { JobStatusResponse, UploadedAnalysisResponse } from '../types/api'
import { formatNumber, formatTimestamp } from '../utils/format'

export function Dashboard() {
  const { data, loading, error, reload, analyzePcap, clearUploadedAnalysis, setUploadedAnalysis, analysisSource, uploadError } = useProductionData()
  const [file, setFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [selectionError, setSelectionError] = useState<string | null>(null)
  const [activeJob, setActiveJob] = useState<JobStatusResponse | null>(null)
  const [jobResult, setJobResult] = useState<UploadedAnalysisResponse | null>(null)
  const [showDemoMode, setShowDemoMode] = useState<boolean>(false)
  const [isDragging, setIsDragging] = useState<boolean>(false)

  if (loading && !data) return <LoadingState />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />
  const { traffic, detection } = data.results
  const windows = traffic.windows_data ?? []
  const effectiveResult = jobResult ?? (analysisSource === 'uploaded' ? (data.results as unknown as UploadedAnalysisResponse) : null)

  const handleFileSelect = (selected: File | null) => {
    if (!selected) {
      setFile(null)
      return
    }
    const ext = selected.name.slice(selected.name.lastIndexOf('.')).toLowerCase()
    const supported = ['.pcap', '.pcapng'].includes(ext)
    if (!supported) {
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
      // Initiate async processing job
      const job = await api.createJob(file)
      setActiveJob(job)
      let cur = job
      while (cur.status === 'QUEUED' || cur.status === 'PROCESSING') {
        await new Promise((r) => setTimeout(r, 300))
        cur = await api.getJobStatus(job.job_id)
        setActiveJob(cur)
      }
      if (cur.status === 'COMPLETED') {
        const res = await api.getJobResult(cur.job_id)
        setJobResult(res)
        await setUploadedAnalysis(res)
      }
    } catch {
      // Graceful fallback to legacy synchronous upload
      await analyzePcap(file)
    } finally {
      setUploading(false)
      setFile(null)
    }
  }

  const resetJobView = () => {
    setActiveJob(null)
    setJobResult(null)
    setShowDemoMode(false)
    void clearUploadedAnalysis()
  }

  return (
    <div className="page-stack page-enter">
      <SectionHeading
        eyebrow={
          effectiveResult?.is_demo
            ? 'DEMO DATA / EVALUATION SCENARIO'
            : effectiveResult
            ? 'LIVE PCAP ANALYSIS / FORENSIC INTELLIGENCE'
            : 'NETWORK THREAT FORECASTING & CAPTURE AUDIT'
        }
        title="PCAP Forensic Analysis & Forecast Engine"
        description={
          effectiveResult?.is_demo
            ? `SIH Demo Evaluation: ${effectiveResult.demo_scenario_name}. Deterministic forward assessment without live capture dependency.`
            : effectiveResult
            ? `Forensic analysis complete for: ${effectiveResult.source?.name || 'Uploaded PCAP'}. All indicators derived from live capture.`
            : 'Upload an authorized .pcap or .pcapng capture to reconstruct temporal windows, project attack horizon, and compile explainable causal chains.'
        }
        action={
          <div className="heading-actions">
            {(analysisSource === 'uploaded' || effectiveResult || activeJob) && (
              <button
                className="button button-quiet"
                onClick={resetJobView}
                aria-label="Return to reference dataset"
              >
                Return to reference dataset
              </button>
            )}
            <button
              className={`button button-quiet ${showDemoMode ? 'active' : ''}`}
              onClick={() => setShowDemoMode(!showDemoMode)}
            >
              <Sparkles size={14} color="var(--accent)" /> {showDemoMode ? 'Close Demo Mode' : 'Demo Mode'}
            </button>
            <button className="button button-quiet" onClick={() => void reload()}>
              <TimerReset size={15} /> Refresh data
            </button>
          </div>
        }
      />

      {/* SIH Demo Mode Selector */}
      {showDemoMode && !activeJob && (
        <DemoModeSelector
          onSelectScenario={async (res) => {
            setJobResult(res)
            setActiveJob(null)
            await setUploadedAnalysis(res)
          }}
          onClose={() => setShowDemoMode(false)}
        />
      )}

      {/* 1. HERO PCAP Upload Panel (Primary Hero Workflow when no active result) */}
      {!effectiveResult && !activeJob && (
        <Panel
          className={`capture-upload ${isDragging ? 'drag-over' : ''}`}
          style={{
            border: isDragging ? '2px dashed var(--accent)' : '1px solid var(--border-strong)',
            background: isDragging ? 'var(--accent-muted)' : 'var(--bg-surface)',
            padding: '28px',
            transition: 'all 0.2s ease',
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
          <div style={{ maxWidth: '650px' }}>
            <span className="eyebrow" style={{ color: 'var(--accent)' }}>HERO WORKFLOW · LIVE CAPTURE INGESTION</span>
            <h3 style={{ fontSize: '20px', margin: '6px 0 8px 0', color: 'var(--text-primary)' }}>
              Analyze a PCAP or PCAPNG capture
            </h3>
            <p style={{ margin: '0 0 10px 0', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
              Drag and drop an authorized capture file here, or select from your filesystem.
              The pipeline executes full 5-tuple flow reconstruction, sliding 60-second temporal windows,
              45-feature state vector assembly, and multi-horizon attack forecasting.
            </p>
            <small style={{ fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
              Supported: .pcap, .pcapng &middot; Maximum size: 64 MB &middot; Magic-byte verified &middot; Zero RTT fabrication
            </small>
          </div>

          <div className="capture-actions" style={{ marginTop: '14px' }}>
            <label className="button button-quiet" style={{ cursor: 'pointer' }}>
              <FileUp size={15} /> {file ? file.name : 'Choose capture'}
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
              {uploading ? 'Processing capture...' : 'Analyze PCAP'}
            </button>
            <button
              type="button"
              className="button button-quiet"
              onClick={() => setShowDemoMode(true)}
              style={{ display: 'flex', alignItems: 'center', gap: '5px' }}
            >
              <Sparkles size={14} color="var(--accent)" /> Try Demo
            </button>
          </div>

          {(uploadError || selectionError) && <p className="upload-error" style={{ color: 'var(--danger)', marginTop: '8px' }}>{uploadError ?? selectionError}</p>}
          {uploading && !activeJob && (
            <p className="upload-status" role="status" style={{ color: 'var(--accent)', marginTop: '8px' }}>
              Uploading capture, building packet windows, and running detection rules...
            </p>
          )}
        </Panel>
      )}

      {/* 2. Active Asynchronous Job Progress */}
      {activeJob && !jobResult && (
        <JobProgress job={activeJob} onCancel={resetJobView} />
      )}

      {/* 3. Completed Job Full Result View */}
      {effectiveResult && !effectiveResult.is_demo && (
        <>
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

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '8px' }}>
            <Link to="/forecast" className="button button-quiet">
              <TrendingUp size={14} /> Full Forecast Rollout (T+1..T+5)
            </Link>
            <Link to="/evidence" className="button button-quiet">
              <GitCommit size={14} /> Full Evidence Attribution Graph
            </Link>
            <Link to="/traffic" className="button button-quiet">
              <Radio size={14} /> Traffic Telemetry Evolution
            </Link>
            <Link to="/reports" className="button button-quiet">
              <FileCheck size={14} /> View Signed Forensic Report
            </Link>
          </div>
        </>
      )}

      {effectiveResult && effectiveResult.is_demo && (
        <>
          <div className="provenance-banner demo-mode" data-testid="provenance-banner-demo">
            <div className="provenance-badge-group">
              <span className="provenance-pill demo-pill">DEMO DATA</span>
              <span className="provenance-pill reference-pill">VERIFIED REFERENCE DATASET</span>
              <span className="provenance-pill dataset-pill">{effectiveResult.demo_scenario_name || 'SIH Demo Scenario'}</span>
            </div>
            <div className="provenance-details">
              <p>
                Deterministic evaluation sandbox: <strong>{effectiveResult.demo_scenario_name}</strong>. Validating forward horizon trajectories without live capture dependency.
              </p>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap', marginBottom: '8px' }}>
            <Link to="/forecast" className="button button-quiet">
              <TrendingUp size={14} /> Full Forecast Rollout (T+1..T+5)
            </Link>
            <Link to="/evidence" className="button button-quiet">
              <GitCommit size={14} /> Full Evidence Attribution Graph
            </Link>
            <Link to="/reports" className="button button-quiet">
              <FileCheck size={14} /> View Signed Forensic Report
            </Link>
          </div>
        </>
      )}

      {effectiveResult && (
        <JobResult result={effectiveResult} onReset={resetJobView} />
      )}

      {/* 4. Production Reference Benchmark Panels (Clearly separated at the bottom when no PCAP analyzed) */}
      {!effectiveResult && (
        <div style={{ marginTop: '16px' }}>
          <div className="provenance-banner reference-mode" data-testid="provenance-banner-reference">
            <div className="provenance-badge-group">
              <span className="provenance-pill reference-pill">VERIFIED REFERENCE DATASET</span>
              <span className="provenance-pill dataset-pill">CIC-IDS2017</span>
              <span className="provenance-pill status-pill">No PCAP analyzed yet</span>
            </div>
            <div className="provenance-details">
              <p>
                The telemetry, metric cards, and charts below reflect the verified <strong>CIC-IDS2017</strong> benchmark reference dataset for baseline exploration. <strong>No PCAP has been analyzed yet.</strong> Upload an authorized <code>.pcap</code> or <code>.pcapng</code> capture above to run live analysis, or select Demo Mode.
              </p>
            </div>
          </div>

          <div className="reference-section-header" style={{ marginTop: '12px', marginBottom: '12px' }}>
            <span className="eyebrow" style={{ color: 'var(--amber)' }}>
              CIC-IDS2017 REFERENCE BENCHMARK METRICS (FOR COMPARISON ONLY)
            </span>
          </div>

          <div className="metric-grid">
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
                eyebrow="REFERENCE DATA"
                title="Packet activity"
                description="Reference baseline packets aggregated by verified 60-second analysis windows (CIC-IDS2017)."
              />
              <ActivityChart windows={windows} />
            </Panel>
            <Panel>
              <SectionHeading
                eyebrow="REFERENCE DATA"
                title="Protocol mix"
                description="Observed protocol counts from the CIC-IDS2017 reference dataset."
              />
              <ProtocolBars protocols={traffic.protocol_counts} />
            </Panel>
          </div>

          <div className="content-grid">
            <Panel>
              <SectionHeading
                eyebrow="REFERENCE DATA"
                title="Signal distribution"
                description="Window-level indicators used by the transparent risk method (CIC-IDS2017 Reference)."
              />
              <RiskDistribution windows={windows} />
            </Panel>
            <Panel>
              <SectionHeading
                eyebrow="REFERENCE DATA"
                title="Recent findings"
                description="Reference findings from the CIC-IDS2017 benchmark dataset."
                action={
                  <Link className="text-link" to="/threats">
                    View all <ArrowUpRight size={14} />
                  </Link>
                }
              />
              {detection.findings.length === 0 ? (
                <EmptyState
                  title="No threats detected"
                  message="The reference analysis returned no evidence-based findings."
                />
              ) : (
                <div className="finding-list">
                  {detection.findings.slice(0, 4).map((finding) => (
                    <div className="finding-row" key={finding.finding_id}>
                      <div>
                        <SeverityPill severity={finding.severity} />
                        <strong>{finding.attack_category.replaceAll('_', ' ')}</strong>
                        <small>{formatTimestamp(finding.timestamp)}</small>
                      </div>
                      <b>{finding.risk_score.toFixed(1)}</b>
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          </div>
        </div>
      )}
    </div>
  )
}
