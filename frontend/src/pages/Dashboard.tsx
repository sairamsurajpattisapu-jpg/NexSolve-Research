import { ArrowUpRight, FileUp, Gauge, Radio, ShieldAlert, Sparkles, TimerReset } from 'lucide-react'
import { useState } from 'react'
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

  if (loading && !data) return <LoadingState />
  if (error || !data) return <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />
  const { traffic, detection } = data.results
  const windows = traffic.windows_data ?? []
  const effectiveResult = jobResult ?? (analysisSource === 'uploaded' ? (data.results as unknown as UploadedAnalysisResponse) : null)

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
            : 'VERIFIED REFERENCE DATASET / BENCHMARK BASELINE'
        }
        title="Network Security Posture & Forecast"
        description={
          effectiveResult?.is_demo
            ? `SIH Demo Evaluation: ${effectiveResult.demo_scenario_name}. Deterministic forward assessment without live capture dependency.`
            : effectiveResult
            ? `Forensic analysis complete for: ${effectiveResult.source?.name || 'Uploaded PCAP'}. All indicators derived from live capture.`
            : analysisSource === 'uploaded'
            ? `Live read of uploaded capture: ${data.results.source?.name ?? 'temporary analysis'}.`
            : 'A live read of the verified CIC-IDS2017 packet-window reference benchmark. No PCAP analyzed yet.'
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

      {/* 1. PCAP Upload Panel */}
      {!effectiveResult && !activeJob && (
        <>
          <div className="provenance-banner reference-mode" data-testid="provenance-banner-reference">
            <div className="provenance-badge-group">
              <span className="provenance-pill reference-pill">VERIFIED REFERENCE DATASET</span>
              <span className="provenance-pill dataset-pill">CIC-IDS2017</span>
              <span className="provenance-pill status-pill">No PCAP analyzed yet</span>
            </div>
            <div className="provenance-details">
              <p>
                The telemetry, metric cards, and charts below reflect the verified <strong>CIC-IDS2017</strong> benchmark reference dataset for baseline exploration. <strong>No PCAP has been analyzed yet.</strong> Upload an authorized <code>.pcap</code> or <code>.pcapng</code> capture to run live analysis, or select Demo Mode.
              </p>
            </div>
          </div>

          <Panel className="capture-upload">
            <div>
              <span className="eyebrow">Network capture audit</span>
              <h3>Analyze a PCAP or PCAPNG capture</h3>
              <p>Upload an authorized capture to run full canonical reconstruction, attack horizon, and forensic reporting.</p>
              <small>Supported: .pcap, .pcapng &middot; Maximum size: 64 MB &middot; Magic byte validated</small>
            </div>
            <div className="capture-actions">
              <label className="button button-quiet">
                <FileUp size={15} /> {file ? file.name : 'Choose capture'}
                <input
                  aria-label="Choose PCAP capture"
                  type="file"
                  accept=".pcap,.pcapng"
                  onChange={(event) => {
                    const selected = event.target.files?.[0] ?? null
                    const supported =
                      selected &&
                      ['.pcap', '.pcapng'].includes(selected.name.slice(selected.name.lastIndexOf('.')).toLowerCase())
                    setSelectionError(selected && !supported ? 'Choose a .pcap or .pcapng capture.' : null)
                    setFile(supported ? selected : null)
                  }}
                />
              </label>
              <button className="button" disabled={!file || uploading} onClick={() => void submitCapture()}>
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
            {(uploadError || selectionError) && <p className="upload-error">{uploadError ?? selectionError}</p>}
            {uploading && !activeJob && (
              <p className="upload-status" role="status">
                Uploading capture, building packet windows, and running detection rules...
              </p>
            )}
          </Panel>
        </>
      )}

      {/* 2. Active Asynchronous Job Progress */}
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
            <span className="provenance-pill dataset-pill">{effectiveResult.demo_scenario_name || 'SIH Demo Scenario'}</span>
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

      {/* 4. Production Reference Dashboard Panels (visible when not viewing completed job result) */}
      {!effectiveResult && (
        <>
          <div className="reference-section-header">
            <span className="eyebrow" style={{ color: 'var(--amber)' }}>
              CIC-IDS2017 REFERENCE BENCHMARK METRICS
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
                  <a className="text-link" href="/threats">
                    View all <ArrowUpRight size={14} />
                  </a>
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
        </>
      )}
    </div>
  )
}
