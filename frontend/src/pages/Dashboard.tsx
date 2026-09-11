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
  const { data, loading, error, reload, analyzePcap, clearUploadedAnalysis, analysisSource, uploadError } = useProductionData()
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
        eyebrow="Overview / Predictive Intelligence"
        title="Network Security Posture & Forecast"
        description={
          jobResult?.is_demo
            ? `SIH Demo Evaluation: ${jobResult.demo_scenario_name}. Deterministic forward assessment without live capture dependency.`
            : jobResult
            ? `Forensic analysis complete for: ${jobResult.source?.name || 'Uploaded PCAP'}.`
            : analysisSource === 'uploaded'
            ? `Live read of uploaded capture: ${data.results.source?.name ?? 'temporary analysis'}.`
            : 'A live read of the verified CIC-IDS2017 packet-window analysis.'
        }
        action={
          <div className="heading-actions">
            {(analysisSource === 'uploaded' || jobResult || activeJob) && (
              <button className="button button-quiet" onClick={resetJobView}>
                Return to production
              </button>
            )}
            <button
              className="button button-quiet"
              style={{ color: showDemoMode ? 'var(--teal)' : undefined, borderColor: showDemoMode ? 'var(--teal)' : undefined }}
              onClick={() => setShowDemoMode(!showDemoMode)}
            >
              <Sparkles size={14} color="var(--teal)" /> {showDemoMode ? 'Close Demo Mode' : 'Demo Mode'}
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
          onSelectScenario={(res) => {
            setJobResult(res)
            setActiveJob(null)
          }}
          onClose={() => setShowDemoMode(false)}
        />
      )}

      {/* 1. PCAP Upload Panel */}
      {!jobResult && !activeJob && (
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
              <Sparkles size={14} color="var(--teal)" /> Try Demo
            </button>
          </div>
          {(uploadError || selectionError) && <p className="upload-error">{uploadError ?? selectionError}</p>}
          {uploading && !activeJob && (
            <p className="upload-status" role="status">
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
      {jobResult && (
        <JobResult result={jobResult} onReset={resetJobView} />
      )}

      {/* 4. Legacy Uploaded Capture Result Badge */}
      {analysisSource === 'uploaded' && !jobResult && (
        <Panel className="capture-result">
          <div>
            <span className="eyebrow">Uploaded capture result</span>
            <strong>{data.results.source?.name}</strong>
            <small>
              {data.results.upload?.size_bytes.toLocaleString()} bytes &middot;{' '}
              {data.results.upload?.format.toUpperCase()}
            </small>
          </div>
          <div>
            <span>Duration</span>
            <strong>
              {Math.max(0, (windows.at(-1)?.window_end ?? 0) - (windows[0]?.window_start ?? 0))} seconds
            </strong>
          </div>
          <div>
            <span>Protocols</span>
            <strong>{Object.keys(traffic.protocol_counts).join(', ') || 'None parsed'}</strong>
          </div>
        </Panel>
      )}

      {/* 5. Production Dashboard Panels (visible when not viewing completed job result) */}
      {!jobResult && (
        <>
          <div className="metric-grid">
            <MetricCard
              label="Heuristic risk"
              value={Number.isFinite(detection.risk_score) ? detection.risk_score.toFixed(1) : 'Unavailable'}
              detail={`${detection.threat_level} indicator level`}
              tone="danger"
              icon={<Gauge size={16} />}
            />
            <MetricCard
              label="Packets analyzed"
              value={formatNumber(traffic.packets)}
              detail={`${formatNumber(traffic.windows)} sixty-second windows`}
              tone="accent"
              icon={<Radio size={16} />}
            />
            <MetricCard
              label="Detected indicators"
              value={formatNumber(detection.detected_events)}
              detail="Evidence-based heuristics"
              tone="warning"
              icon={<ShieldAlert size={16} />}
            />
            <MetricCard
              label="Retransmissions"
              value={formatNumber(traffic.retransmissions)}
              detail="Observed TCP activity"
              icon={<ArrowUpRight size={16} />}
            />
          </div>

          <div className="content-grid content-grid-wide">
            <Panel>
              <SectionHeading title="Packet activity" description="Packets aggregated by verified analysis window." />
              <ActivityChart windows={windows} />
            </Panel>
            <Panel>
              <SectionHeading title="Protocol mix" description="Observed protocol counts." />
              <ProtocolBars protocols={traffic.protocol_counts} />
            </Panel>
          </div>

          <div className="content-grid">
            <Panel>
              <SectionHeading
                title="Signal distribution"
                description="Window-level indicators used by the transparent risk method."
              />
              <RiskDistribution windows={windows} />
            </Panel>
            <Panel>
              <SectionHeading
                title="Recent findings"
                action={
                  <a className="text-link" href="/threats">
                    View all <ArrowUpRight size={14} />
                  </a>
                }
              />
              {detection.findings.length === 0 ? (
                <EmptyState
                  title="No threats detected"
                  message="The completed analysis returned no evidence-based findings."
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
