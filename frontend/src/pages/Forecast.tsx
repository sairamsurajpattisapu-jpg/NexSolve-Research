import { useEffect, useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import {
  AlertCircle,
  FileUp,
  Loader2,
  RotateCcw,
  Sparkles,
} from 'lucide-react'
import { ForecastConsole } from '../components/ForecastConsole'
import { ErrorState, LoadingState, Panel } from '../components/Ui'
import { useJobPolling, STAGE_DESCRIPTIONS } from '../hooks/useJobPolling'
import { useProductionData } from '../hooks/useProductionData'
import type { CanonicalAnalysis } from '../types/canonical'
import { adaptToCanonical } from '../utils/canonicalAdapter'

export function Forecast() {
  const { jobId } = useParams<{ jobId?: string }>()
  const navigate = useNavigate()
  const { data, loading: storeLoading, error: storeError, reload: reloadStore } = useProductionData()

  // If a jobId is in the URL, use the polling hook
  const {
    job,
    result: polledResult,
    stage,
    stageDescription,
    progress,
    status: jobStatus,
    error: jobError,
    isPolling,
    reload: reloadJob,
  } = useJobPolling(jobId)

  // Local canonical analysis state
  const [activeAnalysis, setActiveAnalysis] = useState<CanonicalAnalysis | null>(null)

  useEffect(() => {
    if (jobId) {
      if (polledResult) {
        setActiveAnalysis(polledResult)
      }
    } else if (data?.results) {
      const canonical = adaptToCanonical(data.results, data.results.analysis_id)
      setActiveAnalysis(canonical)
    }
  }, [jobId, polledResult, data])

  // CASE 1: Polling an active job that is still processing
  if (jobId && (isPolling || (job && jobStatus !== 'COMPLETED' && !jobError))) {
    const stageOrder = [
      'INGESTION',
      'PARSING',
      'FLOW_RECONSTRUCTION',
      'WINDOWING',
      'NETWORK_STATE',
      'FORECAST',
      'EVIDENCE',
      'REPORT',
      'COMPLETE',
    ]
    const currentStageIdx = stageOrder.indexOf(stage)

    return (
      <div className="page-stack page-enter" style={{ maxWidth: '820px', margin: '40px auto', width: '100%' }}>
        <Panel>
          <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--accent)' }}>
                  ANALYSIS JOB IN PROGRESS &middot; ID: {jobId}
                </span>
                <h2 style={{ fontSize: '18px', fontWeight: 600, margin: '4px 0 0 0', color: 'var(--text-primary)' }}>
                  {stageDescription}
                </h2>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Loader2 size={18} className="spin" color="var(--accent)" />
                <span style={{ fontFamily: 'var(--mono)', fontWeight: 700, fontSize: '14px', color: 'var(--text-primary)' }}>
                  {progress}%
                </span>
              </div>
            </div>

            {/* Progress Bar */}
            <div style={{ width: '100%', height: '6px', background: 'var(--bg-secondary)', borderRadius: '3px', overflow: 'hidden' }}>
              <div
                style={{
                  width: `${progress}%`,
                  height: '100%',
                  background: 'var(--accent)',
                  transition: 'width 0.3s ease',
                }}
              />
            </div>

            {/* Real Processing Stages Timeline (Section 6) */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', marginTop: '8px' }}>
              {stageOrder.slice(0, -1).map((st, i) => {
                const isPassed = i < currentStageIdx
                const isCurrent = i === currentStageIdx
                return (
                  <div
                    key={st}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      padding: '8px 12px',
                      borderRadius: '5px',
                      background: isCurrent ? 'var(--button-secondary-bg)' : 'transparent',
                      border: isCurrent ? '1px solid var(--accent)' : '1px solid transparent',
                      opacity: isPassed || isCurrent ? 1 : 0.4,
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span
                        style={{
                          width: '18px',
                          height: '18px',
                          borderRadius: '50%',
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          fontSize: '10px',
                          fontFamily: 'var(--mono)',
                          fontWeight: 700,
                          background: isPassed ? 'var(--accent)' : isCurrent ? 'var(--button-primary-bg)' : 'var(--border)',
                          color: isPassed ? '#fff' : isCurrent ? 'var(--accent)' : 'var(--text-muted)',
                        }}
                      >
                        {isPassed ? '✓' : i + 1}
                      </span>
                      <span style={{ fontSize: '12.5px', color: isCurrent ? 'var(--text-primary)' : 'var(--text-secondary)', fontWeight: isCurrent ? 600 : 400 }}>
                        {STAGE_DESCRIPTIONS[st] || st}
                      </span>
                    </div>

                    <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                      {st}
                    </span>
                  </div>
                )
              })}
            </div>

            {/* Processing Statistics */}
            {job?.processing_statistics && (
              <div style={{ display: 'flex', gap: '16px', borderTop: '1px solid var(--border)', paddingTop: '14px', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                {job.processing_statistics.packets_processed !== undefined && (
                  <span>Packets: {job.processing_statistics.packets_processed.toLocaleString()}</span>
                )}
                {job.processing_statistics.flows_processed !== undefined && (
                  <span>Flows: {job.processing_statistics.flows_processed.toLocaleString()}</span>
                )}
                {job.processing_statistics.windows_processed !== undefined && (
                  <span>Windows: {job.processing_statistics.windows_processed}</span>
                )}
              </div>
            )}
          </div>
        </Panel>
      </div>
    )
  }

  // CASE 2: Error in Job Polling or Failed Job
  if (jobId && jobError) {
    return (
      <div className="page-stack page-enter" style={{ maxWidth: '680px', margin: '40px auto', width: '100%' }}>
        <Panel style={{ border: '1px solid var(--danger)' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', padding: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--danger)' }}>
              <AlertCircle size={24} />
              <h2 style={{ margin: 0, fontSize: '18px', color: 'var(--text-primary)' }}>
                Analysis Job Failed
              </h2>
            </div>

            <p style={{ margin: 0, fontSize: '13.5px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
              {jobError}
            </p>

            <div style={{ display: 'flex', gap: '10px', marginTop: '8px' }}>
              <button
                type="button"
                className="button"
                onClick={() => navigate('/console/analyze')}
              >
                <FileUp size={14} /> Analyze Another Capture
              </button>
              <button
                type="button"
                className="button button-quiet"
                onClick={reloadJob}
              >
                <RotateCcw size={14} /> Retry Query
              </button>
            </div>
          </div>
        </Panel>
      </div>
    )
  }

  // CASE 3: Loading Active Analysis from store
  if (!jobId && storeLoading && !activeAnalysis) {
    return <LoadingState message="Syncing canonical forecast models..." />
  }

  // CASE 4: Store Error
  if (!jobId && storeError && !activeAnalysis) {
    return (
      <ErrorState
        message={storeError}
        onRetry={() => void reloadStore()}
      />
    )
  }

  // CASE 5: Render completed canonical forecast console!
  if (activeAnalysis) {
    return (
      <ForecastConsole
        analysis={activeAnalysis}
        onAnalyzeNew={() => navigate('/console/analyze')}
      />
    )
  }

  return (
    <div className="page-stack page-enter" style={{ maxWidth: '640px', margin: '40px auto', textAlign: 'center' }}>
      <Panel>
        <div style={{ padding: '24px' }}>
          <h2 style={{ margin: '0 0 8px 0', fontSize: '18px', color: 'var(--text-primary)' }}>
            No Analysis Selected
          </h2>
          <p style={{ margin: '0 0 18px 0', fontSize: '13.5px', color: 'var(--text-secondary)' }}>
            Upload a network capture to run forecasting, or inspect a deterministic SIH demo scenario.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '12px' }}>
            <Link to="/console/analyze" className="button">
              <FileUp size={14} /> Analyze PCAP
            </Link>
            <Link to="/console/demo" className="button button-quiet">
              <Sparkles size={14} /> Open SIH Demo
            </Link>
          </div>
        </div>
      </Panel>
    </div>
  )
}
