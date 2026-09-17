import { useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  AlertTriangle,
  FileUp,
  Radio,
  Sparkles,
} from 'lucide-react'
import { ForecastConsole } from '../components/ForecastConsole'
import { AnalysisPipelineVisualizer } from '../components/AnalysisPipelineVisualizer'
import { Panel } from '../components/Ui'
import { useJobPolling } from '../hooks/useJobPolling'
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
    progress,
    status: jobStatus,
    error: jobError,
    isPolling,
    isReconnecting,
    reconnectAttempt,
    isComplete,
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

  // CASE 1: Polling an active job that is still processing or completing
  if (jobId && (isPolling || (job && jobStatus !== 'COMPLETED' && !jobError) || (!activeAnalysis && !jobError))) {
    return (
      <AnalysisPipelineVisualizer
        jobId={jobId}
        stage={stage}
        progress={job ? job.progress : progress / 100}
        job={job}
        isReconnecting={isReconnecting}
        reconnectAttempt={reconnectAttempt}
        isComplete={isComplete}
        onCancel={() => navigate('/console/analyze')}
      />
    )
  }

  // CASE 2: Error in Job Polling or Failed Job
  if (jobId && jobError) {
    return (
      <div className="page-stack page-enter" style={{ maxWidth: '640px', margin: '60px auto', textAlign: 'center' }}>
        <Panel>
          <div style={{ padding: '32px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <AlertTriangle size={20} color="var(--text-primary)" />
            </div>
            <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              Analysis could not be completed.
            </h2>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-muted)', maxWidth: '440px', lineHeight: 1.5 }}>
              {jobError || 'The packet capture could not be processed into continuous temporal states.'}
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', flexWrap: 'wrap', gap: '10px', marginTop: '8px' }}>
              <button
                type="button"
                className="button button-primary"
                onClick={reloadJob}
                style={{ fontSize: '12px' }}
              >
                Retry Analysis
              </button>
              <button
                type="button"
                className="button button-quiet"
                onClick={() => navigate('/console/analyze')}
                style={{ fontSize: '12px' }}
              >
                Choose Another File
              </button>
              <button
                type="button"
                className="button button-quiet"
                onClick={() => navigate('/console/analyze')}
                style={{ fontSize: '12px' }}
              >
                Return to Console
              </button>
            </div>

            {/* Collapsible Technical Diagnostics */}
            <details
              style={{
                marginTop: '16px',
                textAlign: 'left',
                width: '100%',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '10px 14px',
                fontSize: '11px',
                fontFamily: 'var(--mono)',
              }}
            >
              <summary style={{ cursor: 'pointer', color: 'var(--text-muted)', fontWeight: 600 }}>
                Technical Diagnostics
              </summary>
              <div style={{ marginTop: '8px', display: 'flex', flexDirection: 'column', gap: '4px', color: 'var(--text-secondary)' }}>
                <div><strong>Job ID:</strong> {jobId}</div>
                <div><strong>Timestamp:</strong> {new Date().toISOString()}</div>
                <div><strong>Error Details:</strong> {jobError}</div>
              </div>
            </details>
          </div>
        </Panel>
      </div>
    )
  }

  // CASE 3: Loading Active Analysis from store
  if (!jobId && storeLoading && !activeAnalysis) {
    return (
      <div className="page-stack page-enter" style={{ width: '100%', padding: '24px 0' }}>
        <div style={{ marginBottom: '24px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '4px 10px', borderRadius: '4px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', marginBottom: '12px' }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--text-primary)', display: 'inline-block' }} />
            LOADING FORECAST
          </div>
          <div style={{ height: '24px', width: '280px', background: 'var(--bg-secondary)', borderRadius: '4px', marginBottom: '8px' }} />
          <div style={{ height: '14px', width: '420px', background: 'var(--bg-secondary)', borderRadius: '4px' }} />
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px', marginBottom: '20px' }}>
          {[1, 2, 3, 4].map(i => (
            <div key={i} style={{ height: '100px', background: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border)' }} />
          ))}
        </div>
        <div style={{ height: '340px', background: 'var(--bg-secondary)', borderRadius: '6px', border: '1px solid var(--border)' }} />
      </div>
    )
  }

  // CASE 4: Store Error
  if (!jobId && storeError && !activeAnalysis) {
    return (
      <div className="page-stack page-enter" style={{ maxWidth: '640px', margin: '60px auto', textAlign: 'center' }}>
        <Panel>
          <div style={{ padding: '32px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
            <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <AlertTriangle size={20} color="var(--text-primary)" />
            </div>
            <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
              FORECAST COULD NOT BE LOADED
            </h2>
            <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-muted)', maxWidth: '420px' }}>
              {storeError || 'Try again or return to the analysis.'}
            </p>
            <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '8px' }}>
              <button
                type="button"
                className="button button-primary"
                onClick={() => void reloadStore()}
                style={{ fontSize: '12px' }}
              >
                TRY AGAIN
              </button>
              <button
                type="button"
                className="button button-quiet"
                onClick={() => navigate('/console/analyze')}
                style={{ fontSize: '12px' }}
              >
                BACK TO ANALYZE
              </button>
            </div>
          </div>
        </Panel>
      </div>
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
    <div className="page-stack page-enter" style={{ maxWidth: '640px', margin: '60px auto', textAlign: 'center' }}>
      <Panel>
        <div style={{ padding: '32px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '40px', height: '40px', borderRadius: '50%', background: 'var(--bg-secondary)', border: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <Radio size={20} color="var(--text-muted)" />
          </div>
          <h2 style={{ margin: 0, fontSize: '18px', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            NO ANALYSIS SELECTED
          </h2>
          <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-muted)', maxWidth: '420px' }}>
            Run an analysis or open a demonstration scenario.
          </p>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '10px', marginTop: '8px' }}>
            <button
              type="button"
              className="button button-primary"
              onClick={() => navigate('/console/analyze')}
              style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <FileUp size={14} /> NEW ANALYSIS
            </button>
            <button
              type="button"
              className="button button-quiet"
              onClick={() => navigate('/console/demo')}
              style={{ fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}
            >
              <Sparkles size={14} /> SAMPLE SCENARIOS
            </button>
          </div>
        </div>
      </Panel>
    </div>
  )
}
