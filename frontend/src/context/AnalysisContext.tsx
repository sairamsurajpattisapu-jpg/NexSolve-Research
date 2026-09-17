import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import { api, ApiError } from '../services/api'
import {
  clearUploadedAnalysis,
  getSnapshot,
  refreshProductionData,
  setUploadedAnalysis,
  subscribe,
  ANALYSIS_ID,
} from '../stores/productionStore'
import type {
  AnalysisData,
  AnalysisProvenance,
  JobStageType,
  JobStatusResponse,
  ReportResponse,
  UploadedAnalysisResponse,
} from '../types/api'
import type { CanonicalAnalysis } from '../types/canonical'
import { adaptToCanonical } from '../utils/canonicalAdapter'

const STORAGE_ACTIVE_ID = 'nexsolve-current-analysis-id'
const STORAGE_CANONICAL_CACHE = 'nexsolve-cached-canonical'

export type AnalysisStatusState = 'IDLE' | 'PROCESSING' | 'COMPLETED' | 'FAILED'
export type GlobalAppStatus = 'READY' | 'PROCESSING' | 'OFFLINE'

export interface AnalysisContextValue {
  // Authoritative Analysis Metadata
  jobId: string | null
  filename: string
  analysisStatus: AnalysisStatusState
  analysisTimestamp: string | null
  resultAvailability: boolean
  forecastAvailability: boolean
  evidenceAvailability: boolean
  reportAvailability: boolean
  isDemo: boolean
  provenance: AnalysisProvenance

  // Authoritative Payloads
  canonical: CanonicalAnalysis | null
  rawResults: UploadedAnalysisResponse | AnalysisData['results'] | null
  report: ReportResponse | null
  apiConnected: boolean

  // Job Processing State
  activeJob: JobStatusResponse | null
  jobStage: JobStageType | string
  jobProgress: number
  jobError: string | null
  isSubmitting: boolean

  // Global Navigation Status
  globalStatus: GlobalAppStatus

  // Workflow Actions
  startAnalysisJob: (file: File) => Promise<string>
  loadJob: (jobId: string) => Promise<CanonicalAnalysis | null>
  resetWorkflow: () => Promise<void>
  setDirectAnalysis: (payload: UploadedAnalysisResponse) => Promise<void>
}

const AnalysisContext = createContext<AnalysisContextValue | null>(null)

export function AnalysisProvider({ children }: { children: ReactNode }) {
  // Synchronize with external production store
  const [storeState, setStoreState] = useState(getSnapshot)
  useEffect(() => {
    const unsub = subscribe(() => setStoreState(getSnapshot()))
    return () => {
      unsub()
    }
  }, [])

  // Local Authoritative State
  const [canonical, setCanonical] = useState<CanonicalAnalysis | null>(() => {
    try {
      const cached = sessionStorage.getItem(STORAGE_CANONICAL_CACHE) || localStorage.getItem(STORAGE_CANONICAL_CACHE)
      if (cached) {
        return JSON.parse(cached) as CanonicalAnalysis
      }
    } catch {
      // Ignore parse errors
    }
    return null
  })

  const [activeJobId, setActiveJobId] = useState<string | null>(() => {
    try {
      const id = sessionStorage.getItem(STORAGE_ACTIVE_ID) || localStorage.getItem(STORAGE_ACTIVE_ID)
      return id && id !== ANALYSIS_ID && !id.startsWith('demo-') ? id : null
    } catch {
      return null
    }
  })

  const [activeJob, setActiveJob] = useState<JobStatusResponse | null>(null)
  const [jobStage, setJobStage] = useState<JobStageType | string>('INGESTION')
  const [jobProgress, setJobProgress] = useState<number>(0)
  const [jobError, setJobError] = useState<string | null>(null)
  const [analysisStatus, setAnalysisStatus] = useState<AnalysisStatusState>('IDLE')
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false)

  // Polling Refs to guarantee single instance and clean teardown
  const pollingAbortRef = useRef<AbortController | null>(null)
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const activeJobIdRef = useRef<string | null>(activeJobId)
  activeJobIdRef.current = activeJobId

  // Synchronize Canonical whenever store produces results
  useEffect(() => {
    if (storeState.data?.results && !canonical) {
      const adapted = adaptToCanonical(storeState.data.results, storeState.data.results.analysis_id)
      setCanonical(adapted)
      try {
        sessionStorage.setItem(STORAGE_CANONICAL_CACHE, JSON.stringify(adapted))
      } catch {
        // Storage quota safe
      }
    }
  }, [storeState.data, canonical])

  // Save canonical to storage whenever updated
  const updateCanonical = useCallback((item: CanonicalAnalysis | null) => {
    setCanonical(item)
    if (item) {
      try {
        sessionStorage.setItem(STORAGE_CANONICAL_CACHE, JSON.stringify(item))
        localStorage.setItem(STORAGE_CANONICAL_CACHE, JSON.stringify(item))
      } catch {
        // Ignore quota
      }
    } else {
      sessionStorage.removeItem(STORAGE_CANONICAL_CACHE)
      localStorage.removeItem(STORAGE_CANONICAL_CACHE)
    }
  }, [])

  // Stop polling helper
  const stopPolling = useCallback(() => {
    if (pollTimerRef.current) {
      clearTimeout(pollTimerRef.current)
      pollTimerRef.current = null
    }
    if (pollingAbortRef.current) {
      pollingAbortRef.current.abort()
      pollingAbortRef.current = null
    }
  }, [])

  // Prefetch result upon job completion to avoid blank screen
  const prefetchJobResult = useCallback(async (jobId: string): Promise<CanonicalAnalysis> => {
    setJobStage('COMPLETE')
    setJobProgress(1.0)
    try {
      const res = await api.getJobResult(jobId)
      const adapted = adaptToCanonical(res, jobId)
      updateCanonical(adapted)
      await setUploadedAnalysis(res)
      setAnalysisStatus('COMPLETED')
      return adapted
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Unable to retrieve completed analysis result.'
      setJobError(msg)
      setAnalysisStatus('FAILED')
      throw err
    }
  }, [updateCanonical])

  // Single authoritative polling loop with backoff
  const startJobPolling = useCallback((jobId: string) => {
    stopPolling()

    const abortController = new AbortController()
    pollingAbortRef.current = abortController
    setActiveJobId(jobId)
    setAnalysisStatus('PROCESSING')
    setJobError(null)

    let retryBackoff = 600
    let failureCount = 0

    const poll = async () => {
      if (abortController.signal.aborted) return

      try {
        const curJob = await api.getJobStatus(jobId)
        if (abortController.signal.aborted) return

        setActiveJob(curJob)
        setJobStage(curJob.stage)
        setJobProgress(curJob.progress)
        failureCount = 0
        retryBackoff = 600

        if (curJob.status === 'COMPLETED') {
          // Pre-fetch result BEFORE dropping out of processing
          try {
            await prefetchJobResult(jobId)
          } catch {
            // Error handled in prefetch
          }
          return
        }

        if (curJob.status === 'FAILED' || curJob.status === 'RESOURCE_LIMIT_EXCEEDED') {
          setAnalysisStatus('FAILED')
          const errDetail =
            curJob.error?.explanation ||
            curJob.error?.message ||
            'Analysis encountered a terminal failure during processing.'
          setJobError(errDetail)
          return
        }

        // Active: schedule next poll
        pollTimerRef.current = setTimeout(poll, retryBackoff)
      } catch (err: unknown) {
        if (abortController.signal.aborted) return

        // Try direct result endpoint if status check fails (some backends transition instantly)
        try {
          const directRes = await api.getJobResult(jobId)
          if (abortController.signal.aborted) return
          const adapted = adaptToCanonical(directRes, jobId)
          updateCanonical(adapted)
          await setUploadedAnalysis(directRes)
          setAnalysisStatus('COMPLETED')
          return
        } catch {
          // Fall through to exponential retry
        }

        failureCount += 1
        if (failureCount <= 4) {
          retryBackoff = Math.min(2500, retryBackoff * 1.5)
          pollTimerRef.current = setTimeout(poll, retryBackoff)
        } else {
          setAnalysisStatus('FAILED')
          if (err instanceof ApiError && err.status === 404) {
            setJobError('Analysis job was not found or has expired.')
          } else {
            setJobError('Service unreachable while monitoring analysis progress.')
          }
        }
      }
    }

    void poll()
  }, [prefetchJobResult, stopPolling, updateCanonical])

  // Load a job result directly (used on route refresh or direct navigation to /forecast/:jobId)
  const loadJob = useCallback(async (jobId: string): Promise<CanonicalAnalysis | null> => {
    // If we already have this canonical loaded, return it instantly
    if (canonical && canonical.id === jobId) {
      return canonical
    }

    try {
      // First check status to see if it's still running
      const jobStatus = await api.getJobStatus(jobId)
      if (jobStatus.status === 'QUEUED' || jobStatus.status === 'PROCESSING') {
        startJobPolling(jobId)
        return null
      }
    } catch {
      // If getJobStatus fails, fall through to direct getJobResult
    }

    try {
      const res = await api.getJobResult(jobId)
      const adapted = adaptToCanonical(res, jobId)
      updateCanonical(adapted)
      await setUploadedAnalysis(res)
      setActiveJobId(jobId)
      setAnalysisStatus('COMPLETED')
      return adapted
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setJobError('Analysis result unavailable or not found.')
      } else {
        setJobError('Failed to recover analysis result.')
      }
      setAnalysisStatus('FAILED')
      return null
    }
  }, [canonical, startJobPolling, updateCanonical])

  // Submit capture and create job with double-click guard
  const startAnalysisJob = useCallback(async (file: File): Promise<string> => {
    if (isSubmitting) {
      throw new Error('Analysis request already in progress.')
    }

    setIsSubmitting(true)
    setJobError(null)
    setAnalysisStatus('PROCESSING')
    setJobStage('INGESTION')
    setJobProgress(0.1)

    try {
      const job = await api.createJob(file)
      setActiveJob(job)
      setActiveJobId(job.job_id)

      try {
        sessionStorage.setItem(STORAGE_ACTIVE_ID, job.job_id)
        localStorage.setItem(STORAGE_ACTIVE_ID, job.job_id)
      } catch {
        // Quota safe
      }

      startJobPolling(job.job_id)
      return job.job_id
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'Unable to create analysis job.'
      setJobError(msg)
      setAnalysisStatus('FAILED')
      throw err
    } finally {
      setIsSubmitting(false)
    }
  }, [isSubmitting, startJobPolling])

  // Clean reset workflow (+ New Analysis)
  const resetWorkflow = useCallback(async () => {
    stopPolling()
    setActiveJobId(null)
    setActiveJob(null)
    setJobStage('INGESTION')
    setJobProgress(0)
    setJobError(null)
    setAnalysisStatus('IDLE')
    setIsSubmitting(false)
    updateCanonical(null)

    sessionStorage.removeItem(STORAGE_ACTIVE_ID)
    localStorage.removeItem(STORAGE_ACTIVE_ID)
    sessionStorage.removeItem(STORAGE_CANONICAL_CACHE)
    localStorage.removeItem(STORAGE_CANONICAL_CACHE)

    await clearUploadedAnalysis()
    await refreshProductionData()
  }, [stopPolling, updateCanonical])



  // Direct set analysis (e.g. from fixtures or test mocks)
  const setDirectAnalysis = useCallback(async (payload: UploadedAnalysisResponse) => {
    await setUploadedAnalysis(payload)
    const adapted = adaptToCanonical(payload, payload.analysis_id)
    updateCanonical(adapted)
    setAnalysisStatus('COMPLETED')
  }, [updateCanonical])

  // Cleanup on provider unmount
  useEffect(() => {
    return () => {
      stopPolling()
    }
  }, [stopPolling])

  // Compute Authoritative Metadata
  const isDemo = false
  const rawResults = storeState.data?.results ?? null
  const report = storeState.data?.report ?? null
  const filename = canonical?.input.filename || rawResults?.source?.filename || rawResults?.source?.name || 'capture.pcap'
  const analysisTimestamp = canonical?.createdAt || canonical?.currentState?.timestamp || null
  const resultAvailability = Boolean(canonical || rawResults)
  const forecastAvailability = Boolean(canonical?.forecast?.points?.length || rawResults?.forecasts?.length)
  const evidenceAvailability = Boolean(canonical?.evidence?.chain || rawResults?.evidence_chain)
  const reportAvailability = Boolean(report)

  // Compute Global Application Status (READY | PROCESSING | OFFLINE)
  let globalStatus: GlobalAppStatus = 'READY'
  if (analysisStatus === 'PROCESSING') {
    globalStatus = 'PROCESSING'
  } else if (!storeState.apiConnected || storeState.error) {
    globalStatus = 'OFFLINE'
  } else {
    globalStatus = 'READY'
  }

  const value: AnalysisContextValue = {
    jobId: activeJobId,
    filename,
    analysisStatus,
    analysisTimestamp,
    resultAvailability,
    forecastAvailability,
    evidenceAvailability,
    reportAvailability,
    isDemo,
    provenance: storeState.provenance,
    canonical,
    rawResults,
    report,
    apiConnected: storeState.apiConnected,
    activeJob,
    jobStage,
    jobProgress,
    jobError,
    isSubmitting,
    globalStatus,
    startAnalysisJob,
    loadJob,
    resetWorkflow,
    setDirectAnalysis,
  }

  return <AnalysisContext.Provider value={value}>{children}</AnalysisContext.Provider>
}

export function useAnalysis(): AnalysisContextValue {
  const context = useContext(AnalysisContext)
  if (!context) {
    throw new Error('useAnalysis must be used within an AnalysisProvider')
  }
  return context
}
