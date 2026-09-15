import { useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../services/api'
import { setUploadedAnalysis } from '../stores/productionStore'
import type { JobStageType, JobStatusResponse, JobStatusType } from '../types/api'
import type { CanonicalAnalysis } from '../types/canonical'
import { adaptToCanonical } from '../utils/canonicalAdapter'

export const STAGE_DESCRIPTIONS: Record<string, string> = {
  INGESTION: 'Ingesting and validating telemetry capture...',
  PARSING: 'Parsing protocol headers and packet streams...',
  FLOW_RECONSTRUCTION: 'Reconstructing bidirectional 5-tuple conversations...',
  WINDOWING: 'Partitioning discrete 60-second temporal windows...',
  NETWORK_STATE: 'Assembling 45-feature canonical network state vector...',
  FORECAST: 'Executing multi-step world model rollouts (T+1 .. T+5)...',
  EVIDENCE: 'Calculating counterfactual perturbation & evidence chain...',
  REPORT: 'Generating forensic analysis intelligence report...',
  COMPLETE: 'Analysis and forecasting complete.',
}

export interface UseJobPollingReturn {
  job: JobStatusResponse | null
  result: CanonicalAnalysis | null
  stage: JobStageType | string
  stageDescription: string
  progress: number
  status: JobStatusType | 'IDLE'
  error: string | null
  isPolling: boolean
  reload: () => void
}

export function useJobPolling(jobId: string | undefined): UseJobPollingReturn {
  const [job, setJob] = useState<JobStatusResponse | null>(null)
  const [result, setResult] = useState<CanonicalAnalysis | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isPolling, setIsPolling] = useState<boolean>(false)
  const retryCountRef = useRef<number>(0)
  const activeJobIdRef = useRef<string | undefined>(jobId)

  activeJobIdRef.current = jobId

  const fetchResult = async (id: string) => {
    try {
      const res = await api.getJobResult(id)
      const canonical = adaptToCanonical(res, id)
      setResult(canonical)
      await setUploadedAnalysis(res)
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setError(err.message)
      } else {
        setError('Failed to retrieve completed analysis result.')
      }
    }
  }

  useEffect(() => {
    if (!jobId) {
      setJob(null)
      setResult(null)
      setError(null)
      setIsPolling(false)
      return
    }

    let isMounted = true
    let timer: ReturnType<typeof setTimeout> | null = null
    const abortController = new AbortController()

    setIsPolling(true)
    setError(null)
    retryCountRef.current = 0

    const poll = async () => {
      if (!isMounted) return

      try {
        const curJob = await api.getJobStatus(jobId)
        if (!isMounted) return

        setJob(curJob)
        retryCountRef.current = 0

        if (curJob.status === 'COMPLETED') {
          setIsPolling(false)
          await fetchResult(jobId)
          return
        }

        if (curJob.status === 'FAILED' || curJob.status === 'RESOURCE_LIMIT_EXCEEDED') {
          setIsPolling(false)
          const errDetail = curJob.error?.explanation || curJob.error?.message || 'Processing job encountered a terminal failure.'
          setError(errDetail)
          return
        }

        // Continue polling if still active
        timer = setTimeout(poll, 600)
      } catch (err: unknown) {
        if (!isMounted) return

        // Check if job was already completed or if result endpoint works directly
        try {
          const directRes = await api.getJobResult(jobId)
          if (!isMounted) return
          const canonical = adaptToCanonical(directRes, jobId)
          setResult(canonical)
          setIsPolling(false)
          return
        } catch {
          // Fall through to retry logic
        }

        retryCountRef.current += 1
        if (retryCountRef.current <= 3) {
          timer = setTimeout(poll, 1000)
        } else {
          setIsPolling(false)
          if (err instanceof ApiError && err.status === 404) {
            setError('Analysis result is no longer available or was not found.')
          } else if (err instanceof ApiError) {
            setError(err.message)
          } else {
            setError('Unable to reach backend service while monitoring job.')
          }
        }
      }
    }

    void poll()

    return () => {
      isMounted = false
      if (timer) clearTimeout(timer)
      abortController.abort()
    }
  }, [jobId])

  const stage = job?.stage || 'INGESTION'
  const stageDescription = STAGE_DESCRIPTIONS[stage] || 'Processing capture...'
  const progress = job ? Math.round(job.progress * 100) : 0
  const status: JobStatusType | 'IDLE' = job?.status || (result ? 'COMPLETED' : 'IDLE')

  return {
    job,
    result,
    stage,
    stageDescription,
    progress,
    status,
    error,
    isPolling,
    reload: () => {
      if (jobId) {
        setResult(null)
        setError(null)
        void fetchResult(jobId)
      }
    },
  }
}
