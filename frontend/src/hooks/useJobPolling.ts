import { useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../services/api'
import { setUploadedAnalysis } from '../stores/productionStore'
import type { JobStageType, JobStatusResponse, JobStatusType } from '../types/api'
import type { CanonicalAnalysis } from '../types/canonical'
import { adaptToCanonical } from '../utils/canonicalAdapter'

export const STAGE_DESCRIPTIONS: Record<string, string> = {
  INGESTION: 'Reading the captured network telemetry.',
  PARSING: 'Decoding packet headers and protocol metadata.',
  FLOW_RECONSTRUCTION: 'Reconstructing bidirectional network conversations.',
  WINDOWING: 'Segmenting behavior into temporal network states.',
  NETWORK_STATE: 'Assembling the canonical feature representation.',
  FORECAST: 'Simulating future network states.',
  EVIDENCE: 'Evaluating forecast drivers and supporting evidence.',
  REPORT: 'Compiling the analysis record.',
  COMPLETE: 'Analysis complete. Forecast ready.',
}

export interface UseJobPollingReturn {
  job: JobStatusResponse | null
  result: CanonicalAnalysis | null
  stage: JobStageType | string
  stageDescription: string
  progress: number
  status: JobStatusType | 'IDLE'
  error: string | null
  errorCode: string | null
  isPolling: boolean
  isReconnecting: boolean
  reconnectAttempt: number
  isComplete: boolean
  reload: () => void
}

function translateJobError(status: JobStatusType, rawMessage: string): { code: string; message: string } {
  const lower = rawMessage.toLowerCase()

  if (
    lower.includes('history') ||
    lower.includes('window') ||
    lower.includes('insufficient') ||
    lower.includes('lookback') ||
    lower.includes('continuous')
  ) {
    return {
      code: 'INSUFFICIENT_HISTORY',
      message: 'Not enough continuous temporal history was available to produce a reliable forecast.',
    }
  }

  if (
    lower.includes('magic') ||
    lower.includes('pcap') ||
    lower.includes('encapsulation') ||
    lower.includes('unsupported') ||
    lower.includes('format')
  ) {
    return {
      code: 'UNSUPPORTED_TELEMETRY',
      message: 'This capture does not contain the telemetry required for this analysis.',
    }
  }

  if (
    lower.includes('feature') ||
    lower.includes('schema') ||
    lower.includes('contract') ||
    lower.includes('vector') ||
    lower.includes('compatibility')
  ) {
    return {
      code: 'FEATURE_COMPATIBILITY',
      message: 'The capture could not be represented using the supported network-state schema.',
    }
  }

  if (
    status === 'RESOURCE_LIMIT_EXCEEDED' ||
    lower.includes('limit') ||
    lower.includes('exceed') ||
    lower.includes('too large') ||
    lower.includes('packet limit')
  ) {
    return {
      code: 'RESOURCE_LIMIT',
      message: 'The capture exceeds the safe processing limits for this analysis.',
    }
  }

  return {
    code: 'ANALYSIS_INCOMPLETE',
    message: rawMessage || 'The analysis could not be completed.',
  }
}

export function useJobPolling(jobId: string | undefined): UseJobPollingReturn {
  const [job, setJob] = useState<JobStatusResponse | null>(null)
  const [result, setResult] = useState<CanonicalAnalysis | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [errorCode, setErrorCode] = useState<string | null>(null)
  const [isPolling, setIsPolling] = useState<boolean>(false)
  const [isReconnecting, setIsReconnecting] = useState<boolean>(false)
  const [reconnectAttempt, setReconnectAttempt] = useState<number>(0)
  const [isComplete, setIsComplete] = useState<boolean>(false)

  const retryCountRef = useRef<number>(0)
  const notFoundCountRef = useRef<number>(0)
  const activeJobIdRef = useRef<string | undefined>(jobId)

  activeJobIdRef.current = jobId

  const fetchResult = async (id: string): Promise<CanonicalAnalysis | null> => {
    try {
      const res = await api.getJobResult(id)
      const canonical = adaptToCanonical(res, id)
      setResult(canonical)
      await setUploadedAnalysis(res)
      return canonical
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 404) {
        setErrorCode('RESULT_UNAVAILABLE')
        setError('The analysis result could not be retrieved.')
      } else {
        setErrorCode('TEMPORARILY_UNAVAILABLE')
        setError('The analysis service is temporarily unreachable while retrieving results.')
      }
      return null
    }
  }

  useEffect(() => {
    if (!jobId) {
      setJob(null)
      setResult(null)
      setError(null)
      setErrorCode(null)
      setIsPolling(false)
      setIsReconnecting(false)
      setReconnectAttempt(0)
      setIsComplete(false)
      return
    }

    let isMounted = true
    let timer: ReturnType<typeof setTimeout> | null = null
    const abortController = new AbortController()

    setIsPolling(true)
    setIsComplete(false)
    setError(null)
    setErrorCode(null)
    setIsReconnecting(false)
    setReconnectAttempt(0)
    retryCountRef.current = 0
    notFoundCountRef.current = 0

    const poll = async () => {
      if (!isMounted) return

      try {
        const curJob = await api.getJobStatus(jobId)
        if (!isMounted) return

        setJob(curJob)
        retryCountRef.current = 0
        notFoundCountRef.current = 0
        setIsReconnecting(false)
        setReconnectAttempt(0)

        // Case 1: Job has finished processing
        if (curJob.status === 'COMPLETED') {
          setIsComplete(true)
          try {
            const fetched = await fetchResult(jobId)
            if (!isMounted) return
            if (fetched) {
              await new Promise((resolve) => setTimeout(resolve, 600))
            }
          } finally {
            if (isMounted) {
              setIsPolling(false)
            }
          }
          return
        }

        // Case 2: Job encountered a terminal failure reported by the backend
        if (curJob.status === 'FAILED' || curJob.status === 'RESOURCE_LIMIT_EXCEEDED' || curJob.status === 'ABORTED') {
          if (isMounted) {
            setIsPolling(false)
            const rawMsg = curJob.error?.explanation || curJob.error?.message || ''
            const translated = translateJobError(curJob.status, rawMsg)
            setErrorCode(translated.code)
            setError(translated.message)
          }
          return
        }

        // Case 3: Still actively processing
        timer = setTimeout(poll, 700)
      } catch (err: unknown) {
        if (!isMounted) return

        // First attempt: check if result is already ready despite status route failure
        try {
          const directRes = await api.getJobResult(jobId)
          if (!isMounted) return
          const canonical = adaptToCanonical(directRes, jobId)
          setResult(canonical)
          await setUploadedAnalysis(directRes)
          setIsComplete(true)
          setIsPolling(false)
          return
        } catch {
          // Continue to bounded retry
        }

        // Handle 404 (job deleted or non-existent)
        if (err instanceof ApiError && err.status === 404) {
          notFoundCountRef.current += 1
          if (notFoundCountRef.current >= 2) {
            if (isMounted) {
              setIsPolling(false)
              setErrorCode('ANALYSIS_NOT_FOUND')
              setError('The requested analysis could not be located.')
            }
            return
          }
        }

        // Temporary communication interruption (bounded retry with backoff up to 10 attempts)
        retryCountRef.current += 1
        const attempts = retryCountRef.current
        setReconnectAttempt(attempts)

        if (attempts <= 10) {
          setIsReconnecting(true)
          const delay = Math.min(2500, 600 + attempts * 200)
          timer = setTimeout(poll, delay)
        } else {
          // Bounded timeout after 10 continuous failed attempts
          if (isMounted) {
            setIsPolling(false)
            setIsReconnecting(false)
            setErrorCode('TEMPORARILY_UNAVAILABLE')
            setError('The analysis service is temporarily unreachable. Please try again.')
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

  const stage = job?.stage || (isComplete ? 'COMPLETE' : 'INGESTION')
  const stageDescription = STAGE_DESCRIPTIONS[stage] || 'Processing network telemetry...'
  const progress = job ? Math.round(job.progress * 100) : isComplete ? 100 : 10
  const status: JobStatusType | 'IDLE' = isComplete
    ? 'COMPLETED'
    : job?.status || (result ? 'COMPLETED' : 'IDLE')

  return {
    job,
    result,
    stage,
    stageDescription,
    progress,
    status,
    error,
    errorCode,
    isPolling,
    isReconnecting,
    reconnectAttempt,
    isComplete,
    reload: () => {
      if (jobId) {
        setResult(null)
        setError(null)
        setErrorCode(null)
        setIsPolling(true)
        void fetchResult(jobId)
      }
    },
  }
}
