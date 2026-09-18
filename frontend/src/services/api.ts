import type {
  AnalysisResults,
  AnalysisStatus,
  Finding,
  HealthResponse,
  ReportResponse,
  TrafficSummary,
  UploadedAnalysisResponse,
  JobStatusResponse,
} from '../types/api'

import { CHUNK_SIZE_BYTES, MAX_PCAP_UPLOAD_BYTES, MAX_PCAP_UPLOAD_LABEL } from '../config/constants'

const API_BASE = (import.meta.env.VITE_API_BASE_URL ?? '').replace(/\/$/, '')

export class ApiError extends Error {
  status: number

  constructor(message: string, status = 0) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  // Allow longer timeout for large payloads / uploads
  const isUpload = Boolean(init?.body && (init.body instanceof FormData || typeof init.body === 'string'))
  const timeoutMs = isUpload ? 180000 : 45000
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    let signal = controller.signal
    if (init?.signal) {
      if ('any' in AbortSignal && typeof AbortSignal.any === 'function') {
        signal = AbortSignal.any([init.signal, controller.signal])
      } else {
        init.signal.addEventListener('abort', () => controller.abort(), { once: true })
      }
    }

    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      signal,
      headers: { Accept: 'application/json', ...(init?.headers ?? {}) },
    })
  } catch (err: unknown) {
    clearTimeout(timer)
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new ApiError('Request timed out. Please retry when ready.', 408)
    }
    if (!API_BASE && typeof window !== 'undefined' && window.location.hostname.endsWith('.vercel.app')) {
      throw new ApiError('Service endpoint unconfigured. Please configure VITE_API_BASE_URL.', 0)
    }
    throw new ApiError('Service temporarily unavailable. Please retry when ready.', 0)
  } finally {
    clearTimeout(timer)
  }

  const contentType = response.headers.get('content-type') ?? ''
  if (contentType.includes('text/html')) {
    if (!API_BASE && typeof window !== 'undefined' && window.location.hostname.endsWith('.vercel.app')) {
      throw new ApiError('Service endpoint returned an invalid response. Please verify configuration.', response.status)
    }
    throw new ApiError('The service endpoint returned an unexpected response.', response.status)
  }

  if (!response.ok) {
    let detail = `Request failed with status ${response.status}.`
    try {
      const body = await response.json() as { detail?: string; error?: { message?: string } }
      detail = body.detail ?? body.error?.message ?? detail
    } catch {
      // Keep the status-based message when the server did not return JSON.
    }
    throw new ApiError(detail, response.status)
  }
  try {
    return await response.json() as T
  } catch {
    throw new ApiError('The analysis service returned an invalid response.', response.status)
  }
}

export const api = {
  health: () => request<HealthResponse>('/health'),
  ready: () => request<{ status: string; service: string; database: { status: string; mode: string; detail: string } }>('/ready'),
  startAnalysis: () => request<{ analysis_id: string; status: string }>('/api/analysis', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ source: 'production' }),
  }),
  status: (id: string) => request<AnalysisStatus>(`/api/analysis/${id}/status`),
  results: (id: string) => request<AnalysisResults>(`/api/analysis/${id}/results`),
  alerts: (limit = 500) => request<{ alerts: Finding[] }>(`/api/alerts?limit=${limit}`),
  traffic: () => request<TrafficSummary>('/api/traffic'),
  report: (id: string) => request<ReportResponse>(`/api/reports/${id}`),
  deleteAnalysis: (id: string) => request<void>(`/api/analysis/${id}`, { method: 'DELETE' }),
  uploadPcap: async (file: File) => {
    if (file.size > MAX_PCAP_UPLOAD_BYTES) {
      throw new ApiError(`Capture exceeds the maximum allowed upload size of ${MAX_PCAP_UPLOAD_LABEL}.`, 413)
    }
    const body = new FormData()
    body.append('file', file)
    return request<UploadedAnalysisResponse>('/api/pcap/analyze', { method: 'POST', body })
  },
  uploadPcapChunked: async (
    file: File,
    onProgress?: (progress: { loaded: number; total: number; percentage: number }) => void,
    signal?: AbortSignal
  ): Promise<JobStatusResponse> => {
    if (file.size > MAX_PCAP_UPLOAD_BYTES) {
      throw new ApiError(`Capture exceeds the maximum allowed upload size of ${MAX_PCAP_UPLOAD_LABEL}.`, 413)
    }
    // 1. Initialize session
    const initRes = await request<{
      upload_id: string
      filename: string
      chunk_size: number
      max_size_bytes: number
      status: string
    }>('/api/pcap/upload/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        filename: file.name,
        total_size: file.size,
        chunk_size: CHUNK_SIZE_BYTES,
      }),
      signal,
    })

    const uploadId = initRes.upload_id
    const chunkSize = initRes.chunk_size || CHUNK_SIZE_BYTES
    const totalChunks = Math.ceil(file.size / chunkSize)
    let uploadedBytes = 0

    onProgress?.({ loaded: 0, total: file.size, percentage: 0 })

    // 2. Transmit each chunk with retry logic
    for (let i = 0; i < totalChunks; i++) {
      if (signal?.aborted) {
        await request('/api/pcap/upload/abort', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ upload_id: uploadId }),
        }).catch(() => {})
        throw new ApiError('Upload cancelled.', 0)
      }

      const start = i * chunkSize
      const end = Math.min(file.size, start + chunkSize)
      const chunkBlob = file.slice(start, end)

      let attempts = 0
      const maxRetries = 3
      let chunkUploaded = false

      while (!chunkUploaded) {
        try {
          attempts++
          const formData = new FormData()
          formData.append('upload_id', uploadId)
          formData.append('chunk_index', i.toString())
          formData.append('chunk', chunkBlob, file.name)

          await request<{ upload_id: string; chunk_index: number; status: string }>(
            '/api/pcap/upload/chunk',
            {
              method: 'POST',
              body: formData,
              signal,
            }
          )
          chunkUploaded = true
          uploadedBytes += (end - start)
          const percentage = Math.min(100, Math.round((uploadedBytes / file.size) * 100))
          onProgress?.({ loaded: uploadedBytes, total: file.size, percentage })
        } catch (err) {
          if (
            err instanceof ApiError &&
            (err.status === 413 || err.status === 415 || err.status === 400 || err.status === 422)
          ) {
            throw err
          }
          if (attempts >= maxRetries || signal?.aborted) {
            await request('/api/pcap/upload/abort', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ upload_id: uploadId }),
            }).catch(() => {})
            throw err
          }
          await new Promise((resolve) => setTimeout(resolve, attempts * 400))
        }
      }
    }

    // 3. Complete chunked upload
    return request<JobStatusResponse>('/api/pcap/upload/complete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ upload_id: uploadId }),
      signal,
    })
  },
  createJob: async (
    file: File,
    onProgress?: (progress: { loaded: number; total: number; percentage: number }) => void,
    signal?: AbortSignal
  ): Promise<JobStatusResponse> => {
    if (file.size > MAX_PCAP_UPLOAD_BYTES) {
      throw new ApiError(`Capture exceeds the maximum allowed upload size of ${MAX_PCAP_UPLOAD_LABEL}.`, 413)
    }
    // For captures larger than 5 MB, use chunked upload to protect memory and avoid reverse proxy timeouts
    if (file.size > CHUNK_SIZE_BYTES) {
      try {
        return await api.uploadPcapChunked(file, onProgress, signal)
      } catch (err) {
        // If chunked endpoints are not available (e.g. legacy backend returning 404), fall back to direct upload
        if (err instanceof ApiError && err.status === 404) {
          const body = new FormData()
          body.append('file', file)
          return request<JobStatusResponse>('/jobs', { method: 'POST', body, signal })
        }
        throw err
      }
    }

    const body = new FormData()
    body.append('file', file)
    onProgress?.({ loaded: file.size, total: file.size, percentage: 100 })
    return request<JobStatusResponse>('/jobs', { method: 'POST', body, signal })
  },
  getJobStatus: (jobId: string) => request<JobStatusResponse>(`/jobs/${jobId}`),
  getJobResult: (jobId: string) => request<UploadedAnalysisResponse>(`/jobs/${jobId}/result`),
  getReportJsonUrl: (jobId: string) => `${API_BASE}/jobs/${jobId}/report.json`,
  getReportHtmlUrl: (jobId: string) => `${API_BASE}/jobs/${jobId}/report.html`,
  getCurrentAnalysis: () =>
    request<{
      analysis_id: string
      status: string
      source: { name: string; kind: string; filename?: string; size_bytes?: number }
      is_production: boolean
      results: AnalysisResults
    }>('/api/analysis/current'),
  setCurrentAnalysis: (analysisId: string) =>
    request<{
      analysis_id: string
      status: string
      source: { name: string; kind: string }
      is_production: boolean
    }>('/api/analysis/current', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analysis_id: analysisId }),
    }),
  getHuntTemplates: () =>
    request<{ status: string; count: number; templates: import('../types/api').HuntTemplatePayload[] }>(
      '/api/intelligence/query/templates'
    ),
  getQueryPredicates: () =>
    request<{ status: string; count: number; predicates: import('../types/api').FieldDescriptorPayload[] }>(
      '/api/intelligence/query/predicates'
    ),
  runIntelligenceQuery: (queryRequest: import('../types/api').QueryRequestPayload) =>
    request<import('../types/api').QueryResultPayload>('/api/intelligence/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(queryRequest),
    }),
  getSavedHunts: () =>
    request<{ status: string; count: number; hunts: Array<Record<string, unknown>> }>(
      '/api/intelligence/query/saved'
    ),
  saveHunt: (hunt: Record<string, unknown>) =>
    request<{ status: string; hunt_id: string; entry: Record<string, unknown> }>(
      '/api/intelligence/query/saved',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(hunt),
      }
    ),
  getTemporalWorldState: (analysisId = 'current') =>
    request<{ status: string; world_state: import('../types/api').TemporalNetworkWorldStatePayload }>(
      `/api/intelligence/world?analysis_id=${encodeURIComponent(analysisId)}`
    ),
  getTemporalWindows: (analysisId = 'current') =>
    request<{
      status: string
      capture_id: string
      total_windows: number
      windows: import('../types/api').TemporalNetworkWindowPayload[]
    }>(`/api/intelligence/world/windows?analysis_id=${encodeURIComponent(analysisId)}`),
  getTemporalWindowSnapshot: (windowId: string, analysisId = 'current') =>
    request<{ status: string; snapshot: import('../types/api').WorldStateSnapshotPayload }>(
      `/api/intelligence/world/window/${encodeURIComponent(windowId)}?analysis_id=${encodeURIComponent(analysisId)}`
    ),
  getTemporalWindowDiff: (windowA: number, windowB: number, analysisId = 'current') =>
    request<{ status: string; diff: import('../types/api').WorldStateDiffPayload }>(
      `/api/intelligence/world/diff?window_a=${windowA}&window_b=${windowB}&analysis_id=${encodeURIComponent(analysisId)}`
    ),
  getEntityWorldTimeline: (entityId: string, analysisId = 'current') =>
    request<{
      status: string
      entity_id: string
      active_windows: number[]
      timeline: Array<{
        window_index: number
        window_id?: string
        state?: import('../types/api').EntityTemporalStatePayload
        presence?: string
      }>
      relationships: Record<string, number[]>
    }>(`/api/intelligence/world/entity/${encodeURIComponent(entityId)}/timeline?analysis_id=${encodeURIComponent(analysisId)}`),
  getModelInfo: () =>
    request<import('../types/api').ModelInfoPayload>('/api/model/info'),
  getEvaluationMetrics: () =>
    request<import('../types/api').EvaluationMetricsPayload>('/api/evaluation'),
  runSimulation: (payload: import('../types/api').SimulationRequestPayload) =>
    request<import('../types/api').SimulationResponsePayload>('/api/simulation', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  getReplayScenarios: () =>
    request<import('../types/api').ReplayScenarioSummaryPayload[]>('/api/replay/scenarios'),
  getReplayStream: (scenarioId: string) =>
    request<import('../types/api').ReplayStreamPayload>(`/api/replay/${encodeURIComponent(scenarioId)}`),
}
