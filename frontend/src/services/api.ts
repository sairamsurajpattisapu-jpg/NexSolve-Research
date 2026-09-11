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
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { Accept: 'application/json', ...(init?.headers ?? {}) },
    })
  } catch {
    throw new ApiError('Backend unavailable. Start the FastAPI service and try again.')
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
    throw new ApiError('Backend returned an invalid JSON response.', response.status)
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
  uploadPcap: (file: File) => {
    const body = new FormData()
    body.append('file', file)
    return request<UploadedAnalysisResponse>('/api/pcap/analyze', { method: 'POST', body })
  },
  createJob: (file: File) => {
    const body = new FormData()
    body.append('file', file)
    return request<JobStatusResponse>('/jobs', { method: 'POST', body })
  },
  getJobStatus: (jobId: string) => request<JobStatusResponse>(`/jobs/${jobId}`),
  getJobResult: (jobId: string) => request<UploadedAnalysisResponse>(`/jobs/${jobId}/result`),
  getReportJsonUrl: (jobId: string) => `${API_BASE}/jobs/${jobId}/report.json`,
  getReportHtmlUrl: (jobId: string) => `${API_BASE}/jobs/${jobId}/report.html`,
  getDemoScenarios: () => request<Array<{ id: string; name: string; badge: string; tone: string; description: string; expected_behavior: string }>>('/api/demo/scenarios'),
  getDemoScenarioResult: (scenarioId: string) => request<UploadedAnalysisResponse>(`/api/demo/scenarios/${scenarioId}`),
  getDemoReportJsonUrl: (scenarioId: string) => `${API_BASE}/api/demo/scenarios/${scenarioId}/report.json`,
  getDemoReportHtmlUrl: (scenarioId: string) => `${API_BASE}/api/demo/scenarios/${scenarioId}/report.html`,
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
}
