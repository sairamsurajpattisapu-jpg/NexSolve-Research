import type {
  AnalysisResults,
  AnalysisStatus,
  Finding,
  HealthResponse,
  ReportResponse,
  TrafficSummary,
  UploadedAnalysisResponse,
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
}
