import { api, ApiError } from '../services/api'
import type { AnalysisData, AnalysisProvenance, UploadedAnalysisResponse } from '../types/api'

export const ANALYSIS_ID = ''
const UPLOAD_ID_KEY = 'nexsolve-upload-analysis-id'
const STORAGE_ACTIVE_KEY = 'nexsolve-current-analysis-id'

type StoreState = {
  data: AnalysisData | null
  loading: boolean
  error: string | null
  analysisSource: 'uploaded' | 'production'
  provenance: AnalysisProvenance
  uploadError: string | null
  apiConnected: boolean
}

// Initial state must be completely EMPTY (no fake/reference analysis)
let state: StoreState = {
  data: null,
  loading: false,
  error: null,
  analysisSource: 'uploaded',
  provenance: 'uploaded',
  uploadError: null,
  apiConnected: true,
}
let request: Promise<void> | null = null
const listeners = new Set<() => void>()

function emit() {
  listeners.forEach((listener) => listener())
}

// Sanitize legacy demo/fixture IDs from browser storage
function sanitizeStorage(): string | null {
  try {
    const rawSession = sessionStorage.getItem(UPLOAD_ID_KEY)
    if (rawSession === 'production-cic-ids2017' || rawSession?.includes('demo') || rawSession?.includes('fixture')) {
      sessionStorage.removeItem(UPLOAD_ID_KEY)
    }
    const rawLocal = localStorage.getItem(STORAGE_ACTIVE_KEY)
    if (rawLocal === 'production-cic-ids2017' || rawLocal?.includes('demo') || rawLocal?.includes('fixture')) {
      localStorage.removeItem(STORAGE_ACTIVE_KEY)
    }
    const candidate = sessionStorage.getItem(UPLOAD_ID_KEY) ?? localStorage.getItem(STORAGE_ACTIVE_KEY)
    if (candidate && candidate !== 'production-cic-ids2017' && !candidate.includes('demo') && !candidate.includes('fixture')) {
      return candidate
    }
  } catch {
    // Storage quota or privacy sandbox safe
  }
  return null
}

async function fetchData(targetAnalysisId?: string) {
  state = { ...state, loading: true, error: null }
  emit()
  try {
    let resolvedId = targetAnalysisId
    if (!resolvedId) {
      try {
        const currentMeta = await api.getCurrentAnalysis()
        if (currentMeta?.analysis_id && currentMeta.analysis_id !== 'production-cic-ids2017' && !currentMeta.analysis_id.includes('demo') && !currentMeta.analysis_id.includes('fixture')) {
          resolvedId = currentMeta.analysis_id
        }
      } catch (cause) {
        if (
          cause instanceof ApiError &&
          (cause.status === 0 ||
            cause.status === 408 ||
            cause.message.includes('HTML instead of JSON') ||
            cause.message.includes('Vercel deployment detected'))
        ) {
          state = { ...state, loading: false, apiConnected: false }
          emit()
          return
        }
        resolvedId = sanitizeStorage() ?? undefined
      }
    }

    // If no real user analysis ID exists, check backend health and keep data null (EMPTY STATE)
    if (!resolvedId) {
      try {
        await api.health()
        state = {
          ...state,
          data: null,
          loading: false,
          error: null,
          apiConnected: true,
          analysisSource: 'uploaded',
          provenance: 'uploaded',
        }
      } catch {
        state = {
          ...state,
          data: null,
          loading: false,
          error: null,
          apiConnected: false,
          analysisSource: 'uploaded',
          provenance: 'uploaded',
        }
      }
      return
    }

    // Real analysis ID exists - fetch actual analysis artifacts
    const [results, status, report, health] = await Promise.all([
      api.results(resolvedId),
      api.status(resolvedId),
      api.report(resolvedId),
      api.health(),
    ])
    const traffic = results.traffic

    try {
      sessionStorage.setItem(UPLOAD_ID_KEY, resolvedId)
      localStorage.setItem(STORAGE_ACTIVE_KEY, resolvedId)
    } catch {
      // Storage safe
    }

    state = {
      data: { results: { ...results, traffic }, status, report, health },
      loading: false,
      error: null,
      analysisSource: 'uploaded',
      provenance: 'uploaded',
      uploadError: null,
      apiConnected: true,
    }
  } catch (cause) {
    if (targetAnalysisId && cause instanceof ApiError && cause.status === 404) {
      sessionStorage.removeItem(UPLOAD_ID_KEY)
      localStorage.removeItem(STORAGE_ACTIVE_KEY)
    }
    state = {
      ...state,
      data: null,
      loading: false,
      error: null,
      apiConnected: false,
      analysisSource: 'uploaded',
      provenance: 'uploaded',
    }
  } finally {
    request = null
    emit()
  }
}

export async function setUploadedAnalysis(uploaded: UploadedAnalysisResponse): Promise<void> {
  const analysisId = uploaded.analysis_id

  try {
    sessionStorage.setItem(UPLOAD_ID_KEY, analysisId)
    localStorage.setItem(STORAGE_ACTIVE_KEY, analysisId)
  } catch {
    // Storage safe
  }

  try {
    await api.setCurrentAnalysis(analysisId)
  } catch {
    // Best effort backend sync
  }

  const [report, health] = await Promise.all([
    api.report(analysisId).catch(() => ({
      report_id: analysisId,
      status: uploaded.status,
      metadata: uploaded.source ?? { name: 'Uploaded PCAP', kind: 'uploaded_pcap' },
      validation: uploaded.validation,
      traffic: uploaded.traffic,
      detection: uploaded.detection,
    })),
    api.health().catch(() => state.data?.health ?? {
      service_status: 'ok',
      model_loaded: true,
      model_version: '1.0.0',
      feature_count: 45,
      sequence_length: 8,
      K: 5,
      packet_features_available: true,
    }),
  ])

  state = {
    data: {
      results: {
        analysis_id: uploaded.analysis_id,
        status: uploaded.status,
        source: uploaded.source,
        upload: uploaded.upload,
        validation: uploaded.validation,
        traffic: uploaded.traffic,
        detection: uploaded.detection,
        forecasts: uploaded.forecasts,
        attack_horizon: uploaded.attack_horizon ?? uploaded.attackHorizon,
        evidence_chain: uploaded.evidence_chain ?? uploaded.evidenceChain,
        confidence: uploaded.confidence,
        unknown_behavior: uploaded.unknown_behavior ?? uploaded.unknownBehavior,
        abstention: uploaded.abstention,
      },
      status: {
        analysis_id: uploaded.analysis_id,
        status: uploaded.status,
        windows: uploaded.validation?.rows ?? uploaded.window_count ?? 1,
      },
      report,
      health,
    },
    loading: false,
    error: null,
    apiConnected: true,
    analysisSource: 'uploaded',
    provenance: 'uploaded',
    uploadError: null,
  }
  emit()
}

export function clearUploadError() {
  if (state.uploadError !== null) {
    state = { ...state, uploadError: null }
    emit()
  }
}

export async function uploadPcap(file: File): Promise<string | null> {
  state = { ...state, loading: false, uploadError: null }
  emit()
  try {
    const uploaded = await api.uploadPcap(file)
    await setUploadedAnalysis(uploaded)
    return null
  } catch (cause) {
    const message = cause instanceof ApiError ? cause.message : 'Unable to analyze the uploaded capture.'
    state = { ...state, loading: false, uploadError: message }
    return message
  } finally {
    emit()
  }
}

export async function clearUploadedAnalysis() {
  const uploadId = sessionStorage.getItem(UPLOAD_ID_KEY) ?? localStorage.getItem(STORAGE_ACTIVE_KEY)
  if (uploadId && uploadId !== 'production-cic-ids2017') {
    try {
      await api.deleteAnalysis(uploadId)
    } catch {
      // Ignore delete errors
    }
  }
  sessionStorage.removeItem(UPLOAD_ID_KEY)
  localStorage.removeItem(STORAGE_ACTIVE_KEY)
  state = {
    data: null,
    loading: false,
    error: null,
    apiConnected: state.apiConnected,
    analysisSource: 'uploaded',
    provenance: 'uploaded',
    uploadError: null,
  }
  emit()
}

export function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getSnapshot() {
  return state
}

let initialFetchInitiated = false

export function refreshProductionData(force = false) {
  if (!force && initialFetchInitiated && !request) {
    return Promise.resolve()
  }
  initialFetchInitiated = true
  if (!request) request = fetchData()
  return request
}
