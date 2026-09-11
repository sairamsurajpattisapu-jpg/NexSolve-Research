import { api, ApiError } from '../services/api'
import type { AnalysisData, UploadedAnalysisResponse } from '../types/api'

export const ANALYSIS_ID = 'production-cic-ids2017'
const UPLOAD_ID_KEY = 'nexsolve-upload-analysis-id'
const STORAGE_ACTIVE_KEY = 'nexsolve-current-analysis-id'

type StoreState = {
  data: AnalysisData | null
  loading: boolean
  error: string | null
  analysisSource: 'production' | 'uploaded'
  uploadError: string | null
}

let state: StoreState = { data: null, loading: true, error: null, analysisSource: 'production', uploadError: null }
let request: Promise<void> | null = null
const listeners = new Set<() => void>()

function emit() {
  listeners.forEach((listener) => listener())
}

async function fetchData(targetAnalysisId?: string) {
  state = { ...state, loading: true, error: null }
  emit()
  try {
    let resolvedId = targetAnalysisId
    if (!resolvedId) {
      try {
        const currentMeta = await api.getCurrentAnalysis()
        if (currentMeta?.analysis_id) {
          resolvedId = currentMeta.analysis_id
        }
      } catch {
        // If current analysis endpoint fails (e.g. offline/mock), use stored cache
        resolvedId = sessionStorage.getItem(UPLOAD_ID_KEY) ?? localStorage.getItem(STORAGE_ACTIVE_KEY) ?? ANALYSIS_ID
      }
    }
    const finalId = resolvedId ?? ANALYSIS_ID

    const [results, status, report, health] = await Promise.all([
      api.results(finalId),
      api.status(finalId),
      api.report(finalId),
      api.health(),
    ])
    const traffic = finalId === ANALYSIS_ID ? await api.traffic() : results.traffic
    const isProd = finalId === ANALYSIS_ID

    if (!isProd) {
      sessionStorage.setItem(UPLOAD_ID_KEY, finalId)
      localStorage.setItem(STORAGE_ACTIVE_KEY, finalId)
    } else {
      sessionStorage.removeItem(UPLOAD_ID_KEY)
      localStorage.removeItem(STORAGE_ACTIVE_KEY)
    }

    state = {
      data: { results: { ...results, traffic }, status, report, health },
      loading: false,
      error: null,
      analysisSource: isProd ? 'production' : 'uploaded',
      uploadError: null,
    }
  } catch (cause) {
    if (targetAnalysisId && targetAnalysisId !== ANALYSIS_ID && cause instanceof ApiError && cause.status === 404) {
      sessionStorage.removeItem(UPLOAD_ID_KEY)
      localStorage.removeItem(STORAGE_ACTIVE_KEY)
      try {
        await api.setCurrentAnalysis(ANALYSIS_ID)
      } catch {
        // Ignore reset error
      }
      await fetchData(ANALYSIS_ID)
      return
    }
    state = { ...state, loading: false, error: cause instanceof ApiError ? cause.message : 'Unable to load analysis.' }
  } finally {
    request = null
    emit()
  }
}

export async function setUploadedAnalysis(uploaded: UploadedAnalysisResponse): Promise<void> {
  const analysisId = uploaded.analysis_id
  const isProd = analysisId === ANALYSIS_ID

  if (!isProd) {
    sessionStorage.setItem(UPLOAD_ID_KEY, analysisId)
    localStorage.setItem(STORAGE_ACTIVE_KEY, analysisId)
  } else {
    sessionStorage.removeItem(UPLOAD_ID_KEY)
    localStorage.removeItem(STORAGE_ACTIVE_KEY)
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
      feature_count: 46,
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
        is_demo: uploaded.is_demo,
        demo_scenario_name: uploaded.demo_scenario_name,
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
    analysisSource: isProd ? 'production' : 'uploaded',
    uploadError: null,
  }
  emit()
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
  if (uploadId && uploadId !== ANALYSIS_ID) {
    try {
      await api.deleteAnalysis(uploadId)
    } catch {
      // Ignore delete errors
    }
  }
  sessionStorage.removeItem(UPLOAD_ID_KEY)
  localStorage.removeItem(STORAGE_ACTIVE_KEY)
  try {
    await api.setCurrentAnalysis(ANALYSIS_ID)
  } catch {
    // Best effort reset
  }
  state = { data: null, loading: true, error: null, analysisSource: 'production', uploadError: null }
  emit()
  return fetchData(ANALYSIS_ID)
}

export function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getSnapshot() {
  return state
}

export function refreshProductionData() {
  if (!request) request = fetchData()
  return request
}
