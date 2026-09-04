import { api, ApiError } from '../services/api'
import type { AnalysisData } from '../types/api'

export const ANALYSIS_ID = 'production-cic-ids2017'
const UPLOAD_ID_KEY = 'nexsolve-upload-analysis-id'

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

async function fetchData(analysisId = ANALYSIS_ID) {
  state = { ...state, loading: true, error: null }
  emit()
  try {
    const [results, status, report, health] = await Promise.all([api.results(analysisId), api.status(analysisId), api.report(analysisId), api.health()])
    const traffic = analysisId === ANALYSIS_ID ? await api.traffic() : results.traffic
    state = { data: { results: { ...results, traffic }, status, report, health }, loading: false, error: null, analysisSource: analysisId === ANALYSIS_ID ? 'production' : 'uploaded', uploadError: null }
  } catch (cause) {
    if (analysisId !== ANALYSIS_ID && cause instanceof ApiError && cause.status === 404) {
      sessionStorage.removeItem(UPLOAD_ID_KEY)
      await fetchData()
      return
    }
    state = { ...state, loading: false, error: cause instanceof ApiError ? cause.message : 'Unable to load production analysis.' }
  } finally {
    request = null
    emit()
  }
}

export async function uploadPcap(file: File): Promise<string | null> {
  state = { ...state, loading: false, uploadError: null }
  emit()
  try {
    const uploaded = await api.uploadPcap(file)
    const [report, health] = await Promise.all([api.report(uploaded.analysis_id), api.health()])
    state = {
      data: {
        results: { analysis_id: uploaded.analysis_id, status: uploaded.status, source: uploaded.source, upload: uploaded.upload, validation: uploaded.validation, traffic: uploaded.traffic, detection: uploaded.detection },
        status: { analysis_id: uploaded.analysis_id, status: uploaded.status, windows: uploaded.validation.rows },
        report,
        health,
      },
      loading: false,
      error: null,
      analysisSource: 'uploaded',
      uploadError: null,
    }
    sessionStorage.setItem(UPLOAD_ID_KEY, uploaded.analysis_id)
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
  const uploadId = sessionStorage.getItem(UPLOAD_ID_KEY)
  if (uploadId) {
    try {
      await api.deleteAnalysis(uploadId)
    } catch (cause) {
      if (!(cause instanceof ApiError && cause.status === 404)) {
        state = { ...state, uploadError: cause instanceof ApiError ? cause.message : 'Unable to clear the uploaded analysis.' }
        emit()
        return
      }
    }
  }
  sessionStorage.removeItem(UPLOAD_ID_KEY)
  state = { data: null, loading: true, error: null, analysisSource: 'production', uploadError: null }
  emit()
  return refreshProductionData()
}

export function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getSnapshot() {
  return state
}

export function refreshProductionData() {
  const uploadId = sessionStorage.getItem(UPLOAD_ID_KEY)
  if (!request) request = fetchData(uploadId ?? ANALYSIS_ID)
  return request
}
