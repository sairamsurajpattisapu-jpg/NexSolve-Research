export interface AnalysisHistoryEntry {
  id: string
  filename: string
  filesize?: string
  timestamp: string
  status: 'COMPLETED' | 'PROCESSING' | 'FAILED'
  provenance: 'uploaded' | 'demo' | 'reference'
  peakRiskPct?: number
  predictedStage?: string
}

const STORAGE_KEY = 'nexsolve-analysis-history'

export function getAnalysisHistory(): AnalysisHistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY) || sessionStorage.getItem(STORAGE_KEY)
    if (raw) {
      return JSON.parse(raw) as AnalysisHistoryEntry[]
    }
  } catch {
    // Storage quota safe
  }
  return []
}

export function recordAnalysisHistory(entry: AnalysisHistoryEntry): void {
  try {
    const current = getAnalysisHistory()
    const filtered = current.filter((item) => item.id !== entry.id)
    const updated = [entry, ...filtered].slice(0, 10)
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(updated))
  } catch {
    // Storage quota safe
  }
}

export function clearAnalysisHistory(): void {
  try {
    localStorage.removeItem(STORAGE_KEY)
    sessionStorage.removeItem(STORAGE_KEY)
  } catch {
    // Safe
  }
}
