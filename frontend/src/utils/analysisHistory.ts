import { normalizeRiskPercentage } from './format'

export interface AnalysisHistoryEntry {
  id: string
  filename: string
  filesize?: string
  timestamp: string
  status: 'COMPLETED' | 'PROCESSING' | 'FAILED' | 'QUEUED'
  provenance: 'uploaded' | 'reference'
  peakRiskPct?: number
  predictedStage?: string
}

const STORAGE_KEY = 'nexsolve-analysis-history'

export function getAnalysisHistory(): AnalysisHistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY) || sessionStorage.getItem(STORAGE_KEY)
    if (raw) {
      const parsed = JSON.parse(raw) as AnalysisHistoryEntry[]
      let needsResave = false
      const migrated = parsed.map((item) => {
        if (item.peakRiskPct !== undefined) {
          const normalized = normalizeRiskPercentage(item.peakRiskPct)
          if (normalized !== item.peakRiskPct) {
            needsResave = true
          }
          return {
            ...item,
            peakRiskPct: normalized !== null ? normalized : undefined,
          }
        }
        return item
      })
      if (needsResave) {
        try {
          const serialized = JSON.stringify(migrated)
          localStorage.setItem(STORAGE_KEY, serialized)
          sessionStorage.setItem(STORAGE_KEY, serialized)
        } catch {
          // Storage quota safe
        }
      }
      return migrated
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
    const normalizedEntry = { ...entry }
    if (normalizedEntry.peakRiskPct !== undefined) {
      const normalized = normalizeRiskPercentage(normalizedEntry.peakRiskPct)
      normalizedEntry.peakRiskPct = normalized !== null ? normalized : undefined
    }
    const updated = [normalizedEntry, ...filtered].slice(0, 10)
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
