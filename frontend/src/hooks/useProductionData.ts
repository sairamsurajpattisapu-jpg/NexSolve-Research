import { useEffect, useSyncExternalStore } from 'react'
import {
  clearUploadedAnalysis,
  getSnapshot,
  refreshProductionData,
  subscribe,
  setUploadedAnalysis,
  ANALYSIS_ID,
  uploadPcap,
} from '../stores/productionStore'

export function useProductionData() {
  const snapshot = useSyncExternalStore(subscribe, getSnapshot, getSnapshot)

  useEffect(() => {
    if (!snapshot.data) void refreshProductionData()
  }, [snapshot.analysisSource, snapshot.data])

  const dynamicAnalysisId = snapshot.data?.results?.analysis_id ?? (snapshot.analysisSource === 'production' ? ANALYSIS_ID : 'unknown')

  return {
    ...snapshot,
    reload: refreshProductionData,
    analyzePcap: uploadPcap,
    clearUploadedAnalysis,
    setUploadedAnalysis,
    analysisId: dynamicAnalysisId,
    provenance: snapshot.provenance,
    isReferenceDataset: snapshot.provenance === 'reference',
    isLiveCapture: snapshot.provenance === 'uploaded',
    isDemo: snapshot.provenance === 'demo',
  }
}
