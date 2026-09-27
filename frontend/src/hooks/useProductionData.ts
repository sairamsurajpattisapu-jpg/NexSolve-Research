import { useEffect, useSyncExternalStore } from 'react'
import {
  clearUploadedAnalysis,
  clearUploadError,
  getSnapshot,
  refreshProductionData,
  subscribe,
  setUploadedAnalysis,
  uploadPcap,
} from '../stores/productionStore'

export function useProductionData() {
  const snapshot = useSyncExternalStore(subscribe, getSnapshot, getSnapshot)

  useEffect(() => {
    void refreshProductionData()
  }, [])

  const dynamicAnalysisId = snapshot.data?.results?.analysis_id ?? ''
  const hasValidData = Boolean(snapshot.data?.results)

  return {
    ...snapshot,
    reload: () => refreshProductionData(true),
    analyzePcap: uploadPcap,
    clearUploadedAnalysis,
    clearUploadError,
    setUploadedAnalysis,
    analysisId: dynamicAnalysisId,
    apiConnected: snapshot.apiConnected,
    provenance: snapshot.provenance,
    isReferenceDataset: false,
    isLiveCapture: hasValidData && (snapshot.provenance === 'uploaded' || snapshot.analysisSource === 'uploaded'),
  }
}
