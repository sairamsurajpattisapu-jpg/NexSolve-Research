import { useEffect, useSyncExternalStore } from 'react'
import { clearUploadedAnalysis, getSnapshot, refreshProductionData, subscribe, ANALYSIS_ID, uploadPcap } from '../stores/productionStore'

export function useProductionData() {
  const snapshot = useSyncExternalStore(subscribe, getSnapshot, getSnapshot)

  useEffect(() => {
    if (!snapshot.data) void refreshProductionData()
  }, [snapshot.analysisSource, snapshot.data])

    return { ...snapshot, reload: refreshProductionData, analyzePcap: uploadPcap, clearUploadedAnalysis, analysisId: ANALYSIS_ID }
}
