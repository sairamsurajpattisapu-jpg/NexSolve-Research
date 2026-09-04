import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { useProductionData } from './hooks/useProductionData'
import { Analysis } from './pages/Analysis'
import { Dashboard } from './pages/Dashboard'
import { Reports } from './pages/Reports'
import { Settings } from './pages/Settings'
import { Threats } from './pages/Threats'
import { Traffic } from './pages/Traffic'

function App() {
  const { data, loading, error, analysisSource } = useProductionData()
  const status = loading ? 'Syncing data' : error ? 'API unavailable' : data?.status.status === 'completed' ? 'API connected' : 'Awaiting analysis'

  return <BrowserRouter><Routes>
    <Route element={<Layout status={status} source={analysisSource} />}>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={<Dashboard />} />
      <Route path="/analysis" element={<Analysis />} />
      <Route path="/threats" element={<Threats />} />
      <Route path="/traffic" element={<Traffic />} />
      <Route path="/reports" element={<Reports />} />
      <Route path="/settings" element={<Settings />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Route>
  </Routes></BrowserRouter>
}

export default App
