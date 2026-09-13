import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { useProductionData } from './hooks/useProductionData'
import { Dashboard } from './pages/Dashboard'
import { Demo } from './pages/Demo'
import { Evidence } from './pages/Evidence'
import { Forecast } from './pages/Forecast'
import { Reports } from './pages/Reports'
import { Settings } from './pages/Settings'
import { Threats } from './pages/Threats'
import { Traffic } from './pages/Traffic'

function App() {
  const { data, loading, error, analysisSource, provenance } = useProductionData()
  const status = loading
    ? 'Syncing data'
    : error
    ? 'API unavailable'
    : data?.status.status === 'completed'
    ? 'API connected'
    : 'Awaiting analysis'

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout status={status} source={analysisSource} provenance={provenance} />}>
          <Route path="/" element={<Navigate to="/analyze" replace />} />
          <Route path="/overview" element={<Navigate to="/analyze" replace />} />
          <Route path="/analyze" element={<Dashboard />} />
          <Route path="/dashboard" element={<Navigate to="/analyze" replace />} />
          <Route path="/forecast" element={<Forecast />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/traffic" element={<Traffic />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/demo" element={<Demo />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/analyze" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
