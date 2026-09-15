import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { MarketingLayout } from './components/MarketingLayout'
import { useProductionData } from './hooks/useProductionData'
import { About } from './pages/About'
import { Dashboard } from './pages/Dashboard'
import { Demo } from './pages/Demo'
import { Evidence } from './pages/Evidence'
import { Forecast } from './pages/Forecast'
import { Landing } from './pages/Landing'
import { Reports } from './pages/Reports'
import { Research } from './pages/Research'
import { Security } from './pages/Security'
import { Settings } from './pages/Settings'
import { Threats } from './pages/Threats'
import { Traffic } from './pages/Traffic'
import { Workflow } from './pages/Workflow'

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
        {/* Marketing / Product Experience */}
        <Route element={<MarketingLayout />}>
          <Route path="/" element={<Landing />} />
          <Route path="/workflow" element={<Workflow />} />
          <Route path="/security" element={<Security />} />
          <Route path="/research" element={<Research />} />
          <Route path="/about" element={<About />} />
        </Route>

        {/* Working Application / Console Experience */}
        <Route element={<Layout status={status} source={analysisSource} provenance={provenance} />}>
          <Route path="/console" element={<Navigate to="/analyze" replace />} />
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
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}


export default App
