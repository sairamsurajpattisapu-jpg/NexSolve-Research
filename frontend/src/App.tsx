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
import { AttackReplay } from './pages/AttackReplay'
import { Evaluation } from './pages/Evaluation'
import { Network } from './pages/Network'
import { Simulation } from './pages/Simulation'
import { Threats } from './pages/Threats'
import { Traffic } from './pages/Traffic'
import { Workflow } from './pages/Workflow'

function App() {
  const { data, loading, error, analysisSource, provenance, apiConnected } = useProductionData()
  const status = loading
    ? 'Syncing data'
    : apiConnected === false || error
    ? 'API unavailable'
    : data?.status.status === 'completed'
    ? 'API connected'
    : 'Awaiting analysis'

  return (
    <BrowserRouter>
      <Routes>
        {/* Marketing / Explanatory Pages */}
        <Route element={<MarketingLayout />}>
          <Route path="/" element={<Landing />} />
          <Route path="/workflow" element={<Workflow />} />
          <Route path="/security" element={<Security />} />
          <Route path="/research" element={<Research />} />
          <Route path="/methodology" element={<Research />} />
          <Route path="/about" element={<About />} />
        </Route>

        {/* Operational Console Experience */}
        <Route element={<Layout status={status} source={analysisSource} provenance={provenance} />}>
          {/* Canonical /console/* namespace */}
          <Route path="/console" element={<Navigate to="/console/analyze" replace />} />
          <Route path="/console/overview" element={<Navigate to="/console/analyze" replace />} />
          <Route path="/console/analyze" element={<Dashboard />} />
          <Route path="/console/forecast" element={<Forecast />} />
          <Route path="/console/forecast/:jobId" element={<Forecast />} />
          <Route path="/console/evidence" element={<Evidence />} />
          <Route path="/console/evidence/:jobId" element={<Evidence />} />
          <Route path="/console/network" element={<Network />} />
          <Route path="/console/replay" element={<AttackReplay />} />
          <Route path="/console/simulation" element={<Simulation />} />
          <Route path="/console/evaluation" element={<Evaluation />} />
          <Route path="/console/reports" element={<Reports />} />
          <Route path="/console/reports/:jobId" element={<Reports />} />
          <Route path="/console/demo" element={<Demo />} />
          <Route path="/console/settings" element={<Settings />} />

          {/* Root paths / aliases for direct access and backward compatibility */}
          <Route path="/analyze" element={<Dashboard />} />
          <Route path="/dashboard" element={<Navigate to="/console/analyze" replace />} />
          <Route path="/overview" element={<Navigate to="/console/analyze" replace />} />
          <Route path="/forecast" element={<Forecast />} />
          <Route path="/forecast/:jobId" element={<Forecast />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="/evidence/:jobId" element={<Evidence />} />
          <Route path="/network" element={<Network />} />
          <Route path="/replay" element={<AttackReplay />} />
          <Route path="/simulation" element={<Simulation />} />
          <Route path="/evaluation" element={<Evaluation />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/reports/:jobId" element={<Reports />} />
          <Route path="/demo" element={<Demo />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/traffic" element={<Traffic />} />

          {/* Fallback */}
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
