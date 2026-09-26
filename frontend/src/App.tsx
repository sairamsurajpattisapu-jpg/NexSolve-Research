import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { MarketingLayout } from './components/MarketingLayout'
import { useProductionData } from './hooks/useProductionData'
import { About } from './pages/About'
import { Contact } from './pages/Contact'
import { Dashboard } from './pages/Dashboard'
import { Evidence } from './pages/Evidence'
import { Faq } from './pages/Faq'
import { Forecast } from './pages/Forecast'
import { Landing } from './pages/Landing'
import { NotFound } from './pages/NotFound'
import { Overview } from './pages/Overview'
import { Progression } from './pages/Progression'
import { Reports } from './pages/Reports'
import { Research } from './pages/Research'
import { Security } from './pages/Security'
import { Settings } from './pages/Settings'
import { AttackReplay } from './pages/AttackReplay'
import { Network } from './pages/Network'
import { Simulation } from './pages/Simulation'
import { Threats } from './pages/Threats'
import { Traffic } from './pages/Traffic'
import { Workflow } from './pages/Workflow'

import { AnalysisProvider } from './context/AnalysisContext'

function App() {
  const { loading, error, analysisSource, provenance, apiConnected } = useProductionData()
  const status = loading
    ? 'Syncing data'
    : apiConnected === false || error
    ? 'TEMPORARILY UNAVAILABLE'
    : 'READY'

  return (
    <AnalysisProvider>
      <BrowserRouter>
        <Routes>
        {/* Marketing / Explanatory Pages */}
        <Route element={<MarketingLayout />}>
          <Route path="/" element={<Landing />} />
          <Route path="/cli-quickstart" element={<Landing />} />
          <Route path="/cli" element={<Landing />} />
          <Route path="/workflow" element={<Workflow />} />
          <Route path="/security" element={<Security />} />
          <Route path="/research" element={<Research />} />
          <Route path="/methodology" element={<Research />} />
          <Route path="/faq" element={<Faq />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/about" element={<About />} />
        </Route>

        {/* Operational Console Experience */}
        <Route element={<Layout status={status} source={analysisSource} provenance={provenance} />}>
          {/* Canonical /console/* namespace */}
          <Route path="/console" element={<Overview />} />
          <Route path="/console/overview" element={<Overview />} />
          <Route path="/console/analyze" element={<Dashboard />} />
          <Route path="/console/analysis" element={<Dashboard />} />
          <Route path="/console/network" element={<Network />} />
          <Route path="/console/forecast" element={<Forecast />} />
          <Route path="/console/forecast/:jobId" element={<Forecast />} />
          <Route path="/console/progression" element={<Progression />} />
          <Route path="/console/evidence" element={<Evidence />} />
          <Route path="/console/evidence/:jobId" element={<Evidence />} />
          <Route path="/console/reports" element={<Reports />} />
          <Route path="/console/reports/:jobId" element={<Reports />} />
          <Route path="/console/threats" element={<Threats />} />
          <Route path="/console/traffic" element={<Traffic />} />
          <Route path="/console/replay" element={<AttackReplay />} />
          <Route path="/console/simulation" element={<Simulation />} />
          <Route path="/console/settings" element={<Settings />} />

          {/* Root paths / aliases for direct access and backward compatibility */}
          <Route path="/overview" element={<Overview />} />
          <Route path="/dashboard" element={<Overview />} />
          <Route path="/analyze" element={<Dashboard />} />
          <Route path="/analysis" element={<Dashboard />} />
          <Route path="/network" element={<Network />} />
          <Route path="/forecast" element={<Forecast />} />
          <Route path="/forecast/:jobId" element={<Forecast />} />
          <Route path="/progression" element={<Progression />} />
          <Route path="/evidence" element={<Evidence />} />
          <Route path="/evidence/:jobId" element={<Evidence />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/reports/:jobId" element={<Reports />} />
          <Route path="/replay" element={<AttackReplay />} />
          <Route path="/simulation" element={<Simulation />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/threats" element={<Threats />} />
          <Route path="/traffic" element={<Traffic />} />

          {/* 404 Catch-all */}
          <Route path="*" element={<NotFound />} />
        </Route>
      </Routes>
    </BrowserRouter>
    </AnalysisProvider>
  )
}

export default App
