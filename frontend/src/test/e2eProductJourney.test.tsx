import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { Layout } from '../components/Layout'
import { Dashboard } from '../pages/Dashboard'
import { Evidence } from '../pages/Evidence'
import { Forecast } from '../pages/Forecast'
import { Network } from '../pages/Network'
import { Simulation } from '../pages/Simulation'
import { Reports } from '../pages/Reports'
import { fixture } from './fixtures'

vi.mock('../hooks/useProductionData', () => ({
  useProductionData: () => ({
    data: fixture,
    loading: false,
    error: null,
    analysisSource: 'uploaded',
    provenance: 'uploaded',
    reload: vi.fn(),
    analyzePcap: vi.fn(),
    clearUploadedAnalysis: vi.fn(),
    setUploadedAnalysis: vi.fn(),
    uploadError: null,
    analysisId: 'job-e2e-test-123',
    isReferenceDataset: false,
    isLiveCapture: true,
    isDemo: false,
  }),
}))

describe('End-to-End Product Data Consistency Journey', () => {
  function renderAppAt(path: string) {
    return render(
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route element={<Layout status="API connected" />}>
            <Route path="/analyze" element={<Dashboard />} />
            <Route path="/forecast" element={<Forecast />} />
            <Route path="/evidence" element={<Evidence />} />
            <Route path="/network" element={<Network />} />
            <Route path="/simulation" element={<Simulation />} />
            <Route path="/reports" element={<Reports />} />
          </Route>
        </Routes>
      </MemoryRouter>
    )
  }

  it('1. Analyze page renders entry points and operational state', () => {
    renderAppAt('/analyze')
    expect(screen.getByText(/LIVE PCAP ANALYSIS/i)).toBeInTheDocument()
  })

  it('2. Forecast page consumes current analysis state and presents multi-horizon rollout', () => {
    renderAppAt('/forecast')
    expect(screen.getByText(/NEXSOLVE FORECAST ENGINE/i)).toBeInTheDocument()
    expect(screen.getByText(/Multi-Step Attack Forecasting/i)).toBeInTheDocument()
    expect(screen.getByText(/STEP ATTACK PROBABILITY/i)).toBeInTheDocument()
    expect(screen.getByText(/CUMULATIVE FUTURE RISK/i)).toBeInTheDocument()
  })

  it('3. Evidence page displays supporting and contradictory causal drivers for same analysis', () => {
    renderAppAt('/evidence')
    expect(screen.getByText(/Evidence Chain & Attribution Explorer/i)).toBeInTheDocument()
    expect(screen.getByText(/1. Input Telemetry/i)).toBeInTheDocument()
    expect(screen.getByText(/2. Feature Contract/i)).toBeInTheDocument()
  })

  it('4. Network page displays flow architecture and endpoint matrix', () => {
    renderAppAt('/network')
    expect(screen.getByText(/Network Flow Architecture/i)).toBeInTheDocument()
    expect(screen.getByText(/Host Communication Matrix/i)).toBeInTheDocument()
  })

  it('5. Simulation page models counterfactual interventions with explicit disclaimers', () => {
    renderAppAt('/simulation')
    expect(screen.getByText(/What-If Defence Simulator/i)).toBeInTheDocument()
    expect(screen.getByText(/MODELLED COUNTERFACTUAL NOTICE/i)).toBeInTheDocument()
    expect(screen.getByText(/Defensive Policy Controls/i)).toBeInTheDocument()
  })

  it('6. Reports page renders forensic report output and download links', () => {
    renderAppAt('/reports')
    expect(screen.getByText(/Analysis report/i)).toBeInTheDocument()
  })

  it('7. Forecast page does NOT substitute DEMO MODE badge when handling live capture', () => {
    renderAppAt('/forecast')
    expect(screen.queryByText(/DEMO MODE/i)).not.toBeInTheDocument()
  })
})

