import { render, screen, waitFor } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Layout } from '../components/Layout'
import { Forecast } from '../pages/Forecast'
import { ForecastConsole } from '../components/ForecastConsole'
import { ErrorBoundary } from '../components/ErrorBoundary'
import { AnalysisProvider } from '../context/AnalysisContext'
import { api, ApiError } from '../services/api'
import { fixture } from './fixtures'
import { adaptToCanonical } from '../utils/canonicalAdapter'

describe('Forecast Route Comprehensive Resilience & Repro Test Suite', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    sessionStorage.clear()
    localStorage.clear()
  })

  it('1. When job is completed, resolves job result and renders ForecastConsole', async () => {
    vi.spyOn(api, 'getJobStatus').mockResolvedValue({
      job_id: 'job-completed-1',
      status: 'COMPLETED',
      stage: 'COMPLETE',
      progress: 1.0,
      created_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      error: null,
    })

    vi.spyOn(api, 'getJobResult').mockResolvedValue(fixture.results as any)

    render(
      <AnalysisProvider>
        <MemoryRouter initialEntries={['/console/forecast/job-completed-1']}>
          <Routes>
            <Route element={<Layout status="READY" />}>
              <Route path="/console/forecast/:jobId" element={<Forecast />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AnalysisProvider>
    )

    await waitFor(() => {
      // ForecastConsole should render without crashing
      expect(screen.getByText(/CURRENT POINT \(T0\)/i)).toBeInTheDocument()
    }, { timeout: 5000 })
  })

  it('2. When job is completed with INSUFFICIENT_HISTORY abstention', async () => {
    const abstainedResults = {
      ...fixture.results,
      analysis_id: 'job-abstained-history',
      is_forecast_available: false,
      forecast_summary: {
        available: false,
        status: 'INSUFFICIENT_HISTORY',
        required_windows: 8,
        available_windows: 3,
        required_window_seconds: 60,
        message: 'Forecasting requires at least 8 continuous 60-second windows.',
      },
      forecasts: [],
      forecast: null,
      window_count: 3,
    }

    vi.spyOn(api, 'getJobStatus').mockResolvedValue({
      job_id: 'job-abstained-history',
      status: 'COMPLETED',
      stage: 'COMPLETE',
      progress: 1.0,
      created_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      error: null,
    })

    vi.spyOn(api, 'getJobResult').mockResolvedValue(abstainedResults as any)

    render(
      <AnalysisProvider>
        <MemoryRouter initialEntries={['/console/forecast/job-abstained-history']}>
          <Routes>
            <Route element={<Layout status="READY" />}>
              <Route path="/console/forecast/:jobId" element={<Forecast />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AnalysisProvider>
    )

    await waitFor(() => {
      expect(screen.getByText(/Insufficient temporal history/i)).toBeInTheDocument()
    }, { timeout: 5000 })
  })

  it('3. When job is completed with NON_CONTIGUOUS_TIMESTAMPS abstention', async () => {
    const gappedResults = {
      ...fixture.results,
      analysis_id: 'job-gapped-history',
      is_forecast_available: false,
      forecast_summary: {
        available: false,
        status: 'NON_CONTIGUOUS_TIMESTAMPS',
        required_windows: 8,
        available_windows: 5,
        required_window_seconds: 60,
        message: 'Input sequence contains non-contiguous temporal windows or excessive time gaps.',
      },
      forecasts: [],
      forecast: null,
      network_state: {
        history: {
          status: 'GAPPED_HISTORY',
          reason: 'Input sequence contains non-contiguous temporal windows or excessive time gaps.',
        },
      },
    }

    vi.spyOn(api, 'getJobStatus').mockResolvedValue({
      job_id: 'job-gapped-history',
      status: 'COMPLETED',
      stage: 'COMPLETE',
      progress: 1.0,
      created_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      error: null,
    })

    vi.spyOn(api, 'getJobResult').mockResolvedValue(gappedResults as any)

    render(
      <AnalysisProvider>
        <MemoryRouter initialEntries={['/console/forecast/job-gapped-history']}>
          <Routes>
            <Route element={<Layout status="READY" />}>
              <Route path="/console/forecast/:jobId" element={<Forecast />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AnalysisProvider>
    )

    await waitFor(() => {
      expect(screen.getByText(/Non-contiguous timestamps detected/i)).toBeInTheDocument()
    }, { timeout: 5000 })
  })

  it('4. When backend status returns FAILED with rejected / malformed PCAP error', async () => {
    vi.spyOn(api, 'getJobStatus').mockResolvedValue({
      job_id: 'job-failed-1',
      status: 'FAILED',
      stage: 'WINDOWING',
      progress: 0.4,
      created_at: new Date().toISOString(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      error: {
        code: 'PROCESSING_ERROR',
        message: 'Malformed PCAP frame encountered at offset 1024',
      },
    })

    render(
      <AnalysisProvider>
        <MemoryRouter initialEntries={['/console/forecast/job-failed-1']}>
          <Routes>
            <Route element={<Layout status="READY" />}>
              <Route path="/console/forecast/:jobId" element={<Forecast />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AnalysisProvider>
    )

    await waitFor(() => {
      expect(screen.getByText(/Analysis could not be completed/i)).toBeInTheDocument()
      expect(screen.getByText(/Malformed PCAP frame encountered/i)).toBeInTheDocument()
    })
  })

  it('5. When backend status returns 404 (missing / invalid job ID)', async () => {
    vi.spyOn(api, 'getJobStatus').mockRejectedValue(new ApiError('Not found', 404))
    vi.spyOn(api, 'getJobResult').mockRejectedValue(new ApiError('Not found', 404))

    render(
      <AnalysisProvider>
        <MemoryRouter initialEntries={['/console/forecast/nonexistent-job']}>
          <Routes>
            <Route element={<Layout status="READY" />}>
              <Route path="/console/forecast/:jobId" element={<Forecast />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AnalysisProvider>
    )

    await waitFor(() => {
      expect(screen.getByText(/Analysis could not be completed/i)).toBeInTheDocument()
      expect(screen.getAllByText(/The requested analysis could not be located/i).length).toBeGreaterThanOrEqual(1)
    }, { timeout: 3000 })
  })

  it('6. When backend network fails completely', async () => {
    vi.spyOn(api, 'getJobStatus').mockRejectedValue(new Error('Failed to fetch'))
    vi.spyOn(api, 'getJobResult').mockRejectedValue(new Error('Failed to fetch'))

    render(
      <AnalysisProvider>
        <MemoryRouter initialEntries={['/console/forecast/network-err-job']}>
          <Routes>
            <Route element={<Layout status="READY" />}>
              <Route path="/console/forecast/:jobId" element={<Forecast />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AnalysisProvider>
    )

    // Should initially show Reconnecting / Processing continues banner or Visualizer, then bounded error
    expect(screen.getByText(/PROCESSING/i)).toBeInTheDocument()
  })

  it('7. Direct navigation to /console/forecast without jobId renders clean state without black screen', async () => {
    render(
      <AnalysisProvider>
        <MemoryRouter initialEntries={['/console/forecast']}>
          <Routes>
            <Route element={<Layout status="READY" />}>
              <Route path="/console/forecast" element={<Forecast />} />
            </Route>
          </Routes>
        </MemoryRouter>
      </AnalysisProvider>
    )

    // Either loads reference/cached data or clean empty state, but NEVER black screen
    expect(document.body.innerHTML).not.toBe('')
    expect(screen.getAllByText(/FORECAST/i).length).toBeGreaterThan(0)
  })

  it('8. ErrorBoundary intercepts catastrophic rendering crashes and prevents black screen', () => {
    const ProblematicComponent = () => {
      throw new Error('Simulated critical crash in Forecast child rendering')
    }

    render(
      <ErrorBoundary boundaryName="Forecast View">
        <ProblematicComponent />
      </ErrorBoundary>
    )

    // Should render ErrorBoundary instead of unmounting root to pitch black
    expect(screen.getByText(/Application Error Intercepted/i)).toBeInTheDocument()
    expect(screen.getByText(/Forecast View · Circuit Recovery/i)).toBeInTheDocument()
    expect(screen.getByText(/Return to Analysis/i)).toBeInTheDocument()
  })

  it('9. ForecastConsole safely handles empty forecast points without throwing', () => {
    const canonical = adaptToCanonical(fixture.results, 'test-id')
    const emptyPointsAnalysis = {
      ...canonical,
      forecast: {
        ...canonical.forecast,
        isAvailable: false,
        points: [],
      },
    }

    render(
      <MemoryRouter>
        <ForecastConsole analysis={emptyPointsAnalysis as any} />
      </MemoryRouter>
    )

    // Successfully renders without throwing TypeError
    expect(screen.getAllByText(/SAFETY GUARDRAIL ACTIVE/i).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/FORECAST ROLLOUT/i).length).toBeGreaterThan(0)
  })
})
