import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Layout } from '../components/Layout'
import { Overview } from '../pages/Overview'
import * as useProductionDataModule from '../hooks/useProductionData'
import { REFERENCE_BENCHMARK_DATA } from '../stores/referenceFixture'

describe('Console Entry & Reference Transparency Suite', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('1. Opening /console with no active analysis displays clean empty state without fake data', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: null,
      loading: false,
      error: null,
      analysisSource: 'uploaded',
      provenance: 'uploaded',
      isReferenceDataset: false,
      isLiveCapture: false,
      analysisId: '',
      apiConnected: true,
      uploadError: null,
      reload: vi.fn(),
      analyzePcap: vi.fn(),
      clearUploadedAnalysis: vi.fn(),
      clearUploadError: vi.fn(),
      setUploadedAnalysis: vi.fn(),
    })

    render(
      <MemoryRouter initialEntries={['/console']}>
        <Routes>
          <Route path="/console" element={<Overview />} />
        </Routes>
      </MemoryRouter>
    )

    // Header and callout badges
    expect(screen.getAllByText('NO ACTIVE ANALYSIS').length).toBeGreaterThan(0)

    // Clean callout for visitor
    expect(screen.getByRole('heading', { level: 2, name: /Ready to analyze network traffic captures/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Start New Analysis/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /View CLI Instructions/i })).toBeInTheDocument()

    // Verify absence of fake benchmark / demo states
    expect(screen.queryByText('DEMO / REFERENCE ANALYSIS')).not.toBeInTheDocument()
    expect(screen.queryByText('CIC-IDS2017 BENCHMARK FIXTURE')).not.toBeInTheDocument()
  })

  it('2. Layout does not render fake reference context strip when no live capture is active', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: null,
      loading: false,
      error: null,
      analysisSource: 'uploaded',
      provenance: 'uploaded',
      isReferenceDataset: false,
      isLiveCapture: false,
      analysisId: '',
      apiConnected: true,
      uploadError: null,
      reload: vi.fn(),
      analyzePcap: vi.fn(),
      clearUploadedAnalysis: vi.fn(),
      clearUploadError: vi.fn(),
      setUploadedAnalysis: vi.fn(),
    })

    render(
      <MemoryRouter initialEntries={['/console']}>
        <Routes>
          <Route element={<Layout status="API connected" />}>
            <Route path="/console" element={<div>Console Page Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    )

    const contextStrip = screen.getByTestId('navigation-context-strip')
    expect(contextStrip).toBeInTheDocument()
    expect(contextStrip).not.toHaveTextContent('DEMO / REFERENCE')
    expect(contextStrip).not.toHaveTextContent('CIC-IDS2017 Reference Benchmark')
    expect(contextStrip).not.toHaveTextContent('Reference Baseline Active')
    expect(contextStrip).toHaveTextContent(/Analysis:/i)
    expect(contextStrip).toHaveTextContent(/Status:/i)
    expect(contextStrip).toHaveTextContent('No Active Capture')
    expect(contextStrip).toHaveTextContent('Ready')
  })

  it('3. Layout navigation context strip displays LIVE CAPTURE badge when live upload is active', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: {
        ...REFERENCE_BENCHMARK_DATA,
        results: {
          ...REFERENCE_BENCHMARK_DATA.results,
          source: { name: 'suspicious_traffic.pcap', filename: 'suspicious_traffic.pcap', kind: 'uploaded_pcap' },
          analysis_id: 'job-live-9921',
        },
      } as any,
      loading: false,
      error: null,
      analysisSource: 'uploaded',
      provenance: 'uploaded',
      isReferenceDataset: false,
      isLiveCapture: true,
      analysisId: 'job-live-9921',
      apiConnected: true,
      uploadError: null,
      reload: vi.fn(),
      analyzePcap: vi.fn(),
      clearUploadedAnalysis: vi.fn(),
      clearUploadError: vi.fn(),
      setUploadedAnalysis: vi.fn(),
    })

    render(
      <MemoryRouter initialEntries={['/console']}>
        <Routes>
          <Route element={<Layout status="API connected" />}>
            <Route path="/console" element={<div>Console Page Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    )

    const contextStrip = screen.getByTestId('navigation-context-strip')
    expect(contextStrip).toBeInTheDocument()
    expect(contextStrip).toHaveTextContent('LIVE CAPTURE')
    expect(contextStrip).toHaveTextContent('suspicious_traffic.pcap')
    expect(contextStrip).not.toHaveTextContent('DEMO / REFERENCE')
  })
})
