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

  it('1. Opening /console with reference benchmark explicitly badges DEMO / REFERENCE and clean empty state', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: REFERENCE_BENCHMARK_DATA,
      loading: false,
      error: null,
      analysisSource: 'production',
      provenance: 'reference',
      isReferenceDataset: true,
      isLiveCapture: false,
      analysisId: 'production-cic-ids2017',
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

    // Header badge
    expect(screen.getByText('NO ACTIVE USER SESSION')).toBeInTheDocument()

    // Clean callout for visitor
    expect(screen.getByText('NO ACTIVE ANALYSIS')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 2, name: /Ready to analyze network traffic captures/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Start New Analysis/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /View CLI Instructions/i })).toBeInTheDocument()

    // Reference benchmark explicit labeling
    expect(screen.getByText('DEMO / REFERENCE ANALYSIS')).toBeInTheDocument()
    expect(screen.getByText('CIC-IDS2017 BENCHMARK FIXTURE')).toBeInTheDocument()
    expect(screen.getByText(/The metrics below reflect the pre-computed CIC-IDS2017 benchmark baseline for model verification/i)).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /View Reference Forecast/i })).toBeInTheDocument()
  })

  it('2. Layout navigation context strip displays DEMO / REFERENCE badge and Analyze your PCAP link for reference benchmark', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: REFERENCE_BENCHMARK_DATA,
      loading: false,
      error: null,
      analysisSource: 'production',
      provenance: 'reference',
      isReferenceDataset: true,
      isLiveCapture: false,
      analysisId: 'production-cic-ids2017',
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
    expect(contextStrip).toHaveTextContent('DEMO / REFERENCE')
    expect(contextStrip).toHaveTextContent('CIC-IDS2017 Reference Benchmark')
    expect(contextStrip).toHaveTextContent('Reference Baseline Active')
    expect(screen.getByRole('link', { name: /Analyze your PCAP/i })).toBeInTheDocument()
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
