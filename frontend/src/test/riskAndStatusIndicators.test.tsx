import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { AnalysisStatusBadge } from '../components/AnalysisStatusBadge'
import { Overview } from '../pages/Overview'
import { Dashboard } from '../pages/Dashboard'
import * as useProductionDataModule from '../hooks/useProductionData'
import { REFERENCE_BENCHMARK_DATA } from '../stores/referenceFixture'
import {
  clearAnalysisHistory,
  getAnalysisHistory,
  recordAnalysisHistory,
} from '../utils/analysisHistory'
import {
  formatRiskPercentage,
  normalizeRiskPercentage,
  normalizeRiskPercentageDisplay,
} from '../utils/format'

describe('Peak Risk Percentage Normalization Suite (Section 1, 7, 8)', () => {
  it('correctly normalizes 0–1 probability values into 0–100 percentages', () => {
    expect(normalizeRiskPercentage(0.0)).toBe(0)
    expect(normalizeRiskPercentage(0.25)).toBe(25)
    expect(normalizeRiskPercentage(0.5)).toBe(50)
    expect(normalizeRiskPercentage(0.72)).toBe(72)
    expect(normalizeRiskPercentage(1)).toBe(100)
    expect(normalizeRiskPercentage(1.0)).toBe(100)
  })

  it('correctly preserves 0–100 percentage and score values', () => {
    expect(normalizeRiskPercentage(72)).toBe(72)
    expect(normalizeRiskPercentage(82.5)).toBe(82.5)
    expect(normalizeRiskPercentage(100)).toBe(100)
  })

  it('correctly treats out-of-bound percentages outside [0, 100] as invalid corrupted data returning null', () => {
    expect(normalizeRiskPercentage(120)).toBeNull()
    expect(normalizeRiskPercentage(5042)).toBeNull()
    expect(normalizeRiskPercentage(99999)).toBeNull()
    expect(normalizeRiskPercentage(-10)).toBeNull()
    expect(normalizeRiskPercentage(-0.5)).toBeNull()
  })

  it('safely rejects NaN, Infinity, -Infinity, null, and undefined by returning null', () => {
    expect(normalizeRiskPercentage(NaN)).toBeNull()
    expect(normalizeRiskPercentage(Infinity)).toBeNull()
    expect(normalizeRiskPercentage(-Infinity)).toBeNull()
    expect(normalizeRiskPercentage(null)).toBeNull()
    expect(normalizeRiskPercentage(undefined)).toBeNull()
    expect(normalizeRiskPercentage('invalid' as unknown as number)).toBeNull()
  })

  it('formats risk percentages into human-readable display values (Section 8 assertions)', () => {
    // 0.0 -> 0%
    expect(formatRiskPercentage(0.0)).toBe('0%')
    // 0.25 -> 25%
    expect(formatRiskPercentage(0.25)).toBe('25%')
    // 0.5 -> 50%
    expect(formatRiskPercentage(0.5)).toBe('50%')
    // 0.72 -> 72%
    expect(formatRiskPercentage(0.72)).toBe('72%')
    // 1 -> 100%
    expect(formatRiskPercentage(1)).toBe('100%')
    expect(formatRiskPercentage(1.0)).toBe('100%')

    // Canonical 0–100 values remain unchanged
    expect(formatRiskPercentage(50.42)).toBe('50%')
    expect(formatRiskPercentage(50.42, '—', { decimals: 1 })).toBe('50.4%')
    // 72 -> 72%
    expect(formatRiskPercentage(72)).toBe('72%')
    // 100 -> 100%
    expect(formatRiskPercentage(100)).toBe('100%')

    // Out-of-bounds values are treated as invalid and return fallback '—' (not 100%)
    expect(formatRiskPercentage(120)).toBe('—')
    expect(formatRiskPercentage(5042)).toBe('—')
    expect(formatRiskPercentage(-10)).toBe('—')

    // Defensive fallback handling
    expect(formatRiskPercentage(NaN)).toBe('—')
    expect(formatRiskPercentage(Infinity)).toBe('—')
    expect(formatRiskPercentage(-Infinity)).toBe('—')
    expect(formatRiskPercentage(null)).toBe('—')
    expect(formatRiskPercentage(undefined)).toBe('—')

    // Alias verification
    expect(normalizeRiskPercentageDisplay(0.72)).toBe('72%')
    expect(normalizeRiskPercentageDisplay(5042)).toBe('—')
    expect(normalizeRiskPercentageDisplay(undefined)).toBe('—')
  })
})

describe('Semantic Status Indicators Suite (Sections 2, 3, 4, 5)', () => {
  it('renders COMPLETED with a static muted green indicator dot', () => {
    const { container } = render(<AnalysisStatusBadge status="COMPLETED" />)
    const dot = container.querySelector('.analysis-status-dot.dot-completed')
    expect(dot).toBeInTheDocument()
    expect(screen.getByText('COMPLETED')).toBeInTheDocument()
  })

  it('renders PROCESSING with an animated pulsing muted blue/neutral indicator dot', () => {
    const { container } = render(<AnalysisStatusBadge status="PROCESSING" />)
    const dot = container.querySelector('.analysis-status-dot.dot-processing')
    expect(dot).toBeInTheDocument()
    expect(screen.getByText('PROCESSING')).toBeInTheDocument()
  })

  it('renders FAILED with a static muted red indicator dot', () => {
    const { container } = render(<AnalysisStatusBadge status="FAILED" />)
    const dot = container.querySelector('.analysis-status-dot.dot-failed')
    expect(dot).toBeInTheDocument()
    expect(screen.getByText('FAILED')).toBeInTheDocument()
  })

  it('renders QUEUED with a static muted amber indicator dot', () => {
    const { container } = render(<AnalysisStatusBadge status="QUEUED" />)
    const dot = container.querySelector('.analysis-status-dot.dot-queued')
    expect(dot).toBeInTheDocument()
    expect(screen.getByText('QUEUED')).toBeInTheDocument()
  })
})

describe('Analysis History & Peak Risk Integration (Sections 1, 6, 9)', () => {
  beforeEach(() => {
    clearAnalysisHistory()
    vi.restoreAllMocks()
  })

  it('strips invalid/corrupted risk percentages and normalizes valid values when storing and retrieving from analysis history', () => {
    // 1. Pre-existing corrupted storage entry (e.g. 5042)
    localStorage.setItem(
      'nexsolve-analysis-history',
      JSON.stringify([
        {
          id: 'job-5042',
          filename: 'threat_stream.pcap',
          timestamp: new Date().toISOString(),
          status: 'COMPLETED',
          provenance: 'uploaded',
          peakRiskPct: 5042, // Erroneous raw multiplier
        },
      ])
    )

    // Retrieval should strip 5042 to undefined (not falsely clamp to 100)
    const items = getAnalysisHistory()
    expect(items.length).toBe(1)
    expect(items[0].peakRiskPct).toBeUndefined()

    // Retrieval also migrates and heals storage
    const rawSaved = localStorage.getItem('nexsolve-analysis-history')
    expect(rawSaved).not.toBeNull()
    const parsedSaved = JSON.parse(rawSaved!)
    expect(parsedSaved[0].peakRiskPct).toBeUndefined()

    // 2. Normalizing valid probability when recording new entry
    recordAnalysisHistory({
      id: 'job-prob',
      filename: 'prob_stream.pcap',
      timestamp: new Date().toISOString(),
      status: 'COMPLETED',
      provenance: 'uploaded',
      peakRiskPct: 0.72,
    })

    const itemsAfterRecord = getAnalysisHistory()
    const probItem = itemsAfterRecord.find((i) => i.id === 'job-prob')
    expect(probItem?.peakRiskPct).toBe(72)
  })

  it('Overview page renders PEAK RISK as "—" when historical entry had corrupted 5042 value (not falsely 100%)', () => {
    recordAnalysisHistory({
      id: 'job-corrupted',
      filename: 'corrupted_sample.pcap',
      timestamp: new Date().toISOString(),
      status: 'COMPLETED',
      provenance: 'uploaded',
      peakRiskPct: 5042, // Corrupted data
    })

    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: {
        results: {
          traffic: { windows: 2, flows: 100, packets: 500 },
          detection: { risk_score: 70 },
          analysis_id: 'prod-test-corrupted',
        },
      } as any,
      loading: false,
      error: null,
      analysisSource: 'production',
      provenance: 'reference',
      isReferenceDataset: true,
      isLiveCapture: false,
      analysisId: 'prod-test-corrupted',
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

    // Should display PEAK RISK header
    expect(screen.getByText('PEAK RISK')).toBeInTheDocument()
    // Should display fallback "—", NOT 100% or 5042%
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.queryByText('100%')).not.toBeInTheDocument()
    expect(screen.queryByText(/5042/)).not.toBeInTheDocument()
  })

  it('Overview page renders PEAK RISK with normalized values and never 5042%', () => {
    recordAnalysisHistory({
      id: 'job-test-overview',
      filename: 'perimeter_core.pcap',
      timestamp: new Date().toISOString(),
      status: 'COMPLETED',
      provenance: 'uploaded',
      peakRiskPct: 50.42, // Stored as 50.42%
    })

    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: {
        results: {
          traffic: { windows: 2, flows: 100, packets: 500 },
          detection: { risk_score: 70 },
          analysis_id: 'prod-test',
        },
      } as any,
      loading: false,
      error: null,
      analysisSource: 'production',
      provenance: 'reference',
      isReferenceDataset: true,
      isLiveCapture: false,
      analysisId: 'prod-test',
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

    // Should display PEAK RISK header
    expect(screen.getByText('PEAK RISK')).toBeInTheDocument()
    // 50.42% rounded -> 50%, NOT 5042%
    expect(screen.getByText('50%')).toBeInTheDocument()
    expect(screen.queryByText(/5042%/)).not.toBeInTheDocument()
    // Should have COMPLETED status indicator
    expect(screen.getByText('COMPLETED')).toBeInTheDocument()
  })

  it('Overview page displays — when peak risk is unavailable rather than NaN%', () => {
    recordAnalysisHistory({
      id: 'job-test-no-risk',
      filename: 'empty_scan.pcap',
      timestamp: new Date().toISOString(),
      status: 'PROCESSING',
      provenance: 'uploaded',
      peakRiskPct: undefined,
    })

    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: {
        results: {
          traffic: { windows: 2, flows: 100, packets: 500 },
          detection: { risk_score: 70 },
          analysis_id: 'prod-test-2',
        },
      } as any,
      loading: false,
      error: null,
      analysisSource: 'production',
      provenance: 'reference',
      isReferenceDataset: true,
      isLiveCapture: false,
      analysisId: 'prod-test-2',
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

    expect(screen.getByText('PEAK RISK')).toBeInTheDocument()
    expect(screen.getByText('—')).toBeInTheDocument()
    expect(screen.queryByText(/NaN%/)).not.toBeInTheDocument()
    expect(screen.queryByText(/undefined%/)).not.toBeInTheDocument()
    expect(screen.getByText('PROCESSING')).toBeInTheDocument()
  })

  it('Dashboard renders analysis history with normalized risk percentage and semantic badge', () => {
    recordAnalysisHistory({
      id: 'job-dashboard-test',
      filename: 'perimeter_snort.pcap',
      filesize: '12.0 MB',
      timestamp: new Date().toISOString(),
      status: 'COMPLETED',
      provenance: 'uploaded',
      peakRiskPct: 82.5,
    })

    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: REFERENCE_BENCHMARK_DATA as any,
      loading: false,
      error: null,
      analysisSource: 'production',
      provenance: 'reference',
      isReferenceDataset: true,
      isLiveCapture: false,
      analysisId: 'prod-test-3',
      apiConnected: true,
      uploadError: null,
      reload: vi.fn(),
      analyzePcap: vi.fn(),
      clearUploadedAnalysis: vi.fn(),
      clearUploadError: vi.fn(),
      setUploadedAnalysis: vi.fn(),
    })

    render(
      <MemoryRouter initialEntries={['/analyze']}>
        <Routes>
          <Route path="/analyze" element={<Dashboard />} />
        </Routes>
      </MemoryRouter>
    )

    expect(screen.getByText('perimeter_snort.pcap')).toBeInTheDocument()
    expect(screen.getByText(/Risk: 82.5%/i)).toBeInTheDocument()
    expect(screen.getByText('COMPLETED')).toBeInTheDocument()
  })
})
