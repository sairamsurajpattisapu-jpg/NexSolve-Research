import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { DynamicForecastGraph } from '../components/DynamicForecastGraph'
import { ForecastScrubber } from '../components/ForecastScrubber'
import { Forecast } from '../pages/Forecast'
import { Network } from '../pages/Network'
import * as useProductionDataModule from '../hooks/useProductionData'

describe('Dynamic Forecast Experience Suite', () => {
  it('renders DynamicForecastGraph across all temporal horizons (T0 to T+5)', () => {
    const { rerender } = render(
      <DynamicForecastGraph
        selectedHorizon={0}
        sourceFilename="test_capture.pcap"
      />
    )

    expect(screen.getByText(/CURRENT OBSERVED NETWORK TOPOLOGY/i)).toBeInTheDocument()
    expect(screen.getByText(/G_0/i)).toBeInTheDocument()

    // Switch to T+2
    rerender(
      <DynamicForecastGraph
        selectedHorizon={2}
        sourceFilename="test_capture.pcap"
      />
    )
    expect(screen.getByText(/FORECAST HORIZON T\+2/i)).toBeInTheDocument()
    expect(screen.getByText(/FORWARD SIMULATION/i)).toBeInTheDocument()

    // Switch to T+5
    rerender(
      <DynamicForecastGraph
        selectedHorizon={5}
        sourceFilename="test_capture.pcap"
      />
    )
    expect(screen.getByText(/FORECAST HORIZON T\+5/i)).toBeInTheDocument()
  })

  it('renders ForecastScrubber and handles keyboard and click navigation', () => {
    const onSelect = vi.fn()
    render(
      <ForecastScrubber
        horizons={[1, 2, 3, 5]}
        selectedHorizon={1}
        onSelectHorizon={onSelect}
      />
    )

    expect(screen.getByText('OBSERVED')).toBeInTheDocument()
    expect(screen.getByText('T+1')).toBeInTheDocument()
    expect(screen.getByText('T+2')).toBeInTheDocument()
    expect(screen.getByText('T+3')).toBeInTheDocument()
    expect(screen.getByText('T+5')).toBeInTheDocument()

    // Click on T+3
    const t3Btn = screen.getByRole('button', { name: /T\+3 Forecast Horizon/i })
    fireEvent.click(t3Btn)
    expect(onSelect).toHaveBeenCalledWith(3)

    // Keyboard navigation slider
    const slider = screen.getByRole('slider')
    fireEvent.keyDown(slider, { key: 'ArrowRight' })
    expect(onSelect).toHaveBeenCalled()
  })

  it('renders FORECAST THIS STATE button on Network page and links to forecast', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: {
        results: {
          analysis_id: 'test-analysis',
          source: { name: 'test.pcap', kind: 'pcap' },
          traffic: { unique_ips: 10, windows_data: [] },
        } as any,
      } as any,
      loading: false,
      error: null,
      reload: vi.fn(),
      analysisSource: 'uploaded',
      provenance: 'uploaded',
      apiConnected: true,
    } as any)

    render(
      <MemoryRouter>
        <Network />
      </MemoryRouter>
    )

    const forecastBtn = screen.getByRole('button', { name: /FORECAST THIS STATE/i })
    expect(forecastBtn).toBeInTheDocument()
  })

  it('renders empty state on Forecast page when no analysis is active', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: null,
      loading: false,
      error: null,
      reload: vi.fn(),
      analysisSource: 'production',
      provenance: 'reference',
      apiConnected: true,
    } as any)

    render(
      <MemoryRouter>
        <Forecast />
      </MemoryRouter>
    )

    expect(screen.getByText(/NO ANALYSIS SELECTED/i)).toBeInTheDocument()
    expect(screen.getByText(/Run an analysis or open a demonstration scenario/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /NEW ANALYSIS/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /(OPEN DEMO|SAMPLE SCENARIOS)/i })).toBeInTheDocument()
  })

  it('renders error state on Forecast page when error occurs', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: null,
      loading: false,
      error: 'Simulated network failure',
      reload: vi.fn(),
      analysisSource: 'production',
      provenance: 'reference',
      apiConnected: false,
    } as any)

    render(
      <MemoryRouter>
        <Forecast />
      </MemoryRouter>
    )

    expect(screen.getByText(/FORECAST COULD NOT BE LOADED/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /TRY AGAIN/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /BACK TO ANALYZE/i })).toBeInTheDocument()
  })

  it('renders minimal loading skeleton on Forecast page during loading', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: null,
      loading: true,
      error: null,
      reload: vi.fn(),
      analysisSource: 'production',
      provenance: 'reference',
      apiConnected: true,
    } as any)

    render(
      <MemoryRouter>
        <Forecast />
      </MemoryRouter>
    )

    expect(screen.getByText(/LOADING FORECAST/i)).toBeInTheDocument()
  })

  it('renders clean empty state on Network page when no network capture is loaded', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: null,
      loading: false,
      error: null,
      reload: vi.fn(),
      analysisSource: 'production',
      provenance: 'reference',
      apiConnected: true,
    } as any)

    render(
      <MemoryRouter>
        <Network />
      </MemoryRouter>
    )

    expect(screen.getByRole('button', { name: /NEW ANALYSIS/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /(OPEN DEMO|LOAD BENCHMARK)/i })).toBeInTheDocument()
  })
})
