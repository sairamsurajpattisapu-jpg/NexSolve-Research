import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import type { ReactNode } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Dashboard } from '../pages/Dashboard'
import { Threats } from '../pages/Threats'
import { fixture } from './fixtures'

const reload = vi.fn()
const clearUploadedAnalysis = vi.fn()
let hookState: { data: typeof fixture | null; loading: boolean; error: string | null; analysisSource: 'production' | 'uploaded' } = { data: fixture, loading: false, error: null, analysisSource: 'production' }

vi.mock('../hooks/useProductionData', () => ({
  useProductionData: () => ({ ...hookState, reload, analyzePcap: vi.fn().mockResolvedValue(null), clearUploadedAnalysis, clearUploadError: vi.fn(), uploadError: null, analysisId: 'production-cic-ids2017' }),
}))

function renderPage(page: ReactNode) {
  return render(<MemoryRouter>{page}</MemoryRouter>)
}

beforeEach(() => {
  hookState = { data: fixture, loading: false, error: null, analysisSource: 'production' }
  reload.mockReset()
  clearUploadedAnalysis.mockReset()
})

describe('Dashboard', () => {
  it('renders metrics from the API data', () => {
    renderPage(<Dashboard />)
    expect(screen.getByText('12', { selector: '.metric-accent strong' })).toBeInTheDocument()
    expect(screen.getByText('70.0', { selector: '.metric-danger strong' })).toBeInTheDocument()
    expect(screen.getByText('Packet activity')).toBeInTheDocument()
  })

  it('renders the loading state', () => {
    hookState = { data: null, loading: true, error: null, analysisSource: 'production' }
    renderPage(<Dashboard />)
    expect(screen.getByText('Preparing analysis...')).toBeInTheDocument()
  })

  it('renders the backend error state', () => {
    hookState = { data: null, loading: false, error: 'Backend unavailable', analysisSource: 'production' }
    renderPage(<Dashboard />)
    expect(screen.getByText('Service Temporarily Unavailable', { selector: 'strong' })).toBeInTheDocument()
  })

  it('renders the real PCAP upload entry point', () => {
    renderPage(<Dashboard />)
    expect(screen.getByText('Analyze a PCAP or PCAPNG capture')).toBeInTheDocument()
    expect(screen.getByLabelText('Choose PCAP capture')).toHaveAttribute('accept', '.pcap,.pcapng')
  })

  it('rejects unsupported capture extensions and clears uploaded sessions', async () => {
    renderPage(<Dashboard />)
    fireEvent.change(screen.getByLabelText('Choose PCAP capture'), { target: { files: [new File(['data'], 'capture.txt', { type: 'text/plain' })] } })
    expect(screen.getByText('Choose a .pcap or .pcapng capture.')).toBeInTheDocument()
    hookState = { data: fixture, loading: false, error: null, analysisSource: 'uploaded' }
    renderPage(<Dashboard />)
    fireEvent.click(screen.getByRole('button', { name: /Return to (reference dataset|production)/i }))
    expect(clearUploadedAnalysis).toHaveBeenCalled()
  })

  it('renders reference dataset provenance labels when no PCAP is uploaded', () => {
    hookState = { data: fixture, loading: false, error: null, analysisSource: 'production' }
    renderPage(<Dashboard />)
    expect(screen.getByTestId('provenance-banner-reference')).toBeInTheDocument()
    expect(screen.getAllByText('VERIFIED REFERENCE DATASET').length).toBeGreaterThan(0)
    expect(screen.getAllByText('CIC-IDS2017').length).toBeGreaterThan(0)
    expect(screen.getByText('No PCAP analyzed yet')).toBeInTheDocument()
    expect(screen.getByText(/CIC-IDS2017 REFERENCE BENCHMARK METRICS/i)).toBeInTheDocument()
  })

  it('renders live PCAP analysis provenance when an uploaded capture is active', () => {
    const uploadedFixture = {
      ...fixture,
      results: {
        ...fixture.results,
        is_demo: false,
        source: { name: 'sample_capture.pcap', kind: 'uploaded_pcap' },
        analysis_id: 'job-987654321',
      },
    }
    hookState = { data: uploadedFixture, loading: false, error: null, analysisSource: 'uploaded' }
    renderPage(<Dashboard />)
    expect(screen.getByTestId('provenance-banner-live')).toBeInTheDocument()
    expect(screen.getAllByText('LIVE PCAP ANALYSIS').length).toBeGreaterThan(0)
    expect(screen.getAllByText('sample_capture.pcap').length).toBeGreaterThan(0)
    expect(screen.getAllByText(/job-987654321/i).length).toBeGreaterThan(0)
  })

  it('renders demo data and verified reference dataset labels in demo mode', () => {
    const demoFixture = {
      ...fixture,
      results: {
        ...fixture.results,
        is_demo: true,
        demo_scenario_name: 'Port Scan Progression',
        analysis_id: 'demo-port_scan_progression',
      },
    }
    hookState = { data: demoFixture, loading: false, error: null, analysisSource: 'uploaded' }
    renderPage(<Dashboard />)
    expect(screen.getByTestId('provenance-banner-demo')).toBeInTheDocument()
    expect(screen.getAllByText('DEMO DATA').length).toBeGreaterThan(0)
    expect(screen.getAllByText('VERIFIED REFERENCE DATASET').length).toBeGreaterThan(0)
    expect(screen.getAllByText(/Port Scan Progression/i).length).toBeGreaterThan(0)
  })
})

describe('Threats', () => {
  it('supports search and severity filtering', () => {
    renderPage(<Threats />)
    expect(screen.getByText('network reconnaissance')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: 'Search findings' }), { target: { value: 'network reconnaissance' } })
    expect(screen.getByText('network reconnaissance')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: 'Search findings' }), { target: { value: 'not present' } })
    expect(screen.getByText('No matching findings')).toBeInTheDocument()
    fireEvent.change(screen.getByRole('textbox', { name: 'Search findings' }), { target: { value: '' } })
    fireEvent.change(screen.getByRole('combobox', { name: 'Filter severity' }), { target: { value: 'low' } })
    expect(screen.getByText('No matching findings')).toBeInTheDocument()
  })
})
