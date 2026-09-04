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
  useProductionData: () => ({ ...hookState, reload, analyzePcap: vi.fn().mockResolvedValue(null), clearUploadedAnalysis, uploadError: null, analysisId: 'production-cic-ids2017' }),
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
    expect(screen.getByText('Loading production analysis')).toBeInTheDocument()
  })

  it('renders the backend error state', () => {
    hookState = { data: null, loading: false, error: 'Backend unavailable', analysisSource: 'production' }
    renderPage(<Dashboard />)
    expect(screen.getByText('Backend unavailable', { selector: 'strong' })).toBeInTheDocument()
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
    fireEvent.click(screen.getByRole('button', { name: 'Return to production' }))
    expect(clearUploadedAnalysis).toHaveBeenCalled()
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
