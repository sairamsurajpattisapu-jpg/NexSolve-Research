import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Dashboard } from '../pages/Dashboard'
import { Forecast } from '../pages/Forecast'
import { Landing } from '../pages/Landing'
import { Layout } from '../components/Layout'
import { fixture } from './fixtures'
import * as useProductionDataModule from '../hooks/useProductionData'
import * as useJobPollingModule from '../hooks/useJobPolling'
import { clearAnalysisHistory, recordAnalysisHistory } from '../utils/analysisHistory'

describe('End-to-End Analysis Experience & Product Journey (Prompt 3)', () => {
  beforeEach(() => {
    clearAnalysisHistory()
    vi.restoreAllMocks()
  })

  it('1. Landing page features START as primary CTA and routes to /console/analyze', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Landing />} />
        </Routes>
      </MemoryRouter>
    )

    const startLink = screen.getByRole('link', { name: /^START/i })
    expect(startLink).toBeInTheDocument()
    expect(startLink).toHaveAttribute('href', '/console/analyze')

    // Also preserves secondary links
    expect(screen.getByRole('link', { name: /Analyze PCAP/i })).toBeInTheDocument()
    expect(screen.getByRole('link', { name: /Explore Workflow/i })).toBeInTheDocument()
  })

  it('2. Analysis entry screen displays clear narrative and Upload PCAP primary action', () => {
    render(
      <MemoryRouter initialEntries={['/analyze']}>
        <Dashboard />
      </MemoryRouter>
    )

    // Clear narrative
    expect(
      screen.getAllByText(/Upload network telemetry to reconstruct the current network state and forecast future attack progression/i).length
    ).toBeGreaterThan(0)

    // Primary upload action and specifications
    expect(screen.getByText(/Upload PCAP/i)).toBeInTheDocument()
    expect(screen.getByText(/\.pcap, \.pcapng/i)).toBeInTheDocument()
    expect(screen.getByText(/1 GiB/i)).toBeInTheDocument()
  })

  it('3. File dropzone enforces .pcap/.pcapng validation and rejects invalid extensions', () => {
    render(
      <MemoryRouter initialEntries={['/analyze']}>
        <Dashboard />
      </MemoryRouter>
    )

    const input = screen.getByLabelText(/Choose PCAP capture/i)
    expect(input).toHaveAttribute('accept', '.pcap,.pcapng')

    // Simulate uploading unsupported text file
    const invalidFile = new File(['invalid dummy payload'], 'malware_sample.exe', { type: 'application/octet-stream' })
    fireEvent.change(input, { target: { files: [invalidFile] } })

    expect(screen.getByText(/Choose a \.pcap or \.pcapng capture\./i)).toBeInTheDocument()
  })

  it('4. Staged Analysis Confirmation card displays File, Size, Format, Mode, and Start Analysis CTA', async () => {
    render(
      <MemoryRouter initialEntries={['/analyze']}>
        <Dashboard />
      </MemoryRouter>
    )

    const input = screen.getByLabelText(/Choose PCAP capture/i)
    const validFile = new File([new ArrayBuffer(1024 * 1024 * 5)], 'Friday-WorkingHours.pcap', { type: 'application/vnd.tcpdump.pcap' })
    fireEvent.change(input, { target: { files: [validFile] } })

    // Confirmation Card contents
    expect(screen.getByText(/ANALYSIS CONFIRMATION/i)).toBeInTheDocument()
    expect(screen.getByText(/Ready to Start Analysis/i)).toBeInTheDocument()
    expect(screen.getByText('Friday-WorkingHours.pcap')).toBeInTheDocument()
    expect(screen.getByText('5.00 MB')).toBeInTheDocument()
    expect(screen.getByText(/Standard PCAP \(libpcap\)/i)).toBeInTheDocument()
    expect(screen.getByText(/Multi-Horizon \(T\+1\.\.T\+5\)/i)).toBeInTheDocument()
    expect(screen.getByText(/Format validated · Ready for ingestion/i)).toBeInTheDocument()

    // Confirmation Buttons
    expect(screen.getByRole('button', { name: /Start Analysis/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Choose Another File/i })).toBeInTheDocument()
  })

  it('5. Layout renders persistent Navigation Context banner across the session', () => {
    render(
      <MemoryRouter initialEntries={['/analyze']}>
        <Routes>
          <Route element={<Layout status="READY" />}>
            <Route path="*" element={<div>Active Child Page</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    )

    const contextStrip = screen.getByTestId('navigation-context-strip')
    expect(contextStrip).toBeInTheDocument()
    expect(contextStrip).toHaveTextContent(/Analysis:/i)
    expect(contextStrip).toHaveTextContent(/Status:/i)
  })

  it('6. Forecast Console presents concise Result Summary strip without card spam', () => {
    vi.spyOn(useProductionDataModule, 'useProductionData').mockReturnValue({
      data: fixture,
      loading: false,
      error: null,
      reload: vi.fn(),
      analysisSource: 'uploaded',
      provenance: 'uploaded',
      apiConnected: true,
    } as any)

    render(
      <MemoryRouter initialEntries={['/forecast']}>
        <Forecast />
      </MemoryRouter>
    )

    const summaryStrip = screen.getByTestId('result-summary-strip')
    expect(summaryStrip).toBeInTheDocument()
    expect(summaryStrip).toHaveTextContent(/CURRENT NETWORK STATE/i)
    expect(summaryStrip).toHaveTextContent(/FORECAST HORIZON/i)
    expect(summaryStrip).toHaveTextContent(/ATTACK RISK/i)
    expect(summaryStrip).toHaveTextContent(/PREDICTED PROGRESSION/i)
    expect(summaryStrip).toHaveTextContent(/EVIDENCE AVAILABILITY/i)
  })

  it('7. Analysis failure displays friendly recovery with Retry, Another File, Return to Console, and Diagnostics', () => {
    vi.spyOn(useJobPollingModule, 'useJobPolling').mockReturnValue({
      job: { job_id: 'job-err-123', status: 'FAILED', stage: 'INGESTION', progress: 0.1 },
      result: null,
      stage: 'INGESTION',
      progress: 10,
      status: 'FAILED',
      error: 'Truncated packet frame at byte offset 4096.',
      isPolling: false,
      isReconnecting: false,
      reconnectAttempt: 0,
      isComplete: false,
      reload: vi.fn(),
    } as any)

    render(
      <MemoryRouter initialEntries={['/forecast/job-err-123']}>
        <Routes>
          <Route path="/forecast/:jobId" element={<Forecast />} />
        </Routes>
      </MemoryRouter>
    )

    expect(screen.getByText(/Analysis could not be completed\./i)).toBeInTheDocument()
    expect(screen.getAllByText(/Truncated packet frame at byte offset 4096\./i).length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: /Retry Analysis/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Choose Another File/i })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Return to Console/i })).toBeInTheDocument()
    expect(screen.getByText(/Technical Diagnostics/i)).toBeInTheDocument()
  })

  it('8. Analysis History architecture panel records captures and allows context restoration', () => {
    recordAnalysisHistory({
      id: 'job-hist-abc',
      filename: 'perimeter_traffic.pcap',
      filesize: '14.50 MB',
      timestamp: new Date().toISOString(),
      status: 'COMPLETED',
      provenance: 'uploaded',
      peakRiskPct: 82.5,
    })

    render(
      <MemoryRouter initialEntries={['/analyze']}>
        <Dashboard />
      </MemoryRouter>
    )

    expect(screen.getByText(/ANALYSIS HISTORY · SESSION CAPTURES/i)).toBeInTheDocument()
    expect(screen.getByText('perimeter_traffic.pcap')).toBeInTheDocument()
    expect(screen.getByText(/Risk: 82.5%/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Open Forecast/i })).toBeInTheDocument()
  })
})
