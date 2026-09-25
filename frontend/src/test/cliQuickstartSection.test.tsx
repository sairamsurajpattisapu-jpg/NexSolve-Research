import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { CliQuickstartSection } from '../components/landing/CliQuickstartSection'

describe('CliQuickstartSection & CLI Showcase Suite', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    Object.assign(navigator, {
      clipboard: {
        writeText: vi.fn().mockImplementation(() => Promise.resolve()),
      },
    })
  })

  it('renders section title, dual-interface tagline, and descriptive narrative', () => {
    render(
      <MemoryRouter>
        <CliQuickstartSection />
      </MemoryRouter>
    )

    expect(screen.getByRole('heading', { level: 2, name: /Run it from the terminal/i })).toBeInTheDocument()
    expect(screen.getByText('CLI')).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: 'NexSolve CLI' })).toBeInTheDocument()
    expect(screen.getByRole('heading', { level: 3, name: 'Web Investigation Console' })).toBeInTheDocument()
  })

  it('renders all 6 actual supported CLI commands with proper descriptions', () => {
    render(
      <MemoryRouter>
        <CliQuickstartSection />
      </MemoryRouter>
    )

    const expectedCommands = [
      'nexsolve',
      'nexsolve analyze',
      'nexsolve analyze capture.pcap',
      'nexsolve analyze capture.pcap --open',
      'nexsolve doctor',
      'nexsolve version',
    ]

    expectedCommands.forEach((cmd) => {
      expect(screen.getAllByText(cmd).length).toBeGreaterThan(0)
    })
  })

  it('renders the illustrative CLI terminal simulation with exact non-fabricated output', () => {
    render(
      <MemoryRouter>
        <CliQuickstartSection />
      </MemoryRouter>
    )

    expect(screen.getByText('Illustrative CLI output')).toBeInTheDocument()
    expect(screen.getAllByText('nexsolve analyze').length).toBeGreaterThan(0)
    expect(screen.getByText('Select a PCAP...')).toBeInTheDocument()
    expect(screen.getByText(/Native Windows File Picker Opened/i)).toBeInTheDocument()
    expect(screen.getByText(/perimeter_capture\.pcap/i)).toBeInTheDocument()
    expect(screen.getByText('Creating analysis job...')).toBeInTheDocument()
    expect(screen.getByText(/Reconstructing network state/i)).toBeInTheDocument()
    expect(screen.getByText(/Forecasting attack progression/i)).toBeInTheDocument()
    expect(screen.getByText('Analysis complete.')).toBeInTheDocument()
    expect(screen.getByText('Opening web investigation console...')).toBeInTheDocument()
  })

  it('renders all 6 architecture workflow stages from PCAP to INVESTIGATION', () => {
    render(
      <MemoryRouter>
        <CliQuickstartSection />
      </MemoryRouter>
    )

    expect(screen.getByText('PCAP')).toBeInTheDocument()
    expect(screen.getByText('TEMPORAL NETWORK STATE')).toBeInTheDocument()
    expect(screen.getByText('ATTACK PROGRESSION')).toBeInTheDocument()
    expect(screen.getByText('FORECAST')).toBeInTheDocument()
    expect(screen.getByText('EVIDENCE')).toBeInTheDocument()
    expect(screen.getByText('INVESTIGATION')).toBeInTheDocument()
  })

  it('copies command to clipboard and shows accessible Copied confirmation on click', async () => {
    render(
      <MemoryRouter>
        <CliQuickstartSection />
      </MemoryRouter>
    )

    const copyBtn = screen.getByRole('button', { name: 'Copy command nexsolve analyze' })
    expect(copyBtn).toBeInTheDocument()

    fireEvent.click(copyBtn)

    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('nexsolve analyze')
    expect(await screen.findByText('Copied')).toBeInTheDocument()
  })

  it('truthfully documents local repository installation without claiming PyPI availability', () => {
    render(
      <MemoryRouter>
        <CliQuickstartSection />
      </MemoryRouter>
    )

    expect(screen.getByRole('heading', { level: 3, name: /Install the NexSolve CLI/i })).toBeInTheDocument()
    expect(screen.getByText(/LOCAL REPOSITORY INSTALLATION/i)).toBeInTheDocument()
    expect(screen.getByText(/PyPI publication status:/i)).toBeInTheDocument()
    expect(screen.getByText('git clone https://github.com/sairamsurajpattisapu-jpg/NexSolve-Research.git')).toBeInTheDocument()
    expect(screen.getByText('pip install -e cli')).toBeInTheDocument()
    expect(screen.getAllByText('nexsolve doctor').length).toBeGreaterThan(0)
  })
})
