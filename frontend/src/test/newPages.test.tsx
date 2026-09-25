import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { Evidence } from '../pages/Evidence'
import { Faq } from '../pages/Faq'
import { Forecast } from '../pages/Forecast'
import { Landing } from '../pages/Landing'
import { NotFound } from '../pages/NotFound'
import { Progression } from '../pages/Progression'
import { Settings } from '../pages/Settings'
import { fixture } from './fixtures'

vi.mock('../hooks/useProductionData', () => ({
  useProductionData: () => ({
    data: fixture,
    loading: false,
    error: null,
    analysisSource: 'production',
    provenance: 'reference',
    reload: vi.fn(),
    analyzePcap: vi.fn(),
    clearUploadedAnalysis: vi.fn(),
    setUploadedAnalysis: vi.fn(),
    uploadError: null,
    analysisId: 'production-cic-ids2017',
  }),
}))

describe('New Product Pages Suite', () => {
  describe('Landing Page', () => {
    it('renders hero title, taglines, and primary CTAs', () => {
      render(
        <MemoryRouter>
          <Landing />
        </MemoryRouter>
      )

      expect(screen.getByRole('heading', { level: 1, name: /NEXSOLVE/i })).toBeInTheDocument()
      expect(screen.getAllByRole('link', { name: /Use NexSolve CLI/i })[0]).toBeInTheDocument()
      expect(screen.getByRole('link', { name: /View CLI Commands/i })).toBeInTheDocument()
      expect(screen.getByRole('link', { name: /View workflow/i })).toBeInTheDocument()
    })

    it('supports interactive pipeline tour stage navigation', async () => {
      const user = userEvent.setup()
      render(
        <MemoryRouter>
          <Landing />
        </MemoryRouter>
      )

      expect(screen.getByText(/STAGE 01 OF 08/i)).toBeInTheDocument()
      const nextBtn = screen.getByRole('button', { name: /Next Stage/i })
      await user.click(nextBtn)
      expect(screen.getByText(/STAGE 02 OF 08/i)).toBeInTheDocument()
    })
  })

  describe('Forecast Page', () => {
    it('renders multi-horizon forecast rollout headers and governance', () => {
      render(
        <MemoryRouter>
          <Forecast />
        </MemoryRouter>
      )

      expect(screen.getByText(/Multi-Step Attack Forecasting/i)).toBeInTheDocument()
      expect(screen.getByText(/CHAMPION MODEL/i)).toBeInTheDocument()
      expect(screen.getAllByText(/Persistence Baseline/i)[0]).toBeInTheDocument()
      expect(screen.getByText(/LSTM45 Model \(HOLD\)/i)).toBeInTheDocument()
    })
  })

  describe('Evidence Page', () => {
    it('renders evidence attribution summary and filter controls', () => {
      render(
        <MemoryRouter>
          <Evidence />
        </MemoryRouter>
      )

      expect(screen.getByText(/Evidence Chain & Attribution Explorer/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /All/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Supporting/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Contradictory/i })).toBeInTheDocument()
      expect(screen.getByPlaceholderText(/Search features/i)).toBeInTheDocument()
    })
  })

  describe('Progression Page', () => {
    it('renders multi-step dynamics, 3-tier operational linkage, and horizon steppers', () => {
      render(
        <MemoryRouter>
          <Progression />
        </MemoryRouter>
      )

      expect(screen.getByText(/ATTACK PROGRESSION TIMELINE/i)).toBeInTheDocument()
      expect(screen.getByText(/3-TIER OPERATIONAL LINKAGE/i)).toBeInTheDocument()
      expect(screen.getByText(/01 · OBSERVED EVIDENCE/i)).toBeInTheDocument()
      expect(screen.getByText(/02 · DETECTED BEHAVIOR/i)).toBeInTheDocument()
      expect(screen.getByText(/03 · PREDICTED PROGRESSION/i)).toBeInTheDocument()
      expect(screen.getByText(/MITRE ATT&CK BEHAVIORAL INTERPRETATION/i)).toBeInTheDocument()
    })
  })

  describe('NotFound Page', () => {
    it('renders 404 header and recovery CTAs', () => {
      render(
        <MemoryRouter>
          <NotFound />
        </MemoryRouter>
      )

      expect(screen.getByText(/404/i)).toBeInTheDocument()
      expect(screen.getByText(/Page Not Found/i)).toBeInTheDocument()
      expect(screen.getByRole('link', { name: /Back to Console/i })).toBeInTheDocument()
      expect(screen.getByRole('link', { name: /Return Home/i })).toBeInTheDocument()
    })
  })

  describe('Faq Page', () => {
    it('renders categories, accordion questions, and toggles items', async () => {
      const user = userEvent.setup()
      render(
        <MemoryRouter>
          <Faq />
        </MemoryRouter>
      )

      expect(screen.getByText(/Technical & Operational FAQ/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /^ALL$/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /^Data Ingestion$/i })).toBeInTheDocument()

      const questionBtn = screen.getByRole('button', { name: /Does NexSolve analyze PCAP files\?/i })
      expect(questionBtn).toBeInTheDocument()
      await user.click(questionBtn)
      expect(screen.getByText(/NexSolve natively ingests microsecond-precision/i)).toBeInTheDocument()
    })
  })

  describe('Settings Page', () => {
    it('renders appearance and motion controls', async () => {
      const user = userEvent.setup()
      render(
        <MemoryRouter>
          <Settings />
        </MemoryRouter>
      )

      expect(screen.getByText(/System configuration/i)).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Dark Theme/i })).toBeInTheDocument()
      expect(screen.getByRole('button', { name: /Light Theme/i })).toBeInTheDocument()

      const motionToggle = screen.getByRole('button', { name: /Toggle Reduced Motion/i })
      expect(motionToggle).toBeInTheDocument()
      await user.click(motionToggle)
      expect(motionToggle).toHaveAttribute('aria-pressed', 'true')
    })
  })
})
