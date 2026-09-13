import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { Demo } from '../pages/Demo'
import { Evidence } from '../pages/Evidence'
import { Forecast } from '../pages/Forecast'
import { Landing } from '../pages/Landing'
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
      expect(screen.getByText(/See where the network is heading/i)).toBeInTheDocument()
      expect(screen.getByRole('link', { name: /Analyze a PCAP Capture/i })).toBeInTheDocument()
      expect(screen.getByRole('link', { name: /Explore Judge Demo/i })).toBeInTheDocument()
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

  describe('Demo Page', () => {
    it('renders 60-second judge guidance and scenario selector', () => {
      render(
        <MemoryRouter>
          <Demo />
        </MemoryRouter>
      )

      expect(screen.getByText(/SIH Judge Demo Explorer & Evaluation Journey/i)).toBeInTheDocument()
      expect(screen.getByText(/60-SECOND JURY EVALUATION JOURNEY/i)).toBeInTheDocument()
      expect(screen.getByText(/1. Early Attack Signal/i)).toBeInTheDocument()
      expect(screen.getByText(/2. Contradictory Evidence/i)).toBeInTheDocument()
      expect(screen.getByText(/3. Forecast Abstained/i)).toBeInTheDocument()
    })
  })
})
