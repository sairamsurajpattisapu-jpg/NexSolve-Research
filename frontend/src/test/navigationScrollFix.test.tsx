import { render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Landing } from '../pages/Landing'
import { CliQuickstartSection } from '../components/landing/CliQuickstartSection'

describe('Analyze Navigation & Scroll Anchoring Suite', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    window.scrollTo = vi.fn()
  })

  it('renders "Analyze a PCAP" CTA in Landing Hero that navigates to /console', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Landing />} />
        </Routes>
      </MemoryRouter>
    )

    const analyzeLinks = screen.getAllByRole('link', { name: 'Analyze a PCAP' })
    expect(analyzeLinks.length).toBeGreaterThanOrEqual(1)
    const heroAnalyzeLink = analyzeLinks[0]
    expect(heroAnalyzeLink).toBeInTheDocument()
    expect(heroAnalyzeLink.getAttribute('href')).toMatch(/^\/console(\/analyze)?$/)
  })

  it('renders "Analyze a PCAP" CTA in Landing Bottom section that navigates to /console', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Landing />} />
        </Routes>
      </MemoryRouter>
    )

    const analyzeLinks = screen.getAllByRole('link', { name: 'Analyze a PCAP' })
    expect(analyzeLinks.length).toBeGreaterThanOrEqual(2)
    analyzeLinks.forEach((link) => {
      expect(link.getAttribute('href')).toMatch(/^\/console(\/analyze)?$/)
    })
  })

  it('renders "Analyze a PCAP" in CliQuickstartSection navigating to /console/analyze', () => {
    render(
      <MemoryRouter>
        <CliQuickstartSection />
      </MemoryRouter>
    )

    const analyzeLink = screen.getByRole('link', { name: /Analyze a PCAP/i })
    expect(analyzeLink).toBeInTheDocument()
    expect(analyzeLink).toHaveAttribute('href', '/console/analyze')
  })

  it('preserves secondary CLI quickstart link for terminal exploration', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <Routes>
          <Route path="/" element={<Landing />} />
        </Routes>
      </MemoryRouter>
    )

    const cliLink = screen.getByRole('link', { name: /View CLI Commands/i })
    expect(cliLink).toBeInTheDocument()
    expect(cliLink).toHaveAttribute('href', '#cli-quickstart')
  })
})
