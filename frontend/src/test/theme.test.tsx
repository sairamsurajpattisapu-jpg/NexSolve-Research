import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { DemoModeSelector } from '../components/DemoModeSelector'
import { Layout } from '../components/Layout'
import { ReportActions } from '../components/ReportActions'
import { Settings } from '../pages/Settings'
import { DEMO_SCENARIO_PAYLOADS } from '../fixtures/demoScenarios'
import { api } from '../services/api'
import { applyTheme, getTheme, THEME_STORAGE_KEY } from '../stores/themeStore'

describe('NexSolve Theme System & Controls', () => {
  beforeEach(() => {
    localStorage.clear()
    applyTheme('dark')
  })

  it('defaults to DARK theme with data-theme="dark" on root', () => {
    expect(getTheme()).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    expect(document.documentElement.style.colorScheme).toBe('dark')
  })

  it('switches to LIGHT theme and updates DOM and storage', () => {
    applyTheme('light')
    expect(getTheme()).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(document.documentElement.style.colorScheme).toBe('light')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('light')
  })

  it('switches back from LIGHT to DARK theme', () => {
    applyTheme('light')
    expect(getTheme()).toBe('light')

    applyTheme('dark')
    expect(getTheme()).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    expect(document.documentElement.style.colorScheme).toBe('dark')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBe('dark')
  })

  it('toggles theme using the navbar toggle button in Layout', async () => {
    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Routes>
          <Route element={<Layout status="Operational" />}>
            <Route path="*" element={<div>Dashboard Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    )

    const toggleBtn = screen.getByRole('button', { name: /switch to light theme/i })
    expect(toggleBtn).toBeInTheDocument()

    // Click to toggle to Light
    await user.click(toggleBtn)
    expect(getTheme()).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')

    // Click to toggle back to Dark
    const toggleBackBtn = screen.getByRole('button', { name: /switch to dark theme/i })
    await user.click(toggleBackBtn)
    expect(getTheme()).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('switches themes using Settings page appearance buttons', async () => {
    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/settings']}>
        <Routes>
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </MemoryRouter>
    )

    // Wait for settings to render
    const lightBtn = await screen.findByRole('button', { name: /light theme/i })
    const darkBtn = await screen.findByRole('button', { name: /dark theme/i })

    expect(darkBtn).toHaveAttribute('aria-pressed', 'true')
    expect(lightBtn).toHaveAttribute('aria-pressed', 'false')

    // Click Light Theme
    await user.click(lightBtn)
    expect(getTheme()).toBe('light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
    expect(lightBtn).toHaveAttribute('aria-pressed', 'true')
    expect(darkBtn).toHaveAttribute('aria-pressed', 'false')

    // Click Dark Theme
    await user.click(darkBtn)
    expect(getTheme()).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    expect(darkBtn).toHaveAttribute('aria-pressed', 'true')
  })

  it('preserves Demo scenario button interactivity and state', async () => {
    vi.spyOn(api, 'getDemoScenarioResult').mockResolvedValue(DEMO_SCENARIO_PAYLOADS.EARLY_WARNING)
    const onSelect = vi.fn()
    render(<DemoModeSelector onSelectScenario={onSelect} />)

    const earlyBtn = screen.getByRole('tab', { name: /Early Attack Signal/i })
    expect(earlyBtn).toBeInTheDocument()
    expect(earlyBtn).toHaveClass('button')
    expect(earlyBtn).toHaveClass('button-quiet')

    await act(async () => {
      fireEvent.click(earlyBtn)
    })

    expect(earlyBtn).toHaveClass('active')
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /Load Early Attack Signal/i })).toBeInTheDocument()
    })
    expect(onSelect).toHaveBeenCalledWith(DEMO_SCENARIO_PAYLOADS.EARLY_WARNING)
  })

  it('verifies ReportActions buttons render and execute click handlers', async () => {
    const onReset = vi.fn()
    const user = userEvent.setup()
    render(<ReportActions jobId="job-test-theme-01" onReset={onReset} />)

    const htmlReportLink = screen.getByRole('link', { name: /Open HTML Report/i })
    expect(htmlReportLink).toBeInTheDocument()
    expect(htmlReportLink).toHaveAttribute('target', '_blank')

    const jsonDownloadLink = screen.getByRole('link', { name: /Download JSON/i })
    expect(jsonDownloadLink).toBeInTheDocument()
    expect(jsonDownloadLink).toHaveAttribute('download')

    const uploadAnotherBtn = screen.getByRole('button', { name: /Upload Another/i })
    expect(uploadAnotherBtn).toBeInTheDocument()

    await user.click(uploadAnotherBtn)
    expect(onReset).toHaveBeenCalledTimes(1)
  })

  it('renders correct provenance indicators in Layout across modes', () => {
    const { rerender } = render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Routes>
          <Route element={<Layout status="Operational" provenance="reference" />}>
            <Route path="*" element={<div>Dashboard</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    )
    expect(screen.getByText('Reference')).toBeInTheDocument()

    rerender(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Routes>
          <Route element={<Layout status="Operational" provenance="uploaded" />}>
            <Route path="*" element={<div>Dashboard</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    )
    expect(screen.getByText('Live capture')).toBeInTheDocument()

    rerender(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Routes>
          <Route element={<Layout status="Operational" provenance="demo" />}>
            <Route path="*" element={<div>Dashboard</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    )
    expect(screen.getByText('Demo')).toBeInTheDocument()
  })
})
