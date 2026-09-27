import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Layout } from '../components/Layout'
import { ReportActions } from '../components/ReportActions'
import { Settings } from '../pages/Settings'
import { applyTheme, getTheme, THEME_STORAGE_KEY, toggleTheme } from '../stores/themeStore'

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

  it('enforces permanent DARK theme even if applyTheme or toggleTheme is invoked', () => {
    applyTheme('light')
    expect(getTheme()).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
    expect(document.documentElement.style.colorScheme).toBe('dark')
    expect(localStorage.getItem(THEME_STORAGE_KEY)).toBeNull()

    toggleTheme()
    expect(getTheme()).toBe('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('does not render theme toggle button in Layout navbar', () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <Routes>
          <Route element={<Layout status="Operational" />}>
            <Route path="*" element={<div>Dashboard Content</div>} />
          </Route>
        </Routes>
      </MemoryRouter>
    )

    expect(screen.queryByRole('button', { name: /switch to/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /theme/i })).not.toBeInTheDocument()
  })

  it('displays permanent dark console theme in Settings and has no light switch buttons', async () => {
    render(
      <MemoryRouter initialEntries={['/settings']}>
        <Routes>
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </MemoryRouter>
    )

    expect(await screen.findByText(/Dark · Monochromatic SOC Console \(Permanent\)/i)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /light theme/i })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: /switch to light/i })).not.toBeInTheDocument()
  })

  it('toggles reduced motion preference in Settings and updates document class', async () => {
    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/settings']}>
        <Routes>
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </MemoryRouter>
    )

    const motionToggle = await screen.findByRole('button', { name: /toggle reduced motion/i })
    expect(motionToggle).toBeInTheDocument()
    expect(motionToggle).toHaveAttribute('aria-pressed', 'false')

    await user.click(motionToggle)
    expect(motionToggle).toHaveAttribute('aria-pressed', 'true')
    expect(document.documentElement.classList.contains('reduced-motion')).toBe(true)
    expect(localStorage.getItem('nexsolve-reduced-motion')).toBe('true')
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
})
