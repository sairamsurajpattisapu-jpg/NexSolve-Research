import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { Layout } from '../components/Layout'
import { ReportActions } from '../components/ReportActions'
import { Settings } from '../pages/Settings'
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
