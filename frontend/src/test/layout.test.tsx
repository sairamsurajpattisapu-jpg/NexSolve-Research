import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { Layout } from '../components/Layout'

function renderLayout(path = '/analyze', status = 'API connected') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route element={<Layout status={status} />}>
          <Route path="*" element={<div>Route content</div>} />
        </Route>
      </Routes>
    </MemoryRouter>
  )
}

describe('Application Header & Navigation Layout', () => {
  it('renders ONLY Analyze, Forecast, Evidence, Reports in primary navbar (NO SIH DEMO)', () => {
    renderLayout('/analyze')
    const primaryNav = screen.getByRole('navigation', { name: 'Primary navigation' })
    expect(primaryNav).toBeInTheDocument()

    const links = screen.getAllByRole('link')
    const primaryLinkNames = links
      .filter((link) => primaryNav.contains(link))
      .map((link) => link.textContent?.trim())

    expect(primaryLinkNames).toEqual(['Analyze', 'Forecast', 'Evidence', 'Reports'])
    expect(primaryNav).not.toHaveTextContent('SIH DEMO')
    expect(primaryNav).not.toHaveTextContent('SIH Demo')
  })

  it('does NOT display "Demo" text in the header status area', () => {
    renderLayout('/analyze')
    const header = screen.getByRole('banner')
    expect(header).not.toHaveTextContent('Demo')
  })

  it('displays correct backend status labels based on API health', () => {
    const { unmount } = renderLayout('/analyze', 'API connected')
    expect(screen.getByText('API CONNECTED')).toBeInTheDocument()
    unmount()

    renderLayout('/analyze', 'API unavailable')
    expect(screen.getByText('API OFFLINE')).toBeInTheDocument()
  })

  it('provides a functional hamburger menu with ARIA attributes, keyboard escape, and click outside', async () => {
    const user = userEvent.setup()
    renderLayout('/analyze')

    const menuBtn = screen.getByRole('button', { name: /Open navigation menu/i })
    expect(menuBtn).toBeInTheDocument()
    expect(menuBtn).toHaveAttribute('aria-expanded', 'false')

    // 1. Click to open
    await user.click(menuBtn)
    expect(menuBtn).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByRole('navigation', { name: 'Application menu' })).toBeInTheDocument()

    // 2. Press Escape key to close
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(menuBtn).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByRole('navigation', { name: 'Application menu' })).not.toBeInTheDocument()

    // 3. Open menu again and click outside to close
    await user.click(menuBtn)
    expect(menuBtn).toHaveAttribute('aria-expanded', 'true')
    fireEvent.mouseDown(document.body)
    expect(menuBtn).toHaveAttribute('aria-expanded', 'false')

    // 4. Open menu and click a menu item to navigate and close
    await user.click(menuBtn)
    const appMenu = screen.getByRole('navigation', { name: 'Application menu' })
    const networkLink = screen.getByRole('link', { name: 'Network' })
    expect(appMenu.contains(networkLink)).toBe(true)

    await user.click(networkLink)
    expect(menuBtn).toHaveAttribute('aria-expanded', 'false')
  })
})
