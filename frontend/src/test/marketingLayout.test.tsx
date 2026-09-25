import { fireEvent, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { describe, expect, it } from 'vitest'
import { MarketingLayout } from '../components/MarketingLayout'

function renderMarketingLayout(initialPath = '/') {
  return render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route element={<MarketingLayout />}>
          <Route path="/" element={<div>Home Page Content</div>} />
          <Route path="/workflow" element={<div>Workflow Content</div>} />
          <Route path="/security" element={<div>Security Content</div>} />
          <Route path="/research" element={<div>Research Content</div>} />
          <Route path="/faq" element={<div>FAQ Content</div>} />
          <Route path="/about" element={<div>About Content</div>} />
          <Route path="/console/analyze" element={<div>Console Analyze Content</div>} />
        </Route>
      </Routes>
    </MemoryRouter>
  )
}

describe('MarketingLayout Navigation & Mobile Drawer Suite', () => {
  it('renders brand, desktop navigation links, and START primary CTA in header', () => {
    renderMarketingLayout('/')

    // Brand link
    const brand = screen.getByRole('link', { name: /NexSolve Home/i })
    expect(brand).toBeInTheDocument()
    expect(brand).toHaveAttribute('href', '/')

    // Desktop nav
    const desktopNav = screen.getByRole('navigation', { name: 'Product navigation' })
    expect(desktopNav).toBeInTheDocument()

    const navLinks = within(desktopNav).getAllByRole('link')
    const navText = navLinks.map((l) => l.textContent?.trim())
    expect(navText).toEqual(['Product', 'CLI', 'How It Works', 'Security', 'Research', 'FAQ', 'About'])

    // Header START CTA
    const startCta = screen.getByRole('link', { name: /START — Analysis Console/i })
    expect(startCta).toBeInTheDocument()
    expect(startCta).toHaveAttribute('href', '/console/analyze')
  })

  it('provides a functional 40px morphing hamburger menu with ARIA accessibility', async () => {
    const user = userEvent.setup()
    renderMarketingLayout('/')

    const menuBtn = screen.getByRole('button', { name: 'Open navigation' })
    expect(menuBtn).toBeInTheDocument()
    expect(menuBtn).toHaveAttribute('aria-expanded', 'false')
    expect(menuBtn).toHaveAttribute('aria-controls', 'mobile-navigation-drawer')

    // 1. Click to open
    await user.click(menuBtn)
    expect(menuBtn).toHaveAttribute('aria-expanded', 'true')
    expect(menuBtn).toHaveAttribute('aria-label', 'Close navigation')
    expect(document.body.style.overflow).toBe('hidden')

    const mobileDrawer = screen.getByRole('complementary', { name: 'Mobile navigation' })
    expect(mobileDrawer).toBeInTheDocument()
    expect(mobileDrawer).toHaveClass('is-open')

    // 2. Press Escape key to close
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(menuBtn).toHaveAttribute('aria-expanded', 'false')
    expect(menuBtn).toHaveAttribute('aria-label', 'Open navigation')
    expect(document.body.style.overflow).not.toBe('hidden')
    expect(mobileDrawer).not.toHaveClass('is-open')

    // 3. Open menu again and click outside to close
    await user.click(menuBtn)
    expect(menuBtn).toHaveAttribute('aria-expanded', 'true')
    expect(document.body.style.overflow).toBe('hidden')

    fireEvent.mouseDown(document.body)
    expect(menuBtn).toHaveAttribute('aria-expanded', 'false')
    expect(document.body.style.overflow).not.toBe('hidden')

    // 4. Open menu and click a drawer link to navigate and close
    await user.click(menuBtn)
    const workflowLink = within(mobileDrawer).getByRole('link', { name: 'How It Works' })
    await user.click(workflowLink)
    expect(menuBtn).toHaveAttribute('aria-expanded', 'false')
    expect(document.body.style.overflow).not.toBe('hidden')
  })

  it('contains START link inside the mobile drawer navigating to /console/analyze', async () => {
    const user = userEvent.setup()
    renderMarketingLayout('/')

    const menuBtn = screen.getByRole('button', { name: 'Open navigation' })
    await user.click(menuBtn)

    const mobileDrawer = screen.getByRole('complementary', { name: 'Mobile navigation' })
    const drawerStartBtn = within(mobileDrawer).getByRole('link', { name: /START — Analysis Console/i })
    expect(drawerStartBtn).toBeInTheDocument()
    expect(drawerStartBtn).toHaveAttribute('href', '/console/analyze')

    await user.click(drawerStartBtn)
    expect(menuBtn).toHaveAttribute('aria-expanded', 'false')
    expect(document.body.style.overflow).not.toBe('hidden')
  })
})
