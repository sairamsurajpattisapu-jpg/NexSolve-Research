import { useEffect, useRef, useState } from 'react'
import { NavLink, Link, Outlet, useLocation } from 'react-router-dom'
import { ArrowRight, X } from 'lucide-react'
import { SiteFooter } from './SiteFooter'

export function MarketingLayout() {
  const [open, setOpen] = useState(false)
  const navRef = useRef<HTMLElement>(null)
  const drawerRef = useRef<HTMLElement>(null)
  const location = useLocation()

  // Body scroll lock management when mobile drawer is open
  useEffect(() => {
    if (open) {
      const originalOverflow = document.body.style.overflow
      document.body.style.overflow = 'hidden'
      return () => {
        document.body.style.overflow = originalOverflow
      }
    }
  }, [open])

  // Accessible click-outside and Escape key listener for mobile menu
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node
      if (
        open &&
        drawerRef.current &&
        !drawerRef.current.contains(target) &&
        navRef.current &&
        !navRef.current.contains(target)
      ) {
        setOpen(false)
      }
    }

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        setOpen(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    document.addEventListener('keydown', handleKeyDown)

    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [open])

  // Track window scroll position to compact navbar
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20)
    }
    window.addEventListener('scroll', handleScroll, { passive: true })
    handleScroll()
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  const handleAnchorClick = (id: string) => (event: React.MouseEvent<HTMLAnchorElement>) => {
    setOpen(false)
    if (location.pathname === '/') {
      event.preventDefault()
      const element = document.getElementById(id)
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' })
        window.history.pushState(null, '', `#${id}`)
      }
    }
  }

  return (
    <div className="app-shell marketing-shell">
      <header
        className={`navbar-shell marketing-navbar ${scrolled ? 'is-scrolled' : ''}`}
        ref={navRef}
      >
        <div className="navbar-inner">
          <Link className="brand-block" to="/" aria-label="NexSolve Home">
            <span className="brand-label">NEXSOLVE</span>
          </Link>

          {/* Minimal Restrained Navigation matching Section 11 */}
          <nav className="desktop-nav" aria-label="Product navigation">
            <a
              href="/#how-it-works"
              onClick={handleAnchorClick('how-it-works')}
              className="nav-link"
            >
              How It Works
            </a>
            <a
              href="/#forecasting"
              onClick={handleAnchorClick('forecasting')}
              className="nav-link"
            >
              Forecasting
            </a>
            <a
              href="/#evidence"
              onClick={handleAnchorClick('evidence')}
              className="nav-link"
            >
              Evidence
            </a>
            <NavLink
              to="/research"
              onClick={() => setOpen(false)}
              className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
            >
              Research
            </NavLink>
          </nav>

          <div className="navbar-right">
            <Link
              to="/console"
              className="header-console-btn"
              aria-label="Open Console"
            >
              <span>Open Console</span>
              <ArrowRight size={13} className="header-console-arrow" />
            </Link>

            <button
              type="button"
              className={`menu-toggle-btn ${open ? 'is-open' : ''}`}
              onClick={() => setOpen(!open)}
              aria-label={open ? 'Close navigation' : 'Open navigation'}
              aria-expanded={open}
              aria-controls="mobile-navigation-drawer"
            >
              <span className="hamburger-box" aria-hidden="true">
                <span className="hamburger-line line-1" />
                <span className="hamburger-line line-2" />
                <span className="hamburger-line line-3" />
              </span>
            </button>
          </div>
        </div>
      </header>

      {/* Mobile Backdrop Overlay */}
      {open && (
        <div
          className="mobile-nav-backdrop"
          onClick={() => setOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Compact Floating Mobile Navigation Panel */}
      <aside
        id="mobile-navigation-drawer"
        className={`mobile-floating-panel ${open ? 'is-open' : ''}`}
        aria-label="Mobile navigation"
        aria-hidden={!open}
        ref={drawerRef}
      >
        <div className="mobile-panel-header">
          <div className="mobile-panel-brand">
            <span className="brand-label">NEXSOLVE</span>
            <span className="mobile-panel-tag">RESEARCH</span>
          </div>
          <button
            type="button"
            className="mobile-panel-close-btn"
            onClick={() => setOpen(false)}
            aria-label="Close navigation"
          >
            <X size={15} />
          </button>
        </div>

        <nav className="mobile-panel-links" aria-label="Mobile navigation links">
          <a
            href="/#how-it-works"
            onClick={handleAnchorClick('how-it-works')}
            className="mobile-panel-link"
          >
            How It Works
          </a>
          <a
            href="/#forecasting"
            onClick={handleAnchorClick('forecasting')}
            className="mobile-panel-link"
          >
            Forecasting
          </a>
          <a
            href="/#evidence"
            onClick={handleAnchorClick('evidence')}
            className="mobile-panel-link"
          >
            Evidence
          </a>
          <NavLink
            to="/research"
            onClick={() => setOpen(false)}
            className={({ isActive }) =>
              isActive ? 'mobile-panel-link active' : 'mobile-panel-link'
            }
          >
            Research
          </NavLink>
        </nav>

        <div className="mobile-panel-footer">
          <Link
            to="/console"
            onClick={() => setOpen(false)}
            className="mobile-panel-console-btn"
            aria-label="Open Console"
          >
            <span>Open Console</span>
            <ArrowRight size={13} />
          </Link>
        </div>
      </aside>

      <main className="main-area marketing-main">
        <Outlet />
      </main>

      <SiteFooter />
    </div>
  )
}

export default MarketingLayout
