import { useEffect, useRef, useState } from 'react'
import { NavLink, Link, Outlet } from 'react-router-dom'
import { ArrowRight, Moon, Sun, X } from 'lucide-react'
import { useTheme } from '../hooks/useTheme'
import { NexSolveBackground } from './background/NexSolveBackground'
import { SiteFooter } from './SiteFooter'

export function MarketingLayout() {
  const [open, setOpen] = useState(false)
  const { isDark, toggleTheme } = useTheme()
  const navRef = useRef<HTMLElement>(null)
  const drawerRef = useRef<HTMLElement>(null)

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

    if (open) {
      document.addEventListener('mousedown', handleClickOutside)
      document.addEventListener('keydown', handleKeyDown)
    }

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

  return (
    <div className="app-shell marketing-shell">
      <NexSolveBackground />
      <header className={`navbar-shell marketing-navbar ${scrolled ? 'is-scrolled' : ''}`} ref={navRef}>
        <div className="navbar-inner">
          <Link className="brand-block" to="/" aria-label="NexSolve Home">
            <span className="brand-label">NEXSOLVE</span>
          </Link>

          <nav className="desktop-nav" aria-label="Product navigation">
            <NavLink to="/" end onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>Product</NavLink>
            <NavLink to="/workflow" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>How It Works</NavLink>
            <NavLink to="/security" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>Security</NavLink>
            <NavLink to="/research" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>Research</NavLink>
            <NavLink to="/faq" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>FAQ</NavLink>
            <NavLink to="/about" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>About</NavLink>
          </nav>

          <div className="navbar-right">
            <button
              type="button"
              className="theme-toggle-btn"
              onClick={toggleTheme}
              aria-label={`Switch to ${isDark ? 'light' : 'dark'} theme`}
              title={`Switch to ${isDark ? 'light' : 'dark'} theme`}
            >
              {isDark ? <Sun size={14} /> : <Moon size={14} />}
            </button>

            <Link
              to="/console/analyze"
              className="header-start-btn"
              aria-label="START — Analysis Console"
            >
              <span>START</span>
              <ArrowRight size={13} className="header-start-arrow" />
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
          <NavLink to="/" end onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'mobile-panel-link active' : 'mobile-panel-link')}>
            Product
          </NavLink>
          <NavLink to="/workflow" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'mobile-panel-link active' : 'mobile-panel-link')}>
            How It Works
          </NavLink>
          <NavLink to="/security" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'mobile-panel-link active' : 'mobile-panel-link')}>
            Security
          </NavLink>
          <NavLink to="/research" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'mobile-panel-link active' : 'mobile-panel-link')}>
            Research
          </NavLink>
          <NavLink to="/faq" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'mobile-panel-link active' : 'mobile-panel-link')}>
            FAQ
          </NavLink>
          <NavLink to="/about" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'mobile-panel-link active' : 'mobile-panel-link')}>
            About
          </NavLink>
        </nav>

        <div className="mobile-panel-footer">
          <Link
            to="/console/analyze"
            onClick={() => setOpen(false)}
            className="mobile-panel-start-btn"
            aria-label="START — Analysis Console"
          >
            <span>START</span>
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
