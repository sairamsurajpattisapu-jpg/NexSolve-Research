import { useEffect, useRef, useState } from 'react'
import { NavLink, Link, Outlet } from 'react-router-dom'
import { ArrowRight, Moon, Sun, X } from 'lucide-react'
import { useTheme } from '../hooks/useTheme'
import { NexSolveBackground } from './background/NexSolveBackground'

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

  return (
    <div className="app-shell marketing-shell">
      <NexSolveBackground />
      <header className="navbar-shell marketing-navbar" ref={navRef}>
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

      <footer className="marketing-footer">
        <div className="marketing-footer-inner">
          <div className="footer-brand-col">
            <div className="footer-brand-header">
              <span className="brand-label">NEXSOLVE</span>
              <span className="footer-meta-mono">v0.9.4 PRODUCTION</span>
            </div>
            <p className="footer-desc">
              Network attack forecasting from passive telemetry. Temporal trajectory simulation across forward lookahead horizons.
            </p>
            <div className="footer-meta-mono" style={{ color: 'var(--text-muted)' }}>
              Offline-First · 45-Feature Contract · Data Integrity Verified
            </div>
          </div>

          <div className="footer-nav-col">
            <div className="footer-col-title">Platform</div>
            <Link to="/" className="footer-link">Product</Link>
            <Link to="/workflow" className="footer-link">How It Works</Link>
            <Link to="/security" className="footer-link">Security</Link>
            <Link to="/research" className="footer-link">Research</Link>
            <Link to="/faq" className="footer-link">FAQ</Link>
            <Link to="/about" className="footer-link">About</Link>
            <Link to="/contact" className="footer-link">Contact</Link>
            <Link to="/console" className="footer-link">Console</Link>
          </div>

          <div className="footer-nav-col">
            <div className="footer-col-title">Console</div>
            <Link to="/analyze" className="footer-link">Analyze PCAP</Link>
            <Link to="/forecast" className="footer-link">Forecast Rollout</Link>
            <Link to="/progression" className="footer-link">Attack Progression</Link>
            <Link to="/evidence" className="footer-link">Evidence Drivers</Link>
            <Link to="/reports" className="footer-link">Reports</Link>
          </div>

          <div className="footer-nav-col">
            <div className="footer-col-title">Governance</div>
            <span className="footer-meta-item">Canonical 45-Dim PCAP</span>
            <span className="footer-meta-item">60s Discrete Windows</span>
            <span className="footer-meta-item">Horizons T+1 to T+5</span>
            <span className="footer-meta-item">SHA-256 Content Hash</span>
          </div>
        </div>

        <div className="footer-bottom-bar">
          <div className="footer-bottom-left">
            NexSolve Research & Engineering. Autonomous Attack Forecasting Engine.
          </div>
          <div className="footer-bottom-right">
            <span className="footer-meta-mono">AIR-GAPPED COMPATIBLE</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
