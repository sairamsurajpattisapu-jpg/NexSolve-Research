import { useEffect, useRef, useState } from 'react'
import { NavLink, Link, Outlet } from 'react-router-dom'
import { Menu, Moon, Sun, X } from 'lucide-react'
import { useTheme } from '../hooks/useTheme'
import { NexSolveBackground } from './background/NexSolveBackground'

export function MarketingLayout() {
  const [open, setOpen] = useState(false)
  const { isDark, toggleTheme } = useTheme()
  const navRef = useRef<HTMLElement>(null)

  // Accessible click-outside and Escape key listener for mobile menu
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (navRef.current && !navRef.current.contains(event.target as Node)) {
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
            <NavLink to="/security" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>Security</NavLink>
            <NavLink to="/research" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>Research</NavLink>
            <NavLink to="/about" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>About</NavLink>
          </nav>

          <div className="navbar-right">
            <NavLink to="/workflow" className={({ isActive }) => (isActive ? 'nav-link workflow-nav-btn active' : 'nav-link workflow-nav-btn')}>Workflow</NavLink>

            <button
              type="button"
              className="theme-toggle-btn"
              onClick={toggleTheme}
              aria-label={`Switch to ${isDark ? 'light' : 'dark'} theme`}
              title={`Switch to ${isDark ? 'light' : 'dark'} theme`}
            >
              {isDark ? <Sun size={14} /> : <Moon size={14} />}
            </button>

            <Link to="/analyze" className="button button-primary header-cta-btn">
              <span>Launch Console</span>
            </Link>

            <button
              className="menu-button"
              onClick={() => setOpen(!open)}
              aria-label={open ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={open}
            >
              {open ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>

        {open && (
          <nav className="mobile-nav" aria-label="Mobile product navigation">
            <NavLink to="/" end onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>Product</NavLink>
            <NavLink to="/workflow" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>Workflow</NavLink>
            <NavLink to="/security" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>Security</NavLink>
            <NavLink to="/research" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>Research</NavLink>
            <NavLink to="/about" onClick={() => setOpen(false)} className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}>About</NavLink>
            <div style={{ padding: '16px 0 6px' }}>
              <Link
                to="/analyze"
                onClick={() => setOpen(false)}
                className="button button-primary"
                style={{ width: '100%', justifyContent: 'center' }}
              >
                Launch Console
              </Link>
            </div>
          </nav>
        )}
      </header>

      {open && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setOpen(false)} />}

      <main className="main-area marketing-main">
        <Outlet />
      </main>

      <footer className="marketing-footer">
        <div className="marketing-footer-inner">
          <div className="footer-brand-col">
            <div className="footer-brand-header">
              <span className="brand-label">NEXSOLVE</span>
              <span className="footer-meta-mono">SIH 2026 #26153</span>
            </div>
            <p className="footer-desc">
              Network attack forecasting from passive telemetry. Temporal trajectory simulation across forward lookahead horizons.
            </p>
            <div className="footer-meta-mono" style={{ color: 'var(--text-muted)' }}>
              Offline-First · 45-Feature Contract · Zero Fabrication
            </div>
          </div>

          <div className="footer-nav-col">
            <div className="footer-col-title">Architecture</div>
            <Link to="/workflow" className="footer-link">Workflow</Link>
            <Link to="/security" className="footer-link">Security</Link>
            <Link to="/research" className="footer-link">Research</Link>
            <Link to="/about" className="footer-link">About</Link>
          </div>

          <div className="footer-nav-col">
            <div className="footer-col-title">Console</div>
            <Link to="/analyze" className="footer-link">Analyze PCAP</Link>
            <Link to="/forecast" className="footer-link">Forecast Rollout</Link>
            <Link to="/evidence" className="footer-link">Evidence Drivers</Link>
            <Link to="/demo" className="footer-link">Evaluation Scenarios</Link>
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
            NexSolve Research. Problem Statement 26153.
          </div>
          <div className="footer-bottom-right">
            <span className="footer-meta-mono">AIR-GAPPED COMPATIBLE</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
