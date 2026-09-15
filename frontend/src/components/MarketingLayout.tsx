import { useState } from 'react'
import { NavLink, Link, Outlet } from 'react-router-dom'
import { Menu, Moon, Sun, X, Terminal, Shield } from 'lucide-react'
import { useTheme } from '../hooks/useTheme'
import { NexSolveBackground } from './background/NexSolveBackground'

const marketingNav = [
  { to: '/', label: 'Product', end: true },
  { to: '/workflow', label: 'Workflow' },
  { to: '/security', label: 'Security' },
  { to: '/research', label: 'Research' },
  { to: '/about', label: 'About' },
]

export function MarketingLayout() {
  const [open, setOpen] = useState(false)
  const { isDark, toggleTheme } = useTheme()

  return (
    <div className="app-shell marketing-shell">
      <NexSolveBackground />
      <header className="navbar-shell marketing-navbar">
        <div className="navbar-inner">
          <Link className="brand-block" to="/" aria-label="NexSolve Home">
            <span className="brand-label">NexSolve</span>
            <span className="brand-badge-sub">FORECASTING</span>
          </Link>

          <nav className="desktop-nav" aria-label="Product navigation">
            {marketingNav.map(({ to, label, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                onClick={() => setOpen(false)}
                className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
              >
                <span>{label}</span>
              </NavLink>
            ))}
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

            <Link to="/analyze" className="button button-primary header-cta-btn">
              <Terminal size={14} />
              <span>Launch Console</span>
            </Link>

            <button
              className="menu-button"
              onClick={() => setOpen(!open)}
              aria-label={open ? 'Close navigation' : 'Open navigation'}
            >
              {open ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>

        {open && (
          <nav className="mobile-nav" aria-label="Mobile product navigation">
            {marketingNav.map(({ to, label, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                onClick={() => setOpen(false)}
                className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
              >
                <span>{label}</span>
              </NavLink>
            ))}
            <div style={{ padding: '12px 16px' }}>
              <Link
                to="/analyze"
                onClick={() => setOpen(false)}
                className="button button-primary"
                style={{ width: '100%', justifyContent: 'center' }}
              >
                <Terminal size={14} /> Launch Console
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
              <span className="brand-label">NexSolve</span>
              <span className="provenance-pill status-pill">SIH 2026 #26153</span>
            </div>
            <p className="footer-desc">
              AI-powered network attack forecasting from telemetry. Moves network defense from reactive triage to predictive trajectory simulation.
            </p>
            <div className="footer-guarantee">
              <Shield size={13} style={{ color: 'var(--accent)' }} />
              <span>Offline-First · 45-Dim Contract · Zero RTT Fabrication</span>
            </div>
          </div>

          <div className="footer-nav-col">
            <div className="footer-col-title">Product & Pipeline</div>
            <Link to="/workflow" className="footer-link">9-Step Workflow</Link>
            <Link to="/security" className="footer-link">Security Architecture</Link>
            <Link to="/research" className="footer-link">Research & Benchmarks</Link>
            <Link to="/about" className="footer-link">Mission & Principles</Link>
          </div>

          <div className="footer-nav-col">
            <div className="footer-col-title">Live Application</div>
            <Link to="/analyze" className="footer-link">Telemetry Console</Link>
            <Link to="/forecast" className="footer-link">Multi-Horizon Rollout</Link>
            <Link to="/evidence" className="footer-link">Evidence & Drivers</Link>
            <Link to="/demo" className="footer-link">Judge Demo Mode</Link>
          </div>

          <div className="footer-nav-col">
            <div className="footer-col-title">Scientific Governance</div>
            <span className="footer-meta-item">Contract: Canonical 45-Dim</span>
            <span className="footer-meta-item">Rollout: T+1 to T+5</span>
            <span className="footer-meta-item">Telemetry: Passive PCAP/PCAPNG</span>
            <span className="footer-meta-item">Audit: SHA-256 Content Hash</span>
          </div>
        </div>

        <div className="footer-bottom-bar">
          <div className="footer-bottom-left">
            © 2026 NexSolve Research. Built for Smart India Hackathon (Problem Statement 26153).
          </div>
          <div className="footer-bottom-right">
            <span className="provenance-pill reference-pill">AIR-GAPPED COMPATIBLE</span>
          </div>
        </div>
      </footer>
    </div>
  )
}
