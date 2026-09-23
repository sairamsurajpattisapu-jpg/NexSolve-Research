import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Menu, Moon, Plus, Sun, TrendingUp, X } from 'lucide-react'
import { useTheme } from '../hooks/useTheme'
import { NexSolveBackground } from './background/NexSolveBackground'

import { clearUploadedAnalysis } from '../stores/productionStore'
import { useProductionData } from '../hooks/useProductionData'
import { SiteFooter } from './SiteFooter'

// Primary Desktop Navigation (ONLY Analyze, Forecast, Evidence, Reports)
const primaryNavigation = [
  { to: '/console/analyze', matchPaths: ['/analyze', '/console/analyze', '/analysis', '/console/analysis'], label: 'Analyze' },
  { to: '/console/forecast', matchPaths: ['/forecast', '/console/forecast'], label: 'Forecast' },
  { to: '/console/evidence', matchPaths: ['/evidence', '/console/evidence'], label: 'Evidence' },
  { to: '/console/reports', matchPaths: ['/reports', '/console/reports'], label: 'Reports' },
]


import { getServiceStateInfo } from '../utils/serviceState'

export function Layout({
  status,
}: {
  status: string
  source?: 'production' | 'uploaded'
  provenance?: 'reference' | 'uploaded'
}) {
  const [open, setOpen] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const { isDark, toggleTheme } = useTheme()
  const navRef = useRef<HTMLDivElement>(null)
  const drawerRef = useRef<HTMLElement>(null)

  const serviceState = getServiceStateInfo(status)

  let statusTone = serviceState.tone === 'danger' ? 'danger' : serviceState.tone
  let statusLabel = serviceState.label
  let statusDescription = serviceState.description

  if (status === 'Syncing data') {
    statusTone = 'warning'
    statusLabel = 'PREPARING'
    statusDescription = 'Preparing analysis telemetry'
  } else if (statusLabel === 'ANALYZING') {
    statusTone = 'warning status-pulse'
  }

  // Derive contextual navigation indicators
  const { data, analysisSource, analysisId } = useProductionData()
  const contextFilename =
    data?.results?.source?.filename ||
    data?.results?.source?.name ||
    (analysisSource === 'uploaded' ? 'Uploaded Capture' : 'CIC-IDS2017 Benchmark')
  const contextStatusText =
    statusLabel === 'ANALYZING'
      ? 'Analyzing Telemetry'
      : (data?.results?.forecasts && data.results.forecasts.length > 0) || Boolean((data?.results as any)?.attack_horizon)
      ? 'Forecast Ready'
      : 'Baseline Active'
  const contextDotColor =
    contextStatusText === 'Forecast Ready'
      ? 'var(--success)'
      : contextStatusText === 'Analyzing Telemetry'
      ? 'var(--accent)'
      : 'var(--amber)'

  const handleNewAnalysis = async () => {
    setOpen(false)
    try {
      sessionStorage.removeItem('nexsolve-current-analysis-id')
      localStorage.removeItem('nexsolve-current-analysis-id')
      sessionStorage.removeItem('nexsolve-cached-canonical')
      localStorage.removeItem('nexsolve-cached-canonical')
      await clearUploadedAnalysis()
    } catch {
      // Ignore clear errors
    }
    navigate('/console/analyze')
  }

  // Handle click outside and Escape key to close navigation menu
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      const target = event.target as Node
      if (
        navRef.current &&
        !navRef.current.contains(target) &&
        (!drawerRef.current || !drawerRef.current.contains(target))
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
    <div className="app-shell">
      <NexSolveBackground />
      <header className="navbar-shell" ref={navRef}>
        <div className="navbar-inner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <NavLink className="brand-block" to="/console" aria-label="NexSolve">
              <span className="brand-label">NexSolve</span>
            </NavLink>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                color: 'var(--text-muted)',
                padding: '2px 6px',
                background: 'var(--bg-secondary)',
                borderRadius: '3px',
                border: '1px solid var(--border)',
              }}
            >
              v0.9
            </span>
          </div>

          <nav className="desktop-nav" aria-label="Primary navigation">
            {primaryNavigation.map(({ to, matchPaths, label }) => {
              const isCurrentActive = matchPaths.some(
                (p) => location.pathname === p || location.pathname.startsWith(`${p}/`)
              )
              return (
                <NavLink
                  key={to}
                  to={to}
                  onClick={() => setOpen(false)}
                  className={`nav-link ${isCurrentActive ? 'active' : ''}`}
                >
                  <span>{label}</span>
                </NavLink>
              )
            })}
          </nav>

          <div className="navbar-right">
            <button
              type="button"
              className="button button-quiet"
              onClick={() => void handleNewAnalysis()}
              style={{ fontSize: '11px', height: '28px', padding: '0 8px', gap: '4px' }}
              title="Launch a new network analysis"
            >
              <Plus size={12} /> New Analysis
            </button>

            <div className={`navbar-status status-${statusTone}`} title={statusDescription}>
              <span className={`status-dot status-${statusTone}`} aria-hidden="true" />
              <span className="status-text">{statusLabel}</span>
            </div>

            <button
              type="button"
              className="theme-toggle-btn"
              onClick={toggleTheme}
              aria-label={`Switch to ${isDark ? 'light' : 'dark'} theme`}
              title={`Switch to ${isDark ? 'light' : 'dark'} theme`}
            >
              {isDark ? <Sun size={14} /> : <Moon size={14} />}
            </button>

            <button
              type="button"
              className="menu-button"
              onClick={() => setOpen(!open)}
              aria-label={open ? 'Close navigation menu' : 'Open navigation menu'}
              aria-expanded={open}
            >
              {open ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>
      </header>

      {/* Command Menu Drawer */}
      {open && (
        <>
          <button
            type="button"
            className="mobile-scrim"
            aria-label="Close command menu"
            onClick={() => setOpen(false)}
          />
          <aside className="command-drawer" aria-label="Command menu" ref={drawerRef}>
            {/* Drawer Header */}
            <div className="drawer-header">
              <div>
                <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  NEXSOLVE CONTROL
                </span>
                <h2 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: '2px 0 0 0', letterSpacing: '-0.02em' }}>
                  Command Menu
                </h2>
              </div>
              <button
                type="button"
                className="icon-button"
                onClick={() => setOpen(false)}
                aria-label="Close command menu"
                style={{ padding: '6px' }}
              >
                <X size={16} />
              </button>
            </div>

            {/* Quick Actions */}
            <div className="drawer-section" style={{ background: 'var(--bg-secondary)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <div className="drawer-section-title">Quick Actions</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
                <button
                  type="button"
                  className="button button-quiet"
                  onClick={() => void handleNewAnalysis()}
                  style={{ fontSize: '11px', padding: '6px 8px', justifyContent: 'flex-start' }}
                >
                  <Plus size={12} /> New Analysis
                </button>
                <button
                  type="button"
                  className="button button-quiet"
                  onClick={() => {
                    navigate('/console/forecast')
                    setOpen(false)
                  }}
                  style={{ fontSize: '11px', padding: '6px 8px', justifyContent: 'flex-start' }}
                >
                  <TrendingUp size={12} /> View Forecast
                </button>
              </div>
            </div>

            {/* Application Menu Nav for Test Compatibility & Full Routing */}
            <nav className="mobile-nav" aria-label="Application menu" style={{ padding: '0 24px' }}>
              {/* Console Navigation Section */}
              <div style={{ padding: '12px 0 6px 0' }}>
                <div className="drawer-section-title">Console</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <NavLink to="/console" end onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Overview</span>
                    <span className="drawer-badge" aria-hidden="true">System</span>
                  </NavLink>
                  <NavLink to="/console/analyze" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Analyze</span>
                    <span className="drawer-badge" aria-hidden="true">PCAP</span>
                  </NavLink>
                  <NavLink to="/console/network" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Network</span>
                    <span className="drawer-badge" aria-hidden="true">Observed</span>
                  </NavLink>
                  <NavLink to="/console/forecast" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Forecast</span>
                    <span className="drawer-badge" aria-hidden="true">T+1..T+5</span>
                  </NavLink>
                  <NavLink to="/console/progression" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Progression</span>
                    <span className="drawer-badge" aria-hidden="true">Lifecycle</span>
                  </NavLink>
                  <NavLink to="/console/evidence" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Evidence</span>
                    <span className="drawer-badge" aria-hidden="true">Attribution</span>
                  </NavLink>
                  <NavLink to="/console/reports" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Reports</span>
                  </NavLink>
                  <NavLink to="/console/settings" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Settings</span>
                    <span className="drawer-badge" aria-hidden="true">Config</span>
                  </NavLink>
                </div>
              </div>

              {/* Documentation & Resources Section */}
              <div style={{ padding: '12px 0 16px 0', borderTop: '1px solid var(--border)' }}>
                <div className="drawer-section-title">Documentation & Resources</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
                  <NavLink to="/workflow" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>How It Works</span>
                  </NavLink>
                  <NavLink to="/security" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Security</span>
                  </NavLink>
                  <NavLink to="/research" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Research</span>
                  </NavLink>
                  <NavLink to="/faq" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>FAQ</span>
                  </NavLink>
                  <NavLink to="/about" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>About</span>
                  </NavLink>
                  <NavLink to="/contact" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Contact</span>
                  </NavLink>
                </div>
              </div>
            </nav>

            {/* Footer */}
            <div style={{ marginTop: 'auto', padding: '16px 24px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'var(--bg-secondary)' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
                NexSolve v0.9 &middot; Cyber Operations
              </span>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: 'var(--text-primary)', border: '1px solid var(--border)', padding: '1px 6px', borderRadius: '3px' }}>
                OFFLINE-FIRST
              </span>
            </div>
          </aside>
        </>
      )}

      <main className="main-area">
        {/* Subtle Navigation Context Banner */}
        <div
          className="navigation-context-strip"
          data-testid="navigation-context-strip"
          style={{
            background: 'var(--bg-secondary)',
            borderBottom: '1px solid var(--border)',
            fontSize: '11px',
            fontFamily: 'var(--mono)',
            width: '100%',
          }}
        >
          <div
            className="context-strip-inner"
            style={{
              width: '100%',
              maxWidth: 'var(--site-max-width, 1240px)',
              marginInline: 'auto',
              paddingInline: 'var(--site-gutter-desktop, 32px)',
              paddingBlock: '6px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: '12px',
              flexWrap: 'wrap',
              boxSizing: 'border-box',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <span style={{ color: 'var(--text-muted)' }}>Analysis:</span>
              <strong style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{contextFilename}</strong>
              <span style={{ color: 'var(--border)' }}>&middot;</span>
              <span style={{ color: 'var(--text-muted)' }}>Status:</span>
              <span style={{ color: 'var(--text-primary)', display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                <span
                  style={{
                    width: '6px',
                    height: '6px',
                    borderRadius: '50%',
                    background: contextDotColor,
                    display: 'inline-block',
                  }}
                />
                {contextStatusText}
              </span>
            </div>
            <div style={{ fontSize: '10.5px', color: 'var(--text-muted)' }}>
              ID: {(analysisId || 'production-cic-ids2017').slice(0, 16)}
            </div>
          </div>
        </div>

        <div className="page-content">
          <Outlet />
        </div>

        <SiteFooter />
      </main>
    </div>
  )
}

