import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { Menu, Plus, TrendingUp, X } from 'lucide-react'

import { clearUploadedAnalysis } from '../stores/productionStore'
import { useProductionData } from '../hooks/useProductionData'
import { SiteFooter } from './SiteFooter'

// Primary Application Navigation (Overview, Analysis, Threats, Traffic, Reports with Settings)
const primaryNavigation = [
  { to: '/console/overview', matchPaths: ['/console', '/console/overview', '/overview', '/dashboard'], label: 'Overview' },
  { to: '/console/analyze', matchPaths: ['/analyze', '/console/analyze', '/analysis', '/console/analysis'], label: 'Analysis' },
  { to: '/console/threats', matchPaths: ['/threats', '/console/threats'], label: 'Threats' },
  { to: '/console/traffic', matchPaths: ['/traffic', '/console/traffic'], label: 'Traffic' },
  { to: '/console/reports', matchPaths: ['/reports', '/console/reports'], label: 'Reports' },
]

const settingsNavigation = {
  to: '/console/settings',
  matchPaths: ['/settings', '/console/settings'],
  label: 'Settings',
}

/**
 * Strict active route matcher ensuring only ONE primary navigation item is selected at a time.
 * Prevents '/console' from greedily matching all '/console/*' child pages.
 */
function isRouteActive(pathname: string, matchPaths: string[]): boolean {
  const normalized = pathname.length > 1 && pathname.endsWith('/') ? pathname.slice(0, -1) : pathname
  return matchPaths.some((p) => {
    if (normalized === p) return true
    if (p === '/console' || p === '/overview') {
      return normalized === p
    }
    return normalized.startsWith(`${p}/`)
  })
}

import { getServiceStateInfo } from '../utils/serviceState'

/**
 * Evaluates whether an authoritative, valid forecast trajectory actually exists.
 * A forecast trajectory exists ONLY when:
 * 1. Forecasting is NOT explicitly abstained or withheld (due to lookback constraint, gaps, etc.)
 * 2. T+1..T+5 forecast results exist with non-null, valid numeric probability predictions.
 */
export function checkForecastTrajectoryExists(res: any): boolean {
  if (!res) return false
  if (res.is_forecast_available === false) return false
  if (res.forecast_summary && res.forecast_summary.available === false) return false
  if (res.forecast_status === 'FORECAST_ABSTAINED') return false
  if (res.analysis_state === 'ANALYSIS_COMPLETE_FORECAST_UNAVAILABLE') return false
  if (res.abstention && (res.abstention.abstained || res.abstention.is_abstained)) return false
  if (res.attack_horizon && (res.attack_horizon.state === 'ABSTAINED' || (res.attack_horizon as any) === 'ABSTAINED')) return false
  if (res.forecast && res.forecast.isAvailable === false) return false

  const pts = Array.isArray(res.forecasts)
    ? res.forecasts
    : Array.isArray(res.forecast?.points)
    ? res.forecast.points
    : []

  if (pts.length < 5) return false

  return pts.slice(0, 5).every((pt: any) => {
    const prob = pt.attack_probability ?? pt.attackProbability ?? pt.stepAttackProbability
    return typeof prob === 'number' && !Number.isNaN(prob) && !pt.abstained
  })
}

/**
 * Derives the truthful contextual status text for the top status bar.
 * Epistemic truth: A withheld or abstained forecast MUST NEVER say "Forecast Ready".
 */
export function computeContextStatusText(
  statusLabel: string,
  isLiveCapture: boolean,
  results: any
): string {
  if (statusLabel === 'ANALYZING') {
    return 'Analyzing Telemetry'
  }

  if (!isLiveCapture || !results) {
    return 'Ready'
  }

  // 1. Check for failed or rejected captures
  const isFailedOrRejected =
    results.status === 'failed' ||
    results.status === 'rejected' ||
    results.status === 'FAILED' ||
    results.status === 'REJECTED' ||
    results.validation?.status === 'INVALID' ||
    results.analysis_state === 'ANALYSIS_REJECTED_INVALID_INPUT'

  if (isFailedOrRejected) {
    if (
      results.status === 'rejected' ||
      results.status === 'REJECTED' ||
      results.analysis_state === 'ANALYSIS_REJECTED_INVALID_INPUT'
    ) {
      return 'Analysis Rejected'
    }
    return 'Analysis Failed'
  }

  // 2. Only assign "Forecast Ready" when an actual forecast trajectory exists
  if (checkForecastTrajectoryExists(results)) {
    return 'Forecast Ready'
  }

  // 3. For captures where static analysis succeeded but forecast was abstained/withheld
  // (insufficient history, non-contiguous timestamps, incompatible features)
  return 'Analysis Complete'
}

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
  const navRef = useRef<HTMLDivElement>(null)
  const drawerRef = useRef<HTMLElement>(null)

  // Ensure scroll is restored to top on every navigation/route transition before paint
  useLayoutEffect(() => {
    window.scrollTo({ top: 0, left: 0, behavior: 'instant' })
    if (document.documentElement) {
      document.documentElement.scrollTop = 0
    }
    if (document.body) {
      document.body.scrollTop = 0
    }
  }, [location.pathname])

  const serviceState = getServiceStateInfo(status)
  let statusLabel = serviceState.label
  if (status === 'Syncing data') {
    statusLabel = 'PREPARING'
  }

  // Derive contextual navigation indicators for real active user analysis
  const { data, analysisId, isLiveCapture } = useProductionData()
  const contextFilename = isLiveCapture
    ? (data?.results?.source?.filename || data?.results?.source?.name || 'Uploaded Capture')
    : 'No Active Capture'
  const contextStatusText = computeContextStatusText(statusLabel, isLiveCapture, data?.results)

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
      <header className="navbar-shell" ref={navRef}>
        <div className="navbar-inner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <NavLink className="brand-block" to="/console" aria-label="NexSolve">
              <span className="brand-label">NexSolve</span>
            </NavLink>
            <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-sans)', borderLeft: '1px solid var(--border)', paddingLeft: '14px' }}>
              Network Attack Forecasting
            </span>
          </div>

          <nav className="desktop-nav" aria-label="Primary navigation">
            {primaryNavigation.map(({ to, matchPaths, label }) => {
              const isCurrentActive = isRouteActive(location.pathname, matchPaths)
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
            <NavLink
              to={settingsNavigation.to}
              onClick={() => setOpen(false)}
              className={`nav-link ${isRouteActive(location.pathname, settingsNavigation.matchPaths) ? 'active' : ''}`}
              style={{ marginLeft: '8px', opacity: 0.85 }}
            >
              <span>{settingsNavigation.label}</span>
            </NavLink>
          </nav>

          <div className="navbar-right">
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
                <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-sans)', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
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
                  <NavLink to="/console/threats" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Threats</span>
                    <span className="drawer-badge" aria-hidden="true">Findings</span>
                  </NavLink>
                  <NavLink to="/console/traffic" onClick={() => setOpen(false)} className={({ isActive }) => `drawer-link ${isActive ? 'active' : ''}`}>
                    <span>Traffic</span>
                    <span className="drawer-badge" aria-hidden="true">Telemetry</span>
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
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-sans)', color: 'var(--text-muted)' }}>
                NexSolve &middot; Cyber Operations
              </span>
              <span style={{ fontSize: '10px', fontFamily: 'var(--font-sans)', fontWeight: 600, color: 'var(--text-secondary)', border: '1px solid var(--border)', padding: '2px 7px', borderRadius: '4px' }}>
                OFFLINE-FIRST
              </span>
            </div>
          </aside>
        </>
      )}

      <main className="main-area">
        {/* Navigation Context Banner */}
        <div
          className="navigation-context-strip"
          data-testid="navigation-context-strip"
          style={{
            background: 'var(--bg-secondary)',
            borderBottom: '1px solid var(--border)',
            fontSize: '11.5px',
            fontFamily: 'var(--font-sans)',
            width: '100%',
          }}
        >
          <div className="context-strip-inner">
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              {isLiveCapture && (
                <span
                  style={{
                    fontSize: '10px',
                    fontFamily: 'var(--font-sans)',
                    padding: '2px 7px',
                    borderRadius: '4px',
                    background: 'var(--button-secondary-bg)',
                    border: '1px solid var(--border)',
                    color: 'var(--text-primary)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.04em',
                    fontWeight: 600,
                  }}
                >
                  LIVE CAPTURE
                </span>
              )}
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
                    background:
                      contextStatusText === 'Analysis Failed' || contextStatusText === 'Analysis Rejected'
                        ? 'var(--danger)'
                        : isLiveCapture
                        ? 'var(--success)'
                        : 'var(--text-muted)',
                    display: 'inline-block',
                  }}
                />
                {contextStatusText}
              </span>
              <span style={{ color: 'var(--border)' }}>&middot;</span>
              <span style={{ color: 'var(--text-muted)' }}>Model:</span>
              <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--mono)', fontSize: '11px' }}>final_world_model v3.0.0</span>
              <span style={{ color: 'var(--border)' }}>&middot;</span>
              <span style={{ color: 'var(--text-muted)' }}>Mode:</span>
              <span style={{ color: 'var(--text-secondary)' }}>Analysis</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '11px', color: 'var(--text-muted)' }}>
              <span>ID: <code style={{ fontFamily: 'var(--mono)', color: 'var(--text-secondary)' }}>{isLiveCapture && analysisId ? analysisId.slice(0, 16) : '—'}</code></span>
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

export default Layout
