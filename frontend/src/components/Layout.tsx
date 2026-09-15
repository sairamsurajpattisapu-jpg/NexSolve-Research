import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { Menu, Moon, Plus, Sun, X } from 'lucide-react'
import { useTheme } from '../hooks/useTheme'
import { NexSolveBackground } from './background/NexSolveBackground'

// Primary Desktop Navigation (ONLY Analyze, Forecast, Evidence, Reports)
const primaryNavigation = [
  { to: '/analyze', label: 'Analyze' },
  { to: '/forecast', label: 'Forecast' },
  { to: '/evidence', label: 'Evidence' },
  { to: '/reports', label: 'Reports' },
]

// Secondary / Drawer Menu Navigation (Existing legitimate routes)
const menuNavigation = [
  { to: '/analyze', label: 'Analyze' },
  { to: '/forecast', label: 'Forecast' },
  { to: '/evidence', label: 'Evidence' },
  { to: '/reports', label: 'Reports' },
  { to: '/network', label: 'Network' },
  { to: '/replay', label: 'Replay' },
  { to: '/simulation', label: 'Simulation' },
  { to: '/evaluation', label: 'Evaluation' },
  { to: '/about', label: 'About' },
  { to: '/demo', label: 'Demo' },
]

export function Layout({
  status,
}: {
  status: string
  source?: 'production' | 'uploaded'
  provenance?: 'reference' | 'uploaded' | 'demo'
}) {
  const [open, setOpen] = useState(false)
  const navigate = useNavigate()
  const { isDark, toggleTheme } = useTheme()
  const navRef = useRef<HTMLDivElement>(null)

  const isUnavailable = status === 'API unavailable'
  const isSyncing = status === 'Syncing data'
  const statusTone = isUnavailable ? 'danger' : isSyncing ? 'warning' : 'success'
  const statusLabel = isUnavailable ? 'API OFFLINE' : isSyncing ? 'SYNCING' : 'API CONNECTED'

  // Handle click outside and Escape key to close navigation menu
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
    <div className="app-shell">
      <NexSolveBackground />
      <header className="navbar-shell" ref={navRef}>
        <div className="navbar-inner">
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
            <NavLink className="brand-block" to="/analyze" aria-label="NexSolve">
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
            {primaryNavigation.map(({ to, label }) => (
              <NavLink
                key={to}
                to={to}
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
              className="button button-quiet"
              onClick={() => {
                navigate('/console/analyze')
                setOpen(false)
              }}
              style={{ fontSize: '11px', height: '28px', padding: '0 8px', gap: '4px' }}
              title="Launch a new network analysis"
            >
              <Plus size={12} /> New Analysis
            </button>

            <div className="navbar-status" title={`Backend status: ${status}`}>
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

        {open && (
          <nav className="mobile-nav" aria-label="Application menu">
            {menuNavigation.map(({ to, label }) => (
              <NavLink
                key={to}
                to={to}
                onClick={() => setOpen(false)}
                className={({ isActive }) => (isActive ? 'nav-link active' : 'nav-link')}
              >
                <span>{label}</span>
              </NavLink>
            ))}
          </nav>
        )}
      </header>
      {open && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setOpen(false)} />}
      <main className="main-area"><div className="page-content"><Outlet /></div></main>
    </div>
  )
}
