import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { Menu, Moon, Sun, X } from 'lucide-react'
import { useTheme } from '../hooks/useTheme'
import { NexSolveBackground } from './background/NexSolveBackground'

const navigation = [
  { to: '/analyze', label: 'Analyze' },
  { to: '/forecast', label: 'Forecast' },
  { to: '/evidence', label: 'Evidence' },
  { to: '/reports', label: 'Reports' },
  { to: '/demo', label: 'SIH Demo' },
]

export function Layout({
  status,
  provenance,
}: {
  status: string
  source?: 'production' | 'uploaded'
  provenance?: 'reference' | 'uploaded' | 'demo'
}) {
  const [open, setOpen] = useState(false)
  const { isDark, toggleTheme } = useTheme()
  const statusTone = status === 'API unavailable' ? 'danger' : status === 'Syncing data' ? 'warning' : 'success'
  const isDemo = provenance === 'demo'
  const isUploaded = !isDemo && provenance === 'uploaded'

  return (
    <div className="app-shell">
      <NexSolveBackground />
      <header className="navbar-shell">
        <div className="navbar-inner">
          <NavLink className="brand-block" to="/analyze" aria-label="NexSolve">
            <span className="brand-label">NexSolve</span>
          </NavLink>

          <nav className="desktop-nav" aria-label="Primary navigation">
            {navigation.map(({ to, label }) => (
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
            <div className="source-tag">
              {isDemo ? 'Demo' : isUploaded ? 'Live capture' : 'Reference'}
            </div>
            <div className="navbar-status">
              <span className={`status-dot status-${statusTone}`} aria-hidden="true" />
              <span className="status-text">{status}</span>
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
              className="menu-button"
              onClick={() => setOpen(!open)}
              aria-label={open ? 'Close navigation' : 'Open navigation'}
            >
              {open ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>

        {open && (
          <nav className="mobile-nav" aria-label="Mobile navigation">
            {navigation.map(({ to, label }) => (
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
