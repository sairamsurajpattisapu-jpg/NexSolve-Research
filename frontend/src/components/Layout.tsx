import { NavLink, Outlet } from 'react-router-dom'
import { Activity, FileText, LayoutDashboard, Menu, Moon, Radar, Settings, ShieldCheck, Sun, X } from 'lucide-react'
import { useState } from 'react'
import { useTheme } from '../hooks/useTheme'

const navigation = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/analysis', label: 'Analysis', icon: Radar },
  { to: '/threats', label: 'Threats', icon: ShieldCheck },
  { to: '/traffic', label: 'Traffic', icon: Activity },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function Layout({
  status,
  source = 'production',
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
  const isUploaded = !isDemo && (provenance === 'uploaded' || (source === 'uploaded' && provenance !== 'reference'))

  return (
    <div className="app-shell">
      <header className="navbar-shell">
        <div className="navbar-inner">
          <NavLink className="brand-block" to="/dashboard" aria-label="NexSolve home">
            <div className="brand-mark"><Radar size={17} /></div>
            <span className="brand-label">NexSolve</span>
          </NavLink>
          <nav className="desktop-nav" aria-label="Main navigation">
            {navigation.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                onClick={() => setOpen(false)}
                className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
              >
                <Icon size={14} strokeWidth={1.8} />
                <span>{label}</span>
              </NavLink>
            ))}
          </nav>
          <div className="navbar-right">
            <div className="navbar-status">
              <span className={`status-dot status-${statusTone}`} aria-hidden="true" />
              <span className="status-text">{status}</span>
            </div>
            <div className="source-indicator">
              <span>{isDemo ? 'DEMO DATA' : isUploaded ? 'LIVE PCAP ANALYSIS' : 'VERIFIED REFERENCE'}</span>
              <small>{isDemo ? 'Scenario evaluation' : isUploaded ? 'User uploaded capture' : 'CIC-IDS2017 (No PCAP)'}</small>
            </div>
            <button
              type="button"
              className="theme-toggle-btn"
              onClick={toggleTheme}
              aria-label={`Switch to ${isDark ? 'light' : 'dark'} theme`}
              title={`Switch to ${isDark ? 'light' : 'dark'} theme`}
            >
              {isDark ? <Sun size={14} /> : <Moon size={14} />}
              <span className="theme-toggle-label">{isDark ? 'LIGHT' : 'DARK'}</span>
            </button>
            <button
              className="menu-button"
              onClick={() => setOpen(!open)}
              aria-label={open ? 'Close navigation' : 'Open navigation'}
            >
              {open ? <X size={19} /> : <Menu size={19} />}
            </button>
          </div>
        </div>
        {open && (
          <nav className="mobile-nav" aria-label="Mobile navigation">
            {navigation.map(({ to, label, icon: Icon }) => (
              <NavLink
                key={to}
                to={to}
                onClick={() => setOpen(false)}
                className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}
              >
                <Icon size={15} />
                <span>{label}</span>
              </NavLink>
            ))}
            <button
              type="button"
              className="theme-toggle-btn"
              onClick={() => {
                toggleTheme()
                setOpen(false)
              }}
              style={{ marginTop: '8px', alignSelf: 'flex-start' }}
              aria-label={`Switch to ${isDark ? 'light' : 'dark'} theme`}
            >
              {isDark ? <Sun size={14} /> : <Moon size={14} />}
              <span>{isDark ? 'Switch to Light Theme' : 'Switch to Dark Theme'}</span>
            </button>
          </nav>
        )}
      </header>
      {open && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setOpen(false)} />}
      <main className="main-area"><div className="page-content"><Outlet /></div></main>
    </div>
  )
}
