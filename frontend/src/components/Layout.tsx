import { NavLink, Outlet } from 'react-router-dom'
import { Activity, FileText, LayoutDashboard, Menu, Radar, Settings, ShieldCheck, X } from 'lucide-react'
import { useState } from 'react'

const navigation = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/analysis', label: 'Analysis', icon: Radar },
  { to: '/threats', label: 'Threats', icon: ShieldCheck },
  { to: '/traffic', label: 'Traffic', icon: Activity },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function Layout({ status, source = 'production' }: { status: string; source?: 'production' | 'uploaded' }) {
  const [open, setOpen] = useState(false)
  const statusTone = status === 'API unavailable' ? 'danger' : status === 'Syncing data' ? 'warning' : 'success'
  return <div className="app-shell">
    <header className="navbar-shell">
      <div className="navbar-inner">
        <NavLink className="brand-block" to="/dashboard" aria-label="NexSolve home"><div className="brand-mark"><Radar size={17} /></div><span className="brand-label">NexSolve</span></NavLink>
        <nav className="desktop-nav" aria-label="Main navigation">{navigation.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} onClick={() => setOpen(false)} className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}><Icon size={14} strokeWidth={1.8} /><span>{label}</span></NavLink>)}</nav>
        <div className="navbar-status"><span className={`status-dot status-${statusTone}`} aria-hidden="true" />{status}</div>
        <div className="source-indicator"><span>{source === 'uploaded' ? 'Uploaded capture' : 'Production dataset'}</span><small>{source === 'uploaded' ? 'Temporary / session only' : 'Read-only / verified'}</small></div>
        <button className="menu-button" onClick={() => setOpen(!open)} aria-label={open ? 'Close navigation' : 'Open navigation'}>{open ? <X size={19} /> : <Menu size={19} />}</button>
      </div>
      {open && <nav className="mobile-nav" aria-label="Mobile navigation">{navigation.map(({ to, label, icon: Icon }) => <NavLink key={to} to={to} onClick={() => setOpen(false)} className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}><Icon size={15} /><span>{label}</span></NavLink>)}</nav>}
    </header>
    {open && <button className="mobile-scrim" aria-label="Close navigation" onClick={() => setOpen(false)} />}
    <main className="main-area"><div className="page-content"><Outlet /></div></main>
  </div>
}
