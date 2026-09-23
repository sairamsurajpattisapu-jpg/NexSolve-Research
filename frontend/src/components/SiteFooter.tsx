import { Link } from 'react-router-dom'

export function SiteFooter() {
  return (
    <footer className="marketing-footer" style={{ borderTop: '1px solid var(--border)' }}>
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
          <Link to="/console/analyze" className="footer-link">Analyze PCAP</Link>
          <Link to="/console/forecast" className="footer-link">Forecast Rollout</Link>
          <Link to="/console/progression" className="footer-link">Attack Progression</Link>
          <Link to="/console/evidence" className="footer-link">Evidence Drivers</Link>
          <Link to="/console/reports" className="footer-link">Reports</Link>
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
  )
}

