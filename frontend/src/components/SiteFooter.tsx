import { Link } from 'react-router-dom'

export function SiteFooter() {
  const handleCliClick = (event: React.MouseEvent<HTMLAnchorElement>) => {
    if (window.location.pathname === '/') {
      event.preventDefault()
      const element = document.getElementById('cli-quickstart')
      if (element) {
        element.scrollIntoView({ behavior: 'smooth' })
        window.history.pushState(null, '', '#cli-quickstart')
      }
    }
  }

  return (
    <footer
      className="marketing-footer"
      style={{
        borderTop: '1px solid rgba(255, 255, 255, 0.08)',
        background: 'rgba(5, 5, 5, 0.75)',
        backdropFilter: 'blur(10px)',
      }}
    >
      <div className="marketing-footer-inner">
        <div className="footer-brand-col">
          <div className="footer-brand-header">
            <span className="brand-label">NEXSOLVE</span>
            <span className="footer-meta-mono">RESEARCH &middot; v0.9.4</span>
          </div>
          <p className="footer-desc">
            Autonomous network attack forecasting from passive telemetry. Temporal trajectory simulation across forward lookahead horizons.
          </p>
          <div className="footer-meta-mono" style={{ color: '#737373' }}>
            Offline-First &middot; 45-Feature Contract &middot; Data Integrity Verified
          </div>
        </div>

        <div className="footer-nav-col">
          <div className="footer-col-title">Platform</div>
          <Link to="/" className="footer-link">Product</Link>
          <a href="/#cli-quickstart" onClick={handleCliClick} className="footer-link">CLI</a>
          <Link to="/workflow" className="footer-link">How It Works</Link>
          <Link to="/research" className="footer-link">Research</Link>
        </div>

        <div className="footer-nav-col">
          <div className="footer-col-title">Resources</div>
          <Link to="/security" className="footer-link">Security</Link>
          <Link to="/faq" className="footer-link">FAQ</Link>
          <Link to="/about" className="footer-link">About</Link>
          <Link to="/console" className="footer-link">Console</Link>
        </div>

        <div className="footer-nav-col">
          <div className="footer-col-title">Governance</div>
          <span className="footer-meta-item">Canonical 45-Dim PCAP</span>
          <span className="footer-meta-item">60s Discrete Windows</span>
          <span className="footer-meta-item">Horizons T+1 to T+5</span>
          <span className="footer-meta-item">SHA-256 Digest Provenance</span>
        </div>
      </div>

      <div className="footer-bottom-bar" style={{ borderTop: '1px solid rgba(255, 255, 255, 0.05)' }}>
        <div className="footer-bottom-left" style={{ color: '#737373' }}>
          &copy; {new Date().getFullYear()} NexSolve Research & Engineering. Autonomous Attack Forecasting Engine.
        </div>
        <div className="footer-bottom-right">
          <span className="footer-meta-mono" style={{ color: '#a3a3a3' }}>AIR-GAPPED COMPATIBLE</span>
        </div>
      </div>
    </footer>
  )
}

export default SiteFooter
