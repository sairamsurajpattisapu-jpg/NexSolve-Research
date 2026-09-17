import { Link } from 'react-router-dom'
import { Compass, Home, LayoutDashboard } from 'lucide-react'
import { Panel } from '../components/Ui'

export function NotFound() {
  return (
    <div className="page-stack page-enter" style={{ maxWidth: '640px', margin: '80px auto', width: '100%', padding: '0 16px', textAlign: 'center' }}>
      <Panel>
        <div style={{ padding: '40px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              width: '52px',
              height: '52px',
              borderRadius: '50%',
              background: 'var(--bg-secondary)',
              border: '1px solid var(--border)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Compass size={26} color="var(--text-primary)" />
          </div>

          <div>
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              404 &middot; ROUTE NOT FOUND
            </span>
            <h1 style={{ fontSize: '26px', fontWeight: 700, margin: '6px 0 10px 0', color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
              Page not found
            </h1>
            <p style={{ fontSize: '14px', color: 'var(--text-secondary)', maxWidth: '440px', margin: '0 auto', lineHeight: 1.55 }}>
              The requested operational route or resource does not exist or has been moved within the platform architecture.
            </p>
          </div>

          <div style={{ display: 'flex', gap: '12px', justifyContent: 'center', flexWrap: 'wrap', marginTop: '8px' }}>
            <Link to="/console" className="button button-primary" style={{ fontSize: '13px', gap: '6px' }}>
              <LayoutDashboard size={14} /> Back to Console
            </Link>
            <Link to="/" className="button button-quiet" style={{ fontSize: '13px', gap: '6px' }}>
              <Home size={14} /> Return Home
            </Link>
          </div>
        </div>
      </Panel>
    </div>
  )
}
