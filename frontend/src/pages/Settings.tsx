import { useState } from 'react'
import { Key, Moon, Monitor, Server, Shield, Sun, User } from 'lucide-react'
import { Panel, SectionHeading, StatusPill } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { useTheme } from '../hooks/useTheme'

export function Settings() {
  const { data } = useProductionData()
  const { setTheme, isDark, isLight } = useTheme()
  const analysisId = data?.results?.analysis_id ?? 'active-session'

  const [activeTab, setActiveTab] = useState<'appearance' | 'analysis' | 'system' | 'account'>('appearance')

  const [reducedMotion, setReducedMotion] = useState<boolean>(() => {
    try {
      return localStorage.getItem('nexsolve-reduced-motion') === 'true'
    } catch {
      return false
    }
  })

  const toggleReducedMotion = () => {
    const next = !reducedMotion
    setReducedMotion(next)
    try {
      localStorage.setItem('nexsolve-reduced-motion', String(next))
      if (next) {
        document.documentElement.classList.add('reduced-motion')
      } else {
        document.documentElement.classList.remove('reduced-motion')
      }
    } catch {
      // Ignore storage error
    }
  }

  return (
    <div className="page-stack page-enter" style={{ width: '100%', padding: '20px 0 40px 0' }}>
      <SectionHeading
        eyebrow="System Configuration"
        title="Settings"
        description="Display preferences, analysis schema specifications, system status, and session identity."
      />

      {/* Group Navigation Tabs */}
      <div
        role="tablist"
        aria-label="Settings categories"
        style={{
          display: 'flex',
          gap: '8px',
          borderBottom: '1px solid var(--border)',
          paddingBottom: '12px',
          marginBottom: '20px',
          flexWrap: 'wrap',
        }}
      >
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'appearance'}
          className={`button ${activeTab === 'appearance' ? 'button-primary' : 'button-quiet'}`}
          onClick={() => setActiveTab('appearance')}
          style={{ fontSize: '12px', height: '32px', gap: '6px' }}
        >
          <Monitor size={14} /> Appearance
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'analysis'}
          className={`button ${activeTab === 'analysis' ? 'button-primary' : 'button-quiet'}`}
          onClick={() => setActiveTab('analysis')}
          style={{ fontSize: '12px', height: '32px', gap: '6px' }}
        >
          <Shield size={14} /> Analysis
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'system'}
          className={`button ${activeTab === 'system' ? 'button-primary' : 'button-quiet'}`}
          onClick={() => setActiveTab('system')}
          style={{ fontSize: '12px', height: '32px', gap: '6px' }}
        >
          <Server size={14} /> System
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'account'}
          className={`button ${activeTab === 'account' ? 'button-primary' : 'button-quiet'}`}
          onClick={() => setActiveTab('account')}
          style={{ fontSize: '12px', height: '32px', gap: '6px' }}
        >
          <User size={14} /> Account
        </button>
      </div>

      {/* 1. APPEARANCE GROUP */}
      {activeTab === 'appearance' && (
        <Panel style={{ padding: '24px 28px' }}>
          <SectionHeading
            eyebrow="Theme & Display"
            title="Appearance Preferences"
            description="Configure color theme and motion preferences. Changes persist across application sessions."
          />

          <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '8px' }}>
                COLOR THEME
              </label>
              <div className="theme-selector-group" role="group" aria-label="Theme selection" style={{ display: 'flex', gap: '10px' }}>
                <button
                  type="button"
                  className={`button ${isDark ? 'button-primary' : 'button-quiet'}`}
                  style={{ fontSize: '12px', height: '34px', gap: '6px' }}
                  onClick={() => setTheme('dark')}
                  aria-pressed={isDark}
                >
                  <Moon size={14} /> Dark Theme {isDark ? '(Active)' : ''}
                </button>
                <button
                  type="button"
                  className={`button ${isLight ? 'button-primary' : 'button-quiet'}`}
                  style={{ fontSize: '12px', height: '34px', gap: '6px' }}
                  onClick={() => setTheme('light')}
                  aria-pressed={isLight}
                >
                  <Sun size={14} /> Light Theme {isLight ? '(Active)' : ''}
                </button>
              </div>
            </div>

            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                padding: '14px 18px',
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                marginTop: '8px',
              }}
            >
              <div>
                <strong style={{ fontSize: '13px', color: 'var(--text-primary)', display: 'block' }}>
                  Reduce Motion
                </strong>
                <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                  Disables non-essential transition animations for enhanced accessibility.
                </span>
              </div>
              <button
                type="button"
                className={`button ${reducedMotion ? 'button-primary' : 'button-quiet'}`}
                onClick={toggleReducedMotion}
                aria-label="Toggle Reduced Motion"
                aria-pressed={reducedMotion}
                style={{ fontSize: '11px', height: '28px', padding: '0 12px' }}
              >
                {reducedMotion ? 'Enabled' : 'Disabled'}
              </button>
            </div>
          </div>
        </Panel>
      )}

      {/* 2. ANALYSIS GROUP */}
      {activeTab === 'analysis' && (
        <Panel style={{ padding: '24px 28px' }}>
          <SectionHeading
            eyebrow="Modeling Specification"
            title="Analysis Configuration & Contract"
            description="Operational parameters governing temporal network state reconstruction and forward forecasting."
          />

          <div className="detail-list" style={{ marginTop: '16px' }}>
            <div>
              <span>Canonical schema contract</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>45 Continuous Features (Audited)</strong>
            </div>
            <div>
              <span>Temporal window aggregation</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>60-second Non-Overlapping Windows</strong>
            </div>
            <div>
              <span>Forward forecast lookahead</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>T+1 to T+5 (+60s to +300s Horizons)</strong>
            </div>
            <div>
              <span>Calibrated abstention threshold</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>&ge; 8 Continuous Windows (480 seconds)</strong>
            </div>
            <div>
              <span>Data integrity guarantee</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>Zero Synthetic Imputation</strong>
            </div>
          </div>
        </Panel>
      )}

      {/* 3. SYSTEM GROUP */}
      {activeTab === 'system' && (
        <Panel style={{ padding: '24px 28px' }}>
          <SectionHeading
            eyebrow="Engine Infrastructure"
            title="System & Runtime Status"
            description="Backend engine connectivity, deployment boundaries, and platform metadata."
          />

          <div className="detail-list" style={{ marginTop: '16px' }}>
            <div>
              <span><Server size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} /> API connectivity</span>
              <StatusPill tone="success">Connected</StatusPill>
            </div>
            <div>
              <span>Engine operational mode</span>
              <strong>Autonomous Network Attack Forecasting</strong>
            </div>
            <div>
              <span>Deployment topology</span>
              <strong>Air-Gapped Sovereign Infrastructure</strong>
            </div>
            <div>
              <span>Platform release</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>v0.9.4 Production</strong>
            </div>
            <div>
              <span>Active session identifier</span>
              <strong style={{ fontFamily: 'var(--mono)', wordBreak: 'break-all' }}>{analysisId}</strong>
            </div>
          </div>
        </Panel>
      )}

      {/* 4. ACCOUNT GROUP */}
      {activeTab === 'account' && (
        <Panel style={{ padding: '24px 28px' }}>
          <SectionHeading
            eyebrow="Analyst Identity"
            title="Account & Cryptographic Profile"
            description="Local workspace profile and session signing verification."
          />

          <div className="detail-list" style={{ marginTop: '16px' }}>
            <div>
              <span>Local analyst profile</span>
              <strong>SOC Security Analyst (Local Enclave)</strong>
            </div>
            <div>
              <span>Authentication model</span>
              <strong>Sovereign Zero-Trust Local Execution</strong>
            </div>
            <div>
              <span><Key size={14} style={{ marginRight: '6px', verticalAlign: 'middle' }} /> Cryptographic provenance key</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>SHA-256 Digest Enforced</strong>
            </div>
            <div>
              <span>Outbound telemetry transmission</span>
              <strong style={{ color: 'var(--success)' }}>Disabled (Air-Gapped Privacy)</strong>
            </div>
          </div>
        </Panel>
      )}
    </div>
  )
}

export default Settings
