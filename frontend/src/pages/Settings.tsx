import { useState } from 'react'
import { Check, Info, Moon, Server, Shield, Sun } from 'lucide-react'
import { ErrorState, LoadingState, Panel, SectionHeading, StatusPill } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { useTheme } from '../hooks/useTheme'

export function Settings() {
  const { data, loading, error, reload } = useProductionData()
  const { setTheme, isDark, isLight } = useTheme()
  const analysisId = data?.results?.analysis_id ?? 'active-session'

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
    <div className="page-stack page-enter">
      <SectionHeading
        eyebrow="Settings / System"
        title="System configuration"
        description="Operational context and display preferences for the NexSolve security console."
      />
      <Panel>
        <SectionHeading
          eyebrow="Display / Theme"
          title="Appearance & Accessibility"
          description="Configure color theme and motion preferences. Changes are saved across reloads."
        />
        <div className="theme-selector-group" role="group" aria-label="Theme selection" style={{ marginBottom: '16px' }}>
          <button
            type="button"
            className={`button ${isDark ? '' : 'button-quiet'}`}
            style={{
              borderColor: isDark ? 'var(--accent)' : 'var(--border)',
              background: isDark ? 'var(--button-primary-bg)' : 'var(--button-secondary-bg)',
              color: isDark ? 'var(--button-primary-text)' : 'var(--text-primary)',
            }}
            onClick={() => setTheme('dark')}
            aria-pressed={isDark}
          >
            <Moon size={15} /> Dark Theme {isDark ? '(Active)' : ''}
          </button>
          <button
            type="button"
            className={`button ${isLight ? '' : 'button-quiet'}`}
            style={{
              borderColor: isLight ? 'var(--accent)' : 'var(--border)',
              background: isLight ? 'var(--button-primary-bg)' : 'var(--button-secondary-bg)',
              color: isLight ? 'var(--button-primary-text)' : 'var(--text-primary)',
            }}
            onClick={() => setTheme('light')}
            aria-pressed={isLight}
          >
            <Sun size={15} /> Light Theme {isLight ? '(Active)' : ''}
          </button>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px' }}>
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
            style={{ fontSize: '11px', height: '28px', padding: '0 10px' }}
          >
            {reducedMotion ? 'Enabled' : 'Disabled'}
          </button>
        </div>
      </Panel>
      {loading ? (
        <LoadingState message="Checking system configuration" />
      ) : error || !data ? (
        <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />
      ) : (
        <>
          <div className="content-grid">
            <Panel>
              <SectionHeading title="System & Connectivity" />
              <div className="detail-list">
                <div>
                  <span><Server size={15} /> API status</span>
                  <StatusPill tone="success">Connected</StatusPill>
                </div>
                <div>
                  <span>Engine mode</span>
                  <strong>Autonomous Forecasting Engine</strong>
                </div>
                <div>
                  <span>Analysis session</span>
                  <strong style={{ wordBreak: 'break-all' }}>{analysisId}</strong>
                </div>
                <div>
                  <span>Deployment</span>
                  <strong>Air-Gapped Local Execution</strong>
                </div>
              </div>
            </Panel>
            <Panel>
              <SectionHeading title="Telemetry Specification" />
              <div className="detail-list">
                <div>
                  <span>Product release</span>
                  <strong>v0.9.4 Production</strong>
                </div>
                <div>
                  <span>Ingestion format</span>
                  <strong>Standard PCAP / PCAPNG</strong>
                </div>
                <div>
                  <span>Canonical schema</span>
                  <strong>45 Features &middot; 60s Windows</strong>
                </div>
                <div>
                  <span>Forecast lookahead</span>
                  <strong>T+1 to T+5 (+300s)</strong>
                </div>
              </div>
            </Panel>
          </div>
          <Panel>
            <SectionHeading title="Operational Boundaries & Governance" />
            <div className="boundary-grid">
              <div className="boundary-card">
                <div className="boundary-icon"><Shield size={18} /></div>
                <div>
                  <h3>Passive Wire Telemetry</h3>
                  <p>Operates strictly on captured packet streams. No active network probing, inline packet modifications, or host agents required.</p>
                  <span className="boundary-state"><Check size={14} /> Active</span>
                </div>
              </div>
              <div className="boundary-card">
                <div className="boundary-icon"><Info size={18} /></div>
                <div>
                  <h3>Autoregressive World Model</h3>
                  <p>Simulates prospective latent network states across forward temporal steps. Dual risk scoring provides both point attack probability and compound cumulative risk.</p>
                  <span className="boundary-state"><Check size={14} /> Verified</span>
                </div>
              </div>
            </div>
          </Panel>
        </>
      )}
    </div>
  )
}

