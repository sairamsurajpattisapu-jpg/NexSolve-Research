import { Check, ExternalLink, Info, Moon, Server, Shield, Sun } from 'lucide-react'
import { ErrorState, LoadingState, Panel, SectionHeading, StatusPill } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'
import { useTheme } from '../hooks/useTheme'

export function Settings() {
  const { data, loading, error, reload } = useProductionData()
  const { setTheme, isDark, isLight } = useTheme()
  const isLocal = typeof window !== 'undefined' && (
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1' ||
    window.location.hostname === '::1'
  )
  const endpointMode = isLocal ? 'Local FastAPI' : 'Production API'
  const analysisId = data?.results?.analysis_id ?? 'production-cic-ids2017'
  const activeSource = data?.results?.source?.name ?? (
    analysisId === 'production-cic-ids2017'
      ? 'CIC-IDS2017 packet windows'
      : analysisId.startsWith('demo-')
        ? `Demo: ${analysisId.replace('demo-', '')}`
        : analysisId
  )
  const sourceMode = data?.results?.source?.kind === 'uploaded_pcap'
    ? 'Uploaded PCAP'
    : analysisId.startsWith('demo-')
      ? 'Demo Simulation'
      : analysisId === 'production-cic-ids2017'
        ? 'Read-only Parquet'
        : (data?.results?.source?.kind ?? 'Live analysis')

  return (
    <div className="page-stack page-enter">
      <SectionHeading
        eyebrow="Settings / System"
        title="System configuration"
        description="Operational context and display preferences for the NexSolve demonstration environment."
      />
      <Panel>
        <SectionHeading
          eyebrow="Display / Theme"
          title="Appearance"
          description="Select your preferred theme. Changes are saved across page reloads."
        />
        <div className="theme-selector-group" role="group" aria-label="Theme selection">
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
      </Panel>
      {loading ? (
        <LoadingState message="Checking system configuration" />
      ) : error || !data ? (
        <ErrorState message={error ?? 'No analysis has been loaded.'} onRetry={() => void reload()} />
      ) : (
        <>
          <div className="content-grid">
            <Panel>
              <SectionHeading title="Connection" />
              <div className="detail-list">
                <div>
                  <span><Server size={15} /> API status</span>
                  <StatusPill>Connected</StatusPill>
                </div>
                <div>
                  <span>Endpoint mode</span>
                  <strong>{endpointMode}</strong>
                </div>
                <div>
                  <span>Analysis ID</span>
                  <strong>{analysisId}</strong>
                </div>
                <div>
                  <span>Service version</span>
                  <strong>{data.health.model_version}</strong>
                </div>
              </div>
            </Panel>
            <Panel>
              <SectionHeading title="Application" />
              <div className="detail-list">
                <div>
                  <span>Product version</span>
                  <strong>0.1.0</strong>
                </div>
                <div>
                  <span>Active source</span>
                  <strong>{activeSource}</strong>
                </div>
                <div>
                  <span>Source mode</span>
                  <strong>{sourceMode}</strong>
                </div>
                <div>
                  <span>Forecast horizon</span>
                  <strong>{data.health.K} windows</strong>
                </div>
              </div>
            </Panel>
          </div>
          <Panel>
            <SectionHeading title="Method boundaries" />
            <div className="boundary-grid">
              <div className="boundary-card">
                <div className="boundary-icon"><Shield size={18} /></div>
                <div>
                  <h3>Packet analysis</h3>
                  <p>Uses packet-window aggregates, traffic indicators, and transparent risk scoring. Findings are evidence-based heuristics.</p>
                  <span className="boundary-state"><Check size={14} /> Active</span>
                </div>
              </div>
              <div className="boundary-card">
                <div className="boundary-icon muted"><Info size={18} /></div>
                <div>
                  <h3>LSTM forecast model</h3>
                  <p>The existing research forecast service is separate. Packet-only production and uploaded data do not satisfy its flow-plus-temporal feature contract.</p>
                  <span className="boundary-state muted-text"><ExternalLink size={14} /> Research endpoint</span>
                </div>
              </div>
            </div>
          </Panel>
        </>
      )}
    </div>
  )
}

