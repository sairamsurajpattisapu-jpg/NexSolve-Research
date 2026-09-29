import { useState } from 'react'
import { Brain, Database, Info, Monitor, Server, Shield } from 'lucide-react'
import { Panel, SectionHeading, StatusPill } from '../components/Ui'
import { useProductionData } from '../hooks/useProductionData'

type SettingsTab = 'display' | 'model' | 'analysis' | 'system' | 'data' | 'about'

export function Settings() {
  const { data } = useProductionData()
  const analysisId = data?.results?.analysis_id ?? 'active-session'

  const [activeTab, setActiveTab] = useState<SettingsTab>('display')

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
    <div className="page-stack page-enter settings-container">
      <SectionHeading
        eyebrow="System Configuration"
        title="Settings"
        description="Display preferences, model specifications, analysis schema contracts, and system topology."
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
          aria-selected={activeTab === 'display'}
          className={`button ${activeTab === 'display' ? 'button-primary' : 'button-quiet'}`}
          onClick={() => setActiveTab('display')}
          style={{ fontSize: '12px', height: '32px', gap: '6px' }}
        >
          <Monitor size={14} /> Display
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'model'}
          className={`button ${activeTab === 'model' ? 'button-primary' : 'button-quiet'}`}
          onClick={() => setActiveTab('model')}
          style={{ fontSize: '12px', height: '32px', gap: '6px' }}
        >
          <Brain size={14} /> Model
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
          aria-selected={activeTab === 'data'}
          className={`button ${activeTab === 'data' ? 'button-primary' : 'button-quiet'}`}
          onClick={() => setActiveTab('data')}
          style={{ fontSize: '12px', height: '32px', gap: '6px' }}
        >
          <Database size={14} /> Data
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={activeTab === 'about'}
          className={`button ${activeTab === 'about' ? 'button-primary' : 'button-quiet'}`}
          onClick={() => setActiveTab('about')}
          style={{ fontSize: '12px', height: '32px', gap: '6px' }}
        >
          <Info size={14} /> About
        </button>
      </div>

      {/* 1. DISPLAY GROUP */}
      {activeTab === 'display' && (
        <Panel style={{ padding: '24px 28px' }}>
          <SectionHeading
            eyebrow="Theme & Display"
            title="Appearance Preferences"
            description="Configure color theme and motion preferences. Changes persist across application sessions."
          />

          <div style={{ marginTop: '16px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-muted)', display: 'block', marginBottom: '8px' }}>
                VISUAL THEME
              </label>
              <div style={{ fontSize: '13px', color: 'var(--text-primary)', fontFamily: 'var(--font-sans)', padding: '8px 12px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: '6px' }}>
                Dark &middot; Monochromatic SOC Console (Permanent)
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

      {/* 2. MODEL GROUP */}
      {activeTab === 'model' && (
        <Panel style={{ padding: '24px 28px' }}>
          <SectionHeading
            eyebrow="Model Architecture & Verification"
            title="World Model Specification"
            description="Operational parameters and verification status of the production forecasting engine."
          />

          <div className="detail-list" style={{ marginTop: '16px' }}>
            <div>
              <span>Model identifier</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>final_world_model v3.0.0</strong>
            </div>
            <div>
              <span>Model architecture</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>Continuous Latent Dynamics (Auto-regressive State Predictor)</strong>
            </div>
            <div>
              <span>Forward projection lookahead</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>Multi-Horizon (T+1..T+5) Sequential Step Progression</strong>
            </div>
            <div>
              <span>Checkpoint provenance</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>epoch_40_checkpoint.pt (Audited Checksum)</strong>
            </div>
            <div>
              <span>Epistemic uncertainty boundaries</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>Calibrated Decision Threshold with Active Abstention</strong>
            </div>
            <div>
              <span>Safety policy</span>
              <StatusPill tone="success">Active (Suppresses OOD Hallucinations)</StatusPill>
            </div>
          </div>
        </Panel>
      )}

      {/* 3. ANALYSIS GROUP */}
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
              <strong style={{ fontFamily: 'var(--font-sans)' }}>45 Continuous Features (Audited)</strong>
            </div>
            <div>
              <span>Temporal window aggregation</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>60-second Non-Overlapping Windows</strong>
            </div>
            <div>
              <span>Forward forecast lookahead</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>T+1 to T+5 (+60s to +300s Horizons)</strong>
            </div>
            <div>
              <span>Calibrated abstention threshold</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>&ge; 8 Continuous Windows (480 seconds)</strong>
            </div>
            <div>
              <span>Data integrity guarantee</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>Zero Synthetic Imputation</strong>
            </div>
          </div>
        </Panel>
      )}

      {/* 4. SYSTEM GROUP */}
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
              <strong style={{ fontFamily: 'var(--font-sans)' }}>Production</strong>
            </div>
            <div>
              <span>Active session identifier</span>
              <strong style={{ fontFamily: 'var(--mono)', wordBreak: 'break-all' }}>{analysisId}</strong>
            </div>
          </div>
        </Panel>
      )}

      {/* 5. DATA GROUP */}
      {activeTab === 'data' && (
        <Panel style={{ padding: '24px 28px' }}>
          <SectionHeading
            eyebrow="Data Ingestion & Integrity"
            title="Telemetry Protocol & Boundaries"
            description="Supported capture formats, passive wire processing, and privacy preservation."
          />

          <div className="detail-list" style={{ marginTop: '16px' }}>
            <div>
              <span>Supported wire formats</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>Standard PCAP (libpcap), PCAPNG (NextGen), CSV</strong>
            </div>
            <div>
              <span>Flow tracking engine</span>
              <strong>Passive Wire Reconstruction (5-Tuple State Tracking)</strong>
            </div>
            <div>
              <span>Cryptographic provenance verification</span>
              <strong style={{ fontFamily: 'var(--font-sans)' }}>SHA-256 Digest Enforced</strong>
            </div>
            <div>
              <span>Outbound telemetry transmission</span>
              <strong style={{ color: 'var(--text-primary)' }}>Disabled (Air-Gapped Sovereign Privacy)</strong>
            </div>
            <div>
              <span>Synthetic data policy</span>
              <strong>Zero Synthetic Imputation</strong>
            </div>
          </div>
        </Panel>
      )}

      {/* 6. ABOUT GROUP */}
      {activeTab === 'about' && (
        <Panel style={{ padding: '24px 28px' }}>
          <SectionHeading
            eyebrow="Platform Identity"
            title="About NexSolve"
            description="Production-grade AI platform for network attack forecasting and cybersecurity analysis."
          />

          <div className="detail-list" style={{ marginTop: '16px' }}>
            <div>
              <span>Product name</span>
              <strong>NexSolve</strong>
            </div>
            <div>
              <span>Subsystem role</span>
              <strong>Network Attack Forecasting &amp; Cybersecurity Analytics</strong>
            </div>
            <div>
              <span>Core engine</span>
              <strong style={{ fontFamily: 'var(--mono)' }}>final_world_model v3.0.0</strong>
            </div>
            <div>
              <span>Environment</span>
              <strong>Production Enterprise Console</strong>
            </div>
            <div>
              <span>Design system</span>
              <strong>High-Contrast Monochrome SOC Specification</strong>
            </div>
          </div>
        </Panel>
      )}
    </div>
  )
}

export default Settings
