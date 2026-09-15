import { useState } from 'react'
import { ChevronDown, ChevronUp, Cpu } from 'lucide-react'
import { Panel } from './Ui'

interface TechnicalStatusDrawerProps {
  modelType?: string
  featureCount?: number
  windowSeconds?: number
  lookbackWindows?: number
  supportedHorizons?: string
  executionMode?: string
  calibrationStatus?: string
  schemaVariant?: string
}

export function TechnicalStatusDrawer({
  modelType = 'NumpyLSTM (Pure Offline Recurrent)',
  featureCount = 45,
  windowSeconds = 60,
  lookbackWindows = 8,
  supportedHorizons = 'T+1 ... T+5 (Simulated +60s ... +300s)',
  executionMode = '100% Offline / Local Edge Processing',
  calibrationStatus = 'UNCALIBRATED (Raw Neural Sigmoidal Posterior)',
  schemaVariant = '45_feature_pcap_compatible (mean_tcp_rtt strictly omitted)',
}: TechnicalStatusDrawerProps) {
  const [isOpen, setIsOpen] = useState(false)

  return (
    <Panel className="technical-status-drawer" style={{ padding: '14px 20px', border: '1px solid var(--border)' }}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          width: '100%',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          padding: 0,
          color: 'var(--text-primary)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Cpu size={16} color="var(--accent)" />
          <span style={{ fontSize: '13px', fontWeight: 600, fontFamily: 'var(--mono)' }}>
            System Technical Specifications & Scientific Contract
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
          <span>{isOpen ? 'Collapse specs' : 'Expand technical specs'}</span>
          {isOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </div>
      </button>

      {isOpen && (
        <div
          style={{
            marginTop: '14px',
            paddingTop: '14px',
            borderTop: '1px solid var(--border)',
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
            gap: '12px',
            fontSize: '11.5px',
            fontFamily: 'var(--mono)',
          }}
        >
          <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>FORECASTING MODEL</span>
            <strong style={{ color: 'var(--accent)' }}>{modelType}</strong>
          </div>

          <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>INPUT DIMENSIONS</span>
            <strong style={{ color: 'var(--text-primary)' }}>{featureCount} Passive PCAP Features</strong>
          </div>

          <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>TEMPORAL WINDOW</span>
            <strong style={{ color: 'var(--text-primary)' }}>{windowSeconds} seconds discrete</strong>
          </div>

          <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>REQUIRED LOOKBACK</span>
            <strong style={{ color: 'var(--text-primary)' }}>{lookbackWindows} continuous windows (480s)</strong>
          </div>

          <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>FORECAST HORIZONS</span>
            <strong style={{ color: 'var(--text-primary)' }}>{supportedHorizons}</strong>
          </div>

          <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>EXECUTION ENVIRONMENT</span>
            <strong style={{ color: 'var(--success)' }}>{executionMode}</strong>
          </div>

          <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>PROBABILITY CALIBRATION</span>
            <strong style={{ color: 'var(--warning)' }}>{calibrationStatus}</strong>
          </div>

          <div style={{ background: 'var(--bg-secondary)', padding: '10px 12px', borderRadius: '4px' }}>
            <span style={{ color: 'var(--text-muted)', display: 'block', fontSize: '10px' }}>SCHEMA CONTRACT</span>
            <strong style={{ color: 'var(--accent)' }}>{schemaVariant}</strong>
          </div>
        </div>
      )}
    </Panel>
  )
}

