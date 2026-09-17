import { CheckCircle2, FastForward, XCircle } from 'lucide-react'
import { Panel } from './Ui'

export function ProductDifferentiatorsView() {
  return (
    <Panel className="product-differentiators-panel" style={{ padding: '24px' }}>
      <div style={{ marginBottom: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <FastForward size={18} color="var(--accent)" />
          <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
            PARADIGM SHIFT · ARCHITECTURAL DIFFERENTIATION
          </span>
        </div>
        <h3 style={{ margin: '4px 0 0 0', color: 'var(--text-primary)', fontSize: '18px', fontWeight: 700 }}>
          Traditional Intrusion Detection vs. NexSolve Attack Forecasting
        </h3>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '16px',
        }}
      >
        {/* Traditional IDS */}
        <div
          style={{
            background: 'var(--bg-secondary)',
            border: '1px solid rgba(237, 128, 111, 0.25)',
            borderRadius: '8px',
            padding: '18px 20px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <XCircle size={18} color="var(--danger)" />
              <strong style={{ fontSize: '15px', color: 'var(--text-primary)' }}>
                Traditional IDS / NIDS Architecture
              </strong>
            </div>
            <div
              style={{
                fontFamily: 'var(--mono)',
                fontSize: '11px',
                color: 'var(--danger)',
                background: 'rgba(237, 128, 111, 0.08)',
                padding: '6px 10px',
                borderRadius: '4px',
                marginBottom: '12px',
              }}
            >
              Observe &rarr; Match Rule &rarr; Alert on Impact (T0)
            </div>

            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <li>
                <strong>Reactive Paradigm:</strong> Only triggers after attack packets or malicious payloads have already hit the network.
              </li>
              <li>
                <strong>Zero Predictive Lead Time:</strong> Lead time is 0 seconds; defenders are already managing an active breach or outage.
              </li>
              <li>
                <strong>Static Thresholds:</strong> Vulnerable to sub-threshold slow scans, distributed reconnaissance, and novel multi-stage vectors.
              </li>
              <li>
                <strong>Alert Fatigue:</strong> Drowns analysts in isolated point-in-time signature hits without behavioral progression.
              </li>
            </ul>
          </div>

          <div style={{ marginTop: '16px', paddingTop: '10px', borderTop: '1px solid var(--border)', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)' }}>
            Posture: Post-compromise incident response
          </div>
        </div>

        {/* NexSolve Forecasting */}
        <div
          style={{
            background: 'radial-gradient(circle at top left, var(--accent-muted), var(--bg-surface) 70%)',
            border: '1px solid var(--accent)',
            borderRadius: '8px',
            padding: '18px 20px',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
              <CheckCircle2 size={18} color="var(--accent)" />
              <strong style={{ fontSize: '15px', color: 'var(--text-primary)' }}>
                NexSolve Temporal Network Forecasting Platform
              </strong>
            </div>
            <div
              style={{
                fontFamily: 'var(--mono)',
                fontSize: '11px',
                color: 'var(--accent)',
                background: 'var(--accent-muted)',
                padding: '6px 10px',
                borderRadius: '4px',
                marginBottom: '12px',
                border: '1px solid var(--accent)',
              }}
            >
              Observe &rarr; Model State &rarr; Simulate Future &rarr; Forecast &rarr; Explain
            </div>

            <ul style={{ margin: 0, paddingLeft: '18px', fontSize: '12.5px', color: 'var(--text-secondary)', display: 'flex', flexDirection: 'column', gap: '8px' }}>
              <li>
                <strong>Proactive Forecasting:</strong> Simulates future state trajectory across continuous horizons (T+1 to T+5).
              </li>
              <li>
                <strong>Actionable Lead Time:</strong> Provides 60s to 300s of advance warning during early reconnaissance before full infiltration.
              </li>
              <li>
                <strong>Physical Telemetry Integrity:</strong> Validated 45-feature schema; never hallucinates or fabricates unobserved TCP RTT.
              </li>
              <li>
                <strong>Explainable Early Warning:</strong> Quantifies composite risk (0-100) and maps future states to MITRE techniques.
              </li>
            </ul>
          </div>

          <div style={{ marginTop: '16px', paddingTop: '10px', borderTop: '1px solid var(--border)', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--accent)' }}>
            Posture: Pre-incident defensive prevention & containment
          </div>
        </div>
      </div>
    </Panel>
  )
}

