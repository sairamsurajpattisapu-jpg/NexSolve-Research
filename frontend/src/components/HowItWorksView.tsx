import { Activity, BrainCircuit, Eye, Info, Sparkles, TrendingUp, Zap } from 'lucide-react'
import { Panel } from './Ui'

const HOW_IT_WORKS_STEPS = [
  {
    step: '01',
    title: 'Observe',
    subtitle: 'Passive Telemetry Ingestion',
    icon: Eye,
    tagline: 'Zero Agent Overhead',
    desc: 'Passively ingests raw network packets and flow records without modifying payloads or deploying intrusive endpoint agents.',
  },
  {
    step: '02',
    title: 'Understand',
    subtitle: '45-Dim State Representation',
    icon: Activity,
    tagline: 'Physical Feature Integrity',
    desc: 'Reconstructs 5-tuples and continuous 60s windows across 45 passive metrics, strictly omitting unobserved metrics like TCP RTT.',
  },
  {
    step: '03',
    title: 'Simulate',
    subtitle: 'Autoregressive World Model',
    icon: BrainCircuit,
    tagline: 'Recurrent State Rollout',
    desc: 'A pure NumpyLSTM world model recurses across future steps S(t+1)...S(t+5), simulating network evolution without future ground truth.',
  },
  {
    step: '04',
    title: 'Forecast',
    subtitle: 'Multi-Horizon Attack Infiltration',
    icon: TrendingUp,
    tagline: 'Lead Time in Minutes',
    desc: 'Evaluates single-step onset probability and cumulative risk to forecast early infiltration before volumetric disruption strikes.',
  },
  {
    step: '05',
    title: 'Explain',
    subtitle: 'MITRE & Top Feature Attribution',
    icon: Zap,
    tagline: 'Audit-Proof Transparency',
    desc: 'Translates trajectory vector deltas directly into MITRE ATT&CK techniques (e.g., T1046, T1498) and explicit domain explanations.',
  },
]

export function HowItWorksView() {
  return (
    <Panel className="how-it-works-panel" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '8px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Sparkles size={16} color="var(--accent)" />
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              INNOVATION BREAKDOWN · ARCHITECTURE OVERVIEW
            </span>
          </div>
          <h3 style={{ margin: '4px 0 0 0', color: 'var(--text-primary)', fontSize: '18px', fontWeight: 700 }}>
            How NexSolve Works
          </h3>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--mono)' }}>
          <Info size={14} color="var(--accent)" />
          <span>Core Workflow: Observe &rarr; Understand &rarr; Simulate &rarr; Forecast &rarr; Explain</span>
        </div>
      </div>

      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '12px',
        }}
      >
        {HOW_IT_WORKS_STEPS.map((s) => {
          const IconComp = s.icon
          return (
            <div
              key={s.step}
              style={{
                background: 'var(--bg-secondary)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                padding: '16px',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                  <span
                    style={{
                      fontSize: '18px',
                      fontFamily: 'var(--mono)',
                      fontWeight: 800,
                      color: 'var(--accent)',
                    }}
                  >
                    {s.step}
                  </span>
                  <div
                    style={{
                      padding: '6px',
                      borderRadius: '6px',
                      background: 'var(--accent-muted)',
                      color: 'var(--accent)',
                      display: 'inline-flex',
                    }}
                  >
                    <IconComp size={16} />
                  </div>
                </div>
                <h4 style={{ margin: '0 0 2px 0', fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {s.title}
                </h4>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', display: 'block', marginBottom: '8px' }}>
                  {s.subtitle}
                </span>
                <p style={{ margin: 0, fontSize: '12px', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  {s.desc}
                </p>
              </div>

              <div
                style={{
                  marginTop: '12px',
                  paddingTop: '8px',
                  borderTop: '1px solid var(--border)',
                  fontSize: '10px',
                  fontFamily: 'var(--mono)',
                  color: 'var(--accent)',
                  fontWeight: 600,
                }}
              >
                {s.tagline}
              </div>
            </div>
          )
        })}
      </div>
    </Panel>
  )
}

