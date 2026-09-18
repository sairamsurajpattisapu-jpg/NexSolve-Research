import { useState } from 'react'
import {
  BrainCircuit,
  FileCode2,
  Gauge,
  Layers,
  Network,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
  Workflow,
  Zap,
} from 'lucide-react'
import { Panel } from './Ui'

interface ArchitectureNode {
  id: string
  label: string
  subtitle: string
  layer: 'OBSERVE' | 'STATE' | 'SIMULATE' | 'INTERPRET' | 'ACTION'
  icon: any
  details: string
  contract: string
}

const ARCHITECTURE_NODES: ArchitectureNode[] = [
  {
    id: 'input',
    label: 'PCAP / Telemetry',
    subtitle: 'Passive packet capture',
    layer: 'OBSERVE',
    icon: FileCode2,
    details: 'Ingests standard .pcap / .pcapng files up to 1 GiB without requiring intrusive kernel drivers or active scanning.',
    contract: 'Zero packet modification; sanitized parsing via Scapy/libpcap fallback.',
  },
  {
    id: 'extraction',
    label: 'Telemetry Extraction',
    subtitle: 'Packet & 5-tuple flow parsing',
    layer: 'OBSERVE',
    icon: Network,
    details: 'Reconstructs directional flows, tracks bidirectional TCP handshakes, window scales, packet sizes, and inter-arrival times.',
    contract: 'Strict omission of unobserved fields. Mean TCP RTT is never fabricated or zero-filled.',
  },
  {
    id: 'temporal_state',
    label: '45-Feature Network State',
    subtitle: 'Discrete 60s windowing',
    layer: 'STATE',
    icon: Layers,
    details: 'Aggregates 17 flow features, 22 packet features, and 6 temporal trend features into a dense network state vector S(t).',
    contract: 'Canonical 45-feature schema matching offline trained network state model weights.',
  },
  {
    id: 'world_model',
    label: 'LSTM Network State Model',
    subtitle: 'Recursive K-step forecast horizon',
    layer: 'SIMULATE',
    icon: BrainCircuit,
    details: 'Autoregressively simulates future network states S(t+1)...S(t+5) using dynamic recurrent hidden transitions without future ground truth.',
    contract: 'L=8 historical lookback windows required. Pure NumPy/Torch offline execution.',
  },
  {
    id: 'risk_forecaster',
    label: 'Attack Risk Forecaster',
    subtitle: 'Single P(Atk) & Cumulative Risk',
    layer: 'SIMULATE',
    icon: TrendingUp,
    details: 'Calculates both single-step onset probabilities p_h and cumulative multi-window infiltration risk: Risk(H) = 1 - ∏(1 - p_h).',
    contract: 'Strict monotonic risk accumulation. Transparently marked as UNCALIBRATED.',
  },
  {
    id: 'progression_engine',
    label: 'Progression & MITRE Engine',
    subtitle: 'Markovian behavioral stage mapping',
    layer: 'INTERPRET',
    icon: ShieldAlert,
    details: 'Maps simulated feature shifts (e.g. port cardinality dispersion, flag surge) directly to MITRE ATT&CK techniques (T1046, T1071, T1190, T1498).',
    contract: 'Separates observed techniques (evidence) from forecasted techniques (predictions).',
  },
  {
    id: 'explainability',
    label: 'Attribution & Early Warning',
    subtitle: 'Top 5 feature drivers & 0-100 score',
    layer: 'INTERPRET',
    icon: Zap,
    details: 'Computes directional feature divergence (e.g., Unique Destination Ports increasing by +600%) and composite Early Warning index.',
    contract: 'Direct mathematical attribution grounded in physical telemetry semantics.',
  },
  {
    id: 'soc_actions',
    label: 'SOC Command Center',
    subtitle: 'Actionable response & reporting',
    layer: 'ACTION',
    icon: Gauge,
    details: 'Provides human-in-the-loop analyst decisions, mitigation playbooks, standalone HTML reports, and threat hunting templates.',
    contract: 'Instantaneous local export (HTML/JSON) with zero cloud dependencies.',
  },
]

export function InteractiveArchitectureView() {
  const [activeNodeId, setActiveNodeId] = useState<string>('world_model')
  const activeNode = ARCHITECTURE_NODES.find((n) => n.id === activeNodeId) ?? ARCHITECTURE_NODES[3]

  return (
    <Panel className="interactive-architecture-panel" style={{ padding: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '10px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Workflow size={18} color="var(--accent)" />
            <span className="eyebrow" style={{ color: 'var(--accent)', margin: 0 }}>
              END-TO-END SYSTEM PIPELINE ARCHITECTURE
            </span>
          </div>
          <h3 style={{ margin: '4px 0 0 0', color: 'var(--text-primary)', fontSize: '18px', fontWeight: 700 }}>
            How NexSolve Forecasts Infiltration Before It Occurs
          </h3>
        </div>
        <span
          style={{
            fontSize: '11px',
            fontFamily: 'var(--mono)',
            padding: '4px 10px',
            borderRadius: '4px',
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            color: 'var(--text-secondary)',
          }}
        >
          CLICK ANY NODE TO INSPECT CONTRACT
        </span>
      </div>

      {/* Interactive Horizontal Flow Map */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))',
          gap: '8px',
          background: 'var(--bg-secondary)',
          padding: '12px',
          borderRadius: '8px',
          border: '1px solid var(--border)',
          marginBottom: '20px',
        }}
      >
        {ARCHITECTURE_NODES.map((node, index) => {
          const isSelected = node.id === activeNodeId
          const IconComp = node.icon
          return (
            <button
              key={node.id}
              type="button"
              onClick={() => setActiveNodeId(node.id)}
              style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'flex-start',
                padding: '10px 12px',
                borderRadius: '6px',
                border: `1px solid ${isSelected ? 'var(--accent)' : 'transparent'}`,
                background: isSelected ? 'var(--accent-muted)' : 'var(--bg-surface)',
                cursor: 'pointer',
                textAlign: 'left',
                transition: 'all 0.15s ease',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%', marginBottom: '6px' }}>
                <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: isSelected ? 'var(--accent)' : 'var(--text-muted)' }}>
                  0{index + 1}
                </span>
                <IconComp size={14} color={isSelected ? 'var(--accent)' : 'var(--text-secondary)'} />
              </div>
              <strong style={{ fontSize: '12px', color: isSelected ? 'var(--text-primary)' : 'var(--text-secondary)', lineHeight: 1.3 }}>
                {node.label}
              </strong>
              <span style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '2px' }}>
                {node.subtitle}
              </span>
            </button>
          )
        })}
      </div>

      {/* Detailed Inspection Card for Active Node */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(12, 1fr)',
          gap: '16px',
          background: 'var(--bg-surface)',
          padding: '18px 20px',
          borderRadius: '8px',
          border: '1px solid var(--border)',
        }}
      >
        <div style={{ gridColumn: 'span 8', display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                padding: '2px 8px',
                borderRadius: '4px',
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                fontWeight: 700,
                background: 'var(--accent-muted)',
                color: 'var(--accent)',
              }}
            >
              LAYER: {activeNode.layer}
            </span>
            <h4 style={{ margin: 0, fontSize: '16px', color: 'var(--text-primary)', fontWeight: 700 }}>
              {activeNode.label} &mdash; {activeNode.subtitle}
            </h4>
          </div>
          <p style={{ margin: 0, fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.55 }}>
            {activeNode.details}
          </p>
        </div>

        <div style={{ gridColumn: 'span 4', borderLeft: '1px solid var(--border)', paddingLeft: '16px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
            <ShieldCheck size={14} color="var(--success)" />
            <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--success)', fontWeight: 700 }}>
              SCIENTIFIC CONTRACT
            </span>
          </div>
          <span style={{ fontSize: '12px', color: 'var(--text-muted)', lineHeight: 1.45 }}>
            {activeNode.contract}
          </span>
        </div>
      </div>
    </Panel>
  )
}

