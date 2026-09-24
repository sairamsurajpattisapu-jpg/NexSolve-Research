import { useState } from 'react'

interface NodeDetail {
  id: string
  label: string
  zone: 'OBSERVED' | 'CURRENT' | 'FORECAST'
  classification: string
  metrics: string
  details: string
}

const NODES: Record<string, NodeDetail> = {
  ingress: {
    id: 'ingress',
    label: 'PCAP Wire Ingress',
    zone: 'OBSERVED',
    classification: 'OBSERVED',
    metrics: '2,277 frames · Microsecond Timestamps',
    details: 'Passive packet capture stream without payload tampering or synthetic imputation.',
  },
  flows: {
    id: 'flows',
    label: 'Bidirectional Flows',
    zone: 'OBSERVED',
    classification: 'OBSERVED',
    metrics: '283 TCP/UDP Flows · 5-Tuple Tracking',
    details: 'Reconstructed Layer 3/4 session state, SYN/ACK handshake asymmetry, and packet size variance.',
  },
  state0: {
    id: 'state0',
    label: 'Canonical State Vector S_0',
    zone: 'CURRENT',
    classification: 'INFERRED',
    metrics: '45 Continuous Features · 60s Window',
    details: 'Current network state representation at temporal boundary T_0. Zero RTT fabrication.',
  },
  t1: {
    id: 't1',
    label: 'T+1 Horizon (+60s)',
    zone: 'FORECAST',
    classification: 'FORECAST',
    metrics: 'P(Atk) = 0.34 · Stage: C2 Beaconing',
    details: 'Projected initial beacon cadence and command channel staging.',
  },
  t2: {
    id: 't2',
    label: 'T+2 Horizon (+120s)',
    zone: 'FORECAST',
    classification: 'FORECAST',
    metrics: 'P(Atk) = 0.52 · Stage: Defense Evasion',
    details: 'Projected log silencing attempts and abnormal protocol port masking.',
  },
  t3: {
    id: 't3',
    label: 'T+3 Horizon (+180s)',
    zone: 'FORECAST',
    classification: 'FORECAST',
    metrics: 'P(Atk) = 0.68 · Stage: Lateral Movement',
    details: 'Projected SMB/RPC lateral pivoting across internal network subnet segments.',
  },
  t4: {
    id: 't4',
    label: 'T+4 Horizon (+240s)',
    zone: 'FORECAST',
    classification: 'FORECAST',
    metrics: 'P(Atk) = 0.79 · Stage: Collection Staging',
    details: 'Projected automated target directory consolidation and staging compression.',
  },
  t5: {
    id: 't5',
    label: 'T+5 Horizon (+300s)',
    zone: 'FORECAST',
    classification: 'FORECAST',
    metrics: 'Risk(5) = 88.4% · Stage: Exfiltration / Impact',
    details: 'Compound forward threat exposure across 5 discrete 60s windows with uncertainty envelope.',
  },
}

export function HeroTemporalVisualization() {
  const [selectedNode, setSelectedNode] = useState<string>('state0')
  const activeDetail = NODES[selectedNode] || NODES['state0']

  return (
    <div className="hero-visual-card">
      <div className="visual-top-bar">
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div className="visual-title-badge">
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#38bdf8', display: 'inline-block' }} />
            TEMPORAL NETWORK GRAPH & ATTACK HORIZON
          </div>
          <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#71717a' }}>
            [Illustrative example · Demonstrates temporal state graph]
          </span>
        </div>
        <div className="visual-legend">
          <span className="legend-tag">
            <span className="tag-badge observed">OBSERVED</span>
            Past Telemetry
          </span>
          <span className="legend-tag">
            <span className="tag-badge inferred">INFERRED</span>
            Current State (T_0)
          </span>
          <span className="legend-tag">
            <span className="tag-badge forecast">FORECAST</span>
            Prospective Rollout
          </span>
        </div>
      </div>

      <svg
        className="hero-svg-canvas"
        viewBox="0 0 920 310"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
        aria-label="NexSolve Temporal State and Attack Forecasting Graph"
      >
        <defs>
          <linearGradient id="observedGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#10b981" stopOpacity="0.2" />
            <stop offset="100%" stopColor="#10b981" stopOpacity="0.8" />
          </linearGradient>
          <linearGradient id="forecastGrad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.8" />
            <stop offset="100%" stopColor="#f59e0b" stopOpacity="0.9" />
          </linearGradient>
          <linearGradient id="uncertaintyEnvelope" x1="420" y1="50" x2="880" y2="50" gradientUnits="userSpaceOnUse">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.04" />
            <stop offset="60%" stopColor="#f59e0b" stopOpacity="0.07" />
            <stop offset="100%" stopColor="#ef4444" stopOpacity="0.10" />
          </linearGradient>
        </defs>

        {/* Background Grid Lines */}
        <line x1="40" y1="70" x2="880" y2="70" stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />
        <line x1="40" y1="150" x2="880" y2="150" stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />
        <line x1="40" y1="230" x2="880" y2="230" stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />

        {/* Uncertainty Cone / Envelope behind Forecast Horizons */}
        <polygon
          points="410,150 880,45 880,255"
          fill="url(#uncertaintyEnvelope)"
        />

        {/* Temporal Boundary (T_0) Divider Line with subtle glow */}
        <line
          x1="410"
          y1="20"
          x2="410"
          y2="280"
          stroke="#ffffff"
          strokeWidth="1.5"
          strokeDasharray="4 4"
          strokeOpacity="0.4"
          className="temporal-boundary-line"
        />
        <text x="410" y="295" fill="#a1a1aa" fontSize="10.5" fontFamily="monospace" textAnchor="middle" fontWeight="bold">
          TEMPORAL BOUNDARY T_0 (NOW)
        </text>

        {/* ---------------- ZONE A: OBSERVED TELEMETRY ---------------- */}
        {/* Animated Wire Ingress to Flow Reconstructor Paths */}
        <path d="M 80 150 L 220 150" stroke="#10b981" strokeWidth="2" strokeOpacity="0.7" className="observed-flow-path" />
        <path d="M 80 150 C 140 100, 160 100, 220 150" stroke="#10b981" strokeWidth="1.2" strokeOpacity="0.35" className="observed-flow-path-subtle" />
        <path d="M 80 150 C 140 200, 160 200, 220 150" stroke="#10b981" strokeWidth="1.2" strokeOpacity="0.35" className="observed-flow-path-subtle" />

        {/* Flow to Current State S_0 */}
        <path d="M 220 150 L 410 150" stroke="#10b981" strokeWidth="2.5" strokeOpacity="0.9" className="observed-flow-path" />

        {/* Dynamic Telemetry Packet Gliders moving along observed paths */}
        <circle cx="150" cy="150" r="3" fill="#10b981" className="telemetry-packet-glider" />
        <circle cx="315" cy="150" r="3" fill="#38bdf8" className="telemetry-packet-glider g2" />

        {/* Sub-telemetry endpoints */}
        <circle cx="140" cy="90" r="3.5" fill="#34d399" />
        <text x="140" y="78" fill="#71717a" fontSize="9" fontFamily="monospace" textAnchor="middle">10.0.0.1</text>
        <circle cx="150" cy="210" r="3.5" fill="#34d399" />
        <text x="150" y="226" fill="#71717a" fontSize="9" fontFamily="monospace" textAnchor="middle">192.168.1.105</text>

        {/* Node: Wire Ingress */}
        <g
          style={{ cursor: 'pointer' }}
          onClick={() => setSelectedNode('ingress')}
          tabIndex={0}
          role="button"
          aria-label="View Ingress Telemetry"
        >
          <circle cx="80" cy="150" r="18" fill="#0d1117" stroke={selectedNode === 'ingress' ? '#ffffff' : '#10b981'} strokeWidth="2" />
          <circle cx="80" cy="150" r="6" fill="#10b981" />
          <text x="80" y="185" fill="#ffffff" fontSize="11" fontFamily="sans-serif" fontWeight="700" textAnchor="middle">PCAP</text>
          <text x="80" y="198" fill="#10b981" fontSize="9" fontFamily="monospace" textAnchor="middle">INGRESS</text>
        </g>

        {/* Node: Bidirectional Flows */}
        <g
          style={{ cursor: 'pointer' }}
          onClick={() => setSelectedNode('flows')}
          tabIndex={0}
          role="button"
          aria-label="View Flow Tracking"
        >
          <circle cx="220" cy="150" r="22" fill="#0d1117" stroke={selectedNode === 'flows' ? '#ffffff' : '#10b981'} strokeWidth="2" />
          <circle cx="220" cy="150" r="8" fill="#34d399" />
          <text x="220" y="190" fill="#ffffff" fontSize="11" fontFamily="sans-serif" fontWeight="700" textAnchor="middle">FLOWS</text>
          <text x="220" y="203" fill="#10b981" fontSize="9" fontFamily="monospace" textAnchor="middle">5-TUPLE</text>
        </g>

        {/* ---------------- ZONE B: CURRENT STATE S_0 ---------------- */}
        <g
          style={{ cursor: 'pointer' }}
          onClick={() => setSelectedNode('state0')}
          tabIndex={0}
          role="button"
          aria-label="View Current State S_0"
        >
          {/* Pulsing ring around current state */}
          <circle cx="410" cy="150" r="36" fill="none" stroke="#38bdf8" strokeWidth="1" strokeOpacity="0.4" className="current-state-pulse" />
          <circle cx="410" cy="150" r="28" fill="#09090b" stroke={selectedNode === 'state0' ? '#ffffff' : '#38bdf8'} strokeWidth="2.5" />
          <circle cx="410" cy="150" r="12" fill="#38bdf8" fillOpacity="0.25" />
          <circle cx="410" cy="150" r="6" fill="#ffffff" />
          <text x="410" y="132" fill="#38bdf8" fontSize="10" fontFamily="monospace" fontWeight="700" textAnchor="middle">S_0 ∈ ℝ^45</text>
          <text x="410" y="196" fill="#ffffff" fontSize="11.5" fontFamily="sans-serif" fontWeight="800" textAnchor="middle">CURRENT</text>
          <text x="410" y="210" fill="#38bdf8" fontSize="9" fontFamily="monospace" textAnchor="middle">STATE (T_0)</text>
        </g>

        {/* ---------------- ZONE C: FORECAST TRAJECTORIES ---------------- */}
        {/* Forward Branching Paths (Dashed, Prospective with subtle animated sweep) */}
        <path d="M 410 150 C 470 150, 480 120, 520 120" stroke="#38bdf8" strokeWidth="2" strokeDasharray="4 3" className="forecast-flow-path" />
        <path d="M 520 120 C 570 120, 580 100, 620 100" stroke="#f59e0b" strokeWidth="2" strokeDasharray="4 3" className="forecast-flow-path" />
        <path d="M 620 100 C 670 100, 680 90, 710 90" stroke="#f59e0b" strokeWidth="2" strokeDasharray="4 3" className="forecast-flow-path" />
        <path d="M 710 90 C 760 90, 770 80, 800 80" stroke="#f59e0b" strokeWidth="2" strokeDasharray="4 3" className="forecast-flow-path" />
        <path d="M 800 80 C 830 80, 840 75, 870 75" stroke="#ef4444" strokeWidth="2" strokeDasharray="4 3" className="forecast-flow-path" />

        {/* Alternative lower branch (benign decay / abstention trajectory) */}
        <path d="M 410 150 C 470 150, 490 200, 550 210" stroke="rgba(255,255,255,0.18)" strokeWidth="1.2" strokeDasharray="3 3" />
        <path d="M 550 210 C 620 220, 700 230, 850 240" stroke="rgba(255,255,255,0.12)" strokeWidth="1" strokeDasharray="3 3" />
        <text x="850" y="255" fill="#71717a" fontSize="8.5" fontFamily="monospace" textAnchor="end">Alternative Baseline (Abstention)</text>

        {/* Horizon Node: T+1 (Progressive appearance toward T+5) */}
        <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t1')} tabIndex={0} role="button" aria-label="Horizon T+1" className="forecast-node-group fn-1">
          <circle cx="520" cy="120" r="16" fill="#0d1117" stroke={selectedNode === 't1' ? '#ffffff' : '#38bdf8'} strokeWidth="1.8" />
          <circle cx="520" cy="120" r="5" fill="#38bdf8" />
          <text x="520" y="150" fill="#ffffff" fontSize="10.5" fontFamily="monospace" fontWeight="700" textAnchor="middle">T+1</text>
          <text x="520" y="162" fill="#38bdf8" fontSize="8.5" fontFamily="monospace" textAnchor="middle">+60s</text>
        </g>

        {/* Horizon Node: T+2 */}
        <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t2')} tabIndex={0} role="button" aria-label="Horizon T+2" className="forecast-node-group fn-2">
          <circle cx="620" cy="100" r="16" fill="#0d1117" stroke={selectedNode === 't2' ? '#ffffff' : '#f59e0b'} strokeWidth="1.8" />
          <circle cx="620" cy="100" r="5" fill="#f59e0b" />
          <text x="620" y="130" fill="#ffffff" fontSize="10.5" fontFamily="monospace" fontWeight="700" textAnchor="middle">T+2</text>
          <text x="620" y="142" fill="#f59e0b" fontSize="8.5" fontFamily="monospace" textAnchor="middle">+120s</text>
        </g>

        {/* Horizon Node: T+3 */}
        <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t3')} tabIndex={0} role="button" aria-label="Horizon T+3" className="forecast-node-group fn-3">
          <circle cx="710" cy="90" r="16" fill="#0d1117" stroke={selectedNode === 't3' ? '#ffffff' : '#f59e0b'} strokeWidth="1.8" />
          <circle cx="710" cy="90" r="5" fill="#f59e0b" />
          <text x="710" y="120" fill="#ffffff" fontSize="10.5" fontFamily="monospace" fontWeight="700" textAnchor="middle">T+3</text>
          <text x="710" y="132" fill="#f59e0b" fontSize="8.5" fontFamily="monospace" textAnchor="middle">+180s</text>
        </g>

        {/* Horizon Node: T+4 */}
        <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t4')} tabIndex={0} role="button" aria-label="Horizon T+4" className="forecast-node-group fn-4">
          <circle cx="800" cy="80" r="16" fill="#0d1117" stroke={selectedNode === 't4' ? '#ffffff' : '#f59e0b'} strokeWidth="1.8" />
          <circle cx="800" cy="80" r="5" fill="#f59e0b" />
          <text x="800" y="110" fill="#ffffff" fontSize="10.5" fontFamily="monospace" fontWeight="700" textAnchor="middle">T+4</text>
          <text x="800" y="122" fill="#f59e0b" fontSize="8.5" fontFamily="monospace" textAnchor="middle">+240s</text>
        </g>

        {/* Horizon Node: T+5 */}
        <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t5')} tabIndex={0} role="button" aria-label="Horizon T+5" className="forecast-node-group fn-5">
          <circle cx="870" cy="75" r="18" fill="#0d1117" stroke={selectedNode === 't5' ? '#ffffff' : '#ef4444'} strokeWidth="2" />
          <circle cx="870" cy="75" r="6" fill="#ef4444" />
          <text x="870" y="105" fill="#ffffff" fontSize="10.5" fontFamily="monospace" fontWeight="800" textAnchor="middle">T+5</text>
          <text x="870" y="117" fill="#ef4444" fontSize="8.5" fontFamily="monospace" textAnchor="middle">+300s</text>
        </g>
      </svg>

      {/* Interactive Telemetry Drawer below SVG */}
      <div style={{
        marginTop: 16,
        padding: '12px 18px',
        background: 'rgba(255, 255, 255, 0.02)',
        border: '1px solid rgba(255, 255, 255, 0.08)',
        borderRadius: 8,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span className={`tag-badge ${activeDetail.classification.toLowerCase()}`}>
            {activeDetail.classification}
          </span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#ffffff' }}>
              {activeDetail.label}
            </div>
            <div style={{ fontSize: 11.5, color: '#a1a1aa', fontFamily: 'monospace' }}>
              {activeDetail.metrics}
            </div>
          </div>
        </div>
        <div style={{ fontSize: 12, color: '#71717a', maxWidth: 440, textAlign: 'right' }}>
          {activeDetail.details}
        </div>
      </div>
    </div>
  )
}
