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
    metrics: 'P(Atk) = 0.34 · Stage: Command & Control',
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
  const [viewMode, setViewMode] = useState<'graph' | 'tree'>('graph')
  const activeDetail = NODES[selectedNode] || NODES['state0']

  return (
    <div className="hero-visual-card" style={{ background: '#0A0A0A', border: '1px solid #222222', borderRadius: '8px' }}>
      {/* Visual Top Bar */}
      <div className="visual-top-bar" style={{ borderBottom: '1px solid #222222', paddingBottom: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <div className="visual-title-badge" style={{ color: '#FFFFFF', fontSize: '11px', fontFamily: 'var(--font-sans)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#FFFFFF', display: 'inline-block' }} />
            TEMPORAL NETWORK BEHAVIOR &middot; OBSERVED &rarr; FORECAST
          </div>
          <span style={{ fontSize: 10.5, fontFamily: 'var(--font-ui)', color: '#737373', borderLeft: '1px solid #222', paddingLeft: 10 }}>
            [Conceptual workflow model &middot; Not live analysis data]
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Mode Switcher */}
          <div style={{ display: 'inline-flex', background: '#141414', border: '1px solid #262626', borderRadius: '4px', padding: '2px' }}>
            <button
              type="button"
              onClick={() => setViewMode('graph')}
              style={{
                background: viewMode === 'graph' ? '#262626' : 'transparent',
                color: viewMode === 'graph' ? '#ffffff' : '#888888',
                border: 'none',
                padding: '3px 8px',
                borderRadius: '3px',
                fontSize: '10.5px',
                fontFamily: 'var(--font-ui)',
                cursor: 'pointer',
              }}
            >
              TRAJECTORY GRAPH
            </button>
            <button
              type="button"
              onClick={() => setViewMode('tree')}
              style={{
                background: viewMode === 'tree' ? '#262626' : 'transparent',
                color: viewMode === 'tree' ? '#ffffff' : '#888888',
                border: 'none',
                padding: '3px 8px',
                borderRadius: '3px',
                fontSize: '10.5px',
                fontFamily: 'var(--font-ui)',
                cursor: 'pointer',
              }}
            >
              TREE HIERARCHY
            </button>
          </div>

          <div className="visual-legend" style={{ display: 'flex', gap: '12px', fontSize: '11px', color: '#999999' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ padding: '1px 6px', border: '1px solid #FFFFFF', color: '#FFFFFF', fontSize: '9.5px', fontFamily: 'var(--font-ui)', borderRadius: '3px' }}>OBSERVED</span>
              Past
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ padding: '1px 6px', background: '#FFFFFF', color: '#000000', fontSize: '9.5px', fontFamily: 'var(--font-ui)', fontWeight: 700, borderRadius: '3px' }}>CURRENT</span>
              Now (T_0)
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ padding: '1px 6px', border: '1px dashed #999999', color: '#CCCCCC', fontSize: '9.5px', fontFamily: 'var(--font-ui)', borderRadius: '3px' }}>FORECAST</span>
              T+1..T+5
            </span>
          </div>
        </div>
      </div>

      {viewMode === 'graph' ? (
        <svg
          className="hero-svg-canvas"
          viewBox="0 0 920 310"
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
          role="img"
          aria-label="NexSolve Temporal State and Attack Forecasting Graph"
          style={{ width: '100%', height: 'auto', display: 'block', margin: '14px 0' }}
        >
          {/* Background Grid Lines */}
          <line x1="40" y1="70" x2="880" y2="70" stroke="#1A1A1A" strokeDasharray="3 3" />
          <line x1="40" y1="150" x2="880" y2="150" stroke="#222222" strokeDasharray="3 3" />
          <line x1="40" y1="230" x2="880" y2="230" stroke="#1A1A1A" strokeDasharray="3 3" />

          {/* Uncertainty Cone / Envelope behind Forecast Horizons */}
          <polygon
            points="410,150 880,45 880,255"
            fill="rgba(255, 255, 255, 0.03)"
            stroke="#2A2A2A"
            strokeWidth="1"
            strokeDasharray="4 4"
          />

          {/* Temporal Boundary (T_0) Divider Line */}
          <line
            x1="410"
            y1="20"
            x2="410"
            y2="280"
            stroke="#FFFFFF"
            strokeWidth="1"
            strokeDasharray="4 4"
            strokeOpacity="0.4"
          />
          <text x="410" y="295" fill="#888888" fontSize="10.5" fontFamily="var(--mono)" textAnchor="middle" fontWeight="bold">
            TEMPORAL BOUNDARY T_0 (NOW)
          </text>

          {/* ---------------- ZONE A: OBSERVED TELEMETRY ---------------- */}
          <path d="M 80 150 L 220 150" stroke="#FFFFFF" strokeWidth="2" strokeOpacity="0.8" />
          <path d="M 80 150 C 140 100, 160 100, 220 150" stroke="#666666" strokeWidth="1" strokeDasharray="2 2" />
          <path d="M 80 150 C 140 200, 160 200, 220 150" stroke="#666666" strokeWidth="1" strokeDasharray="2 2" />

          {/* Flow to Current State S_0 */}
          <path d="M 220 150 L 410 150" stroke="#FFFFFF" strokeWidth="2" strokeOpacity="0.9" />

          {/* Sub-telemetry endpoints */}
          <circle cx="140" cy="90" r="3" fill="#666666" />
          <text x="140" y="78" fill="#666666" fontSize="9" fontFamily="var(--mono)" textAnchor="middle">10.0.0.1</text>
          <circle cx="150" cy="210" r="3" fill="#666666" />
          <text x="150" y="226" fill="#666666" fontSize="9" fontFamily="var(--mono)" textAnchor="middle">192.168.1.105</text>

          {/* Node: Wire Ingress */}
          <g
            style={{ cursor: 'pointer' }}
            onClick={() => setSelectedNode('ingress')}
            tabIndex={0}
            role="button"
            aria-label="View Ingress Telemetry"
          >
            <circle cx="80" cy="150" r="18" fill="#0A0A0A" stroke={selectedNode === 'ingress' ? '#FFFFFF' : '#888888'} strokeWidth="1.5" />
            <circle cx="80" cy="150" r="5" fill="#FFFFFF" />
            <text x="80" y="185" fill="#FFFFFF" fontSize="11" fontFamily="sans-serif" fontWeight="700" textAnchor="middle">PCAP</text>
            <text x="80" y="198" fill="#888888" fontSize="9" fontFamily="var(--mono)" textAnchor="middle">INGRESS</text>
          </g>

          {/* Node: Bidirectional Flows */}
          <g
            style={{ cursor: 'pointer' }}
            onClick={() => setSelectedNode('flows')}
            tabIndex={0}
            role="button"
            aria-label="View Flow Tracking"
          >
            <circle cx="220" cy="150" r="22" fill="#0A0A0A" stroke={selectedNode === 'flows' ? '#FFFFFF' : '#888888'} strokeWidth="1.5" />
            <circle cx="220" cy="150" r="6" fill="#CCCCCC" />
            <text x="220" y="190" fill="#FFFFFF" fontSize="11" fontFamily="sans-serif" fontWeight="700" textAnchor="middle">FLOWS</text>
            <text x="220" y="203" fill="#888888" fontSize="9" fontFamily="var(--mono)" textAnchor="middle">5-TUPLE</text>
          </g>

          {/* ---------------- ZONE B: CURRENT STATE S_0 ---------------- */}
          <g
            style={{ cursor: 'pointer' }}
            onClick={() => setSelectedNode('state0')}
            tabIndex={0}
            role="button"
            aria-label="View Current State S_0"
          >
            <circle cx="410" cy="150" r="30" fill="none" stroke="#444444" strokeWidth="1" strokeDasharray="2 2" />
            <circle cx="410" cy="150" r="24" fill="#FFFFFF" />
            <circle cx="410" cy="150" r="8" fill="#000000" />
            <text x="410" y="195" fill="#FFFFFF" fontSize="12" fontFamily="sans-serif" fontWeight="800" textAnchor="middle">STATE S_0</text>
            <text x="410" y="210" fill="#AAAAAA" fontSize="9.5" fontFamily="var(--mono)" textAnchor="middle">45 FEATURES</text>
          </g>

          {/* ---------------- ZONE C: FORWARD FORECAST ROLLOUT ---------------- */}
          {/* Main Autoregressive Trajectory Vector */}
          <path
            d="M 410 150 C 470 140, 500 120, 540 115 C 580 110, 610 100, 630 95 C 670 90, 700 85, 710 90 C 740 95, 770 85, 800 80 C 830 75, 850 75, 870 75"
            stroke="#FFFFFF"
            strokeWidth="2.5"
            strokeDasharray="6 4"
          />

          {/* Alternative Trajectory Paths (Ensemble Spread) */}
          <path d="M 410 150 C 500 130, 600 70, 870 60" stroke="#555555" strokeWidth="1" strokeDasharray="3 3" />
          <path d="M 410 150 C 500 165, 600 180, 870 200" stroke="#444444" strokeWidth="1" strokeDasharray="3 3" />
          <path d="M 410 150 C 500 180, 650 210, 870 230" stroke="#333333" strokeWidth="1" strokeDasharray="2 4" />

          {/* Horizon Node: T+1 */}
          <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t1')} tabIndex={0} role="button" aria-label="Horizon T+1">
            <circle cx="540" cy="115" r="14" fill="#0A0A0A" stroke={selectedNode === 't1' ? '#FFFFFF' : '#888888'} strokeWidth="1.5" strokeDasharray="3 2" />
            <circle cx="540" cy="115" r="4" fill="#888888" />
            <text x="540" y="145" fill="#FFFFFF" fontSize="10.5" fontFamily="var(--mono)" fontWeight="700" textAnchor="middle">T+1</text>
            <text x="540" y="157" fill="#888888" fontSize="8.5" fontFamily="var(--mono)" textAnchor="middle">+60s</text>
          </g>

          {/* Horizon Node: T+2 */}
          <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t2')} tabIndex={0} role="button" aria-label="Horizon T+2">
            <circle cx="630" cy="95" r="14" fill="#0A0A0A" stroke={selectedNode === 't2' ? '#FFFFFF' : '#888888'} strokeWidth="1.5" strokeDasharray="3 2" />
            <circle cx="630" cy="95" r="4" fill="#999999" />
            <text x="630" y="125" fill="#FFFFFF" fontSize="10.5" fontFamily="var(--mono)" fontWeight="700" textAnchor="middle">T+2</text>
            <text x="630" y="137" fill="#888888" fontSize="8.5" fontFamily="var(--mono)" textAnchor="middle">+120s</text>
          </g>

          {/* Horizon Node: T+3 */}
          <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t3')} tabIndex={0} role="button" aria-label="Horizon T+3">
            <circle cx="710" cy="90" r="14" fill="#0A0A0A" stroke={selectedNode === 't3' ? '#FFFFFF' : '#888888'} strokeWidth="1.5" strokeDasharray="3 2" />
            <circle cx="710" cy="90" r="4" fill="#AAAAAA" />
            <text x="710" y="120" fill="#FFFFFF" fontSize="10.5" fontFamily="var(--mono)" fontWeight="700" textAnchor="middle">T+3</text>
            <text x="710" y="132" fill="#888888" fontSize="8.5" fontFamily="var(--mono)" textAnchor="middle">+180s</text>
          </g>

          {/* Horizon Node: T+4 */}
          <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t4')} tabIndex={0} role="button" aria-label="Horizon T+4">
            <circle cx="800" cy="80" r="16" fill="#0A0A0A" stroke={selectedNode === 't4' ? '#FFFFFF' : '#888888'} strokeWidth="1.5" strokeDasharray="3 2" />
            <circle cx="800" cy="80" r="4" fill="#AAAAAA" />
            <text x="800" y="110" fill="#FFFFFF" fontSize="10.5" fontFamily="var(--mono)" fontWeight="700" textAnchor="middle">T+4</text>
            <text x="800" y="122" fill="#888888" fontSize="8.5" fontFamily="var(--mono)" textAnchor="middle">+240s</text>
          </g>

          {/* Horizon Node: T+5 */}
          <g style={{ cursor: 'pointer' }} onClick={() => setSelectedNode('t5')} tabIndex={0} role="button" aria-label="Horizon T+5">
            <circle cx="870" cy="75" r="18" fill="#0A0A0A" stroke={selectedNode === 't5' ? '#FFFFFF' : '#CCCCCC'} strokeWidth="1.8" strokeDasharray="3 2" />
            <circle cx="870" cy="75" r="5" fill="#FFFFFF" />
            <text x="870" y="105" fill="#FFFFFF" fontSize="10.5" fontFamily="var(--mono)" fontWeight="800" textAnchor="middle">T+5</text>
            <text x="870" y="117" fill="#888888" fontSize="8.5" fontFamily="var(--mono)" textAnchor="middle">+300s</text>
          </g>
        </svg>
      ) : (
        /* Explicit Text Tree Hierarchy View */
        <div
          style={{
            margin: '14px 0',
            padding: '20px 24px',
            background: '#060606',
            border: '1px solid #1c1c1c',
            borderRadius: '6px',
            fontFamily: 'var(--mono)',
            fontSize: '12px',
            color: '#a3a3a3',
            lineHeight: 1.7,
            overflowX: 'auto',
          }}
        >
          <div style={{ color: '#ffffff', fontWeight: 700, marginBottom: '6px' }}>
            PAST NETWORK STATE (TELEMETRY OBSERVED)
          </div>
          <div>│</div>
          <div>├── <span style={{ color: '#ffffff' }}>[observed]</span> Ingress PCAP &bull; Passive Wire Capture (2,277 frames, microsecond stamps)</div>
          <div>├── <span style={{ color: '#ffffff' }}>[observed]</span> 5-Tuple Flows &bull; Bidirectional Handshake State &amp; Flag Variance</div>
          <div>├── <span style={{ color: '#ffffff' }}>[observed]</span> Temporal Windows &bull; Discrete 60-second Non-Overlapping Aggregation</div>
          <div>│</div>
          <div style={{ color: '#ffffff', fontWeight: 700, marginTop: '4px', marginBottom: '6px' }}>
            NOW (TEMPORAL BOUNDARY T_0 &middot; CANONICAL STATE S_0 &middot; 45 PASSIVE CONTINUOUS FEATURES)
          </div>
          <div>│</div>
          <div>├── <span style={{ color: '#e5e5e5' }}>[forecast T+1]</span> +60s Lookahead &bull; P(Atk)=0.34 &bull; Stage: Command &amp; Control (C2 Beacon Cadence)</div>
          <div>├── <span style={{ color: '#e5e5e5' }}>[forecast T+2]</span> +120s Lookahead &bull; P(Atk)=0.52 &bull; Stage: Defense Evasion (Syslog Masking)</div>
          <div>├── <span style={{ color: '#e5e5e5' }}>[forecast T+3]</span> +180s Lookahead &bull; P(Atk)=0.68 &bull; Stage: Lateral Movement (SMB/RPC Multiplexing)</div>
          <div>├── <span style={{ color: '#e5e5e5' }}>[forecast T+4]</span> +240s Lookahead &bull; P(Atk)=0.79 &bull; Stage: Collection Staging (Automated Target Consolidation)</div>
          <div>└── <span style={{ color: '#ffffff', fontWeight: 700 }}>[forecast T+5]</span> +300s Lookahead &bull; Risk(5)=88.4% &bull; Stage: Exfiltration / Impact (High-Volume Egress)</div>
        </div>
      )}

      {/* Interactive Telemetry Drawer below SVG / Tree */}
      <div
        style={{
          marginTop: 14,
          padding: '12px 18px',
          background: '#111111',
          border: '1px solid #222222',
          borderRadius: 4,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: 12,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span
            style={{
              fontSize: '10px',
              fontFamily: 'var(--font-ui)',
              fontWeight: 700,
              padding: '2px 8px',
              borderRadius: '3px',
              background: activeDetail.classification === 'FORECAST' ? 'transparent' : '#FFFFFF',
              color: activeDetail.classification === 'FORECAST' ? '#FFFFFF' : '#000000',
              border: activeDetail.classification === 'FORECAST' ? '1px dashed #FFFFFF' : '1px solid #FFFFFF',
            }}
          >
            {activeDetail.classification}
          </span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 700, color: '#FFFFFF' }}>
              {activeDetail.label}
            </div>
            <div style={{ fontSize: 11.5, color: '#999999', fontFamily: 'var(--mono)' }}>
              {activeDetail.metrics}
            </div>
          </div>
        </div>
        <div style={{ fontSize: 12, color: '#888888', maxWidth: 440, textAlign: 'right' }}>
          {activeDetail.details}
        </div>
      </div>
    </div>
  )
}
