import { useState } from 'react'
import { ArrowRight } from 'lucide-react'

interface StageItem {
  id: string
  num: string
  name: string
  phase: string
  classification: 'OBSERVED' | 'INFERRED' | 'FORECAST'
  stageConfidence: number
  techniqueConfidence: number
  mitre: string
  telemetry: string
  rationale: string
}

const STAGES: StageItem[] = [
  {
    id: 'benign',
    num: '01',
    name: 'Benign Observation',
    phase: 'Baseline',
    classification: 'OBSERVED',
    stageConfidence: 0.99,
    techniqueConfidence: 0.98,
    mitre: 'None (Nominal)',
    telemetry: 'TCP flag symmetry = 1.02 · DNS query rate = 8.4/min',
    rationale: 'Nominal enterprise network baseline conforming to Poisson inter-arrival envelope.',
  },
  {
    id: 'recon',
    num: '02',
    name: 'Reconnaissance',
    phase: 'Penetration',
    classification: 'OBSERVED',
    stageConfidence: 0.94,
    techniqueConfidence: 0.91,
    mitre: 'T1046 (Network Service Discovery)',
    telemetry: 'Unique destination ports = 184 · SYN scan velocity = 48/sec',
    rationale: 'Rapid sequential port probing across ephemeral destination ports.',
  },
  {
    id: 'weaponization',
    num: '03',
    name: 'Weaponization',
    phase: 'Penetration',
    classification: 'INFERRED',
    stageConfidence: 0.82,
    techniqueConfidence: 0.76,
    mitre: 'T1190 (Exploit Public-Facing App)',
    telemetry: 'Inbound packet size skew = 2.8 · Out-of-order frames = 3',
    rationale: 'Structural anomaly in transport packet sizing preceding target service connection.',
  },
  {
    id: 'delivery',
    num: '04',
    name: 'Delivery',
    phase: 'Penetration',
    classification: 'INFERRED',
    stageConfidence: 0.85,
    techniqueConfidence: 0.79,
    mitre: 'T1566 (Phishing / Ingress Transfer)',
    telemetry: 'Sustained unidirectional burst = 480 KiB over 4.2s',
    rationale: 'Sudden transport session burst to previously uncontacted internal target host.',
  },
  {
    id: 'exploitation',
    num: '05',
    name: 'Exploitation',
    phase: 'Penetration',
    classification: 'INFERRED',
    stageConfidence: 0.88,
    techniqueConfidence: 0.84,
    mitre: 'T1203 (Exploitation for Client Execution)',
    telemetry: 'TCP FIN/RST ratio = 3.2 · Response latency variance spike',
    rationale: 'Abnormal termination flag dynamics indicating exploit daemon interaction.',
  },
  {
    id: 'installation',
    num: '06',
    name: 'Installation',
    phase: 'Internal Expansion',
    classification: 'INFERRED',
    stageConfidence: 0.79,
    techniqueConfidence: 0.73,
    mitre: 'T1547 (Boot/Logon Autostart Execution)',
    telemetry: 'Keepalive heartbeat = 30s cadence on port 8443',
    rationale: 'Initial persistence established via regular background control beacon.',
  },
  {
    id: 'c2',
    num: '07',
    name: 'Command & Control',
    phase: 'Internal Expansion',
    classification: 'FORECAST',
    stageConfidence: 0.74,
    techniqueConfidence: 0.69,
    mitre: 'T1071.001 (Application Layer Protocol: Web)',
    telemetry: 'Projected TLS SNI entropy shift · Inter-arrival periodicity',
    rationale: 'State transition model projects persistent outbound encrypted telemetry loop at T+1 (+60s).',
  },
  {
    id: 'priv_esc',
    num: '08',
    name: 'Privilege Escalation',
    phase: 'Internal Expansion',
    classification: 'FORECAST',
    stageConfidence: 0.68,
    techniqueConfidence: 0.62,
    mitre: 'T1068 (Exploitation for Privilege Escalation)',
    telemetry: 'Projected internal loopback burst · Kerberos ticket requests',
    rationale: 'Multi-step rollout indicates escalation sequence attempt at T+2 (+120s).',
  },
  {
    id: 'defense_evasion',
    num: '09',
    name: 'Defense Evasion',
    phase: 'Internal Expansion',
    classification: 'FORECAST',
    stageConfidence: 0.71,
    techniqueConfidence: 0.65,
    mitre: 'T1562 (Impair Defenses / Log Evasion)',
    telemetry: 'Projected suppression of syslog UDP stream (Port 514)',
    rationale: 'Anticipated traffic suppression behavior following initial control establishment.',
  },
  {
    id: 'credential_access',
    num: '10',
    name: 'Credential Access',
    phase: 'Internal Expansion',
    classification: 'FORECAST',
    stageConfidence: 0.65,
    techniqueConfidence: 0.58,
    mitre: 'T1003 (OS Credential Dumping)',
    telemetry: 'Projected SMB session multiplexing on port 445',
    rationale: 'Rollout dynamics indicate credential harvesting activity at T+3 (+180s).',
  },
  {
    id: 'discovery',
    num: '11',
    name: 'Discovery',
    phase: 'Internal Expansion',
    classification: 'FORECAST',
    stageConfidence: 0.73,
    techniqueConfidence: 0.67,
    mitre: 'T1018 (Remote System Discovery)',
    telemetry: 'Projected ARP scan and ICMP echo rate acceleration',
    rationale: 'Internal subnet enumeration following credential compromise.',
  },
  {
    id: 'lateral',
    num: '12',
    name: 'Lateral Movement',
    phase: 'Internal Expansion',
    classification: 'FORECAST',
    stageConfidence: 0.78,
    techniqueConfidence: 0.72,
    mitre: 'T1021.002 (Remote Services: SMB/Windows Admin Shares)',
    telemetry: 'Projected east-west flow expansion across /24 subnet',
    rationale: 'Inter-host pivoting and admin share mounting predicted across horizon T+4 (+240s).',
  },
  {
    id: 'collection',
    num: '13',
    name: 'Collection',
    phase: 'Objective Impact',
    classification: 'FORECAST',
    stageConfidence: 0.69,
    techniqueConfidence: 0.63,
    mitre: 'T1074 (Data Staged for Extraction)',
    telemetry: 'Projected internal byte consolidation on storage target host',
    rationale: 'High-volume internal data staging observed prior to exfiltration.',
  },
  {
    id: 'exfiltration',
    num: '14',
    name: 'Exfiltration',
    phase: 'Objective Impact',
    classification: 'FORECAST',
    stageConfidence: 0.81,
    techniqueConfidence: 0.75,
    mitre: 'T1041 (Exfiltration Over C2 Channel)',
    telemetry: 'Projected egress outbound volume surge (+650% vs baseline)',
    rationale: 'Predicted outbound data transmission across external TLS pipe at T+5 (+300s).',
  },
  {
    id: 'impact',
    num: '15',
    name: 'Impact / Disruption',
    phase: 'Objective Impact',
    classification: 'FORECAST',
    stageConfidence: 0.84,
    techniqueConfidence: 0.79,
    mitre: 'T1498 (Network Denial of Service)',
    telemetry: 'Projected connection saturation · Egress queue exhaustion',
    rationale: 'Final adversarial stage terminating in operational service denial.',
  },
]

export function ProgressionLifecycleVisual() {
  const [selectedIdx, setSelectedIdx] = useState<number>(1) // Default to Reconnaissance
  const current = STAGES[selectedIdx]

  return (
    <div className="progression-browser">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexWrap: 'wrap', gap: 10 }}>
        <div>
          <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#a1a1aa', letterSpacing: '0.1em', textTransform: 'uppercase' }}>
            15-STAGE ATTACK LIFECYCLE MODEL
          </span>
          <h3 style={{ fontSize: 20, fontWeight: 700, margin: '4px 0 0 0', color: '#ffffff' }}>
            Dynamic Stage Progression & Kinematics
          </h3>
        </div>
        <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#71717a' }}>
          * Illustrative telemetry shown for lifecycle demonstration
        </div>
      </div>

      {/* Stepper Scrubber Strip */}
      <div className="progression-stepper-strip" role="tablist" aria-label="15-Stage Attack Progression Stepper">
        {STAGES.map((s, idx) => {
          const isActive = idx === selectedIdx
          const tagClass = s.classification.toLowerCase()
          return (
            <button
              key={s.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              className={`progression-step-btn ${isActive ? 'active' : ''}`}
              onClick={() => setSelectedIdx(idx)}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                <span className="progression-step-num">STAGE {s.num}</span>
                <span className={`tag-badge ${tagClass}`} style={{ fontSize: 8.5, padding: '1px 4px' }}>
                  {s.classification}
                </span>
              </div>
              <span className="progression-step-label">{s.name}</span>
            </button>
          )
        })}
      </div>

      {/* Stage Detail Card */}
      <div className="progression-detail-grid">
        <div className="progression-detail-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#71717a', textTransform: 'uppercase' }}>
              STAGE {current.num} &middot; {current.phase}
            </span>
            <span className={`tag-badge ${current.classification.toLowerCase()}`}>
              [{current.classification}]
            </span>
          </div>

          <h4 style={{ fontSize: 22, fontWeight: 700, color: '#ffffff', margin: '0 0 8px 0' }}>
            {current.name}
          </h4>

          <p style={{ fontSize: 13.5, color: '#a1a1aa', lineHeight: 1.6, margin: '0 0 16px 0' }}>
            {current.rationale}
          </p>

          <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 6, padding: '12px 14px' }}>
            <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#71717a', marginBottom: 4 }}>
              GROUNDED MITRE ATT&CK MAPPING
            </div>
            <div style={{ fontSize: 13, fontFamily: 'monospace', fontWeight: 700, color: '#ffffff' }}>
              {current.mitre}
            </div>
          </div>
        </div>

        <div className="progression-detail-card" style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#71717a', textTransform: 'uppercase', marginBottom: 14 }}>
              SEPARATED CONFIDENCES & PHYSICAL TELEMETRY
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 16 }}>
              <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: 6, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <div style={{ fontSize: 10.5, fontFamily: 'monospace', color: '#a1a1aa' }}>STAGE CONFIDENCE</div>
                <div style={{ fontSize: 18, fontFamily: 'monospace', fontWeight: 800, color: '#ffffff' }}>
                  {(current.stageConfidence * 100).toFixed(0)}%
                </div>
              </div>
              <div style={{ background: 'rgba(255, 255, 255, 0.03)', padding: '10px 12px', borderRadius: 6, border: '1px solid rgba(255, 255, 255, 0.06)' }}>
                <div style={{ fontSize: 10.5, fontFamily: 'monospace', color: '#a1a1aa' }}>TECHNIQUE CERTAINTY</div>
                <div style={{ fontSize: 18, fontFamily: 'monospace', fontWeight: 800, color: '#38bdf8' }}>
                  {(current.techniqueConfidence * 100).toFixed(0)}%
                </div>
              </div>
            </div>

            <div style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid rgba(255, 255, 255, 0.08)', borderRadius: 6, padding: '12px 14px' }}>
              <div style={{ fontSize: 11, fontFamily: 'monospace', color: '#71717a', marginBottom: 4 }}>
                CORROBORATING PASSIVE WIRE TELEMETRY
              </div>
              <div style={{ fontSize: 12, fontFamily: 'monospace', color: '#34d399' }}>
                {current.telemetry}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 16, paddingTop: 12, borderTop: '1px solid rgba(255, 255, 255, 0.08)' }}>
            <span style={{ fontSize: 11, color: '#71717a' }}>
              Transition: S_{current.num} &rarr; S_{Math.min(15, parseInt(current.num, 10) + 1).toString().padStart(2, '0')}
            </span>
            <button
              type="button"
              className="button button-quiet"
              style={{ fontSize: 11, padding: '4px 10px', gap: 4 }}
              disabled={selectedIdx === STAGES.length - 1}
              onClick={() => setSelectedIdx(Math.min(STAGES.length - 1, selectedIdx + 1))}
            >
              Next Lifecycle Stage <ArrowRight size={12} />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
