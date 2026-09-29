import { Link } from 'react-router-dom'
import {
  ArrowRight,
  FileText,
  Network,
  ShieldAlert,
  TrendingUp,
  Workflow,
} from 'lucide-react'

export function ConsoleProductPreview() {
  return (
    <div
      className="console-preview-frame"
      style={{
        width: '100%',
        maxWidth: '1120px',
        margin: '0 auto',
        background: '#070707',
        border: '1px solid #222222',
        borderRadius: '10px',
        overflow: 'hidden',
        boxShadow: '0 20px 48px rgba(0, 0, 0, 0.7)',
        fontFamily: 'var(--font-sans)',
      }}
    >
      {/* 1. Browser / Terminal Chrome Bar */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          padding: '10px 16px',
          background: '#0f0f0f',
          borderBottom: '1px solid #222222',
          flexWrap: 'wrap',
          gap: '8px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <div style={{ display: 'flex', gap: '6px' }}>
            <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: '#262626' }} />
            <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: '#262626' }} />
            <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: '#262626' }} />
          </div>
          <span
            style={{
              fontSize: '11px',
              fontFamily: 'var(--mono)',
              color: '#737373',
              marginLeft: '8px',
              background: '#050505',
              border: '1px solid #1f1f1f',
              padding: '2px 10px',
              borderRadius: '4px',
            }}
          >
            https://nexsolve.internal/console/overview
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <span
            style={{
              fontSize: '10.5px',
              fontFamily: 'var(--mono)',
              color: '#e5e5e5',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
            }}
          >
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#ffffff' }} />
            LIVE TELEMETRY
          </span>
          <span
            style={{
              fontSize: '10px',
              fontFamily: 'var(--mono)',
              padding: '2px 7px',
              border: '1px solid #333333',
              borderRadius: '3px',
              color: '#a3a3a3',
              textTransform: 'uppercase',
            }}
          >
            SOC ACTIVE
          </span>
        </div>
      </div>

      {/* 2. Mock Console Header & Telemetry Provenance */}
      <div
        style={{
          padding: '18px 22px',
          borderBottom: '1px solid #1a1a1a',
          background: '#0a0a0a',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
            <span
              style={{
                fontSize: '10px',
                fontFamily: 'var(--mono)',
                fontWeight: 700,
                color: '#ffffff',
                background: '#141414',
                border: '1px solid #282828',
                padding: '2px 6px',
                borderRadius: '3px',
              }}
            >
              PCAP INGESTION
            </span>
            <span style={{ fontSize: '11px', color: '#737373', fontFamily: 'var(--mono)' }}>
              SHA-256: d49a1...8f02e
            </span>
          </div>
          <div style={{ fontSize: '15.5px', fontWeight: 700, color: '#ffffff', letterSpacing: '-0.01em' }}>
            enterprise_perimeter_traffic.pcapng
          </div>
          <div
            style={{
              fontSize: '11.5px',
              fontFamily: 'var(--mono)',
              color: '#8a8a8a',
              marginTop: '4px',
              display: 'flex',
              gap: '10px',
              flexWrap: 'wrap',
            }}
          >
            <span>14 Windows (840s)</span>
            <span>&middot;</span>
            <span>18,492 Packets</span>
            <span>&middot;</span>
            <span>342 Flows</span>
            <span>&middot;</span>
            <span>45 Continuous Features</span>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <Link
            to="/console"
            className="button button-primary"
            style={{ fontSize: '11.5px', padding: '6px 12px', gap: '6px', height: '32px' }}
          >
            <span>Enter Console</span>
            <ArrowRight size={12} />
          </Link>
        </div>
      </div>

      {/* 3. Four Core Questions Mock Grid */}
      <div style={{ padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* ROW 1: WHAT IS HAPPENING? & WHAT COMES NEXT? */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '14px' }}>
          {/* Question 1: What is happening? */}
          <div
            style={{
              background: '#0d0d0d',
              border: '1px solid #1f1f1f',
              borderRadius: '8px',
              padding: '16px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#737373', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
                1. WHAT IS HAPPENING?
              </span>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '1px 6px', border: '1px solid #444', borderRadius: '3px', color: '#ffffff' }}>
                CURRENT STATE
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '10px' }}>
              <ShieldAlert size={20} color="#ffffff" />
              <div>
                <div style={{ fontSize: '14.5px', fontWeight: 700, color: '#ffffff' }}>
                  ELEVATED THREAT DETECTED
                </div>
                <div style={{ fontSize: '11.5px', color: '#a3a3a3' }}>
                  Observed Stage: Reconnaissance &rarr; Discovery
                </div>
              </div>
            </div>

            <p style={{ fontSize: '12px', color: '#8a8a8a', lineHeight: 1.5, margin: '0 0 10px 0' }}>
              High-rate SYN probes and sequential port sweeps observed against subnet internal gateway (10.0.4.15).
            </p>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px', fontFamily: 'var(--mono)', fontSize: '11px' }}>
              <div style={{ background: '#121212', border: '1px solid #222', padding: '6px 10px', borderRadius: '4px' }}>
                <span style={{ color: '#737373', display: 'block', fontSize: '10px' }}>P(ATTACK NOW)</span>
                <strong style={{ color: '#ffffff', fontSize: '13px' }}>74.2%</strong>
              </div>
              <div style={{ background: '#121212', border: '1px solid #222', padding: '6px 10px', borderRadius: '4px' }}>
                <span style={{ color: '#737373', display: 'block', fontSize: '10px' }}>MITRE TECHNIQUE</span>
                <strong style={{ color: '#ffffff', fontSize: '13px' }}>T1046 (Scan)</strong>
              </div>
            </div>
          </div>

          {/* Question 2: What comes next? */}
          <div
            style={{
              background: '#0d0d0d',
              border: '1px solid #1f1f1f',
              borderRadius: '8px',
              padding: '16px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#737373', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
                2. WHAT COMES NEXT?
              </span>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '1px 6px', border: '1px solid #444', borderRadius: '3px', color: '#ffffff' }}>
                ATTACK HORIZON
              </span>
            </div>

            <div style={{ fontSize: '14.5px', fontWeight: 700, color: '#ffffff', marginBottom: '4px' }}>
              Multi-Horizon Forecast Rollout (T+1 .. T+5)
            </div>
            <div style={{ fontSize: '11.5px', color: '#8a8a8a', marginBottom: '10px' }}>
              Compounding forward risk exposure reaching 98.4% by lookahead T+5.
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '6px' }}>
              {[
                { step: 'T+1', p: '34%', stage: 'Discovery' },
                { step: 'T+2', p: '52%', stage: 'C2 Setup' },
                { step: 'T+3', p: '68%', stage: 'Lateral' },
                { step: 'T+4', p: '79%', stage: 'Collection' },
                { step: 'T+5', p: '88%', stage: 'Exfil' },
              ].map((h) => (
                <div
                  key={h.step}
                  style={{
                    background: '#121212',
                    border: '1px solid #242424',
                    borderRadius: '4px',
                    padding: '6px 4px',
                    textAlign: 'center',
                  }}
                >
                  <div style={{ fontSize: '10px', fontFamily: 'var(--mono)', color: '#737373', fontWeight: 600 }}>{h.step}</div>
                  <div style={{ fontSize: '13px', fontFamily: 'var(--font-sans)', fontWeight: 700, color: '#ffffff', margin: '2px 0' }}>{h.p}</div>
                  <div style={{ fontSize: '8.5px', color: '#a3a3a3', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{h.stage}</div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ROW 2: WHY? & WHAT CAN I INVESTIGATE? */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '14px' }}>
          {/* Question 3: Why? (Evidence) */}
          <div
            style={{
              background: '#0d0d0d',
              border: '1px solid #1f1f1f',
              borderRadius: '8px',
              padding: '16px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#737373', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
                3. WHY? (GROUNDED EVIDENCE)
              </span>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '1px 6px', border: '1px solid #444', borderRadius: '3px', color: '#ffffff' }}>
                DRIVERS
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              {[
                { f: 'syn_count', imp: 'HIGH', desc: 'SYN packet velocity spikes 4.2x above historical window baseline.' },
                { f: 'unique_dst_ports', imp: 'HIGH', desc: 'Horizontal scanning across ports 22, 445, 3389, and 8080.' },
                { f: 'flow_duration_mean', imp: 'MED', desc: 'Short connection durations characteristic of automated reconnaissance.' },
              ].map((d) => (
                <div
                  key={d.f}
                  style={{
                    background: '#121212',
                    border: '1px solid #222222',
                    borderRadius: '4px',
                    padding: '6px 10px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '8px',
                  }}
                >
                  <div>
                    <span style={{ fontFamily: 'var(--mono)', fontSize: '11px', color: '#ffffff', fontWeight: 600 }}>{d.f}</span>
                    <p style={{ margin: 0, fontSize: '10.5px', color: '#8a8a8a', lineHeight: 1.3 }}>{d.desc}</p>
                  </div>
                  <span style={{ fontSize: '9px', fontFamily: 'var(--mono)', border: '1px solid #333', padding: '1px 5px', borderRadius: '2px', color: '#ffffff' }}>
                    {d.imp}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Question 4: What can I investigate? */}
          <div
            style={{
              background: '#0d0d0d',
              border: '1px solid #1f1f1f',
              borderRadius: '8px',
              padding: '16px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
              <span style={{ fontSize: '10.5px', fontFamily: 'var(--mono)', color: '#737373', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
                4. WHAT CAN I INVESTIGATE?
              </span>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '1px 6px', border: '1px solid #444', borderRadius: '3px', color: '#ffffff' }}>
                WORKSPACES
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '8px' }}>
              <div style={{ background: '#121212', border: '1px solid #222', borderRadius: '4px', padding: '8px 10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#ffffff', fontSize: '11.5px', fontWeight: 600 }}>
                  <Network size={12} /> Traffic Flows
                </div>
                <div style={{ fontSize: '10.5px', color: '#737373', marginTop: '2px' }}>5-tuple inspection &amp; filtering</div>
              </div>

              <div style={{ background: '#121212', border: '1px solid #222', borderRadius: '4px', padding: '8px 10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#ffffff', fontSize: '11.5px', fontWeight: 600 }}>
                  <TrendingUp size={12} /> Forecast Rollout
                </div>
                <div style={{ fontSize: '10.5px', color: '#737373', marginTop: '2px' }}>T+1..T+5 trajectory tree</div>
              </div>

              <div style={{ background: '#121212', border: '1px solid #222', borderRadius: '4px', padding: '8px 10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#ffffff', fontSize: '11.5px', fontWeight: 600 }}>
                  <Workflow size={12} /> Progression
                </div>
                <div style={{ fontSize: '10.5px', color: '#737373', marginTop: '2px' }}>Kill-chain transitions</div>
              </div>

              <div style={{ background: '#121212', border: '1px solid #222', borderRadius: '4px', padding: '8px 10px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#ffffff', fontSize: '11.5px', fontWeight: 600 }}>
                  <FileText size={12} /> Reports
                </div>
                <div style={{ fontSize: '10.5px', color: '#737373', marginTop: '2px' }}>HTML &amp; JSON exports</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* 4. Frame Footer CTA */}
      <div
        style={{
          background: '#09090b',
          borderTop: '1px solid #1a1a1a',
          padding: '14px 22px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
        }}
      >
        <div style={{ fontSize: '12.5px', color: '#888888' }}>
          Explore full network analysis, forecasting trajectories, and evidence attribution in the console.
        </div>
        <Link
          to="/console"
          className="button button-primary"
          style={{ fontSize: '12.5px', padding: '8px 18px', gap: '8px', height: '36px' }}
        >
          <span>OPEN THE NEXSOLVE CONSOLE</span>
          <ArrowRight size={13} />
        </Link>
      </div>
    </div>
  )
}
