import { Link } from 'react-router-dom'
import { ArrowRight, ShieldCheck, Cpu, Database, Award } from 'lucide-react'

export function About() {
  return (
    <div className="page-stack page-enter about-editorial-container">
      {/* Editorial Header */}
      <section className="editorial-page-header">
        <div className="editorial-meta-tag">
          MISSION &amp; SCIENTIFIC PRINCIPLES
        </div>
        <h1 className="editorial-display-heading">
          About NexSolve
        </h1>
        <p className="editorial-lead-text">
          Anticipating adversarial network progression through temporal state modeling rather than retrospective signature triage.
        </p>
      </section>

      <div className="editorial-hr" />

      {/* Editorial 4-Part Structured Narrative */}
      <section className="about-editorial-sections">
        {/* 01. What It Is */}
        <div className="about-editorial-row">
          <div className="about-row-label">
            <span>01</span>
            <h2>WHAT IT IS</h2>
          </div>
          <div className="about-row-body">
            <p>
              NexSolve is a scientific network attack forecasting engine built for active security defense.
              Ingesting passive packet streams across discrete 60-second telemetry windows, it models continuous network state
              and projects adversarial trajectory across prospective lookahead horizons (T+1 through T+5).
            </p>
            <div className="editorial-tag-row">
              <span className="editorial-badge"><Database size={11} /> 45-FEATURE SCHEMA</span>
              <span className="editorial-badge">60s TUMBLING WINDOWS</span>
              <span className="editorial-badge">T+1 &rarr; T+5 HORIZONS</span>
              <span className="editorial-badge">PASSIVE OBSERVATION</span>
            </div>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        {/* 02. Why It Exists */}
        <div className="about-editorial-row">
          <div className="about-row-label">
            <span>02</span>
            <h2>WHY IT EXISTS</h2>
          </div>
          <div className="about-row-body">
            <p>
              Traditional intrusion detection systems alert defenders after packets deliver payloads and hosts are compromised.
              NexSolve reframes network security as an autoregressive state simulation problem —
              granting security analysts verified lead time before full kill-chain execution.
            </p>
            <div className="editorial-tag-row">
              <span className="editorial-badge"><ShieldCheck size={11} /> PROACTIVE LEAD TIME</span>
              <span className="editorial-badge">STATE SIMULATION</span>
              <span className="editorial-badge">KILL-CHAIN MAPPING</span>
            </div>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        {/* 03. Scientific Integrity */}
        <div className="about-editorial-row">
          <div className="about-row-label">
            <span>03</span>
            <h2>SCIENTIFIC INTEGRITY</h2>
          </div>
          <div className="about-row-body">
            <p>
              Under our audited Zero-Fabrication Contract, metrics that cannot be genuinely observed from passive packet taps —
              most critically <code>mean_tcp_rtt</code> — are permanently excluded from the 45-feature schema rather than zero-filled or approximated with synthetic heuristics.
            </p>
            <div className="editorial-tag-row">
              <span className="editorial-badge"><Award size={11} /> ZERO FABRICATION</span>
              <span className="editorial-badge">STRICT ABSTENTION</span>
              <span className="editorial-badge">AUDITED CONTRACT</span>
            </div>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        {/* 04. Design Principles */}
        <div className="about-editorial-row">
          <div className="about-row-label">
            <span>04</span>
            <h2>DESIGN PRINCIPLES</h2>
          </div>
          <div className="about-row-body">
            <p>
              Local compute execution guarantees zero external telemetry leakage. All candidate models are benchmarked
              against a rigorous Persistence Champion baseline, and forecasts withhold automatically when continuous history is fewer than 8 windows (&lt; 480s).
            </p>
            <div className="editorial-tag-row">
              <span className="editorial-badge"><Cpu size={11} /> LOCAL COMPUTE</span>
              <span className="editorial-badge">PERSISTENCE CHAMPION</span>
              <span className="editorial-badge">CRYPTOGRAPHIC AUDIT</span>
            </div>
          </div>
        </div>
      </section>

      <div className="editorial-hr" />

      {/* From Detection to Forecasting: Comparative Analysis */}
      <section className="about-comparison-section" style={{ padding: '24px 0 8px 0' }}>
        <div className="editorial-meta-tag">
          PARADIGM SHIFT
        </div>
        <h2 style={{ fontSize: '26px', fontWeight: 700, margin: '8px 0 6px 0', color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
          From Detection to Forecasting
        </h2>
        <p style={{ fontSize: '15px', fontWeight: 500, color: 'var(--text-secondary)', margin: '0 0 12px 0' }}>
          How NexSolve differs from conventional network-security workflows
        </p>
        <p style={{ fontSize: '14px', lineHeight: 1.6, color: 'var(--text-muted)', maxWidth: '820px', margin: '0 0 36px 0' }}>
          Most network-security workflows focus on observing, analyzing, and detecting threats in current or historical traffic. NexSolve extends this workflow with temporal network-state modeling and future attack-state forecasting.
        </p>

        {/* Key Visual: Workflow Evolution */}
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '24px',
            marginBottom: '40px',
          }}
        >
          {/* Traditional Workflow */}
          <div
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              padding: '24px 20px',
              display: 'flex',
              flexDirection: 'column',
            }}
          >
            <div style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.08em', marginBottom: '20px' }}>
              TRADITIONAL SECURITY WORKFLOW
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px', flex: 1, justifyContent: 'center' }}>
              {['Traffic', 'Observe', 'Analyze', 'Detect', 'Alert'].map((step, idx, arr) => (
                <div key={step} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '100%' }}>
                  <div
                    style={{
                      width: '100%',
                      maxWidth: '220px',
                      padding: '8px 12px',
                      borderRadius: '5px',
                      background: 'var(--bg-secondary)',
                      border: '1px solid var(--border)',
                      textAlign: 'center',
                      fontSize: '13px',
                      fontWeight: 600,
                      color: 'var(--text-secondary)',
                      fontFamily: 'var(--mono)',
                    }}
                  >
                    {step}
                  </div>
                  {idx < arr.length - 1 && (
                    <div style={{ color: 'var(--text-muted)', fontSize: '13px', lineHeight: '18px', margin: '2px 0' }}>
                      &darr;
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          {/* NexSolve Workflow */}
          <div
            style={{
              background: 'var(--bg-surface)',
              border: '1.5px solid var(--text-primary)',
              borderRadius: '8px',
              padding: '24px 20px',
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 2px 12px rgba(0, 0, 0, 0.04)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
              <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '0.08em' }}>
                NEXSOLVE
              </span>
              <span style={{ fontSize: '10px', fontFamily: 'var(--mono)', padding: '2px 8px', borderRadius: '4px', background: 'var(--text-primary)', color: 'var(--bg-primary)', fontWeight: 700 }}>
                STATE &amp; FORECAST
              </span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px', flex: 1, justifyContent: 'center' }}>
              {['Traffic', 'Network State', 'Temporal Behavior', 'Detect', 'Forecast', 'Attack Horizon', 'Evidence'].map((step, idx, arr) => (
                <div key={step} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '100%' }}>
                  <div
                    style={{
                      width: '100%',
                      maxWidth: '230px',
                      padding: '7px 12px',
                      borderRadius: '5px',
                      background: idx >= 4 ? 'var(--button-secondary-bg)' : 'var(--bg-secondary)',
                      border: idx >= 4 ? '1px solid var(--text-primary)' : '1px solid var(--border)',
                      textAlign: 'center',
                      fontSize: '12.5px',
                      fontWeight: idx >= 4 ? 700 : 600,
                      color: 'var(--text-primary)',
                      fontFamily: 'var(--mono)',
                    }}
                  >
                    {step}
                  </div>
                  {idx < arr.length - 1 && (
                    <div style={{ color: 'var(--text-primary)', fontSize: '12px', lineHeight: '16px', fontWeight: 700 }}>
                      &darr;
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Comparison Table Section */}
        <div style={{ marginBottom: '16px' }}>
          <div className="editorial-meta-tag">
            CAPABILITY ARCHITECTURE
          </div>
          <h3 style={{ fontSize: '20px', fontWeight: 700, margin: '6px 0 8px 0', color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            Capability Comparison
          </h3>
        </div>

        {/* Responsive Horizontal Scroll Container */}
        <div
          style={{
            overflowX: 'auto',
            border: '1px solid var(--border)',
            borderRadius: '8px',
            background: 'var(--bg-surface)',
            marginBottom: '14px',
          }}
        >
          <table
            style={{
              width: '100%',
              minWidth: '680px',
              borderCollapse: 'collapse',
              textAlign: 'left',
              fontSize: '13px',
            }}
          >
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)' }}>
                <th style={{ padding: '12px 16px', fontWeight: 700, color: 'var(--text-primary)', fontFamily: 'var(--mono)', fontSize: '11.5px', width: '34%' }}>
                  Capability
                </th>
                <th style={{ padding: '12px 12px', fontWeight: 600, color: 'var(--text-secondary)', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: '11px' }}>
                  Wireshark
                </th>
                <th style={{ padding: '12px 12px', fontWeight: 600, color: 'var(--text-secondary)', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: '11px' }}>
                  Zeek
                </th>
                <th style={{ padding: '12px 12px', fontWeight: 600, color: 'var(--text-secondary)', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: '11px' }}>
                  Suricata
                </th>
                <th style={{ padding: '12px 12px', fontWeight: 600, color: 'var(--text-secondary)', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: '11px' }}>
                  Snort
                </th>
                <th style={{ padding: '12px 12px', fontWeight: 600, color: 'var(--text-secondary)', textAlign: 'center', fontFamily: 'var(--mono)', fontSize: '11px' }}>
                  RITA
                </th>
                <th
                  style={{
                    padding: '12px 14px',
                    fontWeight: 700,
                    color: 'var(--text-primary)',
                    textAlign: 'center',
                    fontFamily: 'var(--mono)',
                    fontSize: '11.5px',
                    background: 'var(--bg-secondary)',
                    borderLeft: '1.5px solid var(--text-primary)',
                    borderRight: '1.5px solid var(--text-primary)',
                  }}
                >
                  NexSolve
                </th>
              </tr>
            </thead>
            <tbody>
              {[
                { cap: 'Packet Inspection', ws: '✓', zk: '◐', su: '◐', sn: '◐', rt: '—', nx: '✓' },
                { cap: 'Network Telemetry', ws: '◐', zk: '✓', su: '✓', sn: '✓', rt: '✓', nx: '✓' },
                { cap: 'Flow Analysis', ws: '◐', zk: '✓', su: '✓', sn: '✓', rt: '✓', nx: '✓' },
                { cap: 'Protocol Analysis', ws: '✓', zk: '✓', su: '✓', sn: '✓', rt: '✓', nx: '✓' },
                { cap: 'Behavioral Analysis', ws: '✓', zk: '✓', su: '✓', sn: '✓', rt: '✓', nx: '✓' },
                { cap: 'Signature / Rule Detection', ws: '—', zk: '◐', su: '✓', sn: '✓', rt: '—', nx: '✓' },
                { cap: 'PCAP Analysis', ws: '✓', zk: '✓', su: '✓', sn: '✓', rt: '◐', nx: '✓' },
                { cap: 'Temporal Network-State Modeling', ws: '—', zk: '—', su: '—', sn: '—', rt: '◐', nx: '✓' },
                { cap: 'Attack Progression Modeling', ws: '—', zk: '—', su: '—', sn: '—', rt: '◐', nx: '✓' },
                { cap: 'Future Attack-State Forecasting', ws: '—', zk: '—', su: '—', sn: '—', rt: '—', nx: '✓' },
                { cap: 'Multi-Horizon Forecasting', ws: '—', zk: '—', su: '—', sn: '—', rt: '—', nx: '✓' },
                { cap: 'Attack-Onset Forecasting', ws: '—', zk: '—', su: '—', sn: '—', rt: '—', nx: '✓' },
                { cap: 'Attack Horizon', ws: '—', zk: '—', su: '—', sn: '—', rt: '—', nx: '✓' },
                { cap: 'Evidence-Linked Forecasting', ws: '—', zk: '◐', su: '◐', sn: '◐', rt: '◐', nx: '✓' },
                { cap: 'Uncertainty-Aware Forecasting', ws: '—', zk: '—', su: '—', sn: '—', rt: '—', nx: '✓' },
                { cap: 'Analyst Reporting', ws: '✓', zk: '✓', su: '✓', sn: '✓', rt: '✓', nx: '✓' },
              ].map((row, idx, arr) => (
                <tr
                  key={row.cap}
                  style={{
                    borderBottom: idx < arr.length - 1 ? '1px solid var(--border)' : 'none',
                    background: idx % 2 === 1 ? 'rgba(0,0,0,0.015)' : 'transparent',
                  }}
                >
                  <td style={{ padding: '10px 16px', color: 'var(--text-primary)', fontWeight: 500 }}>
                    {row.cap}
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'center', fontFamily: 'var(--mono)', color: row.ws === '✓' ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    {row.ws}
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'center', fontFamily: 'var(--mono)', color: row.zk === '✓' ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    {row.zk}
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'center', fontFamily: 'var(--mono)', color: row.su === '✓' ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    {row.su}
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'center', fontFamily: 'var(--mono)', color: row.sn === '✓' ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    {row.sn}
                  </td>
                  <td style={{ padding: '10px 12px', textAlign: 'center', fontFamily: 'var(--mono)', color: row.rt === '✓' ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    {row.rt}
                  </td>
                  <td
                    style={{
                      padding: '10px 14px',
                      textAlign: 'center',
                      fontFamily: 'var(--mono)',
                      fontWeight: 700,
                      color: 'var(--text-primary)',
                      background: 'var(--bg-secondary)',
                      borderLeft: '1.5px solid var(--text-primary)',
                      borderRight: '1.5px solid var(--text-primary)',
                    }}
                  >
                    {row.nx}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Legend / Disclaimers */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px', fontSize: '11px', fontFamily: 'var(--mono)', color: 'var(--text-muted)', marginBottom: '40px' }}>
          <div>
            <span>✓ = Core capability</span> &middot; <span>◐ = Partial / workflow-dependent</span> &middot; <span>— = Not a primary capability</span>
          </div>
          <div>
            Conceptual capability comparison, not a benchmark or ranking.
          </div>
        </div>

        {/* NexSolve Differentiators (Below the Table) */}
        <div style={{ marginBottom: '16px' }}>
          <div className="editorial-meta-tag">
            NEXSOLVE DIFFERENTIATORS
          </div>
          <h3 style={{ fontSize: '20px', fontWeight: 700, margin: '6px 0 8px 0', color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
            Core Platform Innovations
          </h3>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))',
            gap: '16px',
            marginBottom: '16px',
          }}
        >
          {[
            {
              num: '01',
              title: 'TEMPORAL NETWORK STATE',
              desc: 'Transforms observed network traffic into structured temporal network states.',
            },
            {
              num: '02',
              title: 'FUTURE-STATE FORECASTING',
              desc: 'Models how network behavior evolves and forecasts future attack states across multiple horizons.',
            },
            {
              num: '03',
              title: 'ATTACK HORIZON',
              desc: 'Turns temporal forecasts into an analyst-facing view of potential attack progression.',
            },
            {
              num: '04',
              title: 'EVIDENCE-DRIVEN DECISIONS',
              desc: 'Connects forecasts to observed network behavior and supporting evidence.',
            },
          ].map((card) => (
            <div
              key={card.num}
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                padding: '18px 16px',
                display: 'flex',
                flexDirection: 'column',
                gap: '8px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px' }}>
                <span style={{ fontSize: '12px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                  {card.num}
                </span>
                <span style={{ fontSize: '11px', fontFamily: 'var(--mono)', fontWeight: 700, color: 'var(--text-muted)', letterSpacing: '0.04em' }}>
                  {card.title}
                </span>
              </div>
              <p style={{ margin: 0, fontSize: '13px', lineHeight: 1.55, color: 'var(--text-secondary)' }}>
                {card.desc}
              </p>
            </div>
          ))}
        </div>
      </section>

      <div className="editorial-hr" />

      {/* Bottom CTA */}
      <section className="editorial-footer-cta">
        <div className="editorial-cta-wrap">
          <span className="editorial-eyebrow">RESEARCH PLATFORM</span>
          <h2>Explore the methodology and live system.</h2>
          <div className="editorial-btn-group" style={{ marginTop: '20px' }}>
            <Link to="/console/analyze" className="button button-primary" style={{ gap: '6px' }}>
              <span>START</span> <ArrowRight size={13} />
            </Link>
            <Link to="/research" className="button button-secondary">
              Read Research
            </Link>
          </div>
        </div>
      </section>
    </div>
  )
}
