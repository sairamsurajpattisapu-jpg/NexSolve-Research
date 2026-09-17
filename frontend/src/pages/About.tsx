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
