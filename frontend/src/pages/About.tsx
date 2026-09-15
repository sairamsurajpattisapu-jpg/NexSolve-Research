import { Link } from 'react-router-dom'

export function About() {
  return (
    <div className="page-stack page-enter about-editorial-container">
      {/* Editorial Header */}
      <section className="editorial-page-header">
        <div className="editorial-meta-tag">
          MISSION & SCIENTIFIC PRINCIPLES
        </div>
        <h1 className="editorial-display-heading">
          About NexSolve
        </h1>
        <p className="editorial-lead-text">
          Anticipating adversarial network progression through temporal state modeling rather than retrospective signature triage.
        </p>
      </section>

      <div className="editorial-hr" />

      {/* Editorial 4-Part Narrative */}
      <section className="about-editorial-sections">
        <div className="about-editorial-row">
          <div className="about-row-label">
            <span>01</span>
            <h2>WHAT IT IS</h2>
          </div>
          <div className="about-row-body">
            <p>
              NexSolve is a scientific network attack forecasting platform built for defensive cybersecurity operations.
              Operating passively from raw packet streams or discrete 60-second telemetry windows, it models continuous network state
              and projects adversarial trajectory across forward lookahead horizons (T+1 through T+5).
            </p>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        <div className="about-editorial-row">
          <div className="about-row-label">
            <span>02</span>
            <h2>WHY IT EXISTS</h2>
          </div>
          <div className="about-row-body">
            <p>
              Traditional intrusion detection systems alert defenders after packets deliver payloads and hosts compromise.
              Under Smart India Hackathon Problem Statement 26153, NexSolve reframes network security as an autoregressive state simulation problem —
              granting security analysts proactive lead time before full kill-chain execution.
            </p>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        <div className="about-editorial-row">
          <div className="about-row-label">
            <span>03</span>
            <h2>SCIENTIFIC INTEGRITY</h2>
          </div>
          <div className="about-row-body">
            <p>
              We reject synthetic heuristics and uncalibrated deep models. NexSolve strictly omits unobservable passive metrics
              such as <code>mean_tcp_rtt</code> under an audited 45-feature contract, enforces deliberate abstention when historical context is insufficient,
              and benchmarks all candidates against a rigorous Persistence Champion baseline.
            </p>
          </div>
        </div>

        <div className="editorial-hr-subtle" />

        <div className="about-editorial-row">
          <div className="about-row-label">
            <span>04</span>
            <h2>LIMITATIONS</h2>
          </div>
          <div className="about-row-body">
            <p>
              NexSolve is designed for structured network telemetry and passive observation taps. It does not perform active payload exploitation,
              does not claim zero-loss prevention guarantees, and treats counterfactual rollouts as modelled scenario explorations
              rather than deterministic physical certainties.
            </p>
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
            <Link to="/analyze" className="button button-primary">
              Launch Console
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
