import { Link } from 'react-router-dom'
import {
  Cpu,
  Eye,
  Shield,
  Sparkles,
  Target,
  Terminal,
} from 'lucide-react'
import { Panel } from '../components/Ui'

export function About() {
  return (
    <div className="page-stack page-enter about-page">
      {/* Hero */}
      <section className="about-hero">
        <div className="about-hero-tag">
          <span className="provenance-pill status-pill">MISSION & ETHOS</span>
          <span className="provenance-pill live-pill">SIH 2026 #26153</span>
        </div>
        <h1 className="about-title">Anticipation Over Reaction</h1>
        <p className="about-subtitle">
          NexSolve was engineered to solve a fundamental deficiency in computer security: modern SOCs respond only after breach indicators appear. We build world models that anticipate trajectories before attacks materialize.
        </p>
      </section>

      {/* The Core Mission */}
      <Panel className="about-mission-panel">
        <div className="panel-header-simple">
          <div>
            <span className="panel-eyebrow">PURPOSE</span>
            <h2 className="panel-title">Why We Built NexSolve</h2>
          </div>
          <span className="provenance-pill reference-pill">SYSTEM PHILOSOPHY</span>
        </div>

        <p className="mission-lead">
          Intrusion Detection Systems (IDS) and Endpoint Detection & Response (EDR) are inherently retrospective. They detect signatures of packets that have already arrived, files that have already dropped, and connections that have already compromised perimeter hosts.
        </p>
        <p className="mission-body">
          Under Smart India Hackathon Problem Statement 26153 (<em>"AI based Network Attack Forecasting from Network Traffic Data"</em>), our objective was to formalize network defense as an autoregressive state simulation problem. By learning the physical dynamics of normal network flows, NexSolve projects future network states across multiple horizons (T+1 to T+5) and alerts analysts to impending threat conditions with genuine lead time.
        </p>
      </Panel>

      {/* Guiding Principles Grid */}
      <section className="principles-section">
        <div className="section-heading-wrap">
          <span className="panel-eyebrow">ENGINEERING VALUES</span>
          <h2 className="section-title">Core Principles</h2>
          <p className="section-desc">
            The scientific constraints and engineering standards that guide every line of code in NexSolve.
          </p>
        </div>

        <div className="principles-detail-grid">
          <div className="principle-card">
            <div className="principle-icon-wrap">
              <Shield size={20} className="text-accent" />
            </div>
            <h3>1. Scientific Honesty Above Hype</h3>
            <p>
              We do not claim 99.9% accuracy with fabricated features. If a baseline like the Persistence Champion calibrates better than an unconstrained deep LSTM, we publish that truth and place deep models on scientific hold.
            </p>
          </div>

          <div className="principle-card">
            <div className="principle-icon-wrap">
              <Cpu size={20} className="text-accent" />
            </div>
            <h3>2. Zero Synthetic Fabrication</h3>
            <p>
              Passive network taps cannot accurately measure round-trip time without active probe injections. We eliminated <code>mean_tcp_rtt</code> from our feature vector rather than substituting zeros or synthetic heuristics.
            </p>
          </div>

          <div className="principle-card">
            <div className="principle-icon-wrap">
              <Eye size={20} className="text-accent" />
            </div>
            <h3>3. Attribution Transparency</h3>
            <p>
              Every forecasted alert is decomposed into supporting vs contradictory evidence nodes via Feature Perturbation Attribution. SOC analysts are never forced to trust an opaque probability scalar.
            </p>
          </div>

          <div className="principle-card">
            <div className="principle-icon-wrap">
              <Target size={20} className="text-accent" />
            </div>
            <h3>4. Operational Air-Gapped Usability</h3>
            <p>
              Critical national infrastructure cannot depend on cloud APIs or outbound internet connectivity. NexSolve runs 100% locally with zero phone-home calls.
            </p>
          </div>
        </div>
      </section>

      {/* The Problem Statement Context */}
      <Panel className="sih-context-panel">
        <div className="sih-context-content">
          <span className="panel-eyebrow">SIH 2026 SPECIFICATION</span>
          <h3>Problem Statement ID: 26153</h3>
          <p>
            <strong>Title:</strong> AI based Network Attack Forecasting from Network Traffic Data
          </p>
          <p>
            <strong>Core Mandate:</strong> Build an AI system that learns the evolving state of a computer network from traffic telemetry and predicts the likelihood and progression of malicious activity across multiple future time steps.
          </p>
          <div className="sih-badges">
            <span className="contract-chip">Domain: Cybersecurity</span>
            <span className="contract-chip">Category: Software</span>
            <span className="contract-chip">Focus: Multi-Step World Model</span>
          </div>
        </div>
      </Panel>

      {/* CTA */}
      <section className="about-cta-strip">
        <div className="cta-strip-content">
          <h2>Experience the forecasting platform</h2>
          <p>
            Launch the interactive console, inspect live packet telemetry, or explore our pre-loaded judge demonstration scenarios.
          </p>
        </div>
        <div className="cta-strip-actions">
          <Link to="/analyze" className="button button-primary">
            <Terminal size={15} /> Launch Console
          </Link>
          <Link to="/demo" className="button button-quiet">
            <Sparkles size={15} style={{ color: 'var(--accent)' }} /> Explore Judge Demo
          </Link>
        </div>
      </section>
    </div>
  )
}
